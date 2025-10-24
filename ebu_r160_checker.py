#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EBU R160-s1 自動チェックツール（Hydra対応・全openポートWebスキャン版）
---------------------------------------------------
注意:
  - Hydra(ブルートフォース)を実行します。必ず対象管理者の許可を得てください。
  - sudo（root）実行を推奨します（nmap -sS を使う場合）。
  - conf.json の tools.hydra.protocols で対象プロトコルを指定できます。
---------------------------------------------------
"""

import argparse, subprocess, threading, sys, json, os, socket, datetime, html, shutil, pwd, xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

# ---------------------------
# Utility
# ---------------------------
def now_ts(): return datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
def vprint(*a, **k): print(*a, **k); sys.stdout.flush()

def run_subproc(cmd: List[str], timeout=600):
    vprint(f"    → 実行: {' '.join(cmd)} (timeout={timeout}s)")
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    full_out, full_err = [], []

    def reader(stream, collect):
        for line in iter(stream.readline, ""):
            collect.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
        stream.close()

    t_out = threading.Thread(target=reader, args=(p.stdout, full_out))
    t_err = threading.Thread(target=reader, args=(p.stderr, full_err))
    t_out.start(); t_err.start()

    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = 124
    t_out.join(); t_err.join()
    return rc, "".join(full_out), "".join(full_err)

# ---------------------------
# Tool discovery (robust)
# ---------------------------
COMMON_BIN_PATHS = [
    "/usr/local/bin", "/usr/bin", "/bin", "/sbin", "/usr/sbin", "/snap/bin"
]

def _path_from_login_shell_for_user(user: Optional[str]) -> str:
    try:
        if user and user != os.environ.get("USER"):
            rc = subprocess.run(["su", "-l", user, "-c", "echo \"$PATH\""], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
            return rc.stdout.strip()
        else:
            rc = subprocess.run(["bash", "-lc", "echo \"$PATH\""], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
            return rc.stdout.strip()
    except Exception:
        return os.environ.get("PATH", "")

def _go_bin_paths_for_user(user: Optional[str]) -> list:
    paths = []
    try:
        cmd = ["bash", "-lc", "go env GOBIN 2>/dev/null || (echo \"$(go env GOPATH 2>/dev/null)/bin\")"]
        if user and user != os.environ.get("USER"):
            cmd = ["su", "-l", user, "-c", "go env GOBIN 2>/dev/null || (echo \"$(go env GOPATH 2>/dev/null)/bin\")"]
        rc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
        p = rc.stdout.strip()
        if p:
            paths.append(p)
    except Exception:
        pass
    try:
        if user and user != os.environ.get("USER"):
            home = pwd.getpwnam(user).pw_dir
        else:
            home = os.path.expanduser("~")
        paths.append(os.path.join(home, "go", "bin"))
        paths.append(os.path.join(home, ".local", "bin"))
    except Exception:
        pass
    return [p for p in paths if p]

def which_executable(name: str, conf_tool_entry: dict = None) -> Optional[str]:
    # conf explicit path
    if conf_tool_entry:
        p = conf_tool_entry.get("path")
        if p:
            rp = os.path.abspath(os.path.expanduser(p))
            if os.path.isfile(rp) and os.access(rp, os.X_OK):
                return rp
    sw = shutil.which(name)
    if sw:
        return sw
    # common dirs + user-local
    user_home = os.path.expanduser("~")
    dirs = COMMON_BIN_PATHS + [os.path.join(user_home, "go", "bin"), os.path.join(user_home, ".local", "bin")]
    for d in dirs:
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        # check login shell PATH for SUDO_USER
        login_path = _path_from_login_shell_for_user(sudo_user)
        for d in login_path.split(":"):
            c = os.path.join(d, name)
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        # go bins for sudo_user
        for d in _go_bin_paths_for_user(sudo_user):
            c = os.path.join(d, name)
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
    # last resort: try command -v via shell
    try:
        rc = subprocess.run(["bash", "-lc", f"command -v {name}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
        p = rc.stdout.strip()
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    except Exception:
        pass
    return None

def resolve_tool(name: str, conf: dict) -> Optional[str]:
    tools_conf = conf.get("tools", {}) if conf else {}
    entry = tools_conf.get(name, {}) if tools_conf else None
    return which_executable(name, entry)

# ---------------------------
# Network Scan
# ---------------------------
def tcp_connect_scan(host:str,ports:List[int],timeout=1.5)->Dict[int,Any]:
    res={}
    vprint(f"  [TCP] 基本ポートスキャン ({len(ports)} ports)")
    for p in ports:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host,p))==0:
                res[p]={"state":"open"}; vprint(f"     - {p}/tcp OPEN")
            else:
                res[p]={"state":"closed"}
        except Exception as e:
            res[p]={"state":"error","error":str(e)}
        finally:
            s.close()
    return res

def run_nmap(host:str,conf:dict)->Dict[str,Any]:
    path=resolve_tool("nmap",conf)
    if not path: return {"note":"nmap_not_installed"}
    cmd=[path,"-sS","-sV","--version-intensity","0","-p-","-Pn","-T{}".format(conf.get("nmap",{}).get("timing_template",4)),"-oX","-",host]
    if os.geteuid()!=0:
        # non-root: use connect scan
        cmd[1]="-sT"
        vprint("    ※ 非root: nmap を -sT (connect) で実行します")
    rc,out,err=run_subproc(cmd,timeout=conf.get("timeouts",{}).get("nmap",900))
    if "</nmaprun>" not in out:
        out += "</nmaprun>"
    return {"rc":rc,"stdout":out,"stderr":err[:2000],"cmd":" ".join(cmd)}

def parse_nmap_open_ports(xml_text:str)->List[Dict[str,Any]]:
    out=[]
    if not xml_text:
        return out
    try:
        root=ET.fromstring(xml_text)
        for port in root.findall(".//port"):
            st=port.find("state")
            if not st or st.attrib.get("state")!="open": continue
            pid=int(port.attrib.get("portid",0))
            svc_el=port.find("service"); svc={}
            if svc_el is not None:
                svc["name"]=svc_el.attrib.get("name","")
                svc["product"]=svc_el.attrib.get("product","")
            # collect banner/script outputs if any
            banner = ""
            for script in port.findall("script"):
                banner += (script.attrib.get("output","") + "\n")
            out.append({"port":pid,"service":svc,"banner":banner.strip()})
    except ET.ParseError:
        pass
    return out

# ---------------------------
# External tools (nuclei/nikto/sslscan)
# ---------------------------
def run_nuclei(url:str,conf:dict):
    path=resolve_tool("nuclei",conf)
    if not path: return {"note":"nuclei_not_installed"}
    cmd=[path,"-u",url]
    # add severity if specified
    sev = conf.get("tools",{}).get("nuclei",{}).get("severity")
    if isinstance(sev,list) and len(sev)>0:
        cmd += ["-severity", ",".join(sev)]
    rc,out,err=run_subproc(cmd,timeout=conf.get("timeouts",{}).get("nuclei",600))
    return {"rc":rc,"stdout":out,"stderr":err}

def run_nikto(url:str,conf:dict):
    path=resolve_tool("nikto",conf)
    if not path: return {"note":"nikto_not_installed"}
    rc,out,err=run_subproc([path,"-h",url],timeout=conf.get("timeouts",{}).get("nikto",600))
    return {"rc":rc,"stdout":out,"stderr":err}

def run_sslscan(host:str,port:int,conf:dict):
    path=resolve_tool("sslscan",conf)
    if not path: return {"note":"sslscan_not_installed"}
    rc,out,err=run_subproc([path,f"{host}:{port}"],timeout=conf.get("timeouts",{}).get("sslscan",300))
    return {"rc":rc,"stdout":out,"stderr":err}

# ---------------------------
# Hydra wrapper
# ---------------------------
def infer_hydra_module(port:int, service:Dict[str,str], banner:str) -> Optional[str]:
    """Existing heuristic - returns a hydra module name or None"""
    name = service.get("name","").lower() if service else ""
    product = service.get("product","").lower() if service else ""
    if "ssh" in name or port == 22:
        return "ssh"
    if "ftp" in name or port == 21:
        return "ftp"
    if "telnet" in name or port == 23:
        return "telnet"
    # HTTP-like
    if "http" in name or "http" in product or "http/" in banner.lower() or port in (80,8080,8000,3000,3001,3002,9000,18870,18872):
        if port in (443,8443,9443):
            return "https-get"
        return "http-get"
    return None

def run_hydra_bruteforce(host:str, port:int, module:str, conf:dict) -> Dict[str,Any]:
    path = resolve_tool("hydra", conf)
    if not path:
        return {"note":"hydra_not_installed"}
    hydra_conf = conf.get("tools", {}).get("hydra", {})
    userlist = hydra_conf.get("userlist", "user.txt")
    passlist = hydra_conf.get("passlist", "pass.txt")
    threads = str(hydra_conf.get("threads", 4))
    stop_on_found = hydra_conf.get("stop_on_success", True)

    if not os.path.exists(userlist) or not os.path.exists(passlist):
        return {"note":"hydra_lists_missing", "userlist": userlist, "passlist": passlist}

    cmd = [path, "-L", userlist, "-P", passlist, "-s", str(port), "-t", threads, host, module]
    if stop_on_found:
        cmd.append("-f")
    rc, out, err = run_subproc(cmd, timeout=conf.get("timeouts",{}).get("hydra",300))
    return {"rc": rc, "stdout": out, "stderr": err, "cmd": " ".join(cmd)}

# ---------------------------
# HTMLレポート（簡易版）
# ---------------------------
def write_html_report(rpt:dict,outdir:str):
    host,ts=rpt["host"],rpt["timestamp"]
    html_fn=os.path.join(outdir,f"summary_{host}_{ts}.html")
    ports=sorted(rpt.get("ports_unified",[]),key=lambda x:x["port"])
    port_rows=""
    for pinfo in ports:
        p=pinfo["port"]
        st=pinfo.get("state","?")
        parts=[]
        if f"nuclei_{p}" in rpt:
            parts.append("<b>nuclei</b><pre>"+html.escape(rpt[f"nuclei_{p}"].get("stdout","")[:800])+"</pre>")
        if f"nikto_{p}" in rpt:
            parts.append("<b>nikto</b><pre>"+html.escape(rpt[f"nikto_{p}"].get("stdout","")[:800])+"</pre>")
        if f"sslscan_{p}" in rpt:
            parts.append("<b>sslscan</b><pre>"+html.escape(rpt[f"sslscan_{p}"].get("stdout","")[:800])+"</pre>")
        if f"hydra_result_{p}" in rpt:
            hr = rpt[f"hydra_result_{p}"]
            if hr.get("note"):
                parts.append("<b>hydra</b><pre>"+html.escape(str(hr.get("note")))+ "</pre>")
            else:
                parts.append("<b>hydra</b><pre>"+html.escape(hr.get("stdout","")[:1200])+"...</pre>")
        port_rows += f"<tr><td>{p}</td><td>{st}</td><td>{''.join(parts) or '—'}</td></tr>"

    html_out = f"""<!doctype html><html><head><meta charset='utf-8'><title>EBU R160 Report {host}</title>
<style>body{{font-family:sans-serif;margin:20px;}}th,td{{border:1px solid #ccc;padding:8px;vertical-align:top;}}table{{border-collapse:collapse;width:100%;}}pre{{background:#f9f9f9;padding:6px;white-space:pre-wrap;}}</style>
</head><body>
<h2>EBU R160-s1 自動検査レポート</h2>
<p>Target: <b>{host}</b>　Scan: {ts}</p>
<table><tr><th>Port</th><th>Status</th><th>Result</th></tr>{port_rows}</table>
<pre>{html.escape(rpt.get("nmap",{}).get("cmd",""))}</pre>
</body></html>"""
    with open(html_fn,"w",encoding="utf-8") as f: f.write(html_out)
    vprint(f"  → HTML出力: {html_fn}")
    return html_fn

# ---------------------------
# Main flow
# ---------------------------
def analyze_target(host:str,conf:dict):
    vprint(f"\n=== Scan start for: {host} ===")
    report = {"host": host, "timestamp": now_ts(), "conf_used_version": conf.get("version")}

    # quick tcp probe initial ports (configurable)
    probe_ports = conf.get("ports_to_probe_quick", [22,21,23,80,443,8080,8443,18870,18872,3000,3001,3002,9000])
    report["tcp_probe"] = tcp_connect_scan(host, probe_ports)

    # run nmap
    nmap_res = run_nmap(host, conf)
    report["nmap"] = {"cmd": nmap_res.get("cmd",""), "rc": nmap_res.get("rc"), "stderr": nmap_res.get("stderr","")[:2000]}
    nmap_stdout = nmap_res.get("stdout","")
    # parse open ports and service info from nmap
    nmap_ports = parse_nmap_open_ports(nmap_stdout)
    report["nmap_ports"] = nmap_ports

    # Merge tcp_probe and nmap discovered ports into unified port list
    unified_ports = {}
    # include all TCP probe entries
    for p,info in report["tcp_probe"].items():
        unified_ports[p] = {"port": p, "state": info.get("state"), "service": {}, "banner": ""}
    # overlay nmap findings (nmap wins)
    for np in nmap_ports:
        p = np["port"]
        unified_ports[p] = {"port": p, "state": "open", "service": np.get("service",{}), "banner": np.get("banner","")}

    report["ports_unified"] = list(unified_ports.values())

    # Detect tools
    report["tools_detected"] = {t: bool(resolve_tool(t, conf)) for t in ["nmap","nuclei","nikto","sslscan","hydra"]}

    # For each open port, run web scans (we take "suspect all open ports" approach)
    open_ports = [p for p,e in unified_ports.items() if e.get("state")=="open"]
    vprint(f"  → Open ports detected: {open_ports}")

    for port in sorted(open_ports):
        proto = "https" if port in (443,8443,9443) else "http"
        url = f"{proto}://{host}:{port}"
        vprint(f"  → Web scan on {url}")
        # nuclei / nikto / sslscan guarded by detection + conf
        if conf.get("tools",{}).get("nuclei",{}).get("enabled", True):
            report[f"nuclei_{port}"] = run_nuclei(url, conf)
        if conf.get("tools",{}).get("nikto",{}).get("enabled", True):
            report[f"nikto_{port}"] = run_nikto(url, conf)
        if conf.get("tools",{}).get("sslscan",{}).get("enabled", True):
            report[f"sslscan_{port}"] = run_sslscan(host, port, conf)

    # Hydra: brute-force across open ports, but only for protocols listed in conf.tools.hydra.protocols
    hydra_conf = conf.get("tools",{}).get("hydra",{})
    hydra_enabled = hydra_conf.get("enabled", False)
    hydra_protocols = hydra_conf.get("protocols", []) if isinstance(hydra_conf.get("protocols",[]), list) else []

    if hydra_enabled:
        vprint("  → Hydra brute-force enabled by configuration")
        for p,entry in unified_ports.items():
            if entry.get("state") != "open":
                continue
            svc = entry.get("service", {}) or {}
            banner = entry.get("banner","") or ""
            inferred = infer_hydra_module(p, svc, banner)
            if not inferred:
                vprint(f"    - {p}: protocol not inferred, skipping Hydra")
                report[f"hydra_result_{p}"] = {"note":"hydra_skipped_no_protocol"}
                continue
            # Only run if inferred protocol is allowed by conf (user-specified)
            if hydra_protocols and inferred not in hydra_protocols:
                vprint(f"    - {p}: inferred '{inferred}' not in hydra.protocols => skip")
                report[f"hydra_result_{p}"] = {"note":"hydra_skipped_not_in_config", "inferred": inferred}
                continue
            vprint(f"    - {p}: inferred '{inferred}' -> running Hydra")
            res = run_hydra_bruteforce(host, p, inferred, conf)
            report[f"hydra_result_{p}"] = res

    vprint("=== Scan finished ===")
    return report

# ---------------------------
# CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="EBU R160-s1 チェッカー（Hydra＋全open Web検査）")
    parser.add_argument("-t","--target", required=True, help="スキャン対象IP/ホスト")
    parser.add_argument("-c","--conf", default="conf.json", help="設定ファイル")
    parser.add_argument("-o","--outdir", default="reports", help="出力ディレクトリ")
    args = parser.parse_args()

    if not os.path.exists(args.conf):
        print(f"設定ファイル {args.conf} が見つかりません。")
        sys.exit(1)
    with open(args.conf, "r", encoding="utf-8") as f:
        conf = json.load(f)

    os.makedirs(args.outdir, exist_ok=True)
    rpt = analyze_target(args.target, conf)

    json_fn = os.path.join(args.outdir, f"report_{args.target}_{rpt['timestamp']}.json")
    with open(json_fn, "w", encoding="utf-8") as f:
        json.dump(rpt, f, indent=2, ensure_ascii=False)
    vprint(f"  → JSON出力: {json_fn}")

    html_fn = write_html_report(rpt, args.outdir)
    vprint(f"✅ 完了: {html_fn}\n")

if __name__ == "__main__":
    main()
