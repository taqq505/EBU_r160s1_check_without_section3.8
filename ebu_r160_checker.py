#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EBU R160-s1 自動チェックツール（全ポートWebスキャン対応版）
---------------------------------------------------
目的:
  - nmapやbannerが取れなくても、全openポートを「HTTP/REST API疑い」として検査。
  - 18870や18872のようなREST API系ポートを確実に捕捉。
  - conf.jsonのhydra設定に従い、認証ブルートフォースも実施可能。

注意:
  - sudo推奨（nmap -sS使用のため）。
  - 許可を得た検査環境でのみ実行すること。
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
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    out=[]
    for line in iter(p.stdout.readline, ""):
        out.append(line); sys.stdout.write(line); sys.stdout.flush()
    try:
        rc=p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); rc=124
    return rc, "".join(out), ""

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
    cmd=[path,"-sS","-sV","--version-intensity","0","-p-","-Pn","-T4","-oX","-",host]
    if os.geteuid()!=0: cmd[1]="-sT"
    rc,out,err=run_subproc(cmd,timeout=conf.get("timeouts",{}).get("nmap",900))
    if "</nmaprun>" not in out: out+="</nmaprun>"
    return {"rc":rc,"stdout":out,"stderr":err[:2000],"cmd":" ".join(cmd)}

def parse_nmap_open_ports(xml_text:str)->List[Dict[str,Any]]:
    out=[]
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
            out.append({"port":pid,"service":svc})
    except Exception: pass
    return out

# ---------------------------
# External tools
# ---------------------------
def run_nuclei(url:str,conf:dict):
    path=resolve_tool("nuclei",conf)
    if not path: return {"note":"nuclei_not_installed"}
    rc,out,err=run_subproc([path,"-u",url],timeout=conf.get("timeouts",{}).get("nuclei",600))
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
# HTMLレポート生成
# ---------------------------
def write_html_report(rpt:dict,outdir:str):
    host,ts=rpt["host"],rpt["timestamp"]
    html_fn=os.path.join(outdir,f"summary_{host}_{ts}.html")
    ports=sorted(rpt.get("ports_unified",[]),key=lambda x:x["port"])
    port_rows=""
    for pinfo in ports:
        port=pinfo["port"]
        st=pinfo.get("state","?")
        web_result=""
        if f"nuclei_{port}" in rpt:
            web_result+="<b>nuclei:</b><pre>"+html.escape(rpt[f"nuclei_{port}"].get("stdout","")[:500])+"</pre>"
        if f"nikto_{port}" in rpt:
            web_result+="<b>nikto:</b><pre>"+html.escape(rpt[f"nikto_{port}"].get("stdout","")[:500])+"</pre>"
        if f"sslscan_{port}" in rpt:
            web_result+="<b>sslscan:</b><pre>"+html.escape(rpt[f"sslscan_{port}"].get("stdout","")[:500])+"</pre>"
        port_rows+=f"<tr><td>{port}</td><td>{st}</td><td>{web_result or '—'}</td></tr>"
    html_out=f"""<!doctype html><html><head><meta charset='utf-8'><title>EBU R160 Report {host}</title>
<style>
body{{font-family:sans-serif;margin:20px;}}th,td{{border:1px solid #ccc;padding:8px;vertical-align:top;}}
table{{border-collapse:collapse;width:100%;}}pre{{background:#f9f9f9;border:1px solid #eee;padding:6px;overflow:auto;}}
</style></head><body>
<h2>EBU R160-s1 自動検査レポート</h2>
<p>Target: <b>{host}</b>　Scan: {ts}</p>
<table><tr><th>Port</th><th>Status</th><th>Result</th></tr>{port_rows}</table>
<pre>{html.escape(rpt.get("nmap",{}).get("cmd",""))}</pre>
</body></html>"""
    with open(html_fn,"w",encoding="utf-8") as f: f.write(html_out)
    vprint(f"  → HTML出力: {html_fn}")
    return html_fn

# ---------------------------
# Main
# ---------------------------
def analyze_target(host:str,conf:dict):
    rpt={"host":host,"timestamp":now_ts(),"conf_used_version":conf.get("version")}
    # 基本ポートスキャン + nmap併用
    probe_ports=conf.get("ports_to_probe_quick",[22,21,23,80,443,8080,8443,18870,18872,3000,3001,3002,9000])
    tcpres=tcp_connect_scan(host,probe_ports)
    rpt["tcp_probe"]=tcpres
    nmapres=run_nmap(host,conf)
    rpt["nmap"]=nmapres
    nmap_ports=parse_nmap_open_ports(nmapres.get("stdout",""))
    rpt["nmap_ports"]=nmap_ports

    # 統合
    unified={}
    for p,info in tcpres.items():
        unified[p]={"port":p,"state":info["state"],"service":{}}
    for np in nmap_ports:
        unified[np["port"]]={"port":np["port"],"state":"open","service":np.get("service",{})}
    rpt["ports_unified"]=list(unified.values())

    # --- 全openポートに対してWebスキャン ---
    open_ports=[p for p,e in unified.items() if e["state"]=="open"]
    vprint(f"  → Open ports detected: {open_ports}")
    for p in sorted(open_ports):
        proto="https" if p in (443,8443,9443) else "http"
        url=f"{proto}://{host}:{p}"
        vprint(f"  → Web scan on {url}")
        rpt[f"nuclei_{p}"]=run_nuclei(url,conf)
        rpt[f"nikto_{p}"]=run_nikto(url,conf)
        rpt[f"sslscan_{p}"]=run_sslscan(host,p,conf)

    return rpt

def main():
    p=argparse.ArgumentParser(description="EBU R160-s1 チェッカー（全openポートWebスキャン版）")
    p.add_argument("-t","--target",required=True)
    p.add_argument("-c","--conf",default="conf.json")
    p.add_argument("-o","--outdir",default="reports")
    a=p.parse_args()
    with open(a.conf) as f: conf=json.load(f)
    os.makedirs(a.outdir,exist_ok=True)
    rpt=analyze_target(a.target,conf)
    json_fn=os.path.join(a.outdir,f"report_{a.target}_{rpt['timestamp']}.json")
    with open(json_fn,"w",encoding="utf-8") as f: json.dump(rpt,f,indent=2,ensure_ascii=False)
    vprint(f"  → JSON出力: {json_fn}")
    write_html_report(rpt,a.outdir)
    vprint("✅ 完了")

if __name__=="__main__":
    main()
