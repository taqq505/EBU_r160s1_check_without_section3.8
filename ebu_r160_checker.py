#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EBU R160-s1 自動チェックツール（v2025.10）
---------------------------------------------------
・3.8（パッシブ pcap 解析）は除外。
・conf.json で設定。
・--target でIPまたはホスト名を1台指定。
・進捗（verbose）は常時ON。
・出力：reports/ に JSON と HTML。
---------------------------------------------------
使用例:
  python3 ebu_r160_checker.py --target 10.0.0.12 --conf conf.json
"""

import argparse
import subprocess
import threading
import sys
import json
import os
import socket
import datetime
import html
from typing import List, Dict, Any

# -------------------------
# Utility
# -------------------------
def now_ts():
    return datetime.datetime.now().strftime("%Y%m%dT%H%M%S")

def which(cmd: str) -> bool:
    return subprocess.run(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def vprint(*a, **k):
    """進捗ログ（常時ON）"""
    print(*a, **k)
    sys.stdout.flush()

# -------------------------
# Stream付きサブプロセス実行
# -------------------------
def run_subproc(cmd: List[str], timeout=600, stream=True):
    vprint(f"    → 実行: {' '.join(cmd)}")
    if not stream:
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "Timeout"
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    full_out, full_err = [], []

    def reader(stream, collect, prefix=""):
        for line in iter(stream.readline, ""):
            collect.append(line)
            sys.stdout.write(prefix + line)
            sys.stdout.flush()
        stream.close()

    t_out = threading.Thread(target=reader, args=(proc.stdout, full_out, ""))
    t_err = threading.Thread(target=reader, args=(proc.stderr, full_err, ""))
    t_out.start(); t_err.start()

    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = 124
    t_out.join(); t_err.join()
    return rc, "".join(full_out), "".join(full_err)

# -------------------------
# TCPポート簡易スキャン
# -------------------------
def tcp_connect_scan(host: str, ports: List[int], timeout=2.0):
    res = {}
    vprint(f"  [1] TCPポートスキャン開始 ({len(ports)} ports)")
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((host, p))
            if rc == 0:
                try:
                    s.settimeout(1.0)
                    banner = s.recv(4096).decode('latin1', errors='ignore')
                except Exception:
                    banner = ""
                res[p] = {"state":"open", "banner": banner}
                vprint(f"     - {p}/tcp : OPEN")
            else:
                res[p] = {"state":"closed"}
        except Exception as e:
            res[p] = {"state":"error", "error": str(e)}
        finally:
            s.close()
    vprint(f"  → TCPスキャン完了。open={len([p for p,v in res.items() if v.get('state')=='open'])}")
    return res

# -------------------------
# Nmap 実行
# -------------------------
def run_nmap(host: str, conf: Dict[str,Any]):
    if not which("nmap"):
        vprint("  [2] nmap が見つかりません。スキップ。")
        return {"note":"nmap_not_installed"}
    vprint("  [2] nmapスキャン開始（時間がかかる場合があります）")
    cmd = ["nmap"]
    if conf["nmap"].get("use_syn_scan", False): cmd += ["-sS"]
    else: cmd += ["-sT"]
    if conf["nmap"].get("os_detection", False): cmd += ["-O"]
    if conf["nmap"].get("use_service_detection", False): cmd += conf["nmap"].get("service_detection_flags", ["-sV"])
    if conf["nmap"].get("scan_all_tcp_ports", False): cmd += ["-p-"]
    else: cmd += ["--top-ports", "1000"]
    if conf["nmap"].get("safe_mode", True): cmd += ["-Pn"]
    cmd += ["-T{}".format(conf["nmap"].get("timing_template",4)), "-oX", "-", host]
    rc, out, err = run_subproc(cmd, timeout=900, stream=True)
    vprint("  → nmap完了 (rc={})".format(rc))
    return {"rc":rc, "cmd":" ".join(cmd), "stdout":out, "stderr":err}

# -------------------------
# SSL/TLS チェック
# -------------------------
def run_sslscan(host: str):
    if not which("sslscan"):
        vprint("  [3] sslscan が見つかりません。スキップ。")
        return {"note":"sslscan_not_installed"}
    vprint("  [3] SSL/TLS チェック開始 (sslscan)")
    rc, out, err = run_subproc(["sslscan", host], timeout=120, stream=True)
    vprint("  → sslscan完了 (rc={})".format(rc))
    return {"rc":rc, "stdout":out[:3000], "stderr":err}

# -------------------------
# ツール検出
# -------------------------
def detect_tools():
    vprint("  [4] 利用可能なツールを確認中...")
    tools = {}
    for t in ["nmap","nuclei","nikto","binwalk","sslscan","hydra","gvm"]:
        tools[t] = which(t)
        vprint(f"     - {t}: {'✓' if tools[t] else '×'}")
    return tools

# -------------------------
# レポートHTML生成
# -------------------------
def write_html_report(report: Dict[str,Any], outdir: str):
    host = report["host"]
    ts = report["timestamp"]
    html_fn = os.path.join(outdir, f"summary_{host}_{ts}.html")
    tcp = report.get("tcp_probe", {})
    open_ports = [(p,v) for p,v in tcp.items() if v.get("state")=="open"]
    html_out = f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<title>EBU R160-s1 Report {host}</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#222;}}
h1{{color:#114b8a;}} th,td{{padding:6px 10px;border-bottom:1px solid #eee;}}
th{{background:#f3f6fb;}} .open{{color:#fff;background:#2a9d8f;padding:2px 6px;border-radius:3px;}}
.closed{{color:#fff;background:#6c757d;padding:2px 6px;border-radius:3px;}}
</style></head><body>
<h1>EBU R160-s1 自動チェックレポート</h1>
<p>ターゲット: <b>{host}</b>　実行時刻: {ts}</p>
<h2>1) TCPポート検出結果</h2>
<table><tr><th>Port</th><th>State</th><th>Banner</th></tr>"""
    for p,v in tcp.items():
        st = v.get("state")
        color = "open" if st=="open" else "closed"
        banner = html.escape(v.get("banner",""))[:120]
        html_out += f"<tr><td>{p}</td><td><span class='{color}'>{st}</span></td><td>{banner}</td></tr>"
    html_out += "</table><h2>2) nmap 概要</h2><pre>{}</pre>".format(html.escape(report.get("nmap",{}).get("cmd","")))
    html_out += "<h2>3) SSL/TLS チェック</h2><pre>{}</pre>".format(html.escape(report.get("sslscan",{}).get("stdout","")[:1500]))
    html_out += "<h2>4) 検出ツール</h2><ul>"
    for t,ok in report.get("tools_detected",{}).items():
        html_out += f"<li>{t}: {'✓' if ok else '×'}</li>"
    html_out += "</ul><hr><p style='color:#666;font-size:smaller'>自動レポートは偽陽性を含む可能性があります。3.8 (PCAP解析) は本ツールから除外。</p></body></html>"
    with open(html_fn,"w",encoding="utf-8") as f: f.write(html_out)
    vprint(f"  → HTMLレポート出力: {html_fn}")
    return html_fn

# -------------------------
# メイン処理
# -------------------------
def analyze_target(host: str, conf: Dict[str,Any]):
    vprint(f"\n===== {host} のスキャン開始 =====")
    report = {"host": host, "timestamp": now_ts(), "conf_used_version": conf.get("version")}
    ports = conf.get("ports_to_probe_quick", [22,80,443,8080,8443])
    report["tcp_probe"] = tcp_connect_scan(host, ports)
    report["nmap"] = run_nmap(host, conf) if conf.get("enable_nmap", True) else {"note":"nmap disabled"}
    report["sslscan"] = run_sslscan(host)
    report["tools_detected"] = detect_tools()
    vprint(f"===== {host} のスキャン完了 =====\n")
    return report

# -------------------------
# エントリポイント
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="EBU R160-s1 チェッカー（進捗付き）")
    parser.add_argument("-t","--target", required=True, help="スキャン対象のIPまたはホスト名")
    parser.add_argument("-c","--conf", default="conf.json", help="設定ファイル（conf.json）")
    parser.add_argument("-o","--outdir", default="reports", help="レポート出力ディレクトリ")
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
    vprint(f"  → JSONレポート出力: {json_fn}")

    html_fn = write_html_report(rpt, args.outdir)
    vprint(f"✅ レポート生成完了: {html_fn}\n")

if __name__ == "__main__":
    main()
