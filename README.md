# 🧩 EBU R160-s1 チェッカー

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()
[![Status](https://img.shields.io/badge/status-active-success)]()

軽量な **EBU R160-s1 準拠 自動チェックツール**  
3.8（パッシブ PCAP / トラフィック解析）を除外し、個別ホストを対象に  
自動スキャン → JSON & HTML レポートを生成します。

---

## 📘 概要

EBU R160-s1 の以下のカテゴリに対応します：

| カテゴリ | 内容 |
|-----------|------|
| 3.2 | Passive Checks（バナー / HTTP ヘッダ） |
| 3.3 | Port Scan / Service Detection（nmap） |
| 3.4 | Vulnerability Scan（nuclei / Greenbone 等） |
| 3.5 | Web Application Scan（nikto / ZAP） |
| 3.6 | Password Security（hydra / 辞書チェック） |
| 3.7 | Firmware Analysis（binwalk / strings） |
| 3.9 | Management Interfaces / Separation |
| 3.10 | Cryptography / Encryption（sslscan / testssl.sh） |

> 🛑 **3.8「Analysis of Network Traffic（pcap解析）」は除外済み**

---

## ⚙️ 主な機能

- `-t / --target` で単一ホスト指定（必須）
- `-c / --conf` で設定ファイル指定（デフォルト `conf.json`）
- `-o / --outdir` で出力先指定（デフォルト `reports/`）
- 進捗（nmap / sslscanなど）を**リアルタイム表示**
- 実行結果を **JSON + HTML** で自動保存

---

## 🧱 動作環境

- OS: Ubuntu / Debian 系 Linux  
- Python: 3.8 以上  
- 推奨ツール:  
  `nmap`, `nuclei`, `nikto`, `binwalk`, `sslscan`, `hydra`, `gvm (Greenbone/OpenVAS)`

---

## 🚀 インストール&使い方

### 1️⃣ システムパッケージ（Ubuntu / Debian）
```bash
sudo apt update
sudo apt install -y nmap nikto binwalk sslscan hydra git curl python3 python3-venv python3-pip
2️⃣ nuclei（Go 経由で導入）
bash
コードをコピーする
sudo apt install -y golang-go
export GOPATH=$HOME/go
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
sudo cp "$GOPATH/bin/nuclei" /usr/local/bin/ || true
3️⃣ （任意）仮想環境
bash
コードをコピーする
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
⚙️ 設定ファイル conf.json

---

💻 使い方
bash
コードをコピーする
python3 ebu_r160_checker.py -t 10.0.0.1 -c conf.json -o reports
CLI パラメータは短縮形式：

---

📄 出力ファイル
種類	形式	用途
JSON	report_<host>_<timestamp>.json	構造化データ（自動処理向け）
HTML	summary_<host>_<timestamp>.html	ビジュアルサマリ（印刷・共有用）

HTML 出力例（概要）：

html
コードをコピーする
<h2>TCPポート検出結果</h2>
<table>
<tr><th>Port</th><th>State</th><th>Banner</th></tr>
<tr><td>22</td><td>open</td><td>SSH-2.0-OpenSSH_8.2p1</td></tr>
<tr><td>80</td><td>open</td><td>nginx/1.18.0</td></tr>
...
</table>
⚠️ 安全上の注意
必ず対象管理者の許可を得てから実行してください。

hydra 等のパスワード攻撃ツールは非常に危険です。
→ conf.json の設定を false にしておくのが基本です。

nmap -p-, nikto, nuclei も高負荷スキャンのため、
safe_mode を有効にした状態で利用してください。

本ツールは 3.8（パッシブ PCAP 解析）を実施しません。
必要な場合は別途 Wireshark / tshark / Zeek 等を使用してください。

自動レポートには誤検出（False Positive）が含まれる場合があります。