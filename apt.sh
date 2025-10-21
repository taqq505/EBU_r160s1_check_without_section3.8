sudo apt update

# 基本ツール
sudo apt install -y nmap nikto binwalk sslscan openssl git curl python3 python3-pip

# パスワード攻撃ツール（必要なら）
# hydra は強力で影響があるので、conf.json の許可が出ている時のみ導入
sudo apt install -y hydra

# OWASP ZAP (GUI/CLI) - Debian/Ubuntu のパッケージ名は distro による
sudo apt install -y zaproxy || echo "zaproxy install failed - consider manual install from ZAP site"

# Greenbone / OpenVAS（注意：セットアップが複雑。別途ドキュメント参照）
# Ubuntu のパッケージ名やセットアップ手順はディストリにより差異があります。
# 例（環境によっては gvm / openvas のメタパッケージが使える場合あり）
sudo apt install -y gvm || echo "gvm/openvas may require manual setup - see Greenbone docs"

# binwalk の Python 依存を整える（binwalk 本体は apt で入るが、pip 依存もある）
sudo pip3 install pycryptodome

# （推奨）nuclei のインストールは apt にないことが多いので公式の方法で：
# golang があれば go install で入れる方法、もしくは GitHub release からバイナリを落とす方法が確実です。
sudo apt install -y golang-go
export GOPATH=$HOME/go
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
# nuclei binary は $GOPATH/bin に入るので PATH に追加するか /usr/local/bin へコピー
cp "$GOPATH/bin/nuclei" /usr/local/bin/ || true
