#!/bin/bash
#
# SLP Client 一键安装脚本
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 检查架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       log_error "不支持的架构: $ARCH" ;;
esac

# 检查 Go
if ! command -v go &> /dev/null; then
    log_info "安装 Go 1.21..."
    wget -q --show-progress https://go.dev/dl/go1.21.6.linux-${ARCH}.tar.gz -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# 检查 Git
if ! command -v git &> /dev/null; then
    log_info "安装 Git..."
    apt-get update -qq && apt-get install -y -qq git || yum install -y -q git
fi

# 克隆并编译
log_info "克隆仓库..."
rm -rf /tmp/slp-client
git clone --depth 1 https://github.com/waysun001/slp-client.git /tmp/slp-client
cd /tmp/slp-client

log_info "编译中..."
export PATH=$PATH:/usr/local/go/bin
go mod tidy
CGO_ENABLED=0 go build -ldflags "-s -w" -o /usr/local/bin/slp-client ./cmd/slp-client/

# 清理
cd /
rm -rf /tmp/slp-client

log_info "安装完成！"
echo ""
echo "使用方法："
echo "  slp-client -s 服务器IP -t 你的token -insecure"
echo ""
echo "示例："
echo "  slp-client -s 1.2.3.4 -t test123 -insecure"
echo ""
echo "测试代理："
echo "  curl --socks5 127.0.0.1:1080 https://ip.sb"
