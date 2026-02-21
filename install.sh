#!/bin/bash
#
# SLP Client 一键安装脚本
# 将同目录下的预编译二进制安装到系统
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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

# 安装二进制（使用同目录下的文件）
install_binary() {
    local target="/usr/local/bin/slp-client"
    local local_bin="${SCRIPT_DIR}/slp-client-linux-${ARCH}"

    if [[ -f "$local_bin" ]]; then
        log_info "使用本地二进制: ${local_bin}"
        cp "$local_bin" "$target"
    else
        log_error "未找到二进制文件: ${local_bin}\n请将 slp-client-linux-${ARCH} 放在 install.sh 同目录下"
    fi

    chmod +x "${target}"
    log_info "已安装: ${target}"
}

install_binary

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
