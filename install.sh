#!/bin/bash
#
# SLP Client 一键安装脚本
# 从预编译二进制安装，不依赖 Go/Git
#

set -e

# ========== 下载地址（部署前替换为实际服务器地址） ==========
DOWNLOAD_BASE_URL="https://your-server.com/slp"
# ===========================================================

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

# 下载预编译二进制
download_binary() {
    local url="${DOWNLOAD_BASE_URL}/slp-client-linux-${ARCH}"
    local target="/usr/local/bin/slp-client"

    log_info "下载二进制: ${url}"

    if command -v curl &> /dev/null; then
        curl -fSL --progress-bar -o "${target}" "${url}" || log_error "下载失败: ${url}"
    elif command -v wget &> /dev/null; then
        wget -q --show-progress -O "${target}" "${url}" || log_error "下载失败: ${url}"
    else
        log_error "需要 curl 或 wget，请先安装"
    fi

    chmod +x "${target}"
    log_info "已安装: ${target}"
}

download_binary

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
