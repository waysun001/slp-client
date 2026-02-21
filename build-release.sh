#!/bin/bash
#
# SLP Client 交叉编译打包脚本
# 输出到 release/ 目录
#

set -e

VERSION="${VERSION:-1.0.0}"
BUILD_TIME=$(date +%Y%m%d%H%M%S)
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"
RELEASE_DIR="release"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 检查 Go 编译器
command -v go &> /dev/null || log_error "Go 未安装，请先安装 Go 1.21+"

# 清理并创建输出目录
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

log_info "开始编译 SLP Client v${VERSION} ..."

# 标准架构: amd64, arm64
for arch in amd64 arm64; do
    output="${RELEASE_DIR}/slp-client-linux-${arch}"
    log_info "编译 linux/${arch} -> ${output}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
        go build -ldflags "${LDFLAGS}" -o "${output}" ./cmd/slp-client/
    chmod +x "${output}"
done

# MIPS 架构 (OpenWrt 路由器, softfloat)
for arch in mipsle mips; do
    output="${RELEASE_DIR}/slp-client-linux-${arch}"
    log_info "编译 linux/${arch} (softfloat) -> ${output}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" GOMIPS=softfloat \
        go build -ldflags "${LDFLAGS}" -o "${output}" ./cmd/slp-client/
    chmod +x "${output}"
done

echo ""
log_info "编译完成！输出文件:"
ls -lh "${RELEASE_DIR}/"

echo ""
log_info "上传到服务器示例:"
echo "  scp ${RELEASE_DIR}/slp-client-linux-* user@your-server.com:/var/www/slp/"
echo "  # 或"
echo "  rsync -avz ${RELEASE_DIR}/slp-client-linux-* user@your-server.com:/var/www/slp/"
