# SLP Client
V1.01.08
SmartLink Protocol 客户端 - 支持 Linux 服务器测试和 OpenWrt 路由器

## 编译

```bash
# Linux AMD64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o slp-client ./cmd/slp-client/

# Linux ARM64 (OpenWrt 路由器)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o slp-client-arm64 ./cmd/slp-client/
```

## 快速测试（命令行模式）

```bash
# 最简单的测试
./slp-client -s 服务器IP -t 你的token -insecure

# 完整参数
./slp-client \
  -s 1.2.3.4 \
  -p 443 \
  -t your-secret-token \
  -transport quic \
  -l 1080 \
  -insecure

# 参数说明
#   -s          服务器地址
#   -p          服务器端口（默认 443）
#   -t          认证 token
#   -transport  传输模式：quic/websocket/kcp（默认 quic）
#   -l          本地 SOCKS5 端口（默认 1080）
#   -insecure   跳过 TLS 验证（自签名证书需要）
```

## 配置文件模式

```bash
./slp-client -c client.yaml
```

配置文件示例：
```yaml
log_level: info

tunnels:
  - name: "us-server"
    enabled: true
    server: "1.2.3.4"
    port: 443
    transport: "quic"
    token: "your-token-here"
    local_port: 1080
    insecure: true
    keepalive: 15

  - name: "jp-server"
    enabled: true
    server: "5.6.7.8"
    port: 8443
    transport: "websocket"
    ws_path: "/ws"
    token: "another-token"
    local_port: 1081
    insecure: true
```

## 测试代理

```bash
# 启动客户端后，测试 SOCKS5 代理
curl --socks5 127.0.0.1:1080 https://ip.sb

# 应该显示服务器的出口 IP
```

## 测试流程

### 1. 部署服务端
```bash
# 在 VPS 上
./install.sh
# 记下输出的 token
```

### 2. 启动客户端
```bash
# 在测试机上
./slp-client -s VPS_IP -t TOKEN -insecure
```

### 3. 验证
```bash
# 测试连通性
curl --socks5 127.0.0.1:1080 https://ip.sb

# 测试速度
curl --socks5 127.0.0.1:1080 -o /dev/null https://speed.cloudflare.com/__down?bytes=100000000
```
