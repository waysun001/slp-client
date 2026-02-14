package tunnel

import (
	"net"

	"github.com/smartlink/slp-client/internal/config"
)

// Tunnel 隧道接口
type Tunnel interface {
	Connect() error
	Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error
	Close()
	IsConnected() bool
}

// New 根据配置创建隧道
func New(cfg *config.TunnelConfig) Tunnel {
	switch cfg.Transport {
	case "quic":
		return NewQUICTunnel(cfg)
	case "websocket":
		return NewWebSocketTunnel(cfg)
	case "kcp":
		return NewKCPTunnel(cfg)
	default:
		return NewQUICTunnel(cfg)
	}
}
