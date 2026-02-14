package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	tls "github.com/refraction-networking/utls"
	"github.com/smartlink/slp-client/internal/config"
	"github.com/smartlink/slp-client/internal/protocol"
)

type WebSocketTunnel struct {
	cfg       *config.TunnelConfig
	mu        sync.Mutex
	connected bool
	done      chan struct{}
}

func NewWebSocketTunnel(cfg *config.TunnelConfig) *WebSocketTunnel {
	return &WebSocketTunnel{
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

func (t *WebSocketTunnel) Connect() error {
	t.connected = true
	log.Printf("[%s] WebSocket tunnel ready (connect on demand)", t.cfg.Name)
	return nil
}

// dialTLSWithFingerprint 使用 Chrome 指纹建立 TLS 连接
func (t *WebSocketTunnel) dialTLSWithFingerprint(ctx context.Context, network, addr string) (net.Conn, error) {
	// 先建立 TCP 连接
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// 提取主机名
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	// 使用 utls 建立 TLS 连接，模拟 Chrome 指纹
	tlsConn := tls.UClient(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.cfg.Insecure,
	}, tls.HelloChrome_Auto) // 自动选择最新 Chrome 指纹

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (t *WebSocketTunnel) Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error {
	scheme := "wss"
	path := t.cfg.WSPath
	if path == "" {
		path = "/ws"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", t.cfg.Server, t.cfg.Port),
		Path:   path,
	}

	// 使用自定义 TLS 拨号器（Chrome 指纹）
	dialer := websocket.Dialer{
		NetDialTLSContext:  t.dialTLSWithFingerprint,
		HandshakeTimeout:   10 * time.Second,
	}

	log.Printf("[%s] WS connecting to %s (Chrome fingerprint)", t.cfg.Name, u.String())

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// 认证
	token := []byte(t.cfg.Token)
	authFrame := make([]byte, 4+len(token))
	authFrame[0] = protocol.Version
	authFrame[1] = protocol.AuthToken
	authFrame[2] = byte(len(token) >> 8)
	authFrame[3] = byte(len(token))
	copy(authFrame[4:], token)

	if err := conn.WriteMessage(websocket.BinaryMessage, authFrame); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write auth: %w", err)
	}

	_, resp, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if len(resp) < 2 || resp[1] != 0x01 {
		conn.Close()
		return protocol.ErrAuthFailed
	}

	// 发送连接请求
	addrBytes := []byte(targetAddr)
	connectFrame := make([]byte, 3+len(addrBytes)+2)
	connectFrame[0] = protocol.FrameTCP
	connectFrame[1] = protocol.AddrDomain
	connectFrame[2] = byte(len(addrBytes))
	copy(connectFrame[3:], addrBytes)
	connectFrame[3+len(addrBytes)] = byte(targetPort >> 8)
	connectFrame[3+len(addrBytes)+1] = byte(targetPort)

	if err := conn.WriteMessage(websocket.BinaryMessage, connectFrame); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write connect: %w", err)
	}

	log.Printf("[%s] WS Proxying to %s:%d", t.cfg.Name, targetAddr, targetPort)

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// local -> ws
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	// ws -> local
	go func() {
		defer wg.Done()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if _, err := localConn.Write(data); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	conn.Close()
	localConn.Close()
	return nil
}

func (t *WebSocketTunnel) Close() {
	close(t.done)
}

func (t *WebSocketTunnel) IsConnected() bool {
	return t.connected
}

var _ Tunnel = (*WebSocketTunnel)(nil)
