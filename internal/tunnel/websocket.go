package tunnel

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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
	// WebSocket 模式下，每次 Proxy 创建新连接，这里只标记为已连接
	t.connected = true
	log.Printf("[%s] WebSocket tunnel ready (connect on demand)", t.cfg.Name)
	return nil
}

func (t *WebSocketTunnel) Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error {
	// 每次代理请求创建新的 WebSocket 连接
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

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: t.cfg.Insecure,
		},
		HandshakeTimeout: 10 * time.Second,
	}

	log.Printf("[%s] WS connecting to %s for %s:%d", t.cfg.Name, u.String(), targetAddr, targetPort)

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
