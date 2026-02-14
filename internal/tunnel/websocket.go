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
	conn      *websocket.Conn
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

	log.Printf("[%s] Connecting to %s (WebSocket)...", t.cfg.Name, u.String())

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	t.conn = conn

	// 认证
	if err := t.authenticate(); err != nil {
		conn.Close()
		return err
	}

	t.connected = true
	log.Printf("[%s] Connected and authenticated", t.cfg.Name)

	// 启动心跳
	go t.heartbeat()

	return nil
}

func (t *WebSocketTunnel) authenticate() error {
	// 构建认证帧
	token := []byte(t.cfg.Token)
	frame := make([]byte, 4+len(token))
	frame[0] = protocol.Version
	frame[1] = protocol.AuthToken
	frame[2] = byte(len(token) >> 8)
	frame[3] = byte(len(token))
	copy(frame[4:], token)

	if err := t.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		return fmt.Errorf("failed to write auth: %w", err)
	}

	// 读取响应
	_, resp, err := t.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if len(resp) < 2 || resp[1] != 0x01 {
		return protocol.ErrAuthFailed
	}

	return nil
}

func (t *WebSocketTunnel) heartbeat() {
	ticker := time.NewTicker(time.Duration(t.cfg.Keepalive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.mu.Lock()
			err := t.conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.FrameHeartbeat, 0x00, 0x00})
			t.mu.Unlock()
			if err != nil {
				log.Printf("[%s] Heartbeat failed: %v", t.cfg.Name, err)
			}
		}
	}
}

func (t *WebSocketTunnel) Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error {
	// WebSocket 是单连接多路复用，这里简化处理
	// 实际应该用 stream ID 区分不同的代理连接
	
	log.Printf("[%s] WS Proxying to %s:%d", t.cfg.Name, targetAddr, targetPort)

	// 发送连接请求
	t.mu.Lock()
	// 构建连接帧
	addrBytes := []byte(targetAddr)
	frame := make([]byte, 3+len(addrBytes)+2)
	frame[0] = protocol.FrameTCP
	frame[1] = protocol.AddrDomain
	frame[2] = byte(len(addrBytes))
	copy(frame[3:], addrBytes)
	frame[3+len(addrBytes)] = byte(targetPort >> 8)
	frame[3+len(addrBytes)+1] = byte(targetPort)
	
	err := t.conn.WriteMessage(websocket.BinaryMessage, frame)
	t.mu.Unlock()
	
	if err != nil {
		return err
	}

	// 双向转发（简化版，实际需要更复杂的多路复用）
	go func() {
		defer localConn.Close()
		
		// local -> ws
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := localConn.Read(buf)
				if err != nil {
					return
				}
				t.mu.Lock()
				t.conn.WriteMessage(websocket.BinaryMessage, buf[:n])
				t.mu.Unlock()
			}
		}()

		// ws -> local
		for {
			_, data, err := t.conn.ReadMessage()
			if err != nil {
				return
			}
			localConn.Write(data)
		}
	}()

	return nil
}

func (t *WebSocketTunnel) Close() {
	close(t.done)
	if t.conn != nil {
		t.conn.Close()
	}
}

func (t *WebSocketTunnel) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

var _ Tunnel = (*WebSocketTunnel)(nil)
