package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/smartlink/slp-client/internal/config"
	"github.com/smartlink/slp-client/internal/protocol"
)

type QUICTunnel struct {
	cfg        *config.TunnelConfig
	conn       quic.Connection
	authStream quic.Stream
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	connected  bool
}

func NewQUICTunnel(cfg *config.TunnelConfig) *QUICTunnel {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICTunnel{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (t *QUICTunnel) Connect() error {
	addr := fmt.Sprintf("%s:%d", t.cfg.Server, t.cfg.Port)

	tlsConfig := &tls.Config{
		NextProtos:         []string{"slp", "h3"},
		InsecureSkipVerify: t.cfg.Insecure,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: time.Duration(t.cfg.Keepalive) * time.Second,
	}

	log.Printf("[%s] Connecting to %s (QUIC)...", t.cfg.Name, addr)

	conn, err := quic.DialAddr(t.ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	t.conn = conn

	// 认证
	if err := t.authenticate(); err != nil {
		conn.CloseWithError(1, "auth failed")
		return err
	}

	t.connected = true
	log.Printf("[%s] Connected and authenticated", t.cfg.Name)

	// 启动心跳
	go t.heartbeat()

	return nil
}

func (t *QUICTunnel) authenticate() error {
	stream, err := t.conn.OpenStreamSync(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to open auth stream: %w", err)
	}

	// 发送认证帧
	if err := protocol.WriteAuthFrame(stream, t.cfg.Token); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write auth: %w", err)
	}

	// 读取响应
	success, err := protocol.ReadAuthResponse(stream)
	if err != nil {
		stream.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	stream.Close()

	if !success {
		return protocol.ErrAuthFailed
	}

	return nil
}

func (t *QUICTunnel) heartbeat() {
	interval := t.cfg.Keepalive
	if interval <= 0 {
		interval = 15 // 默认 15 秒
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			if err := t.sendHeartbeat(); err != nil {
				log.Printf("[%s] Heartbeat failed: %v", t.cfg.Name, err)
				// TODO: 触发重连
			}
		}
	}
}

func (t *QUICTunnel) sendHeartbeat() error {
	stream, err := t.conn.OpenStreamSync(t.ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(5 * time.Second))

	if err := protocol.WriteHeartbeat(stream); err != nil {
		return err
	}

	return protocol.ReadHeartbeatResponse(stream)
}

// Proxy 代理一个连接到目标
func (t *QUICTunnel) Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error {
	t.mu.Lock()
	if !t.connected {
		t.mu.Unlock()
		return fmt.Errorf("tunnel not connected")
	}
	t.mu.Unlock()

	// 打开新的 stream
	stream, err := t.conn.OpenStreamSync(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}

	// 发送目标地址
	if err := protocol.WriteConnectFrame(stream, targetAddr, targetPort); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write connect frame: %w", err)
	}

	log.Printf("[%s] Proxying to %s:%d", t.cfg.Name, targetAddr, targetPort)

	// 双向转发（在当前 goroutine 中阻塞执行）
	var wg sync.WaitGroup
	wg.Add(2)

	// local -> remote
	go func() {
		defer wg.Done()
		io.Copy(stream, localConn)
		stream.Close() // 关闭写方向
	}()

	// remote -> local
	go func() {
		defer wg.Done()
		io.Copy(localConn, stream)
		localConn.Close() // 关闭写方向
	}()

	wg.Wait()
	return nil
}

func (t *QUICTunnel) Close() {
	t.cancel()
	if t.conn != nil {
		t.conn.CloseWithError(0, "client shutdown")
	}
}

func (t *QUICTunnel) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}
