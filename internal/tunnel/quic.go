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
	"github.com/smartlink/slp-client/internal/obfs"
	"github.com/smartlink/slp-client/internal/protocol"
)

// idleTimeoutReader wraps a reader with deadline-based idle timeout.
// On each Read call, it resets the read deadline so that idle streams
// are automatically closed after the timeout period.
type idleTimeoutReader struct {
	reader      io.Reader
	setDeadline func(time.Time) error
	timeout     time.Duration
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	if err := r.setDeadline(time.Now().Add(r.timeout)); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

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

// Connect establishes the QUIC connection and starts the heartbeat goroutine.
// This is the public entry point; heartbeat is started only here (not on reconnect).
func (t *QUICTunnel) Connect() error {
	if err := t.connectInternal(); err != nil {
		return err
	}

	// Start heartbeat (only from Connect, reconnect reuses the same goroutine)
	go t.heartbeat()

	return nil
}

// connectInternal establishes connection and authenticates, without starting heartbeat.
// Used by both Connect() (initial) and reconnect() (auto-recovery).
func (t *QUICTunnel) connectInternal() error {
	addr := fmt.Sprintf("%s:%d", t.cfg.Server, t.cfg.Port)

	tlsConfig := &tls.Config{
		NextProtos:         []string{"slp", "h3"},
		InsecureSkipVerify: t.cfg.Insecure,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      time.Duration(t.cfg.Keepalive) * time.Second,
		HandshakeIdleTimeout: 15 * time.Second,
	}

	var conn quic.Connection
	var err error

	// Dial context with 30s timeout to prevent infinite hang on weak networks
	dialCtx, dialCancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer dialCancel()

	if t.cfg.Obfs {
		obfsKey := t.cfg.ObfsKey
		if obfsKey == "" {
			obfsKey = t.cfg.Token
		}

		log.Printf("[%s] Connecting to %s (QUIC + Obfs)...", t.cfg.Name, addr)

		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("failed to resolve addr: %w", err)
		}

		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("failed to create UDP conn: %w", err)
		}

		obfsConn := obfs.NewObfsPacketConn(udpConn, obfsKey)

		tr := &quic.Transport{Conn: obfsConn}
		conn, err = tr.Dial(dialCtx, udpAddr, tlsConfig, quicConfig)
		if err != nil {
			udpConn.Close()
			return fmt.Errorf("failed to connect: %w", err)
		}
	} else {
		log.Printf("[%s] Connecting to %s (QUIC)...", t.cfg.Name, addr)
		conn, err = quic.DialAddr(dialCtx, addr, tlsConfig, quicConfig)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	// Authenticate
	if err := t.authenticate(); err != nil {
		conn.CloseWithError(1, "auth failed")
		return err
	}

	t.mu.Lock()
	t.connected = true
	t.mu.Unlock()

	log.Printf("[%s] Connected and authenticated", t.cfg.Name)
	return nil
}

func (t *QUICTunnel) authenticate() error {
	stream, err := t.conn.OpenStreamSync(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to open auth stream: %w", err)
	}

	if err := protocol.WriteAuthFrame(stream, t.cfg.Token); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write auth frame: %w", err)
	}

	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	success, err := protocol.ReadAuthResponse(stream)
	if err != nil {
		stream.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if !success {
		stream.Close()
		return protocol.ErrAuthFailed
	}

	t.authStream = stream
	return nil
}

func (t *QUICTunnel) heartbeat() {
	interval := t.cfg.Keepalive
	if interval <= 0 {
		interval = 15
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	failCount := 0

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			if err := t.sendHeartbeat(); err != nil {
				failCount++
				log.Printf("[%s] Heartbeat failed (%d/3): %v", t.cfg.Name, failCount, err)
				if failCount >= 3 {
					log.Printf("[%s] Heartbeat failed 3 consecutive times, reconnecting...", t.cfg.Name)
					t.reconnect()
					failCount = 0
				}
			} else {
				failCount = 0
			}
		}
	}
}

// reconnect performs auto-reconnect with exponential backoff.
// Called from heartbeat goroutine, so no new goroutine is spawned.
func (t *QUICTunnel) reconnect() {
	t.mu.Lock()
	t.connected = false
	if t.conn != nil {
		t.conn.CloseWithError(0, "reconnecting")
	}
	t.mu.Unlock()

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		log.Printf("[%s] Reconnecting (backoff: %v)...", t.cfg.Name, backoff)
		time.Sleep(backoff)

		if err := t.connectInternal(); err != nil {
			log.Printf("[%s] Reconnect failed: %v", t.cfg.Name, err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("[%s] Reconnected successfully", t.cfg.Name)
		return
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

// Proxy proxies a local connection through the QUIC tunnel to the target.
// Both directions use idle timeout to prevent hung streams from exhausting QUIC stream capacity.
func (t *QUICTunnel) Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error {
	t.mu.Lock()
	if !t.connected {
		t.mu.Unlock()
		return fmt.Errorf("tunnel not connected")
	}
	t.mu.Unlock()

	stream, err := t.conn.OpenStreamSync(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}

	if err := protocol.WriteConnectFrame(stream, targetAddr, targetPort); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write connect frame: %w", err)
	}

	log.Printf("[%s] Proxying to %s:%d", t.cfg.Name, targetAddr, targetPort)

	const idleTimeout = 60 * time.Second

	var wg sync.WaitGroup
	wg.Add(2)

	// local -> remote (idle timeout on local read)
	go func() {
		defer wg.Done()
		r := &idleTimeoutReader{
			reader:      localConn,
			setDeadline: localConn.SetReadDeadline,
			timeout:     idleTimeout,
		}
		io.Copy(stream, r)
		stream.Close()
	}()

	// remote -> local (idle timeout on stream read)
	go func() {
		defer wg.Done()
		r := &idleTimeoutReader{
			reader:      stream,
			setDeadline: stream.SetReadDeadline,
			timeout:     idleTimeout,
		}
		io.Copy(localConn, r)
		localConn.Close()
	}()

	wg.Wait()
	return nil
}

// ForwardDNS 通过 QUIC 隧道转发 DNS 查询（DNS-over-TCP）
// 服务端视为普通 TCP 代理到 8.8.8.8:53，无需任何修改
func (t *QUICTunnel) ForwardDNS(query []byte) ([]byte, error) {
	t.mu.Lock()
	if !t.connected {
		t.mu.Unlock()
		return nil, fmt.Errorf("tunnel not connected")
	}
	t.mu.Unlock()

	stream, err := t.conn.OpenStreamSync(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(10 * time.Second))

	// 发送 CONNECT 帧：目标 8.8.8.8:53
	if err := protocol.WriteConnectFrame(stream, "8.8.8.8", 53); err != nil {
		return nil, fmt.Errorf("failed to write connect frame: %w", err)
	}

	// DNS-over-TCP: 写入 [2-byte 长度][查询数据]
	lenBuf := make([]byte, 2)
	lenBuf[0] = byte(len(query) >> 8)
	lenBuf[1] = byte(len(query))
	if _, err := stream.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("failed to write DNS query length: %w", err)
	}
	if _, err := stream.Write(query); err != nil {
		return nil, fmt.Errorf("failed to write DNS query: %w", err)
	}

	// DNS-over-TCP: 读取 [2-byte 长度][响应数据]
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read DNS response length: %w", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen == 0 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DNS response length: %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}

	return resp, nil
}

func (t *QUICTunnel) Close() {
	t.cancel()
	if t.conn != nil {
		t.conn.CloseWithError(0, "client closed")
	}
}

func (t *QUICTunnel) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

var _ Tunnel = (*QUICTunnel)(nil)
