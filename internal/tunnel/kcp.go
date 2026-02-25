package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/smartlink/slp-client/internal/config"
	"github.com/smartlink/slp-client/internal/protocol"
	"github.com/xtaci/kcp-go/v5"
)

type KCPTunnel struct {
	cfg       *config.TunnelConfig
	conn      *kcp.UDPSession
	mu        sync.Mutex
	connected bool
	done      chan struct{}
}

func NewKCPTunnel(cfg *config.TunnelConfig) *KCPTunnel {
	return &KCPTunnel{
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

// Connect establishes the KCP connection and starts the heartbeat goroutine.
// This is the public entry point; heartbeat is started only here (not on reconnect).
func (t *KCPTunnel) Connect() error {
	if err := t.connectInternal(); err != nil {
		return err
	}

	// Start heartbeat (only from Connect, reconnect reuses the same goroutine)
	go t.heartbeat()

	return nil
}

// connectInternal establishes connection and authenticates, without starting heartbeat.
// Used by both Connect() (initial) and reconnect() (auto-recovery).
func (t *KCPTunnel) connectInternal() error {
	addr := fmt.Sprintf("%s:%d", t.cfg.Server, t.cfg.Port)

	// 加密（与服务端一致）
	key := []byte("slp-kcp-key-0123")
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// FEC 配置
	dataShards := 10
	parityShards := 3

	log.Printf("[%s] Connecting to %s (KCP)...", t.cfg.Name, addr)

	// KCP 库不支持 context，使用 goroutine + timer 实现超时
	type dialResult struct {
		conn *kcp.UDPSession
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		c, e := kcp.DialWithOptions(addr, newBlockCrypt(block), dataShards, parityShards)
		ch <- dialResult{c, e}
	}()

	var conn *kcp.UDPSession
	select {
	case result := <-ch:
		if result.err != nil {
			return fmt.Errorf("failed to connect: %w", result.err)
		}
		conn = result.conn
	case <-time.After(30 * time.Second):
		return fmt.Errorf("KCP dial timeout after 30s")
	}

	// 设置 KCP 参数
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(1024, 1024)
	conn.SetMtu(1350)
	conn.SetACKNoDelay(true)

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	// 认证
	if err := t.authenticate(); err != nil {
		conn.Close()
		return err
	}

	t.mu.Lock()
	t.connected = true
	t.mu.Unlock()

	log.Printf("[%s] Connected and authenticated", t.cfg.Name)
	return nil
}

func (t *KCPTunnel) authenticate() error {
	if err := protocol.WriteAuthFrame(t.conn, t.cfg.Token); err != nil {
		return fmt.Errorf("failed to write auth: %w", err)
	}

	success, err := protocol.ReadAuthResponse(t.conn)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if !success {
		return protocol.ErrAuthFailed
	}

	return nil
}

func (t *KCPTunnel) heartbeat() {
	interval := t.cfg.Keepalive
	if interval <= 0 {
		interval = 15
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	failCount := 0

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.mu.Lock()
			err := protocol.WriteHeartbeat(t.conn)
			t.mu.Unlock()

			if err != nil {
				failCount++
				log.Printf("[%s] KCP heartbeat failed (%d/3): %v", t.cfg.Name, failCount, err)
				if failCount >= 3 {
					log.Printf("[%s] KCP heartbeat failed 3 consecutive times, reconnecting...", t.cfg.Name)
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
func (t *KCPTunnel) reconnect() {
	t.mu.Lock()
	t.connected = false
	if t.conn != nil {
		t.conn.Close()
	}
	t.mu.Unlock()

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-t.done:
			return
		default:
		}

		log.Printf("[%s] KCP reconnecting (backoff: %v)...", t.cfg.Name, backoff)
		time.Sleep(backoff)

		if err := t.connectInternal(); err != nil {
			log.Printf("[%s] KCP reconnect failed: %v", t.cfg.Name, err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("[%s] KCP reconnected successfully", t.cfg.Name)
		return
	}
}

func (t *KCPTunnel) Proxy(localConn net.Conn, targetAddr string, targetPort uint16) error {
	log.Printf("[%s] KCP Proxying to %s:%d", t.cfg.Name, targetAddr, targetPort)

	// 发送连接请求
	t.mu.Lock()
	err := protocol.WriteConnectFrame(t.conn, targetAddr, targetPort)
	t.mu.Unlock()

	if err != nil {
		return err
	}

	// 双向转发
	go func() {
		defer localConn.Close()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(t.conn, localConn)
		}()

		go func() {
			defer wg.Done()
			io.Copy(localConn, t.conn)
		}()

		wg.Wait()
	}()

	return nil
}

// ForwardDNS KCP 隧道不支持 DNS 转发（单连接复用，不适合独立 stream）
func (t *KCPTunnel) ForwardDNS(query []byte) ([]byte, error) {
	return nil, fmt.Errorf("ForwardDNS not supported on KCP")
}

func (t *KCPTunnel) Close() {
	close(t.done)
	if t.conn != nil {
		t.conn.Close()
	}
}

func (t *KCPTunnel) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

// blockCrypt 实现 kcp.BlockCrypt 接口
type blockCrypt struct {
	block cipher.Block
}

func newBlockCrypt(block cipher.Block) *blockCrypt {
	return &blockCrypt{block: block}
}

func (c *blockCrypt) Encrypt(dst, src []byte) {
	iv := make([]byte, c.block.BlockSize())
	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(dst, src)
}

func (c *blockCrypt) Decrypt(dst, src []byte) {
	iv := make([]byte, c.block.BlockSize())
	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(dst, src)
}

var _ kcp.BlockCrypt = (*blockCrypt)(nil)
var _ Tunnel = (*KCPTunnel)(nil)
