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

func (t *KCPTunnel) Connect() error {
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

	conn, err := kcp.DialWithOptions(addr, newBlockCrypt(block), dataShards, parityShards)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// 设置 KCP 参数
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(1024, 1024)
	conn.SetMtu(1350)
	conn.SetACKNoDelay(true)

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
	ticker := time.NewTicker(time.Duration(t.cfg.Keepalive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.mu.Lock()
			protocol.WriteHeartbeat(t.conn)
			t.mu.Unlock()
		}
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
