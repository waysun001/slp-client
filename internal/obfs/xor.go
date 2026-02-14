package obfs

import (
	"crypto/sha256"
	"net"
	"sync"
)

// XORObfuscator 基于密钥的 XOR 混淆器
type XORObfuscator struct {
	key []byte
}

// NewXORObfuscator 创建混淆器
func NewXORObfuscator(password string) *XORObfuscator {
	// 用 SHA256 扩展密码为固定长度密钥
	hash := sha256.Sum256([]byte(password))
	return &XORObfuscator{key: hash[:]}
}

// Obfuscate 混淆数据
func (o *XORObfuscator) Obfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(o.key)
	for i, b := range data {
		result[i] = b ^ o.key[i%keyLen]
	}
	return result
}

// Deobfuscate 解混淆数据（XOR 是对称的）
func (o *XORObfuscator) Deobfuscate(data []byte) []byte {
	return o.Obfuscate(data) // XOR 两次还原
}

// ObfsPacketConn 混淆的 UDP 连接
type ObfsPacketConn struct {
	net.PacketConn
	obfs *XORObfuscator
	mu   sync.Mutex
}

// NewObfsPacketConn 包装 UDP 连接
func NewObfsPacketConn(conn net.PacketConn, password string) *ObfsPacketConn {
	return &ObfsPacketConn{
		PacketConn: conn,
		obfs:       NewXORObfuscator(password),
	}
}

// ReadFrom 读取并解混淆
func (c *ObfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	
	// 解混淆
	deobfs := c.obfs.Deobfuscate(p[:n])
	copy(p, deobfs)
	return n, addr, nil
}

// WriteTo 混淆后发送
func (c *ObfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// 混淆
	obfs := c.obfs.Obfuscate(p)
	return c.PacketConn.WriteTo(obfs, addr)
}

// ObfsConn 混淆的 UDP 连接（用于 Dial 模式）
type ObfsConn struct {
	net.Conn
	obfs *XORObfuscator
	mu   sync.Mutex
}

// NewObfsConn 包装连接
func NewObfsConn(conn net.Conn, password string) *ObfsConn {
	return &ObfsConn{
		Conn: conn,
		obfs: NewXORObfuscator(password),
	}
}

// Read 读取并解混淆
func (c *ObfsConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return
	}
	
	deobfs := c.obfs.Deobfuscate(p[:n])
	copy(p, deobfs)
	return n, nil
}

// Write 混淆后发送
func (c *ObfsConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	obfs := c.obfs.Obfuscate(p)
	return c.Conn.Write(obfs)
}
