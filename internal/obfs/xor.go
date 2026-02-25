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

// Obfuscate 混淆数据（就地 XOR，直接修改 data）
func (o *XORObfuscator) Obfuscate(data []byte) {
	keyLen := len(o.key)
	for i, b := range data {
		data[i] = b ^ o.key[i%keyLen]
	}
}

// obfsBufPool 混淆写入缓冲池，避免每次 WriteTo/Write 分配内存
var obfsBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 2048)
		return &buf
	},
}

// ObfsPacketConn 混淆的 UDP 连接
type ObfsPacketConn struct {
	net.PacketConn
	obfs *XORObfuscator
}

// NewObfsPacketConn 包装 UDP 连接
func NewObfsPacketConn(conn net.PacketConn, password string) *ObfsPacketConn {
	return &ObfsPacketConn{
		PacketConn: conn,
		obfs:       NewXORObfuscator(password),
	}
}

// ReadFrom 读取并就地解混淆
func (c *ObfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	// XOR 就地解混淆，无需额外分配
	c.obfs.Obfuscate(p[:n])
	return n, addr, nil
}

// WriteTo 混淆后发送（无锁，使用 sync.Pool 缓冲区）
func (c *ObfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// 从池中获取缓冲区
	bufp := obfsBufPool.Get().(*[]byte)
	buf := *bufp
	if len(buf) < len(p) {
		buf = make([]byte, len(p))
		*bufp = buf
	}
	buf = buf[:len(p)]

	// 拷贝并 XOR 混淆（不修改原始数据）
	copy(buf, p)
	c.obfs.Obfuscate(buf)

	_, err = c.PacketConn.WriteTo(buf, addr)
	obfsBufPool.Put(bufp)
	// 返回原始数据长度
	return len(p), err
}

// ObfsConn 混淆的 UDP 连接（用于 Dial 模式）
type ObfsConn struct {
	net.Conn
	obfs *XORObfuscator
}

// NewObfsConn 包装连接
func NewObfsConn(conn net.Conn, password string) *ObfsConn {
	return &ObfsConn{
		Conn: conn,
		obfs: NewXORObfuscator(password),
	}
}

// Read 读取并就地解混淆
func (c *ObfsConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return
	}
	// XOR 就地解混淆，无需额外分配
	c.obfs.Obfuscate(p[:n])
	return n, nil
}

// Write 混淆后发送（无锁，使用 sync.Pool 缓冲区）
func (c *ObfsConn) Write(p []byte) (n int, err error) {
	// 从池中获取缓冲区
	bufp := obfsBufPool.Get().(*[]byte)
	buf := *bufp
	if len(buf) < len(p) {
		buf = make([]byte, len(p))
		*bufp = buf
	}
	buf = buf[:len(p)]

	// 拷贝并 XOR 混淆（不修改原始数据）
	copy(buf, p)
	c.obfs.Obfuscate(buf)

	_, err = c.Conn.Write(buf)
	obfsBufPool.Put(bufp)
	// 返回原始数据长度
	return len(p), err
}
