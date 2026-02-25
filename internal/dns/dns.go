package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSForwarder DNS 查询转发接口（由 tunnel 实现）
type DNSForwarder interface {
	ForwardDNS(query []byte) ([]byte, error)
}

// ============================================================
// HostnameCache — IP → hostname 反查缓存
// ============================================================

type cacheEntry struct {
	hostname string
	expireAt time.Time
}

// HostnameCache 存储 DNS 响应中的 IP→hostname 映射，供 SOCKS5 redir-host 反查
type HostnameCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry // key: IP 地址字符串
}

const minTTL = 60 // 最小缓存时间（秒），避免 TTL=0 的记录立即过期

func NewHostnameCache() *HostnameCache {
	c := &HostnameCache{
		entries: make(map[string]cacheEntry),
	}
	go c.cleanupLoop()
	return c
}

// Store 存储 hostname→IP 映射（从 DNS 响应中提取）
func (c *HostnameCache) Store(hostname string, ips []string, ttl uint32) {
	if ttl < minTTL {
		ttl = minTTL
	}
	expireAt := time.Now().Add(time.Duration(ttl) * time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ip := range ips {
		c.entries[ip] = cacheEntry{
			hostname: hostname,
			expireAt: expireAt,
		}
	}
}

// Lookup 反查 IP 对应的原始域名
func (c *HostnameCache) Lookup(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[ip]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expireAt) {
		return "", false
	}
	return entry.hostname, true
}

// cleanupLoop 定期清理过期条目
func (c *HostnameCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for ip, entry := range c.entries {
			if now.After(entry.expireAt) {
				delete(c.entries, ip)
			}
		}
		c.mu.Unlock()
	}
}

// ============================================================
// DNSProxy — UDP DNS 代理，通过隧道转发并缓存 hostname→IP
// ============================================================

// DNSProxy UDP DNS 代理服务器
type DNSProxy struct {
	port      int
	forwarder DNSForwarder
	cache     *HostnameCache
	conn      *net.UDPConn
	done      chan struct{}
}

// New 创建 DNS 代理
func New(port int, forwarder DNSForwarder, cache *HostnameCache) *DNSProxy {
	return &DNSProxy{
		port:      port,
		forwarder: forwarder,
		cache:     cache,
		done:      make(chan struct{}),
	}
}

// Start 启动 DNS 代理
func (p *DNSProxy) Start() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: p.port,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns proxy listen failed: %w", err)
	}
	p.conn = conn

	go p.serve()

	log.Printf("DNS proxy listening on 127.0.0.1:%d", p.port)
	return nil
}

// Stop 停止 DNS 代理
func (p *DNSProxy) Stop() {
	close(p.done)
	if p.conn != nil {
		p.conn.Close()
	}
}

func (p *DNSProxy) serve() {
	buf := make([]byte, 4096)

	for {
		select {
		case <-p.done:
			return
		default:
		}

		p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-p.done:
				return
			default:
				log.Printf("DNS proxy read error: %v", err)
				continue
			}
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		go p.handleQuery(query, clientAddr)
	}
}

func (p *DNSProxy) handleQuery(query []byte, clientAddr *net.UDPAddr) {
	// 通过隧道转发 DNS 查询
	resp, err := p.forwarder.ForwardDNS(query)
	if err != nil {
		log.Printf("DNS forward failed: %v", err)
		// 返回 SERVFAIL 响应
		p.sendServFail(query, clientAddr)
		return
	}

	// 解析响应，提取 hostname→IP 映射存入缓存
	p.extractAndCache(resp)

	// 将原始响应返回给客户端
	p.conn.WriteToUDP(resp, clientAddr)
}

// sendServFail 返回 SERVFAIL 响应
func (p *DNSProxy) sendServFail(query []byte, clientAddr *net.UDPAddr) {
	if len(query) < 12 {
		return
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x82 // RA=1, RCODE=2 (SERVFAIL)
	p.conn.WriteToUDP(resp, clientAddr)
}

// ============================================================
// DNS 响应解析（手写，无外部依赖）
// ============================================================

// extractAndCache 解析 DNS 响应，提取 hostname→IP 映射
func (p *DNSProxy) extractAndCache(resp []byte) {
	if len(resp) < 12 {
		return
	}

	// DNS 头部
	qdcount := binary.BigEndian.Uint16(resp[4:6])
	ancount := binary.BigEndian.Uint16(resp[6:8])

	if ancount == 0 {
		return
	}

	// 解析 Question 段获取查询域名
	offset := 12
	var queryName string

	for i := uint16(0); i < qdcount; i++ {
		name, newOffset, err := readDNSName(resp, offset)
		if err != nil {
			return
		}
		if i == 0 {
			queryName = name
		}
		offset = newOffset + 4 // 跳过 QTYPE(2) + QCLASS(2)
	}

	if queryName == "" {
		return
	}

	// 解析 Answer 段提取 A/AAAA 记录
	var ips []string
	var minAnswerTTL uint32 = 0xFFFFFFFF

	for i := uint16(0); i < ancount; i++ {
		if offset >= len(resp) {
			break
		}

		_, newOffset, err := readDNSName(resp, offset)
		if err != nil {
			break
		}
		offset = newOffset

		if offset+10 > len(resp) {
			break
		}

		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		// rclass := binary.BigEndian.Uint16(resp[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
		rdlength := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlength) > len(resp) {
			break
		}

		rdata := resp[offset : offset+int(rdlength)]

		switch rtype {
		case 1: // A (IPv4)
			if rdlength == 4 {
				ip := net.IP(rdata).String()
				ips = append(ips, ip)
				if ttl < minAnswerTTL {
					minAnswerTTL = ttl
				}
			}
		case 28: // AAAA (IPv6)
			if rdlength == 16 {
				ip := net.IP(rdata).String()
				ips = append(ips, ip)
				if ttl < minAnswerTTL {
					minAnswerTTL = ttl
				}
			}
		}

		offset += int(rdlength)
	}

	if len(ips) == 0 {
		return
	}

	// 所有 A/AAAA 记录的 IP 都映射到原始查询域名
	// CNAME 链情况下（queryName → CNAME → IP），仍映射到 queryName
	hostname := strings.ToLower(queryName)

	p.cache.Store(hostname, ips, minAnswerTTL)
	log.Printf("DNS cache: %s → %v (TTL: %ds)", hostname, ips, minAnswerTTL)
}

// readDNSName 读取 DNS 名称（支持压缩指针，RFC 1035 Section 4.1.4）
func readDNSName(msg []byte, offset int) (string, int, error) {
	if offset >= len(msg) {
		return "", offset, fmt.Errorf("offset out of bounds")
	}

	var parts []string
	visited := make(map[int]bool) // 防止循环指针
	newOffset := -1               // 记录第一次遇到指针前的位置
	ptr := offset

	for {
		if ptr >= len(msg) {
			return "", offset, fmt.Errorf("unexpected end of message")
		}

		b := msg[ptr]

		if b == 0 {
			// 名称结束
			if newOffset == -1 {
				newOffset = ptr + 1
			}
			break
		}

		if b&0xC0 == 0xC0 {
			// 压缩指针
			if ptr+1 >= len(msg) {
				return "", offset, fmt.Errorf("truncated pointer")
			}
			if newOffset == -1 {
				newOffset = ptr + 2
			}
			ptrTarget := int(binary.BigEndian.Uint16(msg[ptr:ptr+2])) & 0x3FFF
			if visited[ptrTarget] {
				return "", offset, fmt.Errorf("pointer loop")
			}
			visited[ptrTarget] = true
			ptr = ptrTarget
			continue
		}

		// 普通标签
		labelLen := int(b)
		ptr++
		if ptr+labelLen > len(msg) {
			return "", offset, fmt.Errorf("label exceeds message")
		}
		parts = append(parts, string(msg[ptr:ptr+labelLen]))
		ptr += labelLen
	}

	return strings.Join(parts, "."), newOffset, nil
}
