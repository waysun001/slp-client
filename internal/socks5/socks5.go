package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

// Server SOCKS5 服务器
type Server struct {
	addr     string
	listener net.Listener
	handler  ProxyHandler
	done     chan struct{}
	wg       sync.WaitGroup
}

// ProxyHandler 代理处理器接口
type ProxyHandler interface {
	Proxy(conn net.Conn, targetAddr string, targetPort uint16) error
}

// New 创建 SOCKS5 服务器
func New(port int, handler ProxyHandler) *Server {
	return &Server{
		addr:    fmt.Sprintf("127.0.0.1:%d", port),
		handler: handler,
		done:    make(chan struct{}),
	}
}

// Start 启动服务器
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln

	log.Printf("SOCKS5 listening on %s", s.addr)

	s.wg.Add(1)
	go s.accept()

	return nil
}

// Stop 停止服务器
func (s *Server) Stop() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

func (s *Server) accept() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 握手
	// 1. 读取版本和认证方法
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	if buf[0] != 0x05 {
		return // 不是 SOCKS5
	}

	// 2. 响应：无需认证
	conn.Write([]byte{0x05, 0x00})

	// 3. 读取请求
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		// 只支持 CONNECT 命令
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 4. 解析目标地址
	var targetAddr string
	var targetPort uint16
	var addrEnd int

	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = uint16(buf[8])<<8 | uint16(buf[9])
		addrEnd = 10
	case 0x03: // 域名
		addrLen := int(buf[4])
		if n < 5+addrLen+2 {
			return
		}
		targetAddr = string(buf[5 : 5+addrLen])
		targetPort = uint16(buf[5+addrLen])<<8 | uint16(buf[5+addrLen+1])
		addrEnd = 5 + addrLen + 2
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = uint16(buf[20])<<8 | uint16(buf[21])
		addrEnd = 22
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	_ = addrEnd // 避免未使用警告

	log.Printf("SOCKS5 request: %s:%d", targetAddr, targetPort)

	// 5. 通过隧道代理
	if err := s.handler.Proxy(conn, targetAddr, targetPort); err != nil {
		log.Printf("Proxy error: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 6. 响应成功
	// 返回绑定地址（这里用 0.0.0.0:0）
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 连接已被 handler.Proxy 接管，等待完成
	// 由于 Proxy 是异步的，这里需要等待
	select {}
}

// Addr 返回监听地址
func (s *Server) Addr() string {
	return s.addr
}

// ParseAddr 解析 host:port
func ParseAddr(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}

var _ io.Closer = (*Server)(nil)

func (s *Server) Close() error {
	s.Stop()
	return nil
}
