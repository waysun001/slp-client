package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
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
	// 不要在这里 defer conn.Close()，让 Proxy 接管

	// SOCKS5 握手
	// 1. 读取版本和认证方法
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		conn.Close()
		return
	}

	if buf[0] != 0x05 {
		conn.Close()
		return // 不是 SOCKS5
	}

	// 2. 响应：无需认证
	conn.Write([]byte{0x05, 0x00})

	// 3. 读取请求
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		conn.Close()
		return
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		// 只支持 CONNECT 命令
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	}

	// 4. 解析目标地址
	var targetAddr string
	var targetPort uint16

	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			conn.Close()
			return
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = uint16(buf[8])<<8 | uint16(buf[9])
	case 0x03: // 域名
		addrLen := int(buf[4])
		if n < 5+addrLen+2 {
			conn.Close()
			return
		}
		targetAddr = string(buf[5 : 5+addrLen])
		targetPort = uint16(buf[5+addrLen])<<8 | uint16(buf[5+addrLen+1])
	case 0x04: // IPv6
		if n < 22 {
			conn.Close()
			return
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = uint16(buf[20])<<8 | uint16(buf[21])
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	}

	log.Printf("SOCKS5 request: %s:%d", targetAddr, targetPort)

	// 5. 先发送成功响应，再开始代理
	// 响应格式: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 6. 通过隧道代理（阻塞直到完成）
	if err := s.handler.Proxy(conn, targetAddr, targetPort); err != nil {
		log.Printf("Proxy error: %v", err)
	}
	// Proxy 完成后连接自动关闭
}

// Addr 返回监听地址
func (s *Server) Addr() string {
	return s.addr
}

var _ io.Closer = (*Server)(nil)

func (s *Server) Close() error {
	s.Stop()
	return nil
}
