package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	Version = 0x01

	// Auth types
	AuthToken = 0x01

	// Frame types
	FrameTCP       = 0x01
	FrameUDP       = 0x02
	FrameHeartbeat = 0xFE
	FrameClose     = 0xFF

	// Address types
	AddrIPv4   = 0x01
	AddrIPv6   = 0x04
	AddrDomain = 0x03
)

var (
	ErrInvalidVersion  = errors.New("invalid protocol version")
	ErrAuthFailed      = errors.New("authentication failed")
)

// WriteAuthFrame 写入认证帧
func WriteAuthFrame(w io.Writer, token string) error {
	tokenBytes := []byte(token)
	frame := make([]byte, 4+len(tokenBytes))
	frame[0] = Version
	frame[1] = AuthToken
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(tokenBytes)))
	copy(frame[4:], tokenBytes)
	_, err := w.Write(frame)
	return err
}

// ReadAuthResponse 读取认证响应
func ReadAuthResponse(r io.Reader) (bool, error) {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return false, err
	}
	if resp[0] != Version {
		return false, ErrInvalidVersion
	}
	return resp[1] == 0x01, nil
}

// WriteConnectFrame 写入连接请求帧（目标地址）
func WriteConnectFrame(w io.Writer, addr string, port uint16) error {
	// 解析地址类型
	var addrType byte
	var addrBytes []byte

	if ip := net.ParseIP(addr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = AddrIPv4
			addrBytes = ip4
		} else {
			addrType = AddrIPv6
			addrBytes = ip.To16()
		}
	} else {
		addrType = AddrDomain
		addrBytes = []byte(addr)
	}

	// 构建帧: Type(1) + AddrType(1) + AddrLen(1) + Addr(n) + Port(2)
	frame := make([]byte, 3+len(addrBytes)+2)
	frame[0] = FrameTCP
	frame[1] = addrType
	frame[2] = byte(len(addrBytes))
	copy(frame[3:], addrBytes)
	binary.BigEndian.PutUint16(frame[3+len(addrBytes):], port)

	_, err := w.Write(frame)
	return err
}

// WriteHeartbeat 写入心跳帧
func WriteHeartbeat(w io.Writer) error {
	_, err := w.Write([]byte{FrameHeartbeat, 0x00, 0x00})
	return err
}

// ReadHeartbeatResponse 读取心跳响应
func ReadHeartbeatResponse(r io.Reader) error {
	resp := make([]byte, 3)
	_, err := io.ReadFull(r, resp)
	return err
}
