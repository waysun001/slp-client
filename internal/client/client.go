package client

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/smartlink/slp-client/internal/config"
	"github.com/smartlink/slp-client/internal/dns"
	"github.com/smartlink/slp-client/internal/socks5"
	"github.com/smartlink/slp-client/internal/tunnel"
)

type Client struct {
	cfg        *config.Config
	tunnels    []tunnelEntry
	socks      []*socks5.Server
	dnsProxies []*dns.DNSProxy
	mu         sync.Mutex
}

type tunnelEntry struct {
	cfg    *config.TunnelConfig
	tunnel tunnel.Tunnel
}

func New(cfg *config.Config) (*Client, error) {
	return &Client{
		cfg: cfg,
	}, nil
}

func (c *Client) Start() error {
	for _, tcfg := range c.cfg.Tunnels {
		if !tcfg.Enabled && tcfg.Name != "cli" {
			continue
		}

		cfg := tcfg // 复制一份

		// 创建隧道
		t := tunnel.New(&cfg)

		// 连接
		if err := t.Connect(); err != nil {
			log.Printf("[%s] Failed to connect: %v", cfg.Name, err)
			continue
		}

		entry := tunnelEntry{
			cfg:    &cfg,
			tunnel: t,
		}
		c.tunnels = append(c.tunnels, entry)

		// DNS 代理 + hostname 缓存（配置了 dns_port 时启用）
		var cache *dns.HostnameCache
		if cfg.DNSPort > 0 {
			cache = dns.NewHostnameCache()
			dnsProxy := dns.New(cfg.DNSPort, t, cache)
			if err := dnsProxy.Start(); err != nil {
				log.Printf("[%s] DNS proxy failed: %v", cfg.Name, err)
				cache = nil // DNS 代理未启动，禁用 redir-host
			} else {
				log.Printf("[%s] DNS proxy on :%d", cfg.Name, cfg.DNSPort)
				c.dnsProxies = append(c.dnsProxies, dnsProxy)
			}
		}

		// 创建本地 SOCKS5 服务
		handler := &proxyHandler{tunnel: t}
		s := socks5.New(cfg.LocalPort, handler)

		// 启用 redir-host 模式（DNS 缓存存在时）
		if cache != nil {
			s.SetResolver(cache)
		}

		if err := s.Start(); err != nil {
			log.Printf("[%s] Failed to start SOCKS5: %v", cfg.Name, err)
			continue
		}
		c.socks = append(c.socks, s)

		log.Printf("[%s] Tunnel ready, SOCKS5 on :%d", cfg.Name, cfg.LocalPort)
	}

	if len(c.tunnels) == 0 {
		return fmt.Errorf("no tunnels connected")
	}

	return nil
}

func (c *Client) Stop() {
	for _, p := range c.dnsProxies {
		p.Stop()
	}
	for _, s := range c.socks {
		s.Stop()
	}
	for _, t := range c.tunnels {
		t.tunnel.Close()
	}
}

// proxyHandler 实现 socks5.ProxyHandler
type proxyHandler struct {
	tunnel tunnel.Tunnel
}

func (h *proxyHandler) Proxy(conn net.Conn, targetAddr string, targetPort uint16) error {
	return h.tunnel.Proxy(conn, targetAddr, targetPort)
}
