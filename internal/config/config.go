package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel string         `yaml:"log_level"`
	Tunnels  []TunnelConfig `yaml:"tunnels"`
}

type TunnelConfig struct {
	Name      string `yaml:"name"`
	Enabled   bool   `yaml:"enabled"`
	Server    string `yaml:"server"`
	Port      int    `yaml:"port"`
	Transport string `yaml:"transport"` // quic, websocket, kcp
	Token     string `yaml:"token"`
	LocalPort int    `yaml:"local_port"` // 本地 SOCKS5 端口
	Insecure  bool   `yaml:"insecure"`   // 跳过 TLS 验证
	
	// WebSocket 专用
	WSPath string `yaml:"ws_path"`
	
	// KCP 专用
	FEC int `yaml:"fec"` // FEC 冗余百分比
	
	// 高级选项
	PoolSize  int `yaml:"pool_size"`  // 连接池大小
	Keepalive int `yaml:"keepalive"`  // 心跳间隔（秒）
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Port == 0 {
			cfg.Tunnels[i].Port = 443
		}
		if cfg.Tunnels[i].Transport == "" {
			cfg.Tunnels[i].Transport = "quic"
		}
		if cfg.Tunnels[i].LocalPort == 0 {
			cfg.Tunnels[i].LocalPort = 1080 + i
		}
		if cfg.Tunnels[i].WSPath == "" {
			cfg.Tunnels[i].WSPath = "/ws"
		}
		if cfg.Tunnels[i].Keepalive == 0 {
			cfg.Tunnels[i].Keepalive = 15
		}
		if cfg.Tunnels[i].PoolSize == 0 {
			cfg.Tunnels[i].PoolSize = 2
		}
	}

	return &cfg, nil
}
