package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/smartlink/slp-client/internal/client"
	"github.com/smartlink/slp-client/internal/config"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("c", "/etc/slp/client.yaml", "config file path")
	showVersion := flag.Bool("v", false, "show version")
	
	// 快速测试模式（命令行参数）
	server := flag.String("s", "", "server address")
	port := flag.Int("p", 443, "server port")
	token := flag.String("t", "", "auth token")
	transport := flag.String("transport", "quic", "transport mode: quic/websocket/kcp")
	localPort := flag.Int("l", 1080, "local SOCKS5 port")
	insecure := flag.Bool("insecure", false, "skip TLS verification (for self-signed certs)")
	
	flag.Parse()

	if *showVersion {
		log.Printf("SLP Client %s (built %s)", Version, BuildTime)
		return
	}

	var cfg *config.Config
	var err error

	// 命令行模式
	if *server != "" && *token != "" {
		cfg = &config.Config{
			Tunnels: []config.TunnelConfig{
				{
					Name:       "cli",
					Server:     *server,
					Port:       *port,
					Transport:  *transport,
					Token:      *token,
					LocalPort:  *localPort,
					Insecure:   *insecure,
				},
			},
		}
	} else {
		// 配置文件模式
		cfg, err = config.Load(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// 创建客户端
	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// 启动
	if err := c.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	log.Printf("SLP Client started (version %s)", Version)

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	c.Stop()
}
