package pingtunnel

import (
	"net"
	"time"
)

type TCPTuningConfig struct {
	NoDelay      bool
	KeepAlive    bool
	KeepIdle     time.Duration
	KeepInterval time.Duration
	KeepCount    int
	UserTimeout  time.Duration
	NotSentLowat int
	QuickAck     bool
	MaxSegment   int
}

var tcpTuning = TCPTuningConfig{
	NoDelay:      true,
	KeepAlive:    true,
	KeepIdle:     30 * time.Second,
	KeepInterval: 10 * time.Second,
	KeepCount:    3,
	UserTimeout:  60 * time.Second,
	NotSentLowat: 16 * 1024,
	QuickAck:     true,
	MaxSegment:   0,
}

func ConfigureTCPTuning(cfg TCPTuningConfig) {
	if cfg.KeepIdle <= 0 {
		cfg.KeepIdle = 30 * time.Second
	}
	if cfg.KeepInterval <= 0 {
		cfg.KeepInterval = 10 * time.Second
	}
	if cfg.KeepCount <= 0 {
		cfg.KeepCount = 3
	}
	if cfg.UserTimeout < 0 {
		cfg.UserTimeout = 0
	}
	if cfg.NotSentLowat < 0 {
		cfg.NotSentLowat = 0
	}
	if cfg.MaxSegment < 0 {
		cfg.MaxSegment = 0
	}
	tcpTuning = cfg
}

func tuneTCPConn(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok || tcp == nil {
		return
	}
	cfg := tcpTuning
	if cfg.NoDelay {
		_ = tcp.SetNoDelay(true)
	}
	if cfg.KeepAlive {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(cfg.KeepIdle)
	}
	applyPlatformTCPOptions(tcp, cfg)
}
