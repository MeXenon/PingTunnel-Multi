//go:build linux

package pingtunnel

import (
	"net"
	"syscall"
)

const (
	tcpKeepIdle     = 4
	tcpKeepIntvl    = 5
	tcpKeepCnt      = 6
	tcpUserTimeout  = 18
	tcpNotSentLowat = 25
)

func applyPlatformTCPOptions(conn *net.TCPConn, cfg TCPTuningConfig) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		if cfg.KeepAlive {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, int(cfg.KeepIdle.Seconds()))
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, int(cfg.KeepInterval.Seconds()))
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, cfg.KeepCount)
		}
		if cfg.UserTimeout > 0 {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(cfg.UserTimeout.Milliseconds()))
		}
		if cfg.NotSentLowat > 0 {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpNotSentLowat, cfg.NotSentLowat)
		}
		if cfg.QuickAck {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
		}
		if cfg.MaxSegment > 0 {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, cfg.MaxSegment)
		}
	})
}
