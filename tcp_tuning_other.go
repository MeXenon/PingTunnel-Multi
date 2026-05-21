//go:build !linux

package pingtunnel

import "net"

func applyPlatformTCPOptions(conn *net.TCPConn, cfg TCPTuningConfig) {}
