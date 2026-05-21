package pingtunnel

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestReadSocks5RequestConnectDomain(t *testing.T) {
	reqBytes := []byte{
		0x05, 0x01, 0x00, 0x03,
		0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xbb,
	}
	req, err := readSocks5Request(bytesReader(reqBytes))
	if err != nil {
		t.Fatalf("readSocks5Request returned error: %v", err)
	}
	if req.Command != socks5CmdConnect {
		t.Fatalf("expected CONNECT command, got %d", req.Command)
	}
	if req.Address != "example.com:443" {
		t.Fatalf("unexpected addr: %s", req.Address)
	}
}

func TestReadSocks5RequestUdpAssociateIPv4(t *testing.T) {
	reqBytes := []byte{
		0x05, 0x03, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	req, err := readSocks5Request(bytesReader(reqBytes))
	if err != nil {
		t.Fatalf("readSocks5Request returned error: %v", err)
	}
	if req.Command != socks5CmdUDPAssociate {
		t.Fatalf("expected UDP ASSOCIATE command, got %d", req.Command)
	}
	if req.Address != "0.0.0.0:0" {
		t.Fatalf("unexpected addr: %s", req.Address)
	}
}

func TestAcceptSock5ConnAcceptsUDPAssociate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		client := &Client{tcpaddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
		client.AcceptSock5Conn(conn.(*net.TCPConn))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	handshakeResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeResp); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if handshakeResp[0] != 0x05 || handshakeResp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %v", handshakeResp)
	}

	if _, err := conn.Write([]byte{
		0x05, 0x03, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}); err != nil {
		t.Fatalf("write udp associate request: %v", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read udp associate response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != socks5ReplySucceeded {
		t.Fatalf("unexpected udp associate response: %v", resp)
	}
	conn.Close()
	<-done
}

func TestSocks5UDPDatagramRoundTrip(t *testing.T) {
	packet, err := buildSocks5UDPDatagram("example.com:443", []byte("hello"))
	if err != nil {
		t.Fatalf("buildSocks5UDPDatagram returned error: %v", err)
	}
	target, payload, err := parseSocks5UDPDatagram(packet)
	if err != nil {
		t.Fatalf("parseSocks5UDPDatagram returned error: %v", err)
	}
	if target != "example.com:443" {
		t.Fatalf("unexpected target: %s", target)
	}
	if string(payload) != "hello" {
		t.Fatalf("unexpected payload: %q", string(payload))
	}
}

func TestDialUDPThroughProxyNoAuth(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()

	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpLn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Version, 0x00})

		req, err := readSocks5Request(conn)
		if err != nil || req.Command != socks5CmdUDPAssociate {
			return
		}
		_ = writeSocks5Reply(conn, socks5ReplySucceeded, udpLn.LocalAddr().String())

		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, _ = conn.Read(buf[:1])
	}()

	cfg, err := ParseForwardURL("socks5://" + tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("ParseForwardURL returned error: %v", err)
	}
	assoc, err := DialUDPThroughProxy(cfg, time.Second)
	if err != nil {
		t.Fatalf("DialUDPThroughProxy returned error: %v", err)
	}
	defer assoc.ControlConn.Close()
	defer assoc.UDPConn.Close()

	if assoc.RelayAddr.String() != udpLn.LocalAddr().String() {
		t.Fatalf("unexpected relay address: %s", assoc.RelayAddr.String())
	}
	assoc.ControlConn.Close()
	<-done
}

func TestDialUDPThroughProxyNormalizesUnspecifiedRelayAddress(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()

	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpLn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Version, 0x00})

		req, err := readSocks5Request(conn)
		if err != nil || req.Command != socks5CmdUDPAssociate {
			return
		}
		replyAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: udpLn.LocalAddr().(*net.UDPAddr).Port}
		_ = writeSocks5Reply(conn, socks5ReplySucceeded, replyAddr.String())
	}()

	cfg, err := ParseForwardURL("socks5://" + tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("ParseForwardURL returned error: %v", err)
	}
	assoc, err := DialUDPThroughProxy(cfg, time.Second)
	if err != nil {
		t.Fatalf("DialUDPThroughProxy returned error: %v", err)
	}
	defer assoc.ControlConn.Close()
	defer assoc.UDPConn.Close()

	if assoc.RelayAddr.IP.String() != "127.0.0.1" {
		t.Fatalf("relay ip was not normalized: %s", assoc.RelayAddr.String())
	}
	if assoc.RelayAddr.Port != udpLn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("unexpected relay port: %d", assoc.RelayAddr.Port)
	}
	udpLn.Close()
	assoc.ControlConn.Close()
	<-done
}

func TestNormalizeSocks5UDPRelayAddressRewritesRemoteLoopback(t *testing.T) {
	relay := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1080}

	got := normalizeSocks5UDPRelayAddr(relay, remote)

	if got.IP.String() != "203.0.113.10" {
		t.Fatalf("relay ip was not normalized: %s", got.String())
	}
	if got.Port != 53000 {
		t.Fatalf("unexpected relay port: %d", got.Port)
	}
}

func TestNormalizeSocks5UDPRelayAddressKeepsLocalLoopback(t *testing.T) {
	relay := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}

	got := normalizeSocks5UDPRelayAddr(relay, remote)

	if got.IP.String() != "127.0.0.1" {
		t.Fatalf("local relay ip should stay loopback: %s", got.String())
	}
}

func TestExchangeDNSOverTCPViaProxy(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()

	query := []byte{0x12, 0x34, 0x01, 0x00}
	response := []byte{0x12, 0x34, 0x81, 0x80}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Version, 0x00})

		req, err := readSocks5Request(conn)
		if err != nil || req.Command != socks5CmdConnect || req.Address != "1.1.1.1:53" {
			return
		}
		_ = writeSocks5Reply(conn, socks5ReplySucceeded, "127.0.0.1:0")

		length := make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		payload := make([]byte, int(length[0])<<8|int(length[1]))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		if string(payload) != string(query) {
			return
		}
		reply := []byte{0x00, byte(len(response))}
		reply = append(reply, response...)
		_, _ = conn.Write(reply)
	}()

	cfg, err := ParseForwardURL("socks5://" + tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("ParseForwardURL returned error: %v", err)
	}
	got, err := exchangeDNSOverTCPViaProxy(cfg, "1.1.1.1:53", query, time.Second)
	if err != nil {
		t.Fatalf("exchangeDNSOverTCPViaProxy returned error: %v", err)
	}
	if string(got) != string(response) {
		t.Fatalf("unexpected response: %v", got)
	}
	<-done
}

func TestIsDNSForwardTarget(t *testing.T) {
	if !isDNSForwardTarget("1.1.1.1:53") {
		t.Fatal("expected IPv4 DNS target")
	}
	if !isDNSForwardTarget("[2606:4700:4700::1111]:53") {
		t.Fatal("expected IPv6 DNS target")
	}
	if isDNSForwardTarget("1.1.1.1:853") {
		t.Fatal("did not expect non-DNS target")
	}
}

type byteReader struct {
	data []byte
	off  int
}

func bytesReader(data []byte) io.Reader {
	return &byteReader{data: append([]byte(nil), data...)}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}
