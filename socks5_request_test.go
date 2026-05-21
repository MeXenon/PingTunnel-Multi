package pingtunnel

import (
	"io"
	"net"
	"testing"
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
	if req.cmd != socks5CmdConnect {
		t.Fatalf("expected CONNECT command, got %d", req.cmd)
	}
	if req.addr != "example.com:443" {
		t.Fatalf("unexpected addr: %s", req.addr)
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
	if req.cmd != socks5CmdUDPAssociate {
		t.Fatalf("expected UDP ASSOCIATE command, got %d", req.cmd)
	}
	if req.addr != "0.0.0.0:0" {
		t.Fatalf("unexpected addr: %s", req.addr)
	}
}

func TestAcceptSock5ConnRejectsUDPAssociate(t *testing.T) {
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
		client := &Client{}
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
	if resp[0] != 0x05 || resp[1] != socks5ReplyCmdNA {
		t.Fatalf("unexpected udp associate response: %v", resp)
	}
	<-done
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
