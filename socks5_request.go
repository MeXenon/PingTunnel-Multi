package pingtunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	socks5Version        = 0x05
	socks5ReplySucceeded = 0x00
	socks5ReplyGeneral   = 0x01
	socks5ReplyCmdNA     = 0x07
	socks5ReplyAddrNA    = 0x08

	socks5CmdConnect      = 0x01
	socks5CmdBind         = 0x02
	socks5CmdUDPAssociate = 0x03
)

var (
	errSocks5Version = errors.New("socks version not supported")
	errSocks5Addr    = errors.New("socks address type not supported")
)

type socks5Request struct {
	cmd  byte
	addr string
}

func readSocks5Request(r io.Reader) (socks5Request, error) {
	var req socks5Request

	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return req, err
	}
	if header[0] != socks5Version {
		return req, errSocks5Version
	}

	req.cmd = header[1]
	atyp := header[3]

	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, ip); err != nil {
			return req, err
		}
		host = net.IP(ip).String()
	case 0x03:
		alen := make([]byte, 1)
		if _, err := io.ReadFull(r, alen); err != nil {
			return req, err
		}
		alenInt := int(alen[0])
		if alenInt <= 0 {
			return req, errSocks5Addr
		}
		domain := make([]byte, alenInt)
		if _, err := io.ReadFull(r, domain); err != nil {
			return req, err
		}
		host = string(domain)
	case 0x04:
		ip := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, ip); err != nil {
			return req, err
		}
		host = net.IP(ip).String()
	default:
		return req, errSocks5Addr
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return req, err
	}
	port := binary.BigEndian.Uint16(portBuf)
	req.addr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return req, nil
}

func writeSocks5Reply(w io.Writer, rep byte, bindAddr string) error {
	host := "0.0.0.0"
	port := 0

	if bindAddr != "" {
		if parsedHost, parsedPort, err := net.SplitHostPort(bindAddr); err == nil {
			host = parsedHost
			if n, err := strconv.Atoi(parsedPort); err == nil && n >= 0 && n <= 65535 {
				port = n
			}
		}
	}

	ip := net.ParseIP(host)
	atyp := byte(0x01)
	var addrBytes []byte
	if ip != nil {
		addrBytes = ip.To4()
	}
	if addrBytes == nil {
		atyp = 0x04
		if ip != nil {
			addrBytes = ip.To16()
		}
		if addrBytes == nil {
			atyp = 0x01
			addrBytes = net.IPv4zero
		}
	}

	resp := make([]byte, 0, 22)
	resp = append(resp, socks5Version, rep, 0x00, atyp)
	resp = append(resp, addrBytes...)
	resp = append(resp, byte(port>>8), byte(port))
	_, err := w.Write(resp)
	return err
}

func socks5FailureReplyForErr(err error) byte {
	switch {
	case errors.Is(err, errSocks5Addr):
		return socks5ReplyAddrNA
	case errors.Is(err, errSocks5Version):
		return socks5ReplyGeneral
	default:
		return socks5ReplyGeneral
	}
}
