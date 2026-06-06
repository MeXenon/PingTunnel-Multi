package pingtunnel

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type UDPForwardAssociation struct {
	ControlConn net.Conn
	UDPConn     *net.UDPConn
	RelayAddr   *net.UDPAddr
}

type ForwardConfig struct {
	Scheme   string
	Host     string
	Port     int
	Username string
	Password string
}

func ParseForwardURL(rawURL string) (*ForwardConfig, error) {
	if rawURL == "" {
		return nil, nil
	}
	if isDirectForwardURL(rawURL) {
		return nil, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid forward URL: %w", err)
	}
	if u.Scheme != "socks5" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("missing proxy host in forward URL")
	}

	portStr := u.Port()
	if portStr == "" {
		return nil, errors.New("missing proxy port in forward URL")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid proxy port: %s", portStr)
	}

	password, _ := u.User.Password()
	return &ForwardConfig{
		Scheme:   u.Scheme,
		Host:     host,
		Port:     port,
		Username: u.User.Username(),
		Password: password,
	}, nil
}

func isDirectForwardURL(rawURL string) bool {
	value := strings.TrimSpace(strings.ToLower(rawURL))
	return value == "direct" || value == "direct://" || value == "none" || value == "off"
}

func (f *ForwardConfig) Address() string {
	return net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
}

func (f *ForwardConfig) CacheKey() string {
	if f == nil {
		return "direct"
	}
	auth := ""
	if f.Username != "" || f.Password != "" {
		auth = f.Username + ":" + f.Password + "@"
	}
	return f.Scheme + "://" + auth + f.Address()
}

func DialThroughProxy(config *ForwardConfig, targetAddr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", config.Address(), timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}
	tuneTCPConn(conn)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	switch config.Scheme {
	case "socks5":
		if err := socks5Handshake(conn, targetAddr, config.Username, config.Password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
		}
	case "http":
		if err := httpConnectHandshake(conn, targetAddr, config.Username, config.Password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("HTTP CONNECT handshake failed: %w", err)
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported proxy scheme: %s", config.Scheme)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to clear deadline: %w", err)
	}

	return conn, nil
}

func DialUDPThroughProxy(config *ForwardConfig, timeout time.Duration) (*UDPForwardAssociation, error) {
	if config == nil {
		return nil, errors.New("missing forward config")
	}
	if config.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported proxy scheme for UDP: %s", config.Scheme)
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open local udp socket: %w", err)
	}

	tcpConn, err := net.DialTimeout("tcp", config.Address(), timeout)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}
	tuneTCPConn(tcpConn)

	closeAllWithErr := func(cause error) (*UDPForwardAssociation, error) {
		tcpConn.Close()
		udpConn.Close()
		return nil, cause
	}

	if err := tcpConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return closeAllWithErr(fmt.Errorf("failed to set deadline: %w", err))
	}

	if err := socks5Negotiate(tcpConn, config.Username, config.Password); err != nil {
		return closeAllWithErr(fmt.Errorf("SOCKS5 negotiation failed: %w", err))
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	associateAddr := socks5UDPAssociateAddr(localAddr)
	if err := socks5SendCommand(tcpConn, socks5CmdUDPAssociate, associateAddr); err != nil {
		return closeAllWithErr(fmt.Errorf("failed to send UDP ASSOCIATE: %w", err))
	}

	rep, relayAddrStr, err := socks5ReadReply(tcpConn)
	if err != nil {
		return closeAllWithErr(fmt.Errorf("failed to read UDP ASSOCIATE reply: %w", err))
	}
	if rep != socks5ReplySucceeded {
		return closeAllWithErr(fmt.Errorf("SOCKS5 UDP ASSOCIATE failed with code: %d", rep))
	}

	relayAddr, err := net.ResolveUDPAddr("udp", relayAddrStr)
	if err != nil {
		return closeAllWithErr(fmt.Errorf("failed to resolve relay address %q: %w", relayAddrStr, err))
	}
	relayAddr = normalizeSocks5UDPRelayAddr(relayAddr, tcpConn.RemoteAddr())

	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		return closeAllWithErr(fmt.Errorf("failed to clear deadline: %w", err))
	}

	return &UDPForwardAssociation{ControlConn: tcpConn, UDPConn: udpConn, RelayAddr: relayAddr}, nil
}

func normalizeSocks5UDPRelayAddr(relayAddr *net.UDPAddr, proxyRemote net.Addr) *net.UDPAddr {
	if relayAddr == nil || relayAddr.IP == nil {
		return relayAddr
	}
	if !relayAddr.IP.IsUnspecified() && !relayAddr.IP.IsLoopback() {
		return relayAddr
	}
	tcpRemote, ok := proxyRemote.(*net.TCPAddr)
	if !ok || tcpRemote.IP == nil || tcpRemote.IP.IsUnspecified() {
		return relayAddr
	}
	if relayAddr.IP.IsLoopback() && tcpRemote.IP.IsLoopback() {
		return relayAddr
	}
	return &net.UDPAddr{IP: tcpRemote.IP, Port: relayAddr.Port, Zone: relayAddr.Zone}
}

func socks5UDPAssociateAddr(localAddr *net.UDPAddr) string {
	if localAddr == nil {
		return "0.0.0.0:0"
	}
	if localAddr.IP == nil || localAddr.IP.IsUnspecified() {
		return net.JoinHostPort("0.0.0.0", strconv.Itoa(localAddr.Port))
	}
	return net.JoinHostPort(localAddr.IP.String(), strconv.Itoa(localAddr.Port))
}

func socks5Negotiate(conn net.Conn, username string, password string) error {
	if username != "" || password != "" {
		if _, err := conn.Write([]byte{socks5Version, 0x02, 0x00, 0x02}); err != nil {
			return fmt.Errorf("failed to send greeting: %w", err)
		}
	} else {
		if _, err := conn.Write([]byte{socks5Version, 0x01, 0x00}); err != nil {
			return fmt.Errorf("failed to send greeting: %w", err)
		}
	}

	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("failed to read greeting response: %w", err)
	}
	if response[0] != socks5Version {
		return fmt.Errorf("unexpected SOCKS version: %d", response[0])
	}

	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		if username == "" && password == "" {
			return errors.New("SOCKS5 proxy requires username/password")
		}
		return socks5UsernamePasswordAuth(conn, username, password)
	case 0xff:
		return errors.New("SOCKS5 no acceptable auth method")
	default:
		return fmt.Errorf("unexpected SOCKS5 auth method: %d", response[1])
	}
}

func socks5UsernamePasswordAuth(conn net.Conn, username string, password string) error {
	user := []byte(username)
	pass := []byte(password)
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("SOCKS5 username/password is too long")
	}

	payload := make([]byte, 0, 3+len(user)+len(pass))
	payload = append(payload, 0x01, byte(len(user)))
	payload = append(payload, user...)
	payload = append(payload, byte(len(pass)))
	payload = append(payload, pass...)
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("failed to send username/password auth: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("failed to read username/password auth reply: %w", err)
	}
	if reply[0] != 0x01 || reply[1] != 0x00 {
		return errors.New("SOCKS5 username/password authentication failed")
	}
	return nil
}

func socks5SendCommand(conn net.Conn, cmd byte, targetAddr string) error {
	encodedAddr, err := encodeSocks5Address(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}

	request := make([]byte, 0, 3+len(encodedAddr))
	request = append(request, socks5Version, cmd, 0x00)
	request = append(request, encodedAddr...)
	_, err = conn.Write(request)
	return err
}

func socks5ReadReply(conn net.Conn) (rep byte, bindAddr string, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", fmt.Errorf("failed to read reply header: %w", err)
	}

	if header[0] != socks5Version {
		return 0, "", fmt.Errorf("unexpected SOCKS version in reply: %d", header[0])
	}
	if header[2] != 0x00 {
		return 0, "", fmt.Errorf("invalid socks reserved byte in reply: %d", header[2])
	}

	addr, err := readSocks5AddressFromReader(conn, header[3])
	if err != nil {
		return 0, "", err
	}

	return header[1], addr, nil
}

func socks5Handshake(conn net.Conn, targetAddr string, username string, password string) error {
	if err := socks5Negotiate(conn, username, password); err != nil {
		return err
	}
	if err := socks5SendCommand(conn, socks5CmdConnect, targetAddr); err != nil {
		return err
	}
	rep, _, err := socks5ReadReply(conn)
	if err != nil {
		return err
	}
	if rep != socks5ReplySucceeded {
		return fmt.Errorf("SOCKS5 connect failed with code: %d", rep)
	}
	return nil
}

func httpConnectHandshake(conn net.Conn, targetAddr string, username string, password string) error {
	headers := []string{
		fmt.Sprintf("CONNECT %s HTTP/1.1", targetAddr),
		fmt.Sprintf("Host: %s", targetAddr),
	}
	if username != "" || password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		headers = append(headers, "Proxy-Authorization: Basic "+token)
	}

	request := ""
	for _, header := range headers {
		request += header + "\r\n"
	}
	request += "\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read response status line: %w", err)
	}

	var httpVersion string
	var statusCode int
	var statusText string
	n, err := fmt.Sscanf(statusLine, "%s %d %s", &httpVersion, &statusCode, &statusText)
	if err != nil || n < 2 {
		return fmt.Errorf("invalid HTTP response: %s", statusLine)
	}
	if statusCode != 200 {
		return fmt.Errorf("HTTP CONNECT failed with status: %d", statusCode)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read response headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
}
