package pingtunnel

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/network"
	"github.com/esrrhs/gohome/thread"
	"github.com/esrrhs/pingtunnel/internal/loggo"
	oldproto "github.com/golang/protobuf/proto"
	"golang.org/x/net/icmp"
)

func NewServer(icmpAddr string, key int, maxconn int, maxprocessthread int, maxprocessbuffer int, connecttmeout int, cryptoConfig *CryptoConfig) (*Server, error) {
	return NewServerWithDBForward(icmpAddr, key, maxconn, maxprocessthread, maxprocessbuffer, connecttmeout, cryptoConfig, "", nil)
}

func NewServerWithDB(icmpAddr string, key int, maxconn int, maxprocessthread int, maxprocessbuffer int, connecttmeout int, cryptoConfig *CryptoConfig, dbPath string) (*Server, error) {
	return NewServerWithDBForward(icmpAddr, key, maxconn, maxprocessthread, maxprocessbuffer, connecttmeout, cryptoConfig, dbPath, nil)
}

// NewServerWithDBForward creates a server with optional multi-user auth and upstream proxy forwarding.
func NewServerWithDBForward(icmpAddr string, key int, maxconn int, maxprocessthread int, maxprocessbuffer int, connecttmeout int, cryptoConfig *CryptoConfig, dbPath string, forwardConfig *ForwardConfig) (*Server, error) {
	s := &Server{
		icmpAddr:         icmpAddr,
		exit:             false,
		key:              key,
		maxconn:          maxconn,
		maxprocessthread: maxprocessthread,
		maxprocessbuffer: maxprocessbuffer,
		connecttmeout:    connecttmeout,
		cryptoConfig:     cryptoConfig,
		forwardConfig:    forwardConfig,
		useMultiAuth:     false,
		connToUser:       make(map[string]int64),
		replyTokens:      make(map[string][]icmpReplyToken),
	}

	// Initialize auth manager if database path provided
	if dbPath != "" {
		am, err := NewAuthManager(dbPath)
		if err != nil {
			loggo.Error("Failed to initialize auth manager: %s", err.Error())
			// Fall back to single-key mode
		} else {
			s.authManager = am
			s.useMultiAuth = true
			loggo.Info("Multi-user authentication enabled with %d users", am.GetUserCount())
		}
	}

	if maxprocessthread > 0 {
		s.processtp = thread.NewThreadPool(maxprocessthread, maxprocessbuffer, func(v interface{}) {
			packet := v.(*Packet)
			s.processDataPacket(packet)
		})
	}

	return s, nil
}

const (
	serverTCPDefaultBufferSize      = 1024 * 1024
	serverTCPDefaultMaxWindow       = 128
	serverTCPDefaultMinResendMillis = 1000
	serverTCPMaxWindowEnv           = "PINGTUNNEL_SERVER_TCP_MAXWIN"
	serverTCPMinResendMillisEnv     = "PINGTUNNEL_SERVER_TCP_MIN_RESEND_MS"
	serverICMPDefaultReplyBurst     = 1
	serverICMPMaxReplyBurst         = 16
	serverICMPMaxReplyTokens        = 4096
	serverICMPReplyBurstEnv         = "PINGTUNNEL_SERVER_ICMP_REPLY_BURST"
)

func sanitizeServerTCPParams(bufferSize int, windowSize int, resendMillis int) (int, int, int) {
	if bufferSize <= 0 {
		bufferSize = serverTCPDefaultBufferSize
	}

	maxWindow := readPositiveIntEnv(serverTCPMaxWindowEnv, serverTCPDefaultMaxWindow)
	if maxWindow > FRAME_MAX_ID/10 {
		maxWindow = FRAME_MAX_ID / 10
	}
	if windowSize <= 0 || windowSize > maxWindow {
		windowSize = maxWindow
	}

	minResendMillis := readPositiveIntEnv(serverTCPMinResendMillisEnv, serverTCPDefaultMinResendMillis)
	if resendMillis <= 0 || resendMillis < minResendMillis {
		resendMillis = minResendMillis
	}

	return bufferSize, windowSize, resendMillis
}

func readPositiveIntEnv(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func readBoundedPositiveIntEnv(name string, fallback int, max int) int {
	value := readPositiveIntEnv(name, fallback)
	if value > max {
		return max
	}
	return value
}

func replyTokenSourceKey(src *net.IPAddr, echoId int) string {
	if src == nil {
		return fmt.Sprintf("#%d", echoId)
	}
	return fmt.Sprintf("%s#%d", src.String(), echoId)
}

func (p *Server) queueReplyTokens(sourceKey string, echoId int, echoSeq int) {
	if sourceKey == "" {
		return
	}
	burst := readBoundedPositiveIntEnv(serverICMPReplyBurstEnv, serverICMPDefaultReplyBurst, serverICMPMaxReplyBurst)
	p.replyTokenMu.Lock()
	defer p.replyTokenMu.Unlock()

	if p.replyTokens == nil {
		p.replyTokens = make(map[string][]icmpReplyToken)
	}
	tokens := p.replyTokens[sourceKey]
	for i := 0; i < burst; i++ {
		tokens = append(tokens, icmpReplyToken{id: echoId, seq: echoSeq})
	}
	if len(tokens) > serverICMPMaxReplyTokens {
		tokens = tokens[len(tokens)-serverICMPMaxReplyTokens:]
	}
	p.replyTokens[sourceKey] = tokens
}

func (p *Server) hasReplyToken(sourceKey string) bool {
	p.replyTokenMu.Lock()
	defer p.replyTokenMu.Unlock()
	return len(p.replyTokens[sourceKey]) > 0
}

func (p *Server) popReplyToken(sourceKey string) (icmpReplyToken, bool) {
	p.replyTokenMu.Lock()
	defer p.replyTokenMu.Unlock()

	tokens := p.replyTokens[sourceKey]
	if len(tokens) == 0 {
		return icmpReplyToken{}, false
	}
	token := tokens[0]
	copy(tokens, tokens[1:])
	tokens = tokens[:len(tokens)-1]
	if len(tokens) == 0 {
		delete(p.replyTokens, sourceKey)
	} else {
		p.replyTokens[sourceKey] = tokens
	}
	return token, true
}

func (p *Server) clearReplyTokens(sourceKey string) {
	if sourceKey == "" {
		return
	}
	p.replyTokenMu.Lock()
	delete(p.replyTokens, sourceKey)
	p.replyTokenMu.Unlock()
}

func (p *Server) hasActiveTCPConnForSource(sourceKey string) bool {
	if sourceKey == "" {
		return false
	}
	found := false
	p.localConnMap.Range(func(_, value interface{}) bool {
		conn := value.(*ServerConn)
		if !conn.exit && conn.tcpmode > 0 && conn.sourceKey == sourceKey {
			found = true
			return false
		}
		return true
	})
	return found
}

func (p *Server) notifyTCPConnsForSource(sourceKey string) {
	if sourceKey == "" {
		return
	}
	p.localConnMap.Range(func(_, value interface{}) bool {
		conn := value.(*ServerConn)
		if !conn.exit && conn.tcpmode > 0 && conn.sourceKey == sourceKey {
			notifyActivity(conn.activity)
		}
		return true
	})
}

func prioritizeServerFrames(sendlist *list.List) []*network.Frame {
	dataFrames := make([]*network.Frame, 0, sendlist.Len())
	otherFrames := make([]*network.Frame, 0)
	for e := sendlist.Front(); e != nil; e = e.Next() {
		f := e.Value.(*network.Frame)
		if f.Type == int32(network.Frame_DATA) {
			dataFrames = append(dataFrames, f)
		} else {
			otherFrames = append(otherFrames, f)
		}
	}
	return append(dataFrames, otherFrames...)
}

func (p *Server) sendTCPFrame(conn *ServerConn, src *net.IPAddr, f *network.Frame, responseKey int) bool {
	token, ok := p.popReplyToken(conn.sourceKey)
	if !ok {
		return false
	}

	mb, err := conn.fm.MarshalFrame(f)
	if err != nil {
		loggo.Error("Error tcp Marshal %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
		return false
	}
	sendICMP(token.id, token.seq, *p.conn, src, "", conn.id, (uint32)(MyMsg_DATA), mb,
		conn.rproto, -1, responseKey, 0,
		0, 0, 0, 0, 0,
		0, p.cryptoConfig)
	p.sendPacket++
	p.sendPacketSize += (uint64)(len(mb))

	if p.useMultiAuth && p.authManager != nil && conn.userID != 0 {
		p.authManager.AddTraffic(conn.userID, int64(len(mb)), 0)
	}
	return true
}

type Server struct {
	exit             bool
	key              int
	workResultLock   sync.WaitGroup
	maxconn          int
	maxprocessthread int
	maxprocessbuffer int
	connecttmeout    int
	cryptoConfig     *CryptoConfig
	forwardConfig    *ForwardConfig

	icmpAddr string

	conn *icmp.PacketConn

	localConnMap sync.Map
	connErrorMap sync.Map

	sendPacket       uint64
	recvPacket       uint64
	sendPacketSize   uint64
	recvPacketSize   uint64
	localConnMapSize int

	processtp   *thread.ThreadPool
	recvcontrol chan int

	// Multi-user auth
	useMultiAuth bool
	authManager  *AuthManager
	connToUser   map[string]int64 // connection ID -> user ID
	connUserMu   sync.RWMutex

	replyTokenMu sync.Mutex
	replyTokens  map[string][]icmpReplyToken
}

type ServerConn struct {
	exit           bool
	timeout        int
	ipaddrTarget   *net.UDPAddr
	conn           *net.UDPConn
	udpTargetAddr  string
	udpRelayAddr   *net.UDPAddr
	udpViaProxy    bool
	tcpaddrTarget  *net.TCPAddr
	tcpconn        net.Conn
	id             string
	activeRecvTime time.Time
	activeSendTime time.Time
	close          bool
	rproto         int
	fm             *network.FrameMgr
	tcpmode        int
	echoId         int
	echoSeq        int
	sourceKey      string
	activity       chan struct{}

	// Multi-user tracking
	userID  int64
	userKey int
}

type icmpReplyToken struct {
	id  int
	seq int
}

func (p *Server) Run() error {

	conn, err := icmp.ListenPacket("ip4:icmp", p.icmpAddr)
	if err != nil {
		loggo.Error("Error listening for ICMP packets: %s", err.Error())
		return err
	}
	p.conn = conn

	recv := make(chan *Packet, 10000)
	p.recvcontrol = make(chan int, 1)
	go recvICMP(&p.workResultLock, &p.exit, *p.conn, recv, p.cryptoConfig, func() []int {
		if p.authManager != nil {
			return p.authManager.GetActiveKeys()
		}
		return nil
	})

	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			p.checkTimeoutConn()
			p.showNet()
			p.updateConnError()
			time.Sleep(time.Second)
		}
	}()

	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			select {
			case <-p.recvcontrol:
				return
			case r := <-recv:
				p.processPacket(r)
			}
		}
	}()

	return nil
}

func (p *Server) Stop() {
	p.exit = true
	p.recvcontrol <- 1
	p.workResultLock.Wait()
	if p.processtp != nil {
		p.processtp.Stop()
	}
	p.conn.Close()

	// Stop auth manager
	if p.authManager != nil {
		p.authManager.Stop()
	}
}

func (p *Server) processPacket(packet *Packet) {
	// Drop replies (rproto < 0) to avoid processing our own responses on loopback.
	if packet.my.Rproto < 0 {
		return
	}

	var user *AuthUser
	var err error

	if p.useMultiAuth && p.authManager != nil {
		key := int(packet.my.Key)
		clientIP := packet.src.String()

		// Multi-user authentication
		user, err = p.authManager.ValidateKey(key)
		if err != nil {
			loggo.Info("Auth REJECTED from %s key %d: %s", packet.src.String(), packet.my.Key, err.Error())
			return
		}

		// Check single session enforcement
		if !p.authManager.CanConnect(key, clientIP) {
			loggo.Info("Session already exists for key %d from different IP", packet.my.Key)
			p.remoteError(packet.echoId, packet.echoSeq, packet.my.Id, (int)(packet.my.Rproto), packet.src, key)
			return
		}

		// Refresh session activity (and create if missing)
		p.authManager.TouchSession(key, user.ID, clientIP)

	} else {
		// Legacy single-key authentication
		if packet.my.Key != (int32)(p.key) {
			return
		}
	}

	sourceKey := replyTokenSourceKey(packet.src, packet.echoId)

	if packet.my.Type == (int32)(MyMsg_PING) {
		t := time.Time{}
		t.UnmarshalBinary(packet.my.Data)
		loggo.Info("ping from %s %s %d %d %d", packet.src.String(), t.String(), packet.my.Rproto, packet.echoId, packet.echoSeq)

		if p.hasActiveTCPConnForSource(sourceKey) {
			p.queueReplyTokens(sourceKey, packet.echoId, packet.echoSeq)
			p.notifyTCPConnsForSource(sourceKey)
			return
		}

		// Use the validated key for response
		responseKey := p.key
		if user != nil {
			responseKey = int(user.Key)
		}

		sendICMP(packet.echoId, packet.echoSeq, *p.conn, packet.src, "", "", (uint32)(MyMsg_PING), packet.my.Data,
			(int)(packet.my.Rproto), -1, responseKey,
			0, 0, 0, 0, 0, 0,
			0, p.cryptoConfig)
		return
	}

	p.queueReplyTokens(sourceKey, packet.echoId, packet.echoSeq)

	if packet.my.Type == (int32)(MyMsg_KICK) {
		localConn := p.getServerConnById(packet.my.Id)
		if localConn != nil {
			// Unregister session when connection closes
			if p.useMultiAuth && localConn.userKey != 0 {
				p.authManager.UnregisterSession(localConn.userKey)
			}
			p.close(localConn)
			loggo.Info("remote kick local %s", packet.my.Id)
		}
		return
	}

	// Track traffic for multi-user mode
	if p.useMultiAuth && user != nil {
		// Store connection -> user mapping
		p.connUserMu.Lock()
		p.connToUser[packet.my.Id] = user.ID
		p.connUserMu.Unlock()

		// Add received traffic
		p.authManager.AddTraffic(user.ID, 0, int64(len(packet.my.Data)))
	}

	if p.maxprocessthread > 0 {
		p.processtp.AddJob((int)(common.HashString(packet.my.Id)), packet)
	} else {
		p.processDataPacket(packet)
	}
}

func (p *Server) processDataPacketNewConn(id string, packet *Packet) *ServerConn {

	now := common.GetNowUpdateInSecond()
	responseKey := p.key
	if p.useMultiAuth {
		responseKey = int(packet.my.Key)
	}

	loggo.Info("start add new connect  %s %s", id, packet.my.Target)

	if p.maxconn > 0 && p.localConnMapSize >= p.maxconn {
		loggo.Info("too many connections %d, server connected target fail %s", p.localConnMapSize, packet.my.Target)
		p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src, responseKey)
		return nil
	}

	addr := packet.my.Target
	if p.isConnError(addr) {
		loggo.Info("addr connect Error before: %s %s", id, addr)
		p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src, responseKey)
		return nil
	}

	// Get user ID for this connection
	var userID int64
	var userKey int
	if p.useMultiAuth {
		p.connUserMu.RLock()
		userID = p.connToUser[id]
		p.connUserMu.RUnlock()
		userKey = int(packet.my.Key)
	}

	if packet.my.Tcpmode > 0 {

		var c net.Conn
		var err error
		if p.forwardConfig != nil {
			c, err = DialThroughProxy(p.forwardConfig, addr, time.Millisecond*time.Duration(p.connecttmeout))
		} else {
			c, err = net.DialTimeout("tcp", addr, time.Millisecond*time.Duration(p.connecttmeout))
		}
		if err != nil {
			loggo.Error("Error listening for tcp packets: %s %s", id, err.Error())
			p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src, responseKey)
			p.addConnError(addr)
			return nil
		}
		var ipaddrTarget *net.TCPAddr
		if p.forwardConfig != nil {
			ipaddrTarget, _ = net.ResolveTCPAddr("tcp", addr)
		} else {
			ipaddrTarget = c.RemoteAddr().(*net.TCPAddr)
		}
		if ipaddrTarget == nil {
			ipaddrTarget = &net.TCPAddr{}
		}

		tcpBufferSize, tcpMaxWindow, tcpResendMillis := sanitizeServerTCPParams((int)(packet.my.TcpmodeBuffersize), (int)(packet.my.TcpmodeMaxwin), (int)(packet.my.TcpmodeResendTimems))
		fm := network.NewFrameMgr(FRAME_MAX_SIZE, FRAME_MAX_ID, tcpBufferSize, tcpMaxWindow, tcpResendMillis, (int)(packet.my.TcpmodeCompress),
			(int)(packet.my.TcpmodeStat))

		localConn := &ServerConn{exit: false, timeout: (int)(packet.my.Timeout), tcpconn: c, tcpaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.my.Rproto), fm: fm, tcpmode: (int)(packet.my.Tcpmode), sourceKey: replyTokenSourceKey(packet.src, packet.echoId), activity: make(chan struct{}, 1), userID: userID, userKey: userKey}

		p.addServerConn(id, localConn)

		go p.RecvTCP(localConn, id, packet.src)
		return localConn

	} else {
		if p.forwardConfig != nil {
			if p.forwardConfig.Scheme != "socks5" {
				loggo.Error("UDP forwarding requires SOCKS5 proxy, got %s", p.forwardConfig.Scheme)
				p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src, responseKey)
				p.addConnError(addr)
				return nil
			}

			if isDNSForwardTarget(addr) {
				response, dnsErr := exchangeDNSOverTCPViaProxy(p.forwardConfig, addr, packet.my.Data, time.Millisecond*time.Duration(p.connecttmeout))
				if dnsErr == nil {
					sendICMP(packet.echoId, packet.echoSeq, *p.conn, packet.src, addr, id, (uint32)(MyMsg_DATA), response,
						(int)(packet.my.Rproto), -1, responseKey, 0,
						0, 0, 0, 0, 0,
						0, p.cryptoConfig)
					p.sendPacket++
					p.sendPacketSize += (uint64)(len(response))
					if p.useMultiAuth && p.authManager != nil && userID != 0 {
						p.authManager.AddTraffic(userID, int64(len(response)), 0)
					}
					return nil
				}
				loggo.Error("DNS over TCP proxy fallback failed: %s %s", id, dnsErr.Error())
			}

			association, err := DialUDPThroughProxy(p.forwardConfig, time.Millisecond*time.Duration(p.connecttmeout))
			if err != nil {
				loggo.Error("Error creating udp forward association: %s %s", id, err.Error())
				p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src, responseKey)
				p.addConnError(addr)
				return nil
			}

			localConn := &ServerConn{
				exit:           false,
				timeout:        (int)(packet.my.Timeout),
				conn:           association.UDPConn,
				udpTargetAddr:  addr,
				udpRelayAddr:   association.RelayAddr,
				udpViaProxy:    true,
				tcpconn:        association.ControlConn,
				id:             id,
				activeRecvTime: now,
				activeSendTime: now,
				close:          false,
				rproto:         (int)(packet.my.Rproto),
				tcpmode:        (int)(packet.my.Tcpmode),
				sourceKey:      replyTokenSourceKey(packet.src, packet.echoId),
				userID:         userID,
				userKey:        userKey,
			}

			p.addServerConn(id, localConn)
			go p.Recv(localConn, id, packet.src)
			return localConn
		}

		c, err := net.DialTimeout("udp", addr, time.Millisecond*time.Duration(p.connecttmeout))
		if err != nil {
			loggo.Error("Error listening for udp packets: %s %s", id, err.Error())
			p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src, responseKey)
			p.addConnError(addr)
			return nil
		}
		targetConn := c.(*net.UDPConn)
		ipaddrTarget := targetConn.RemoteAddr().(*net.UDPAddr)

		localConn := &ServerConn{exit: false, timeout: (int)(packet.my.Timeout), conn: targetConn, ipaddrTarget: ipaddrTarget, udpTargetAddr: addr, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.my.Rproto), tcpmode: (int)(packet.my.Tcpmode), sourceKey: replyTokenSourceKey(packet.src, packet.echoId), userID: userID, userKey: userKey}

		p.addServerConn(id, localConn)

		go p.Recv(localConn, id, packet.src)

		return localConn
	}

	return nil
}

func isDNSForwardTarget(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return port == "53"
}

func exchangeDNSOverTCPViaProxy(config *ForwardConfig, targetAddr string, query []byte, timeout time.Duration) ([]byte, error) {
	if len(query) == 0 {
		return nil, fmt.Errorf("empty dns query")
	}
	if len(query) > 65535 {
		return nil, fmt.Errorf("dns query too large: %d", len(query))
	}

	conn, err := DialThroughProxy(config, targetAddr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set dns tcp deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("failed to write dns tcp query: %w", err)
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read dns tcp response length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if length <= 0 {
		return nil, fmt.Errorf("empty dns tcp response")
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("failed to read dns tcp response: %w", err)
	}
	return response, nil
}

func (p *Server) processDataPacket(packet *Packet) {

	loggo.Debug("processPacket %s %s %d", packet.my.Id, packet.src.String(), len(packet.my.Data))

	now := common.GetNowUpdateInSecond()

	id := packet.my.Id
	localConn := p.getServerConnById(id)
	if localConn == nil {
		localConn = p.processDataPacketNewConn(id, packet)
		if localConn == nil {
			return
		}
	}

	localConn.activeRecvTime = now
	localConn.echoId = packet.echoId
	localConn.echoSeq = packet.echoSeq
	if localConn.sourceKey == "" {
		localConn.sourceKey = replyTokenSourceKey(packet.src, packet.echoId)
	}

	if packet.my.Type == (int32)(MyMsg_DATA) {

		if localConn.tcpmode > 0 {
			f := &network.Frame{}
			err := oldproto.Unmarshal(packet.my.Data, f)
			if err != nil {
				loggo.Error("Unmarshal tcp Error %s", err)
				return
			}

			localConn.fm.OnRecvFrame(f)
			notifyActivity(localConn.activity)

		} else {
			if packet.my.Data == nil {
				return
			}
			var err error
			if localConn.udpViaProxy {
				targetAddr := localConn.udpTargetAddr
				if packet.my.Target != "" {
					targetAddr = packet.my.Target
				}
				if targetAddr == "" {
					loggo.Info("missing udp target for proxied udp conn %s", id)
					localConn.close = true
					return
				}
				udpPacket, packetErr := buildSocks5UDPDatagram(targetAddr, packet.my.Data)
				if packetErr != nil {
					loggo.Info("build socks5 udp datagram error %s", packetErr)
					localConn.close = true
					return
				}
				if localConn.udpRelayAddr == nil {
					loggo.Info("missing udp relay addr for proxied udp conn %s", id)
					localConn.close = true
					return
				}
				_, err = localConn.conn.WriteToUDP(udpPacket, localConn.udpRelayAddr)
			} else {
				_, err = localConn.conn.Write(packet.my.Data)
			}
			if err != nil {
				loggo.Info("WriteToUDP Error %s", err)
				localConn.close = true
				return
			}
		}

		p.recvPacket++
		p.recvPacketSize += (uint64)(len(packet.my.Data))
	}
}

func (p *Server) RecvTCP(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	loggo.Info("server waiting target response %s -> %s %s", conn.tcpaddrTarget.String(), conn.id, conn.tcpconn.LocalAddr().String())

	loggo.Info("start wait remote connect tcp %s %s", conn.id, conn.tcpaddrTarget.String())
	startConnectTime := common.GetNowUpdateInSecond()
	connectWait := newAdaptiveLoopWait(2*time.Millisecond, 80*time.Millisecond)

	// Get the key to use for responses
	responseKey := p.key
	if p.useMultiAuth && conn.userKey != 0 {
		responseKey = conn.userKey
	}

	for !p.exit && !conn.exit {
		if conn.fm.IsConnected() {
			break
		}
		conn.fm.Update()
		hadWork := false
		if p.hasReplyToken(conn.sourceKey) {
			sendlist := conn.fm.GetSendList()
			for _, f := range prioritizeServerFrames(sendlist) {
				if !p.sendTCPFrame(conn, src, f, responseKey) {
					break
				}
				hadWork = true
			}
		}
		time.Sleep(time.Millisecond * 10)
		now := common.GetNowUpdateInSecond()
		diffclose := now.Sub(startConnectTime)
		if diffclose > time.Second*5 {
			loggo.Info("can not connect remote tcp %s %s", conn.id, conn.tcpaddrTarget.String())
			p.close(conn)
			p.remoteError(conn.echoId, conn.echoSeq, id, conn.rproto, src, responseKey)
			return
		}
		if hadWork {
			connectWait.hit()
			continue
		}
		wait := connectWait.miss()
		select {
		case <-conn.activity:
			connectWait.hit()
		case <-time.After(wait):
		}
	}

	if !conn.exit {
		loggo.Info("remote connected tcp %s %s", conn.id, conn.tcpaddrTarget.String())
	}

	bytes := make([]byte, 10240)

	tcpActiveRecvUnix := atomic.Int64{}
	tcpActiveRecvUnix.Store(common.GetNowUpdateInSecond().UnixNano())
	tcpActiveSendTime := common.GetNowUpdateInSecond()
	readErr := make(chan error, 1)
	stopRead := make(chan struct{})

	go func() {
		defer common.CrashLog()

		readWait := newAdaptiveLoopWait(2*time.Millisecond, 80*time.Millisecond)
		for !p.exit && !conn.exit {
			left := common.MinOfInt(conn.fm.GetSendBufferLeft(), len(bytes))
			if left <= 0 {
				wait := readWait.miss()
				select {
				case <-stopRead:
					return
				case <-conn.activity:
					readWait.hit()
					continue
				case <-time.After(wait):
					continue
				}
			}
			readWait.hit()

			conn.tcpconn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.tcpconn.Read(bytes[0:left])
			if err != nil {
				nerr, ok := err.(net.Error)
				if ok && nerr.Timeout() {
					continue
				}
				select {
				case readErr <- err:
				default:
				}
				return
			}
			if n <= 0 {
				continue
			}

			conn.fm.WriteSendBuffer(bytes[:n])
			tcpActiveRecvUnix.Store(common.GetNowUpdateInSecond().UnixNano())
			notifyActivity(conn.activity)
		}
	}()

	loopWait := newAdaptiveLoopWait(2*time.Millisecond, 250*time.Millisecond)
	remoteInputClosed := false

mainLoop:
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()
		hadWork := false

		conn.fm.Update()

		if p.hasReplyToken(conn.sourceKey) {
			sendlist := conn.fm.GetSendList()
			conn.activeSendTime = now
			for _, f := range prioritizeServerFrames(sendlist) {
				if !p.sendTCPFrame(conn, src, f, responseKey) {
					break
				}
				hadWork = true
			}
		}

		if conn.fm.GetRecvBufferSize() > 0 {
			hadWork = true
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := conn.tcpconn.Write(rr)
			if err != nil {
				nerr, ok := err.(net.Error)
				if !ok || !nerr.Timeout() {
					loggo.Info("Error write tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break mainLoop
				}
			}
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				tcpActiveSendTime = now
			}
		}

		if conn.fm.IsRemoteClosed() && !remoteInputClosed && conn.fm.GetRecvBufferSize() == 0 {
			remoteInputClosed = true
			loggo.Info("remote finished sending conn %s %s", conn.id, conn.tcpaddrTarget.String())
		}

		select {
		case err := <-readErr:
			if err != nil {
				loggo.Info("Error read tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
				conn.fm.Close()
				break mainLoop
			}
		default:
		}

		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		tcpdiffrecv := now.Sub(time.Unix(0, tcpActiveRecvUnix.Load()))
		tcpdiffsend := now.Sub(tcpActiveSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) ||
			(tcpdiffrecv > time.Second*(time.Duration(conn.timeout)) && tcpdiffsend > time.Second*(time.Duration(conn.timeout))) {
			loggo.Info("close inactive conn %s %s", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}

		if !hadWork {
			wait := loopWait.miss()
			select {
			case <-conn.activity:
				loopWait.hit()
			case err := <-readErr:
				if err != nil {
					loggo.Info("Error read tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break mainLoop
				}
			case <-time.After(wait):
			}
		} else {
			loopWait.hit()
		}
	}
	close(stopRead)

	conn.fm.Close()

	startCloseTime := common.GetNowUpdateInSecond()
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()

		conn.fm.Update()

		if p.hasReplyToken(conn.sourceKey) {
			sendlist := conn.fm.GetSendList()
			for _, f := range prioritizeServerFrames(sendlist) {
				if !p.sendTCPFrame(conn, src, f, responseKey) {
					break
				}
			}
		}

		nodatarecv := true
		if conn.fm.GetRecvBufferSize() > 0 {
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(time.Millisecond * 100))
			n, _ := conn.tcpconn.Write(rr)
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				nodatarecv = false
			}
		}

		diffclose := now.Sub(startCloseTime)
		if diffclose > time.Second*60 {
			loggo.Info("close conn had timeout %s %s", conn.id, conn.tcpaddrTarget.String())
			break
		}

		remoteclosed := conn.fm.IsRemoteClosed()
		if remoteclosed && nodatarecv {
			loggo.Info("remote conn had closed %s %s", conn.id, conn.tcpaddrTarget.String())
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second)

	loggo.Info("close tcp conn %s %s", conn.id, conn.tcpaddrTarget.String())

	p.close(conn)
}

func (p *Server) Recv(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	loggo.Info("server waiting target response %s -> %s %s", conn.udpTargetString(), conn.id, conn.conn.LocalAddr().String())

	bytes := make([]byte, 65535)

	// Get the key to use for responses
	responseKey := p.key
	if p.useMultiAuth && conn.userKey != 0 {
		responseKey = conn.userKey
	}

	for !p.exit {

		conn.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, srcAddr, err := conn.conn.ReadFromUDP(bytes)
		if err != nil {
			nerr, ok := err.(net.Error)
			if !ok || !nerr.Timeout() {
				loggo.Info("ReadFromUDP Error read udp %s", err)
				conn.close = true
				return
			}
		}
		if n <= 0 {
			continue
		}

		now := common.GetNowUpdateInSecond()
		conn.activeSendTime = now

		targetAddr := conn.udpTargetString()
		payload := bytes[:n]
		if conn.udpViaProxy {
			if conn.udpRelayAddr != nil && !sameUDPAddr(srcAddr, conn.udpRelayAddr) {
				continue
			}
			parsedTarget, parsedPayload, parseErr := parseSocks5UDPDatagram(bytes[:n])
			if parseErr != nil {
				loggo.Debug("parse udp datagram from socks5 relay failed: %s", parseErr)
				continue
			}
			targetAddr = parsedTarget
			payload = parsedPayload
		}

		sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, targetAddr, id, (uint32)(MyMsg_DATA), payload,
			conn.rproto, -1, responseKey, 0,
			0, 0, 0, 0, 0,
			0, p.cryptoConfig)

		p.sendPacket++
		p.sendPacketSize += (uint64)(len(payload))

		// Track sent traffic
		if p.useMultiAuth && p.authManager != nil && conn.userID != 0 {
			p.authManager.AddTraffic(conn.userID, int64(len(payload)), 0)
		}
	}
}

func (p *Server) close(conn *ServerConn) {
	if p.getServerConnById(conn.id) != nil {
		conn.exit = true
		if conn.conn != nil {
			conn.conn.Close()
		}
		if conn.tcpconn != nil {
			conn.tcpconn.Close()
		}
		p.deleteServerConn(conn.id)

		// Clean up connection -> user mapping
		if p.useMultiAuth {
			p.connUserMu.Lock()
			delete(p.connToUser, conn.id)
			p.connUserMu.Unlock()
		}
		if conn.sourceKey != "" && !p.hasActiveTCPConnForSource(conn.sourceKey) {
			p.clearReplyTokens(conn.sourceKey)
		}
	}
}

func (p *Server) checkTimeoutConn() {

	tmp := make(map[string]*ServerConn)
	p.localConnMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		serverConn := value.(*ServerConn)
		tmp[id] = serverConn
		return true
	})

	now := common.GetNowUpdateInSecond()
	for _, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) {
			conn.close = true
		}
	}

	for id, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		if conn.close {
			loggo.Info("close inactive conn %s %s", id, conn.udpTargetString())
			p.close(conn)
		}
	}
}

func (conn *ServerConn) udpTargetString() string {
	if conn.udpTargetAddr != "" {
		return conn.udpTargetAddr
	}
	if conn.ipaddrTarget != nil {
		return conn.ipaddrTarget.String()
	}
	return "unknown"
}

func sameUDPAddr(a *net.UDPAddr, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if b.Port != 0 && a.Port != b.Port {
		return false
	}
	if b.IP == nil || b.IP.IsUnspecified() {
		return true
	}
	if a.IP == nil {
		return false
	}
	return a.IP.Equal(b.IP)
}

func (p *Server) showNet() {
	p.localConnMapSize = 0
	p.localConnMap.Range(func(key, value interface{}) bool {
		p.localConnMapSize++
		return true
	})

	sessionInfo := ""
	if p.useMultiAuth && p.authManager != nil {
		sessionInfo = fmt.Sprintf(" %dSessions", p.authManager.GetActiveSessionCount())
	}

	loggo.Info("send %dPacket/s %dKB/s recv %dPacket/s %dKB/s %dConnections%s",
		p.sendPacket, p.sendPacketSize/1024, p.recvPacket, p.recvPacketSize/1024, p.localConnMapSize, sessionInfo)
	p.sendPacket = 0
	p.recvPacket = 0
	p.sendPacketSize = 0
	p.recvPacketSize = 0
}

func (p *Server) addServerConn(uuid string, serverConn *ServerConn) {
	p.localConnMap.Store(uuid, serverConn)
}

func (p *Server) getServerConnById(uuid string) *ServerConn {
	ret, ok := p.localConnMap.Load(uuid)
	if !ok {
		return nil
	}
	return ret.(*ServerConn)
}

func (p *Server) deleteServerConn(uuid string) {
	p.localConnMap.Delete(uuid)
}

func (p *Server) remoteError(echoId int, echoSeq int, uuid string, rprpto int, src *net.IPAddr, key int) {
	sendICMP(echoId, echoSeq, *p.conn, src, "", uuid, (uint32)(MyMsg_KICK), []byte{},
		rprpto, -1, key,
		0, 0, 0, 0, 0, 0, 0,
		p.cryptoConfig)
}

func (p *Server) addConnError(addr string) {
	_, ok := p.connErrorMap.Load(addr)
	if !ok {
		now := common.GetNowUpdateInSecond()
		p.connErrorMap.Store(addr, now)
	}
}

func (p *Server) isConnError(addr string) bool {
	_, ok := p.connErrorMap.Load(addr)
	return ok
}

func (p *Server) updateConnError() {

	tmp := make(map[string]time.Time)
	p.connErrorMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		t := value.(time.Time)
		tmp[id] = t
		return true
	})

	now := common.GetNowUpdateInSecond()
	for id, t := range tmp {
		diff := now.Sub(t)
		if diff > time.Second*5 {
			p.connErrorMap.Delete(id)
		}
	}
}
