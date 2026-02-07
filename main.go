package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	TCP_FORWARD  = 1
	UDP_FORWARD  = 2
	SO_REUSEPORT = 15
)

type ForwardRule struct {
	srcPort    string
	targetPort string
	proto      int
}

type UDPSession struct {
	conn       *net.UDPConn
	stream     quic.Stream
	clientAddr *net.UDPAddr
	lastActive time.Time
	mu         sync.Mutex
}

type RelayConnection struct {
	host       string
	conn       quic.Connection
	active     atomic.Bool
	connected  atomic.Bool
	lastCheck  time.Time
	mu         sync.Mutex
}

type RelayManager struct {
	relays        []*RelayConnection
	activeRelay   atomic.Value // *RelayConnection
	token         string
	forwardRules  string
	strategy      string
	reconnectChan chan string
	mu            sync.RWMutex
}

type ActiveRelaySession struct {
	conn      quic.Connection
	listeners []io.Closer
	mu        sync.Mutex
}

var (
	mode       = flag.String("mode", "", "Mode: relay or vpn")
	port       = flag.String("port", "", "Relay server port")
	host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple servers)")
	token      = flag.String("token", "", "Authentication token")
	forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
	forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
	strategy   = flag.String("strategy", "multi", "Strategy: multi (all relays active) or failover (one active at a time)")
	certFile   = flag.String("cert", "", "TLS certificate file (optional, auto-generated if not provided)")
	keyFile    = flag.String("key", "", "TLS key file (optional, auto-generated if not provided)")

	currentRelaySession   *ActiveRelaySession
	currentRelaySessionMu sync.Mutex
)

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	if *mode == "relay" {
		if *port == "" {
			log.Fatal("Port is required for relay mode")
		}
		runRelay()
	} else if *mode == "vpn" {
		if *host == "" {
			log.Fatal("Host is required for vpn mode")
		}
		runVPN()
	} else {
		log.Fatal("Invalid mode. Use 'relay' or 'vpn'")
	}
}

func generateTLSConfig(isServer bool) (*tls.Config, error) {
	// Check if cert/key files exist
	if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return nil, err
		}
		if isServer {
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"relay-quic"},
			}, nil
		}
		return &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"relay-quic"},
		}, nil
	}

	// Generate self-signed certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Relay VPN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	if isServer {
		return &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"relay-quic"},
		}, nil
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"relay-quic"},
	}, nil
}

func runRelay() {
	tlsConfig, err := generateTLSConfig(true)
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}

	// Optimized QUIC config for low latency
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     1 * 1024 * 1024,  // 1MB
		MaxStreamReceiveWindow:         4 * 1024 * 1024,  // 4MB
		InitialConnectionReceiveWindow: 4 * 1024 * 1024,  // 4MB
		MaxConnectionReceiveWindow:     16 * 1024 * 1024, // 16MB
		EnableDatagrams:                true,
		Allow0RTT:                      true,
	}

	listener, err := quic.ListenAddr(":"+*port, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to start QUIC relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("QUIC relay server listening on :%s", *port)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleRelayConnection(conn)
	}
}

func closeCurrentSession() {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	if currentRelaySession != nil {
		currentRelaySession.mu.Lock()
		log.Printf("Closing previous session to allow immediate reconnection...")

		for _, l := range currentRelaySession.listeners {
			l.Close()
		}
		currentRelaySession.listeners = nil

		if currentRelaySession.conn != nil {
			currentRelaySession.conn.CloseWithError(0, "new session")
		}
		currentRelaySession.mu.Unlock()

		currentRelaySession = nil
		log.Printf("Previous session closed, ports freed")
	}
}

func setCurrentSession(conn quic.Connection) *ActiveRelaySession {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	currentRelaySession = &ActiveRelaySession{
		conn:      conn,
		listeners: make([]io.Closer, 0),
	}
	return currentRelaySession
}

func (ars *ActiveRelaySession) addListener(l io.Closer) {
	ars.mu.Lock()
	defer ars.mu.Unlock()
	ars.listeners = append(ars.listeners, l)
}

func handleRelayConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "session ended")

	// Accept control stream for authentication
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Failed to accept auth stream: %v", err)
		return
	}

	// Authenticate: read exact token length
	tokLen := len(*token)
	tokBuf := make([]byte, tokLen)
	if _, err := io.ReadFull(stream, tokBuf); err != nil {
		log.Printf("Auth read error from %s: %v", conn.RemoteAddr(), err)
		stream.Close()
		return
	}
	if string(tokBuf) != *token {
		log.Printf("Authentication failed from %s", conn.RemoteAddr())
		stream.Close()
		return
	}

	// Close any existing session BEFORE sending OK
	closeCurrentSession()

	// Send OK
	if _, err := stream.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK: %v", err)
		stream.Close()
		return
	}
	log.Printf("VPN client authenticated: %s", conn.RemoteAddr())

	// Receive forward rules
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		log.Printf("Failed to read forward rules length: %v", err)
		stream.Close()
		return
	}
	ruleLen := binary.BigEndian.Uint16(lenBuf)

	var forwardRules, forwardudpRules string
	if ruleLen > 0 {
		ruleBuf := make([]byte, ruleLen)
		if _, err := io.ReadFull(stream, ruleBuf); err != nil {
			log.Printf("Failed to read forward rules: %v", err)
			stream.Close()
			return
		}

		parts := strings.Split(string(ruleBuf), "|")
		if len(parts) >= 1 {
			forwardRules = parts[0]
		}
		if len(parts) >= 2 {
			forwardudpRules = parts[1]
		}
		log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)
	}

	stream.Close()

	// Register this connection as the current active session
	activeSession := setCurrentSession(conn)

	// Parse forward rules
	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

	// Start TCP forwarders
	for _, rule := range tcpRules {
		listener, err := createReusableListener("tcp", ":"+rule.srcPort)
		if err != nil {
			log.Printf("Failed to listen on TCP port %s: %v", rule.srcPort, err)
			continue
		}
		activeSession.addListener(listener)

		go startTCPForwarderWithListener(conn, rule, listener)
	}

	// Start UDP forwarders
	for _, rule := range udpRules {
		addr, err := net.ResolveUDPAddr("udp", ":"+rule.srcPort)
		if err != nil {
			log.Printf("Failed to resolve UDP address %s: %v", rule.srcPort, err)
			continue
		}
		udpConn, err := createReusableUDPListener(addr)
		if err != nil {
			log.Printf("Failed to listen on UDP port %s: %v", rule.srcPort, err)
			continue
		}
		activeSession.addListener(udpConn)

		go startUDPForwarderWithConn(conn, rule, udpConn)
	}

	// Keep connection alive while active
	<-conn.Context().Done()
	log.Printf("QUIC connection closed")
}

func startTCPForwarderWithListener(qConn quic.Connection, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
			return
		}

		go func(c net.Conn) {
			defer c.Close()

			if tcpConn, ok := c.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}

			stream, err := qConn.OpenStreamSync(context.Background())
			if err != nil {
				log.Printf("Failed to open QUIC stream for TCP forward: %v", err)
				return
			}
			defer stream.Close()

			// Send forward header
			header := []byte{TCP_FORWARD}
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				log.Printf("Target port string too long: %s", rule.targetPort)
				return
			}
			header = append(header, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				log.Printf("Failed to write header to stream: %v", err)
				return
			}

			// Bidirectional copy
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				buf := make([]byte, 32*1024)
				io.CopyBuffer(stream, c, buf)
				stream.Close()
			}()

			go func() {
				defer wg.Done()
				buf := make([]byte, 32*1024)
				io.CopyBuffer(c, stream, buf)
				c.Close()
			}()

			wg.Wait()
		}(conn)
	}
}

func startUDPForwarderWithConn(qConn quic.Connection, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := make(map[string]*UDPSession)
	var sessionsMu sync.RWMutex

	stopCleanup := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCleanup:
				return
			case <-ticker.C:
				sessionsMu.Lock()
				now := time.Now()
				for key, sess := range sessions {
					sess.mu.Lock()
					if now.Sub(sess.lastActive) > 2*time.Minute {
						sess.stream.Close()
						delete(sessions, key)
					}
					sess.mu.Unlock()
				}
				sessionsMu.Unlock()
			}
		}
	}()
	defer close(stopCleanup)

	buf := make([]byte, 16*1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			sessionsMu.Lock()
			for _, sess := range sessions {
				sess.stream.Close()
			}
			sessionsMu.Unlock()
			log.Printf("UDP read error on %s: %v", rule.srcPort, err)
			return
		}

		sessionKey := clientAddr.String()

		sessionsMu.RLock()
		sess, exists := sessions[sessionKey]
		sessionsMu.RUnlock()

		if !exists {
			stream, err := qConn.OpenStreamSync(context.Background())
			if err != nil {
				log.Printf("Failed to open QUIC stream for UDP client %s: %v", sessionKey, err)
				continue
			}

			// Send forward header
			header := []byte{UDP_FORWARD}
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				log.Printf("Target port string too long: %s", rule.targetPort)
				stream.Close()
				continue
			}
			header = append(header, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				log.Printf("Failed to write UDP header: %v", err)
				stream.Close()
				continue
			}

			sess = &UDPSession{
				conn:       conn,
				stream:     stream,
				clientAddr: clientAddr,
				lastActive: time.Now(),
			}

			sessionsMu.Lock()
			sessions[sessionKey] = sess
			sessionsMu.Unlock()

			keyCopy := sessionKey
			go func(s quic.Stream, session *UDPSession, sessKey string) {
				defer s.Close()
				respBuf := make([]byte, 16*1024)
				for {
					lenBuf := make([]byte, 2)
					if _, err := io.ReadFull(s, lenBuf); err != nil {
						sessionsMu.Lock()
						if v, ok := sessions[sessKey]; ok && v == session {
							delete(sessions, sessKey)
						}
						sessionsMu.Unlock()
						return
					}
					length := binary.BigEndian.Uint16(lenBuf)
					if int(length) > len(respBuf) {
						sessionsMu.Lock()
						if v, ok := sessions[sessKey]; ok && v == session {
							delete(sessions, sessKey)
						}
						sessionsMu.Unlock()
						return
					}

					if _, err := io.ReadFull(s, respBuf[:length]); err != nil {
						sessionsMu.Lock()
						if v, ok := sessions[sessKey]; ok && v == session {
							delete(sessions, sessKey)
						}
						sessionsMu.Unlock()
						return
					}

					session.mu.Lock()
					session.conn.WriteToUDP(respBuf[:length], session.clientAddr)
					session.lastActive = time.Now()
					session.mu.Unlock()
				}
			}(stream, sess, keyCopy)
		}

		sess.mu.Lock()
		sess.lastActive = time.Now()
		if n > 65535 {
			sess.mu.Unlock()
			continue
		}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		if _, err := sess.stream.Write(lenBuf); err != nil {
			sess.stream.Close()
			deleteSessionSafe(&sessions, &sessionsMu, sessionKey)
			sess.mu.Unlock()
			continue
		}
		if _, err := sess.stream.Write(buf[:n]); err != nil {
			sess.stream.Close()
			deleteSessionSafe(&sessions, &sessionsMu, sessionKey)
			sess.mu.Unlock()
			continue
		}
		sess.mu.Unlock()
	}
}

func deleteSessionSafe(sessions *map[string]*UDPSession, mu *sync.RWMutex, key string) {
	mu.Lock()
	if s, ok := (*sessions)[key]; ok {
		s.stream.Close()
		delete(*sessions, key)
	}
	mu.Unlock()
}

func runVPN() {
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("Configuring VPN with %d relay servers: %v", len(hosts), hosts)
	log.Printf("Strategy: %s", *strategy)

	forwardRules := *forward + "|" + *forwardudp

	manager := &RelayManager{
		relays:        make([]*RelayConnection, len(hosts)),
		token:         *token,
		forwardRules:  forwardRules,
		strategy:      *strategy,
		reconnectChan: make(chan string, len(hosts)),
	}

	for i, h := range hosts {
		manager.relays[i] = &RelayConnection{
			host: h,
		}
	}

	var wg sync.WaitGroup
	for _, relay := range manager.relays {
		wg.Add(1)
		go func(r *RelayConnection) {
			defer wg.Done()
			manager.maintainConnection(r)
		}(relay)
	}

	go manager.monitorRelays()

	wg.Wait()
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	tlsConfig, err := generateTLSConfig(false)
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     1 * 1024 * 1024,
		MaxStreamReceiveWindow:         4 * 1024 * 1024,
		InitialConnectionReceiveWindow: 4 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
		EnableDatagrams:                true,
		Allow0RTT:                      false, // Client doesn't use 0-RTT for security
	}

	for {
		log.Printf("[%s] Connecting to QUIC relay server...", relay.host)

		conn, err := quic.DialAddr(context.Background(), relay.host, tlsConfig, quicConfig)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v. Retrying in 2s...", relay.host, err)
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		// Open control stream for authentication
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			log.Printf("[%s] Failed to open auth stream: %v", relay.host, err)
			conn.CloseWithError(0, "auth failed")
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		// Authenticate
		if _, err := stream.Write([]byte(rm.token)); err != nil {
			log.Printf("[%s] Failed to send token: %v", relay.host, err)
			stream.Close()
			conn.CloseWithError(0, "auth failed")
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(stream, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("[%s] Authentication failed: %v", relay.host, err)
			stream.Close()
			conn.CloseWithError(0, "auth failed")
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		// Send forward rules
		ruleLen := make([]byte, 2)
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			stream.Close()
			conn.CloseWithError(0, "rules too long")
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
		if _, err := stream.Write(ruleLen); err != nil {
			log.Printf("[%s] Failed to send forward rules length: %v", relay.host, err)
			stream.Close()
			conn.CloseWithError(0, "send rules failed")
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		if len(rm.forwardRules) > 0 {
			if _, err := stream.Write([]byte(rm.forwardRules)); err != nil {
				log.Printf("[%s] Failed to send forward rules: %v", relay.host, err)
				stream.Close()
				conn.CloseWithError(0, "send rules failed")
				relay.connected.Store(false)
				time.Sleep(2 * time.Second)
				continue
			}
		}

		stream.Close()
		log.Printf("[%s] Connected and authenticated", relay.host)

		relay.mu.Lock()
		relay.conn = conn
		relay.lastCheck = time.Now()
		relay.mu.Unlock()
		relay.connected.Store(true)

		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		rm.handleVPNSession(relay, conn)

		relay.mu.Lock()
		relay.active.Store(false)
		relay.connected.Store(false)
		relay.mu.Unlock()

		conn.CloseWithError(0, "reconnecting")
		log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (rm *RelayManager) monitorRelays() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.checkAndSwitchRelay()
		case <-rm.reconnectChan:
			rm.checkAndSwitchRelay()
		}
	}
}

func (r *RelayConnection) connIsClosed() bool {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn == nil {
		return true
	}
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		for _, relay := range rm.relays {
			connClosed := relay.connIsClosed()
			if relay.connected.Load() && !connClosed {
				if !relay.active.Load() {
					relay.active.Store(true)
					log.Printf("[%s] Marked as ACTIVE (multi strategy)", relay.host)
				}
			} else {
				if relay.active.Load() {
					relay.active.Store(false)
					log.Printf("[%s] Marked as INACTIVE (disconnected)", relay.host)
				}
			}
		}
		return
	}

	// Failover strategy
	currentActive := rm.activeRelay.Load()
	var currentRelay *RelayConnection
	if currentActive != nil {
		currentRelay = currentActive.(*RelayConnection)
	}

	if currentRelay != nil && currentRelay.connected.Load() && !currentRelay.connIsClosed() {
		return
	}

	if currentRelay != nil {
		currentRelay.active.Store(false)
		log.Printf("[%s] Marked as inactive", currentRelay.host)
	}

	for _, relay := range rm.relays {
		if relay.connected.Load() && !relay.connIsClosed() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
			return
		}
	}

	if currentRelay != nil {
		log.Printf("WARNING: No relay servers available, waiting for reconnection...")
	}
}

func (rm *RelayManager) handleVPNSession(relay *RelayConnection, conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go func(s quic.Stream) {
			defer s.Close()

			header := make([]byte, 2)
			if _, err := io.ReadFull(s, header); err != nil {
				return
			}

			proto := header[0]
			portLen := header[1]
			if portLen == 0 {
				return
			}
			portBuf := make([]byte, portLen)
			if _, err := io.ReadFull(s, portBuf); err != nil {
				return
			}

			targetPort := string(portBuf)

			if !relay.active.Load() {
				return
			}

			if proto == TCP_FORWARD {
				handleTCPStream(s, targetPort)
			} else if proto == UDP_FORWARD {
				handleUDPStream(s, targetPort)
			}
		}(stream)
	}
}

func handleTCPStream(stream quic.Stream, targetPort string) {
	target, err := net.Dial("tcp", "127.0.0.1:"+targetPort)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		io.CopyBuffer(target, stream, buf)
		target.Close()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		io.CopyBuffer(stream, target, buf)
		stream.Close()
	}()

	wg.Wait()
}

func handleUDPStream(stream quic.Stream, targetPort string) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+targetPort)
	if err != nil {
		log.Printf("Failed to resolve UDP target %s: %v", targetPort, err)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("Failed to dial UDP target %s: %v", targetPort, err)
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		for {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(buf) {
				return
			}
			if _, err := io.ReadFull(stream, buf[:length]); err != nil {
				return
			}
			if _, err := conn.Write(buf[:length]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 65535 {
				return
			}
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(n))
			if _, err := stream.Write(lenBuf); err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func parseForwardRules(rules string, proto int) []ForwardRule {
	if rules == "" {
		return nil
	}

	var result []ForwardRule
	pairs := strings.Split(rules, ";")
	for _, pair := range pairs {
		parts := strings.Split(pair, ",")
		if len(parts) == 2 {
			result = append(result, ForwardRule{
				srcPort:    strings.TrimSpace(parts[0]),
				targetPort: strings.TrimSpace(parts[1]),
				proto:      proto,
			})
		}
	}
	return result
}

func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1); e != nil && err == nil {
					err = e
				}
			})
			return err
		},
	}
	return lc.Listen(context.Background(), network, address)
}

func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, a string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1); e != nil && err == nil {
					err = e
				}
			})
			return err
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
