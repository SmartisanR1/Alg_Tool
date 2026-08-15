package utils

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// ============================================================
// TLS/TLCP 双向连接演示（左侧服务端 / 右侧客户端）
// ============================================================

// TLSDemoStartRequest starts a local TLS/TLCP server.
type TLSDemoStartRequest struct {
	Protocol  string `json:"protocol"` // tls1.2, tls1.3, tlcp
	EnablePQC bool   `json:"enablePQC"`
}

// TLSDemoSessionRequest refers to an existing demo session.
type TLSDemoSessionRequest struct {
	SessionID string `json:"sessionId"`
}

// TLSDemoSendRequest sends a message from one side.
type TLSDemoSendRequest struct {
	SessionID string `json:"sessionId"`
	Side      string `json:"side"` // client | server
	Message   string `json:"message"`
}

// TLSDemoResult is the combined state of a demo session.
type TLSDemoResult struct {
	Success        bool     `json:"success"`
	Error          string   `json:"error"`
	SessionID      string   `json:"sessionId"`
	Port           int      `json:"port"`
	ServerStatus   string   `json:"serverStatus"`   // idle | listening | connected | error
	ClientStatus   string   `json:"clientStatus"`   // idle | connected | error
	ServerTimeline []string `json:"serverTimeline"` // 服务端视角协商流程
	ClientTimeline []string `json:"clientTimeline"` // 客户端视角协商流程
	ServerMessages []string `json:"serverMessages"` // 服务端收到的消息
	ClientMessages []string `json:"clientMessages"` // 客户端收到的消息
	CipherSuite    string   `json:"cipherSuite"`
	TLSVersion     string   `json:"tlsVersion"`
	CurveUsed      string   `json:"curveUsed"`
	Certificate    string   `json:"certificate"`
}

type tlsDemoSession struct {
	mu            sync.Mutex
	protocol      string
	enablePQC     bool
	listener      net.Listener
	serverConn    net.Conn
	clientConn    net.Conn
	serverStatus  string
	clientStatus  string
	serverTimeline []string
	clientTimeline []string
	serverMessages []string
	clientMessages []string
	cipherSuite   string
	tlsVersion    string
	curveUsed     string
	certSubject   string
	port          int
}

var (
	demoMu       sync.Mutex
	demoSessions = map[string]*tlsDemoSession{}
)

// TLSDemoServerStart creates a session, starts a local TLS/TLCP server and
// waits for a client in the background.
func TLSDemoServerStart(req TLSDemoStartRequest) TLSDemoResult {
	protocol := req.Protocol
	if protocol == "" {
		protocol = "tls1.3"
	}

	session := &tlsDemoSession{
		protocol:     protocol,
		enablePQC:    req.EnablePQC,
		serverStatus: "listening",
		clientStatus: "idle",
	}

	if protocol == "tlcp" {
		if err := startTLCPDemoServer(session); err != nil {
			return TLSDemoResult{Error: err.Error()}
		}
	} else {
		if err := startTLSDemoServer(session); err != nil {
			return TLSDemoResult{Error: err.Error()}
		}
	}

	id := fmt.Sprintf("demo-%d", time.Now().UnixNano())
	demoMu.Lock()
	demoSessions[id] = session
	demoMu.Unlock()

	return getDemoState(id, session)
}

// TLSDemoClientConnect connects the client side to the local server.
func TLSDemoClientConnect(req TLSDemoSessionRequest) TLSDemoResult {
	session, ok := getDemoSession(req.SessionID)
	if !ok {
		return TLSDemoResult{Error: "会话不存在，请先启动服务端"}
	}

	session.mu.Lock()
	port := session.port
	protocol := session.protocol
	enablePQC := session.enablePQC
	session.mu.Unlock()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	if protocol == "tlcp" {
		if err := tlcpDemoClientConnect(session, addr); err != nil {
			return getDemoState(req.SessionID, session)
		}
	} else {
		if err := tlsDemoClientConnect(session, addr, protocol, enablePQC); err != nil {
			return getDemoState(req.SessionID, session)
		}
	}
	return getDemoState(req.SessionID, session)
}

// TLSDemoSend sends a message from the given side.
func TLSDemoSend(req TLSDemoSendRequest) TLSDemoResult {
	session, ok := getDemoSession(req.SessionID)
	if !ok {
		return TLSDemoResult{Error: "会话不存在"}
	}

	session.mu.Lock()
	var conn net.Conn
	if req.Side == "server" {
		conn = session.serverConn
	} else {
		conn = session.clientConn
	}
	session.mu.Unlock()

	if conn == nil {
		return getDemoState(req.SessionID, session)
	}

	// Send a newline-terminated frame to make framing robust.
	if !strings.HasSuffix(req.Message, "\n") {
		req.Message += "\n"
	}
	if _, err := conn.Write([]byte(req.Message)); err != nil {
		return getDemoState(req.SessionID, session)
	}

	return getDemoState(req.SessionID, session)
}

// TLSDemoGetState returns the current session state.
func TLSDemoGetState(req TLSDemoSessionRequest) TLSDemoResult {
	session, ok := getDemoSession(req.SessionID)
	if !ok {
		return TLSDemoResult{Error: "会话不存在"}
	}
	return getDemoState(req.SessionID, session)
}

// TLSDemoClose shuts down the session and cleans up.
func TLSDemoClose(req TLSDemoSessionRequest) TLSDemoResult {
	session, ok := getDemoSession(req.SessionID)
	if !ok {
		return TLSDemoResult{Success: true}
	}

	session.mu.Lock()
	if session.listener != nil {
		session.listener.Close()
	}
	if session.serverConn != nil {
		session.serverConn.Close()
	}
	if session.clientConn != nil {
		session.clientConn.Close()
	}
	session.serverStatus = "idle"
	session.clientStatus = "idle"
	session.mu.Unlock()

	demoMu.Lock()
	delete(demoSessions, req.SessionID)
	demoMu.Unlock()

	return TLSDemoResult{Success: true, SessionID: req.SessionID}
}

func getDemoSession(id string) (*tlsDemoSession, bool) {
	demoMu.Lock()
	defer demoMu.Unlock()
	s, ok := demoSessions[id]
	return s, ok
}

func getDemoState(id string, s *tlsDemoSession) TLSDemoResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return TLSDemoResult{
		Success:        true,
		SessionID:      id,
		Port:           s.port,
		ServerStatus:   s.serverStatus,
		ClientStatus:   s.clientStatus,
		ServerTimeline: append([]string{}, s.serverTimeline...),
		ClientTimeline: append([]string{}, s.clientTimeline...),
		ServerMessages: append([]string{}, s.serverMessages...),
		ClientMessages: append([]string{}, s.clientMessages...),
		CipherSuite:    s.cipherSuite,
		TLSVersion:     s.tlsVersion,
		CurveUsed:      s.curveUsed,
		Certificate:    s.certSubject,
	}
}

// appendMessage appends a received message (newline trimmed).
func appendMessage(list *[]string, raw []byte) {
	msg := strings.TrimSpace(string(raw))
	if msg != "" {
		*list = append(*list, msg)
	}
}

// ============================================================
// TLS (1.2 / 1.3) demo
// ============================================================

func startTLSDemoServer(s *tlsDemoSession) error {
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("生成证书失败: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("解析证书失败: %w", err)
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       getTLSMinVersion(s.protocol),
		MaxVersion:       getTLSMaxVersion(s.protocol),
		CurvePreferences: demoCurvePreferences(s.enablePQC),
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		return fmt.Errorf("启动 TLS 服务端失败: %w", err)
	}

	s.listener = listener
	s.port = listener.Addr().(*net.TCPAddr).Port
	s.certSubject = "CN=CryptoKit Self-Test"

	// Background accept loop
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			s.serverStatus = "error"
			s.mu.Unlock()
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			s.mu.Lock()
			s.serverStatus = "error"
			s.serverTimeline = append(s.serverTimeline, "✗ 服务端握手失败: "+err.Error())
			s.mu.Unlock()
			return
		}

		state := tlsConn.ConnectionState()
		s.mu.Lock()
		s.serverConn = conn
		s.serverStatus = "connected"
		s.cipherSuite = tls.CipherSuiteName(state.CipherSuite)
		s.tlsVersion = getTLSVersionName(state.Version)
		s.curveUsed = getCurveName(state.CurveID)
		s.serverTimeline = buildTLSServerTimeline(state, s.protocol, s.enablePQC)
		s.mu.Unlock()

		// Server reader goroutine
		go demoServerReader(s, conn)
	}()

	return nil
}

func tlsDemoClientConnect(s *tlsDemoSession, addr, protocol string, enablePQC bool) error {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         getTLSMinVersion(protocol),
		MaxVersion:         getTLSMaxVersion(protocol),
		CurvePreferences:   demoCurvePreferences(enablePQC),
	}

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		s.mu.Lock()
		s.clientStatus = "error"
		s.clientTimeline = append(s.clientTimeline, "✗ 客户端连接失败: "+err.Error())
		s.mu.Unlock()
		return err
	}

	state := conn.ConnectionState()
	s.mu.Lock()
	s.clientConn = conn
	s.clientStatus = "connected"
	s.cipherSuite = tls.CipherSuiteName(state.CipherSuite)
	s.tlsVersion = getTLSVersionName(state.Version)
	s.curveUsed = getCurveName(state.CurveID)
	s.clientTimeline = buildTLSClientTimeline(state, protocol, enablePQC)
	s.mu.Unlock()

	go demoClientReader(s, conn)
	return nil
}

func demoCurvePreferences(enablePQC bool) []tls.CurveID {
	prefs := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	if enablePQC {
		prefs = []tls.CurveID{
			tls.CurveID(0x11ec), // X25519MLKEM768
			tls.CurveID(0x11eb), // SecP256r1MLKEM768
			tls.X25519,
			tls.CurveP256,
		}
	}
	return prefs
}

func buildTLSClientTimeline(state tls.ConnectionState, protocol string, enablePQC bool) []string {
	curve := getCurveName(state.CurveID)
	suite := tls.CipherSuiteName(state.CipherSuite)
	ver := getTLSVersionName(state.Version)
	ks := "X25519 / P-256 / P-384 / P-521"
	if enablePQC {
		ks = "X25519MLKEM768 / P-256MLKEM768 / X25519"
	}
	return []string{
		"Client → Server: ClientHello (" + ver + ", 密钥交换: " + ks + ")",
		"Server → Client: ServerHello (协商版本: " + ver + ", 密码套件: " + suite + ")",
		"Server → Client: Certificate (自签名 " + state.PeerCertificates[0].Subject.String() + ")",
		"Server → Client: 密钥交换 (协商组: " + curve + ")",
		"Server → Client: Finished",
		"Client → Server: Finished",
		"✓ 握手完成，会话已建立",
	}
}

func buildTLSServerTimeline(state tls.ConnectionState, protocol string, enablePQC bool) []string {
	curve := getCurveName(state.CurveID)
	suite := tls.CipherSuiteName(state.CipherSuite)
	ver := getTLSVersionName(state.Version)
	ks := "X25519 / P-256 / P-384 / P-521"
	if enablePQC {
		ks = "X25519MLKEM768 / P-256MLKEM768 / X25519"
	}
	return []string{
		"Server ← Client: ClientHello (" + ver + ", 密钥交换: " + ks + ")",
		"Server → Client: ServerHello (协商版本: " + ver + ", 密码套件: " + suite + ")",
		"Server → Client: Certificate (自签名 CN=CryptoKit Self-Test)",
		"Server → Client: 密钥交换 (协商组: " + curve + ")",
		"Server → Client: Finished",
		"Server ← Client: Finished",
		"✓ 握手完成，会话已建立",
	}
}

// ============================================================
// TLCP (国密) demo
// ============================================================

func startTLCPDemoServer(s *tlsDemoSession) error {
	signCertPEM, signKeyPEM, err := generateSM2Cert()
	if err != nil {
		return fmt.Errorf("生成签名证书失败: %w", err)
	}
	encCertPEM, encKeyPEM, err := generateSM2Cert()
	if err != nil {
		return fmt.Errorf("生成加密证书失败: %w", err)
	}

	signCert, err := gotlcp.X509KeyPair(signCertPEM, signKeyPEM)
	if err != nil {
		return fmt.Errorf("解析签名证书失败: %w", err)
	}
	encCert, err := gotlcp.X509KeyPair(encCertPEM, encKeyPEM)
	if err != nil {
		return fmt.Errorf("解析加密证书失败: %w", err)
	}

	cert, _ := smx509.ParseCertificatePEM(signCertPEM)
	caPool := smx509.NewCertPool()
	caPool.AddCert(cert)

	cfg := &gotlcp.Config{
		Certificates: []gotlcp.Certificate{signCert, encCert},
		ClientCAs:    caPool,
		ClientAuth:   gotlcp.NoClientCert,
	}

	listener, err := gotlcp.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		return fmt.Errorf("启动 TLCP 服务端失败: %w", err)
	}

	s.listener = listener
	s.port = listener.Addr().(*net.TCPAddr).Port
	s.certSubject = "CN=CryptoKit TLCP Self-Test (SM2 签名+加密双证书)"

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			s.serverStatus = "error"
			s.mu.Unlock()
			return
		}
		tlcpConn := conn.(*gotlcp.Conn)
		if err := tlcpConn.Handshake(); err != nil {
			s.mu.Lock()
			s.serverStatus = "error"
			s.serverTimeline = append(s.serverTimeline, "✗ 服务端握手失败: "+err.Error())
			s.mu.Unlock()
			return
		}

		state := tlcpConn.ConnectionState()
		s.mu.Lock()
		s.serverConn = conn
		s.serverStatus = "connected"
		s.cipherSuite = gotlcp.CipherSuiteName(state.CipherSuite)
		s.tlsVersion = getTLSVersionName(state.Version)
		s.curveUsed = "SM2"
		s.serverTimeline = buildTLCPTimeline("server", state)
		s.mu.Unlock()

		go demoServerReader(s, conn)
	}()

	return nil
}

func tlcpDemoClientConnect(s *tlsDemoSession, addr string) error {
	signCertPEM, signKeyPEM, err := generateSM2Cert()
	if err != nil {
		return err
	}
	encCertPEM, encKeyPEM, err := generateSM2Cert()
	if err != nil {
		return err
	}
	clientSignCert, err := gotlcp.X509KeyPair(signCertPEM, signKeyPEM)
	if err != nil {
		return err
	}
	clientEncCert, err := gotlcp.X509KeyPair(encCertPEM, encKeyPEM)
	if err != nil {
		return err
	}

	cfg := &gotlcp.Config{
		InsecureSkipVerify: true,
		Certificates:       []gotlcp.Certificate{clientSignCert, clientEncCert},
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := gotlcp.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		s.mu.Lock()
		s.clientStatus = "error"
		s.clientTimeline = append(s.clientTimeline, "✗ 客户端连接失败: "+err.Error())
		s.mu.Unlock()
		return err
	}

	state := conn.ConnectionState()
	s.mu.Lock()
	s.clientConn = conn
	s.clientStatus = "connected"
	s.cipherSuite = gotlcp.CipherSuiteName(state.CipherSuite)
	s.tlsVersion = getTLSVersionName(state.Version)
	s.curveUsed = "SM2"
	s.clientTimeline = buildTLCPTimeline("client", state)
	s.mu.Unlock()

	go demoClientReader(s, conn)
	return nil
}

func buildTLCPTimeline(side string, state gotlcp.ConnectionState) []string {
	suite := gotlcp.CipherSuiteName(state.CipherSuite)
	ver := getTLSVersionName(state.Version)
	dir := map[string]string{"client": "Client", "server": "Server"}[side]
	peer := "Server"
	if side == "server" {
		peer = "Client"
	}
	return []string{
		dir + " → " + peer + ": ClientHello (TLCP 1.1, 国密套件: " + suite + ")",
		peer + " → " + dir + ": ServerHello (协商版本: " + ver + ", 密码套件: " + suite + ")",
		peer + " → " + dir + ": Certificate (SM2 签名证书 + 加密证书双证书)",
		peer + " → " + dir + ": ServerKeyExchange (ECC + SM3 签名)",
		peer + " → " + dir + ": Finished",
		dir + " → " + peer + ": Finished",
		"✓ 握手完成，会话已建立 (SM2 密钥交换 + SM4 加密)",
	}
}

// ============================================================
// Reader goroutines
// ============================================================

func demoServerReader(s *tlsDemoSession, conn net.Conn) {
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		appendMessage(&s.serverMessages, buf[:n])
		s.mu.Unlock()
	}
}

func demoClientReader(s *tlsDemoSession, conn net.Conn) {
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		appendMessage(&s.clientMessages, buf[:n])
		s.mu.Unlock()
	}
}

var _ = hex.EncodeToString // keep import if unused later
