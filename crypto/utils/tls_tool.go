package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// TLSConnectRequest represents a TLS/TLCP connection request
type TLSConnectRequest struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Protocol           string `json:"protocol"` // tls1.0, tls1.1, tls1.2, tls1.3, tlcp
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	CACertPEM          string `json:"caCertPEM"`
	ClientCertPEM      string `json:"clientCertPEM"`
	ClientKeyPEM       string `json:"clientKeyPEM"`
	// TLCP dual-cert
	ClientEncCertPEM string `json:"clientEncCertPEM"`
	ClientEncKeyPEM  string `json:"clientEncKeyPEM"`
	TimeoutMs        int    `json:"timeoutMs"`
	// PQC support
	EnablePQC bool `json:"enablePQC"`
}

// CertInfo represents certificate information
type CertInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serialNumber"`
	NotBefore    string   `json:"notBefore"`
	NotAfter     string   `json:"notAfter"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
	IsCA         bool     `json:"isCA"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
	SigAlgorithm string   `json:"sigAlgorithm"`
	Fingerprint  string   `json:"fingerprint"`
	RawPEM       string   `json:"rawPEM"`
}

// TLSConnectResult represents the result of a TLS/TLCP connection
type TLSConnectResult struct {
	Success          bool       `json:"success"`
	Protocol         string     `json:"protocol"`
	CipherSuite      string     `json:"cipherSuite"`
	CipherSuiteID    string     `json:"cipherSuiteId"`
	ServerName       string     `json:"serverName"`
	TLSVersion       string     `json:"tlsVersion"`
	HandshakeTimeMs  int64      `json:"handshakeTimeMs"`
	PeerCertificates []CertInfo `json:"peerCertificates"`
	ALPNProtocol     string     `json:"alpnProtocol"`
	SessionReused    bool       `json:"sessionReused"`
	CurveUsed        string     `json:"curveUsed"`
	Error            string     `json:"error"`
}

// getTLSVersionName returns human-readable TLS version
func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0x0101:
		return "TLCP 1.1"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", version)
	}
}

// getCurveName returns human-readable curve name
func getCurveName(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case 0x11ec:
		return "X25519MLKEM768 (PQC)"
	case 0x11eb:
		return "SecP256r1MLKEM768 (PQC)"
	case 0x11ed:
		return "SecP384r1MLKEM1024 (PQC)"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", id)
	}
}

// getTLSMinVersion returns the minimum TLS version for the protocol
func getTLSMinVersion(protocol string) uint16 {
	switch protocol {
	case "tls1.0":
		return tls.VersionTLS10
	case "tls1.1":
		return tls.VersionTLS11
	case "tls1.2":
		return tls.VersionTLS12
	case "tls1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// getTLSMaxVersion returns the maximum TLS version for the protocol
func getTLSMaxVersion(protocol string) uint16 {
	switch protocol {
	case "tls1.0":
		return tls.VersionTLS10
	case "tls1.1":
		return tls.VersionTLS11
	case "tls1.2":
		return tls.VersionTLS12
	case "tls1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS13
	}
}

// extractCertInfo extracts certificate information
func extractCertInfo(cert interface{}) CertInfo {
	info := CertInfo{}

	switch c := cert.(type) {
	case *x509.Certificate:
		info.Subject = c.Subject.String()
		info.Issuer = c.Issuer.String()
		info.SerialNumber = c.SerialNumber.Text(16)
		info.NotBefore = c.NotBefore.Format("2006-01-02 15:04:05 MST")
		info.NotAfter = c.NotAfter.Format("2006-01-02 15:04:05 MST")
		info.DNSNames = c.DNSNames
		for _, ip := range c.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, ip.String())
		}
		info.IsCA = c.IsCA
		info.KeyAlgorithm = c.PublicKeyAlgorithm.String()
		info.SigAlgorithm = c.SignatureAlgorithm.String()
		fingerprint := sha256.Sum256(c.Raw)
		parts := make([]string, len(fingerprint))
		for i, b := range fingerprint {
			parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
		}
		info.Fingerprint = strings.Join(parts, ":")
	case *smx509.Certificate:
		info.Subject = c.Subject.String()
		info.Issuer = c.Issuer.String()
		info.SerialNumber = c.SerialNumber.Text(16)
		info.NotBefore = c.NotBefore.Format("2006-01-02 15:04:05 MST")
		info.NotAfter = c.NotAfter.Format("2006-01-02 15:04:05 MST")
		info.DNSNames = c.DNSNames
		for _, ip := range c.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, ip.String())
		}
		info.IsCA = c.IsCA
		info.KeyAlgorithm = c.PublicKeyAlgorithm.String()
		info.SigAlgorithm = c.SignatureAlgorithm.String()
		fingerprint := sha256.Sum256(c.Raw)
		parts := make([]string, len(fingerprint))
		for i, b := range fingerprint {
			parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
		}
		info.Fingerprint = strings.Join(parts, ":")
	}

	return info
}

// generateSelfSignedCert generates a self-signed certificate for testing
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CryptoKit Self-Test",
			Organization: []string{"CryptoKit"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateSM2Cert generates a SM2 self-signed certificate for TLCP testing
func generateSM2Cert() (certPEM, keyPEM []byte, err error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &smx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CryptoKit TLCP Self-Test",
			Organization: []string{"CryptoKit"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth, smx509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := smx509.MarshalSM2PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// TLSConnect performs a TLS/TLCP connection and returns connection details
func TLSConnect(req TLSConnectRequest) TLSConnectResult {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return TLSConnectResult{Error: "主机地址不能为空"}
	}

	port := req.Port
	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	timeout := req.TimeoutMs
	if timeout == 0 {
		timeout = 10000
	}

	if req.Protocol == "tlcp" {
		return tlsConnectTLCP(addr, host, req, timeout)
	}
	return tlsConnectTLS(addr, host, req, timeout)
}

// tlsConnectTLS performs a standard TLS connection
func tlsConnectTLS(addr, host string, req TLSConnectRequest, timeoutMs int) TLSConnectResult {
	start := time.Now()

	serverName := req.ServerName
	if serverName == "" {
		serverName = host
	}

	// Build CA pool
	var rootCAs *x509.CertPool
	if req.CACertPEM != "" {
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM([]byte(req.CACertPEM)) {
			return TLSConnectResult{Error: "无法解析 CA 证书"}
		}
	}

	// Build client certificate
	var certificates []tls.Certificate
	if req.ClientCertPEM != "" && req.ClientKeyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM))
		if err != nil {
			return TLSConnectResult{Error: "客户端证书解析失败: " + err.Error()}
		}
		certificates = append(certificates, cert)
	}

	minVersion := getTLSMinVersion(req.Protocol)
	maxVersion := getTLSMaxVersion(req.Protocol)

	// Build curve preferences
	curvePreferences := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	if req.EnablePQC {
		curvePreferences = []tls.CurveID{
			tls.CurveID(0x11ec), // X25519MLKEM768
			tls.CurveID(0x11eb), // SecP256r1MLKEM768
			tls.X25519,
			tls.CurveP256,
		}
	}

	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CurvePreferences:   curvePreferences,
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return TLSConnectResult{Error: "TLS 连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	state := conn.ConnectionState()

	// Get the negotiated curve (key exchange algorithm)
	curveUsed := getCurveName(state.CurveID)

	result := TLSConnectResult{
		Success:         true,
		Protocol:        req.Protocol,
		CipherSuite:     tls.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:   fmt.Sprintf("0x%04X", state.CipherSuite),
		ServerName:      state.ServerName,
		TLSVersion:      getTLSVersionName(state.Version),
		HandshakeTimeMs: handshakeTime,
		ALPNProtocol:    state.NegotiatedProtocol,
		SessionReused:   state.DidResume,
		CurveUsed:       curveUsed,
	}

	for _, cert := range state.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, extractCertInfo(cert))
	}

	return result
}

// tlsConnectTLCP performs a TLCP connection
func tlsConnectTLCP(addr, host string, req TLSConnectRequest, timeoutMs int) TLSConnectResult {
	start := time.Now()

	serverName := req.ServerName
	if serverName == "" {
		serverName = host
	}

	// Build CA pool
	var rootCAs *smx509.CertPool
	if req.CACertPEM != "" {
		rootCAs = smx509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM([]byte(req.CACertPEM)) {
			return TLSConnectResult{Error: "无法解析 CA 证书"}
		}
	}

	// Build certificates (TLCP needs sign + optional enc cert)
	var certificates []gotlcp.Certificate
	if req.ClientCertPEM != "" && req.ClientKeyPEM != "" {
		cert, err := gotlcp.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM))
		if err != nil {
			return TLSConnectResult{Error: "签名证书解析失败: " + err.Error()}
		}
		certificates = append(certificates, cert)
	}
	if req.ClientEncCertPEM != "" && req.ClientEncKeyPEM != "" {
		cert, err := gotlcp.X509KeyPair([]byte(req.ClientEncCertPEM), []byte(req.ClientEncKeyPEM))
		if err != nil {
			return TLSConnectResult{Error: "加密证书解析失败: " + err.Error()}
		}
		certificates = append(certificates, cert)
	}

	config := &gotlcp.Config{
		ServerName:         serverName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := gotlcp.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return TLSConnectResult{Error: "TLCP 连接失败: " + err.Error()}
	}
	defer conn.Close()

	handshakeTime := time.Since(start).Milliseconds()
	state := conn.ConnectionState()

	result := TLSConnectResult{
		Success:         true,
		Protocol:        "tlcp",
		CipherSuite:     gotlcp.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:   fmt.Sprintf("0x%04X", state.CipherSuite),
		ServerName:      state.ServerName,
		TLSVersion:      getTLSVersionName(state.Version),
		HandshakeTimeMs: handshakeTime,
		SessionReused:   state.DidResume,
	}

	for _, cert := range state.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, extractCertInfo(cert))
	}

	return result
}

// ListTLSCipherSuites returns available TLS cipher suites
func ListTLSCipherSuites() ToolResult {
	suites := tls.CipherSuites()
	var names []string
	for _, s := range suites {
		names = append(names, fmt.Sprintf("%s (0x%04X)", s.Name, s.ID))
	}
	return ToolResult{Success: true, Data: strings.Join(names, "\n")}
}

// ListTLCPCipherSuites returns available TLCP cipher suites
func ListTLCPCipherSuites() ToolResult {
	suites := gotlcp.CipherSuites()
	var names []string
	for _, s := range suites {
		names = append(names, fmt.Sprintf("%s (0x%04X)", s.Name, s.ID))
	}
	return ToolResult{Success: true, Data: strings.Join(names, "\n")}
}
