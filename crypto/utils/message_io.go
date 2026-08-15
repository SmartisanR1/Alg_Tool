package utils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	smx509 "github.com/emmansun/gmsm/smx509"
)

type PacketIORequest struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Network            string `json:"network"`
	Transport          string `json:"transport"`
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	HeaderLength       int    `json:"headerLength"`
	TimeoutSec         int    `json:"timeoutSec"`
	Payload            string `json:"payload"`
	PayloadFormat      string `json:"payloadFormat"`
	ResponseFormat     string `json:"responseFormat"`
	FilePath           string `json:"filePath"`
	CACertPEM          string `json:"caCertPem"`
	ClientCertPEM      string `json:"clientCertPem"`
	ClientKeyPEM       string `json:"clientKeyPem"`
	ClientEncCertPEM   string `json:"clientEncCertPem"`
	ClientEncKeyPEM    string `json:"clientEncKeyPem"`
}

type PacketIOResult struct {
	Success       bool   `json:"success"`
	Error         string `json:"error"`
	Response      string `json:"response"`
	ResponseHex   string `json:"responseHex"`
	RequestBytes  int    `json:"requestBytes"`
	ResponseBytes int    `json:"responseBytes"`
	HeaderHex     string `json:"headerHex"`
	DurationMs    int64  `json:"durationMs"`
}

func SendPacket(req PacketIORequest) PacketIOResult {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return PacketIOResult{Error: "主机地址不能为空"}
	}
	if req.Port <= 0 || req.Port > 65535 {
		return PacketIOResult{Error: "端口范围必须在 1-65535"}
	}
	if req.HeaderLength < 0 || req.HeaderLength > 4 {
		return PacketIOResult{Error: "报文头长度仅支持 0-4 字节"}
	}

	network := strings.TrimSpace(req.Network)
	if network == "" {
		network = "auto"
	}
	if network != "auto" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		return PacketIOResult{Error: "网络模式仅支持 auto / tcp / tcp4 / tcp6"}
	}

	transport := strings.TrimSpace(req.Transport)
	if transport == "" {
		transport = "plain"
	}
	if transport != "plain" && transport != "tls" && transport != "tlcp" {
		return PacketIOResult{Error: "传输模式仅支持 plain / tls / tlcp"}
	}

	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	payload, payloadSize, err := resolvePacketPayload(req)
	if err != nil {
		return PacketIOResult{Error: err.Error()}
	}
	if closer, ok := payload.(io.Closer); ok {
		defer closer.Close()
	}
	if payloadSize == 0 {
		return PacketIOResult{Error: "发送内容不能为空"}
	}

	header, err := buildPacketHeader(payloadSize, req.HeaderLength)
	if err != nil {
		return PacketIOResult{Error: err.Error()}
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", req.Port))
	chosenNetwork, err := resolveDialNetwork(host, network)
	if err != nil {
		return PacketIOResult{Error: err.Error()}
	}
	conn, err := dialPacketConn(dialer, chosenNetwork, addr, host, req)
	if err != nil {
		return PacketIOResult{Error: TranslateConnError(err)}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	requestBytes := len(header) + payloadSize
	if len(header) > 0 {
		if _, err := conn.Write(header); err != nil {
			return PacketIOResult{Error: "发送报文头失败: " + TranslateConnError(err)}
		}
	}
	if _, err := io.Copy(conn, payload); err != nil {
		return PacketIOResult{Error: "发送报文体失败: " + TranslateConnError(err)}
	}

	respHeader, respBody, err := readPacketResponse(conn, req.HeaderLength)
	if err != nil {
		return PacketIOResult{
			Error:        TranslateConnError(err),
			RequestBytes: requestBytes,
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	return PacketIOResult{
		Success:       true,
		Response:      formatPacketResponse(respBody, req.ResponseFormat),
		ResponseHex:   strings.ToUpper(hex.EncodeToString(respBody)),
		RequestBytes:  requestBytes,
		ResponseBytes: len(respBody),
		HeaderHex:     strings.ToUpper(hex.EncodeToString(respHeader)),
		DurationMs:    time.Since(start).Milliseconds(),
	}
}

func resolveDialNetwork(host string, network string) (string, error) {
	switch network {
	case "auto":
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				return "tcp4", nil
			}
			return "tcp6", nil
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", fmt.Errorf("DNS 解析失败: %w", err)
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				return "tcp4", nil
			}
		}
		for _, ip := range ips {
			if ip.To16() != nil {
				return "tcp6", nil
			}
		}
		return "", fmt.Errorf("无法解析到 IPv4/IPv6 地址")
	case "tcp", "tcp4", "tcp6":
		return network, nil
	default:
		return "", fmt.Errorf("网络模式仅支持 auto / tcp / tcp4 / tcp6")
	}
}

func dialPacketConn(dialer *net.Dialer, network, addr, host string, req PacketIORequest) (net.Conn, error) {
	switch req.Transport {
	case "tls":
		cfg, err := buildTLSConfig(host, req)
		if err != nil {
			return nil, err
		}
		conn, err := tls.DialWithDialer(dialer, network, addr, cfg)
		if err != nil {
			return nil, fmt.Errorf("TLS 连接失败: %w", err)
		}
		return conn, nil
	case "tlcp":
		cfg, err := buildTLCPConfig(host, req)
		if err != nil {
			return nil, err
		}
		conn, err := gotlcp.DialWithDialer(dialer, network, addr, cfg)
		if err != nil {
			return nil, fmt.Errorf("TLCP 连接失败: %w", err)
		}
		return conn, nil
	default:
		conn, err := dialer.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("连接失败: %w", err)
		}
		return conn, nil
	}
}

func buildTLSConfig(host string, req PacketIORequest) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: req.InsecureSkipVerify,
	}

	serverName := resolveServerName(host, req.ServerName)
	if serverName != "" {
		cfg.ServerName = serverName
	}

	if strings.TrimSpace(req.CACertPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(req.CACertPEM)) {
			return nil, fmt.Errorf("TLS CA 证书解析失败")
		}
		cfg.RootCAs = pool
	}

	if strings.TrimSpace(req.ClientCertPEM) != "" || strings.TrimSpace(req.ClientKeyPEM) != "" {
		if strings.TrimSpace(req.ClientCertPEM) == "" || strings.TrimSpace(req.ClientKeyPEM) == "" {
			return nil, fmt.Errorf("TLS 客户端证书和私钥需要同时提供")
		}
		cert, err := tls.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("TLS 客户端证书解析失败: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

func buildTLCPConfig(host string, req PacketIORequest) (*gotlcp.Config, error) {
	cfg := &gotlcp.Config{
		InsecureSkipVerify: req.InsecureSkipVerify,
		ServerName:         resolveServerName(host, req.ServerName),
	}

	if strings.TrimSpace(req.CACertPEM) != "" {
		pool := smx509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(req.CACertPEM)) {
			return nil, fmt.Errorf("TLCP CA 证书解析失败")
		}
		cfg.RootCAs = pool
	}

	if strings.TrimSpace(req.ClientCertPEM) != "" || strings.TrimSpace(req.ClientKeyPEM) != "" {
		if strings.TrimSpace(req.ClientCertPEM) == "" || strings.TrimSpace(req.ClientKeyPEM) == "" {
			return nil, fmt.Errorf("TLCP 签名证书和私钥需要同时提供")
		}
		signCert, err := gotlcp.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("TLCP 签名证书解析失败: %w", err)
		}
		cfg.Certificates = append(cfg.Certificates, signCert)
	}

	if strings.TrimSpace(req.ClientEncCertPEM) != "" || strings.TrimSpace(req.ClientEncKeyPEM) != "" {
		if strings.TrimSpace(req.ClientEncCertPEM) == "" || strings.TrimSpace(req.ClientEncKeyPEM) == "" {
			return nil, fmt.Errorf("TLCP 加密证书和私钥需要同时提供")
		}
		encCert, err := gotlcp.X509KeyPair([]byte(req.ClientEncCertPEM), []byte(req.ClientEncKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("TLCP 加密证书解析失败: %w", err)
		}
		cfg.Certificates = append(cfg.Certificates, encCert)
	}

	return cfg, nil
}

func resolveServerName(host, configured string) string {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		return configured
	}
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	return host
}

func resolvePacketPayload(req PacketIORequest) (io.Reader, int, error) {
	if strings.TrimSpace(req.FilePath) != "" {
		info, err := os.Stat(req.FilePath)
		if err != nil {
			return nil, 0, fmt.Errorf("读取报文文件失败: %w", err)
		}
		file, err := os.Open(req.FilePath)
		if err != nil {
			return nil, 0, fmt.Errorf("打开报文文件失败: %w", err)
		}
		return file, int(info.Size()), nil
	}

	data, err := decodePacketPayload(req.Payload, req.PayloadFormat)
	if err != nil {
		return nil, 0, err
	}
	return bytes.NewReader(data), len(data), nil
}

func decodePacketPayload(payload string, format string) ([]byte, error) {
	switch format {
	case "hex":
		clean := strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "", "0x", "", "0X", "").Replace(payload)
		if clean == "" {
			return nil, nil
		}
		b, err := hex.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("报文 Hex 不合法: %w", err)
		}
		return b, nil
	default:
		return []byte(payload), nil
	}
}

func buildPacketHeader(bodyLen int, headerLen int) ([]byte, error) {
	if headerLen == 0 {
		return nil, nil
	}
	maxLen := 1<<(uint(headerLen)*8) - 1
	if bodyLen > maxLen {
		return nil, fmt.Errorf("%d 字节报文头无法表示 %d 字节报文体", headerLen, bodyLen)
	}
	header := make([]byte, headerLen)
	for i := headerLen - 1; i >= 0; i-- {
		header[i] = byte(bodyLen & 0xff)
		bodyLen >>= 8
	}
	return header, nil
}

func readPacketResponse(conn net.Conn, headerLen int) ([]byte, []byte, error) {
	if headerLen == 0 {
		var buf bytes.Buffer
		tmp := make([]byte, 32*1024)
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if buf.Len() > 0 {
						return nil, buf.Bytes(), nil
					}
					return nil, nil, fmt.Errorf("接收响应超时")
				}
				if err == io.EOF {
					return nil, buf.Bytes(), nil
				}
				return nil, nil, fmt.Errorf("读取响应失败: %w", err)
			}
		}
	}

	header := make([]byte, headerLen)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("读取响应报文头失败: %w", err)
	}

	bodyLen := 0
	for _, b := range header {
		bodyLen = (bodyLen << 8) | int(b)
	}
	if bodyLen == 0 {
		return header, nil, nil
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return header, nil, fmt.Errorf("读取响应报文体失败: %w", err)
	}
	return header, body, nil
}

func formatPacketResponse(data []byte, format string) string {
	switch format {
	case "hex":
		return strings.ToUpper(hex.EncodeToString(data))
	default:
		if utf8.Valid(data) {
			return string(data)
		}
		return strings.ToUpper(hex.EncodeToString(data))
	}
}
