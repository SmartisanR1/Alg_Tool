package utils

import (
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// PacketPerfRequest 性能测试请求（复用报文发送的连接/传输配置）
type PacketPerfRequest struct {
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
	CACertPEM          string `json:"caCertPem"`
	ClientCertPEM      string `json:"clientCertPem"`
	ClientKeyPEM       string `json:"clientKeyPem"`
	ClientEncCertPEM   string `json:"clientEncCertPem"`
	ClientEncKeyPEM    string `json:"clientEncKeyPem"`
	Concurrency        int    `json:"concurrency"` // 并发连接数 M
	Count              int    `json:"count"`       // 每连接发送次数 K
}

// PacketPerfResult 性能测试结果
type PacketPerfResult struct {
	Success       bool    `json:"success"`
	Error         string  `json:"error"`
	Concurrency   int     `json:"concurrency"`
	Count         int     `json:"count"`
	TotalRequests int     `json:"totalRequests"`
	SuccessCount  int     `json:"successCount"`
	FailCount     int     `json:"failCount"`
	TotalTimeMs   int64   `json:"totalTimeMs"`
	AvgLatencyMs  float64 `json:"avgLatencyMs"`
	MinLatencyMs  float64 `json:"minLatencyMs"`
	MaxLatencyMs  float64 `json:"maxLatencyMs"`
	Throughput    float64 `json:"throughput"`    // 每秒成功请求数 (TPS)
	BytesSent     int64   `json:"bytesSent"`     // 上行字节总数
	BytesReceived int64   `json:"bytesReceived"` // 下行字节总数
	Mbps          float64 `json:"mbps"`          // 双向带宽 (发送+接收, Mbps)
}

// PacketPerfTest performs a real multi-threaded (goroutine) round-trip
// performance test: M concurrent connections × K requests each, measuring
// latency (RTT) and throughput.
func PacketPerfTest(req PacketPerfRequest) PacketPerfResult {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return PacketPerfResult{Error: "主机地址不能为空"}
	}
	if req.Port <= 0 || req.Port > 65535 {
		return PacketPerfResult{Error: "端口范围必须在 1-65535"}
	}
	if req.HeaderLength < 0 || req.HeaderLength > 4 {
		return PacketPerfResult{Error: "报文头长度仅支持 0-4 字节"}
	}

	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 100 {
		concurrency = 100
	}
	count := req.Count
	if count <= 0 {
		count = 100
	}
	if count > 10000 {
		count = 10000
	}

	network := strings.TrimSpace(req.Network)
	if network == "" {
		network = "auto"
	}
	transport := strings.TrimSpace(req.Transport)
	if transport == "" {
		transport = "plain"
	}
	if transport != "plain" && transport != "tls" && transport != "tlcp" {
		return PacketPerfResult{Error: "传输模式仅支持 plain / tls / tlcp"}
	}

	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// 构造可复用的连接请求（共享传输/证书配置）
	connReq := PacketIORequest{
		Host:               host,
		Port:               req.Port,
		Network:            network,
		Transport:          transport,
		ServerName:         req.ServerName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		HeaderLength:       req.HeaderLength,
		TimeoutSec:         req.TimeoutSec,
		Payload:            req.Payload,
		PayloadFormat:      req.PayloadFormat,
		CACertPEM:          req.CACertPEM,
		ClientCertPEM:      req.ClientCertPEM,
		ClientKeyPEM:       req.ClientKeyPEM,
		ClientEncCertPEM:   req.ClientEncCertPEM,
		ClientEncKeyPEM:    req.ClientEncKeyPEM,
	}

	// 预解析载荷与报文头（一次解析，全部连接复用）
	payload, payloadSize, err := resolvePacketPayload(connReq)
	if err != nil {
		return PacketPerfResult{Error: err.Error()}
	}
	if closer, ok := payload.(io.Closer); ok {
		defer closer.Close()
	}
	if payloadSize == 0 {
		return PacketPerfResult{Error: "发送内容不能为空"}
	}
	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return PacketPerfResult{Error: "读取载荷失败: " + err.Error()}
	}
	header, err := buildPacketHeader(payloadSize, req.HeaderLength)
	if err != nil {
		return PacketPerfResult{Error: err.Error()}
	}
	frame := append(append([]byte{}, header...), payloadBytes...)

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", req.Port))
	chosenNetwork, err := resolveDialNetwork(host, network)
	if err != nil {
		return PacketPerfResult{Error: err.Error()}
	}

	start := time.Now()
	var (
		mu            sync.Mutex
		successCount  int
		failCount     int
		totalLatency  float64
		minLatency    = math.MaxFloat64
		maxLatency    float64
		bytesSent     int64
		bytesReceived int64
		firstErr      string
	)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			dialer := &net.Dialer{Timeout: timeout}
			conn, err := dialPacketConn(dialer, chosenNetwork, addr, host, connReq)
			if err != nil {
				// 连接失败：该连接的所有请求都记为失败，并记录首个错误原因
				mu.Lock()
				if firstErr == "" {
					firstErr = TranslateConnError(err)
				}
				failCount += count
				mu.Unlock()
				return
			}
			defer conn.Close()

			respBuf := make([]byte, 65536)
			for j := 0; j < count; j++ {
				_ = conn.SetDeadline(time.Now().Add(timeout))
				reqStart := time.Now()
				if _, err := conn.Write(frame); err != nil {
					mu.Lock()
					failCount++
					mu.Unlock()
					continue
				}
				n, err := conn.Read(respBuf)
				latencyMs := time.Since(reqStart).Seconds() * 1000

				mu.Lock()
				bytesSent += int64(len(frame))
				bytesReceived += int64(n)
				totalLatency += latencyMs
				if latencyMs < minLatency {
					minLatency = latencyMs
				}
				if latencyMs > maxLatency {
					maxLatency = latencyMs
				}
				if err != nil || n == 0 {
					failCount++
				} else {
					successCount++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	totalTime := time.Since(start).Milliseconds()
	totalRequests := concurrency * count
	avg := 0.0
	if totalRequests > 0 {
		avg = totalLatency / float64(totalRequests)
	}
	if minLatency == math.MaxFloat64 {
		minLatency = 0
	}
	throughput := 0.0
	if totalTime > 0 {
		throughput = float64(successCount) / (float64(totalTime) / 1000)
	}
	mbps := 0.0
	if totalTime > 0 {
		// 双向带宽 = (上行+下行) 字节 × 8 bit / 耗时秒 / 1e6
		totalBytes := float64(bytesSent + bytesReceived)
		mbps = totalBytes * 8 / (float64(totalTime) / 1000) / 1e6
	}

	perfErr := ""
	if successCount == 0 && firstErr != "" {
		perfErr = firstErr
	}

	return PacketPerfResult{
		Success:       successCount > 0,
		Error:         perfErr,
		Concurrency:   concurrency,
		Count:         count,
		TotalRequests: totalRequests,
		SuccessCount:  successCount,
		FailCount:     failCount,
		TotalTimeMs:   totalTime,
		AvgLatencyMs:  math.Round(avg*100) / 100,
		MinLatencyMs:  math.Round(minLatency*100) / 100,
		MaxLatencyMs:  math.Round(maxLatency*100) / 100,
		Throughput:    math.Round(throughput*100) / 100,
		BytesSent:     bytesSent,
		BytesReceived: bytesReceived,
		Mbps:          math.Round(mbps*100) / 100,
	}
}
