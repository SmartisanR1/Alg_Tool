package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
)

type CertChainRequest struct {
	Leaf          string `json:"leaf"`
	Intermediates string `json:"intermediates"`
	Roots         string `json:"roots"`
}

type CertChainResult struct {
	Success bool   `json:"success"`
	Valid   bool   `json:"valid"`
	Data    string `json:"data"`
	Error   string `json:"error"`
}

func VerifyCertChain(req CertChainRequest) CertChainResult {
	leafCert, err := parseSingleCert(req.Leaf)
	if err != nil {
		return CertChainResult{Error: "Leaf证书解析失败: " + err.Error()}
	}
	interPool := x509.NewCertPool()
	for _, c := range parseAllCerts(req.Intermediates) {
		interPool.AddCert(c)
	}

	var rootPool *x509.CertPool
	if strings.TrimSpace(req.Roots) == "" {
		rootPool, _ = x509.SystemCertPool()
	} else {
		rootPool = x509.NewCertPool()
		for _, c := range parseAllCerts(req.Roots) {
			rootPool.AddCert(c)
		}
	}
	if rootPool == nil {
		return CertChainResult{Error: "无法加载根证书池"}
	}

	chains, err := leafCert.Verify(x509.VerifyOptions{Intermediates: interPool, Roots: rootPool})
	if err != nil {
		return CertChainResult{Success: true, Valid: false, Data: "验证失败", Error: err.Error()}
	}

	return CertChainResult{Success: true, Valid: true, Data: formatChains(chains)}
}

func parseSingleCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("PEM解析失败")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseAllCerts(pemStr string) []*x509.Certificate {
	var certs []*x509.Certificate
	data := []byte(pemStr)
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
		data = rest
	}
	return certs
}

func formatChains(chains [][]*x509.Certificate) string {
	var sb strings.Builder
	for i, chain := range chains {
		sb.WriteString("Chain " + itoa(i+1) + ":\n")
		for j, cert := range chain {
			sb.WriteString("  " + itoa(j+1) + ". " + cert.Subject.String() + "\n")
		}
	}
	return strings.TrimSpace(sb.String())
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
