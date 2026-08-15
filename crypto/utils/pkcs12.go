package utils

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

type PKCS12Request struct {
	Data     string `json:"data"`
	Format   string `json:"format"` // base64 | hex
	Password string `json:"password"`
}

type PKCS12Result struct {
	Success  bool   `json:"success"`
	KeyPEM   string `json:"keyPem"`
	CertPEM  string `json:"certPem"`
	CaPEM    string `json:"caPem"`
	Error    string `json:"error"`
	CertInfo string `json:"certInfo"`
}

func ParsePKCS12(req PKCS12Request) PKCS12Result {
	b, err := decodePKCS12Input(req.Data, req.Format)
	if err != nil {
		return PKCS12Result{Error: "PFX解析失败: " + err.Error()}
	}

	priv, cert, caCerts, err := pkcs12.DecodeChain(b, req.Password)
	if err != nil {
		return PKCS12Result{Error: "PFX解密失败: " + err.Error()}
	}

	var keyPEM string
	if priv != nil {
		if pkcs8, err := x509.MarshalPKCS8PrivateKey(priv); err == nil {
			keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
		}
	}

	certPEM := ""
	if cert != nil {
		certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	var caBuf strings.Builder
	for _, c := range caCerts {
		caBuf.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
	}

	info := ""
	if cert != nil {
		info = cert.Subject.String()
	}

	return PKCS12Result{Success: true, KeyPEM: keyPEM, CertPEM: certPEM, CaPEM: caBuf.String(), CertInfo: info}
}

func ParsePKCS12File(path string, password string) PKCS12Result {
	b, err := readFileBytes(path)
	if err != nil {
		return PKCS12Result{Error: "读取文件失败: " + err.Error()}
	}
	return ParsePKCS12(PKCS12Request{Data: base64.StdEncoding.EncodeToString(b), Format: "base64", Password: password})
}

func decodePKCS12Input(data, format string) ([]byte, error) {
	trim := strings.TrimSpace(data)
	if trim == "" {
		return nil, errors.New("输入为空")
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "hex":
		return hexToBytes(trim)
	case "base64", "", "auto":
		b, err := base64.StdEncoding.DecodeString(trim)
		if err != nil {
			if b2, err2 := base64.RawStdEncoding.DecodeString(trim); err2 == nil {
				return b2, nil
			}
			return nil, err
		}
		return b, nil
	default:
		return nil, errors.New("不支持的格式")
	}
}
