package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type KeyConvertRequest struct {
	Data   string `json:"data"`
	Format string `json:"format"` // auto | pem | der | hex | base64
}

type KeyConvertResult struct {
	Success   bool   `json:"success"`
	KeyType   string `json:"keyType"`
	PKCS1PEM  string `json:"pkcs1Pem"`
	PKCS8PEM  string `json:"pkcs8Pem"`
	PublicPEM string `json:"publicPem"`
	DerHex    string `json:"derHex"`
	DerBase64 string `json:"derBase64"`
	Error     string `json:"error"`
}

func ConvertKey(req KeyConvertRequest) KeyConvertResult {
	b, err := decodeKeyInput(req.Data, req.Format)
	if err != nil {
		return KeyConvertResult{Error: "密钥解析失败: " + err.Error()}
	}

	var keyType string
	var priv interface{}
	var pub interface{}

	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		priv = k
		pub = &k.PublicKey
		keyType = "RSA Private (PKCS#1)"
	} else if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		priv = k
		switch kk := k.(type) {
		case *rsa.PrivateKey:
			pub = &kk.PublicKey
		case *ecdsa.PrivateKey:
			pub = &kk.PublicKey
		}
		keyType = "Private (PKCS#8)"
	} else if k, err := x509.ParseECPrivateKey(b); err == nil {
		priv = k
		pub = &k.PublicKey
		keyType = "EC Private"
	} else if k, err := x509.ParsePKIXPublicKey(b); err == nil {
		pub = k
		keyType = "Public (PKIX)"
	} else if k, err := x509.ParsePKCS1PublicKey(b); err == nil {
		pub = k
		keyType = "RSA Public (PKCS#1)"
	} else {
		return KeyConvertResult{Error: "不支持的密钥格式"}
	}

	res := KeyConvertResult{Success: true, KeyType: keyType}

	if priv != nil {
		if pkcs8, err := x509.MarshalPKCS8PrivateKey(priv); err == nil {
			res.PKCS8PEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
			res.DerHex = hexUpper(pkcs8)
			res.DerBase64 = base64.StdEncoding.EncodeToString(pkcs8)
		}
		switch k := priv.(type) {
		case *rsa.PrivateKey:
			pkcs1 := x509.MarshalPKCS1PrivateKey(k)
			res.PKCS1PEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}))
		case *ecdsa.PrivateKey:
			pkcs1 := marshalECPrivateKey(k)
			if len(pkcs1) > 0 {
				res.PKCS1PEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkcs1}))
			}
		}
	}

	if pub != nil {
		if pkix, err := x509.MarshalPKIXPublicKey(pub); err == nil {
			res.PublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}))
			if res.DerHex == "" {
				res.DerHex = hexUpper(pkix)
				res.DerBase64 = base64.StdEncoding.EncodeToString(pkix)
			}
		}
	}

	return res
}

func decodeKeyInput(data, format string) ([]byte, error) {
	trim := strings.TrimSpace(data)
	if trim == "" {
		return nil, errors.New("输入为空")
	}

	fmtLower := strings.ToLower(strings.TrimSpace(format))
	if fmtLower == "" || fmtLower == "auto" {
		if strings.Contains(trim, "-----BEGIN") {
			fmtLower = "pem"
		} else if isHexLike(trim) {
			fmtLower = "hex"
		} else {
			fmtLower = "base64"
		}
	}

	switch fmtLower {
	case "pem":
		block, _ := pem.Decode([]byte(trim))
		if block == nil {
			return nil, errors.New("PEM解析失败")
		}
		return block.Bytes, nil
	case "der":
		return []byte(trim), nil
	case "hex":
		return hexToBytes(trim)
	case "base64":
		b, err := base64.StdEncoding.DecodeString(trim)
		if err != nil {
			if b2, err2 := base64.RawStdEncoding.DecodeString(trim); err2 == nil {
				return b2, nil
			}
			return nil, err
		}
		return b, nil
	default:
		return nil, fmt.Errorf("不支持的格式: %s", format)
	}
}

func marshalECPrivateKey(k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil
	}
	return b
}
