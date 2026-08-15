package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash"
	"math/big"
	"strings"
)

type JWTRequest struct {
	Token     string `json:"token"`
	Key       string `json:"key"`
	KeyFormat string `json:"keyFormat"` // auto | pem | jwk | jwks
	Alg       string `json:"alg"`       // optional
	Verify    bool   `json:"verify"`
}

type JWTResult struct {
	Success bool   `json:"success"`
	Header  string `json:"header"`
	Payload string `json:"payload"`
	Valid   bool   `json:"valid"`
	Error   string `json:"error"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
	K   string `json:"k"`
}

func ParseJWT(req JWTRequest) JWTResult {
	parts := strings.Split(strings.TrimSpace(req.Token), ".")
	if len(parts) != 3 {
		return JWTResult{Error: "JWT格式错误"}
	}

	headerBytes, err := base64RawURLDecode(parts[0])
	if err != nil {
		return JWTResult{Error: "Header解码失败: " + err.Error()}
	}
	payloadBytes, err := base64RawURLDecode(parts[1])
	if err != nil {
		return JWTResult{Error: "Payload解码失败: " + err.Error()}
	}

	headerPretty := prettyJSON(headerBytes)
	payloadPretty := prettyJSON(payloadBytes)

	alg := strings.TrimSpace(req.Alg)
	var headerMap map[string]interface{}
	_ = json.Unmarshal(headerBytes, &headerMap)
	if alg == "" {
		if v, ok := headerMap["alg"].(string); ok {
			alg = v
		}
	}

	result := JWTResult{Success: true, Header: headerPretty, Payload: payloadPretty}
	if !req.Verify {
		return result
	}

	if alg == "" || alg == "none" {
		result.Valid = false
		result.Error = "未提供可验证的alg"
		return result
	}

	key, err := parseJWTKey(req.Key, req.KeyFormat, headerMap)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	sig, err := base64RawURLDecode(parts[2])
	if err != nil {
		result.Valid = false
		result.Error = "签名解码失败: " + err.Error()
		return result
	}

	signingInput := parts[0] + "." + parts[1]
	valid, err := verifyJWT(alg, key, []byte(signingInput), sig)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}
	result.Valid = valid
	if !valid {
		result.Error = "签名验证失败"
	}
	return result
}

func verifyJWT(alg string, key interface{}, data, sig []byte) (bool, error) {
	switch strings.ToUpper(alg) {
	case "HS256":
		return verifyHMAC(sha256.New, key, data, sig)
	case "HS384":
		return verifyHMAC(sha512.New384, key, data, sig)
	case "HS512":
		return verifyHMAC(sha512.New, key, data, sig)
	case "RS256":
		return verifyRSA(sha256.New, key, data, sig)
	case "RS384":
		return verifyRSA(sha512.New384, key, data, sig)
	case "RS512":
		return verifyRSA(sha512.New, key, data, sig)
	case "ES256":
		return verifyECDSA(sha256.New, key, data, sig, 32)
	case "ES384":
		return verifyECDSA(sha512.New384, key, data, sig, 48)
	case "ES512":
		return verifyECDSA(sha512.New, key, data, sig, 66)
	case "EDDSA":
		return verifyEd25519(key, data, sig)
	default:
		return false, errors.New("不支持的JWT算法: " + alg)
	}
}

func verifyHMAC(newHash func() hash.Hash, key interface{}, data, sig []byte) (bool, error) {
	k, ok := key.([]byte)
	if !ok {
		return false, errors.New("HMAC密钥格式错误")
	}
	h := hmac.New(newHash, k)
	h.Write(data)
	mac := h.Sum(nil)
	return hmac.Equal(mac, sig), nil
}

func verifyRSA(newHash func() hash.Hash, key interface{}, data, sig []byte) (bool, error) {
	var pub *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PublicKey:
		pub = k
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return false, errors.New("RSA公钥格式错误")
	}
	h := newHash()
	h.Write(data)
	return rsa.VerifyPKCS1v15(pub, hashID(newHash), h.Sum(nil), sig) == nil, nil
}

func verifyECDSA(newHash func() hash.Hash, key interface{}, data, sig []byte, size int) (bool, error) {
	var pub *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		pub = k
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return false, errors.New("ECDSA公钥格式错误")
	}
	if len(sig) != size*2 {
		return false, errors.New("ECDSA签名长度不正确")
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	h := newHash()
	h.Write(data)
	hashBytes := h.Sum(nil)
	return ecdsa.Verify(pub, hashBytes, r, s), nil
}

func verifyEd25519(key interface{}, data, sig []byte) (bool, error) {
	var pub ed25519.PublicKey
	switch k := key.(type) {
	case ed25519.PublicKey:
		pub = k
	case ed25519.PrivateKey:
		pub = k.Public().(ed25519.PublicKey)
	default:
		return false, errors.New("Ed25519公钥格式错误")
	}
	return ed25519.Verify(pub, data, sig), nil
}

func parseJWTKey(raw, format string, header map[string]interface{}) (interface{}, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return nil, errors.New("未提供密钥")
	}

	fmtLower := strings.ToLower(strings.TrimSpace(format))
	if fmtLower == "" || fmtLower == "auto" {
		if strings.HasPrefix(strings.TrimSpace(key), "{") {
			fmtLower = "jwk"
		} else if strings.Contains(key, "-----BEGIN") {
			fmtLower = "pem"
		} else {
			fmtLower = "raw"
		}
	}

	switch fmtLower {
	case "pem":
		return parsePEMKey(key)
	case "jwk", "jwks":
		kid := ""
		if v, ok := header["kid"].(string); ok {
			kid = v
		}
		return parseJWK(key, kid)
	case "raw":
		return []byte(key), nil
	default:
		return nil, errors.New("不支持的密钥格式")
	}
}

func parsePEMKey(s string) (interface{}, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("PEM解析失败")
	}
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}
	if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}
	if priv, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return priv, nil
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	return nil, errors.New("不支持的PEM密钥格式")
}

func parseJWK(s string, kid string) (interface{}, error) {
	trim := strings.TrimSpace(s)
	if strings.HasPrefix(trim, "{") {
		if strings.Contains(trim, "\"keys\"") {
			var set jwkSet
			if err := json.Unmarshal([]byte(trim), &set); err != nil {
				return nil, errors.New("JWK集合解析失败")
			}
			for _, k := range set.Keys {
				if kid == "" || k.Kid == kid {
					return jwkToKey(k)
				}
			}
			return nil, errors.New("未找到匹配的kid")
		}
		var k jwkKey
		if err := json.Unmarshal([]byte(trim), &k); err != nil {
			return nil, errors.New("JWK解析失败")
		}
		return jwkToKey(k)
	}
	return nil, errors.New("JWK格式错误")
}

func jwkToKey(k jwkKey) (interface{}, error) {
	switch k.Kty {
	case "oct":
		b, err := base64RawURLDecode(k.K)
		if err != nil {
			return nil, errors.New("JWK密钥解码失败")
		}
		return b, nil
	case "RSA":
		nBytes, err := base64RawURLDecode(k.N)
		if err != nil {
			return nil, errors.New("RSA n解析失败")
		}
		eBytes, err := base64RawURLDecode(k.E)
		if err != nil {
			return nil, errors.New("RSA e解析失败")
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes).Int64()
		return &rsa.PublicKey{N: n, E: int(e)}, nil
	case "EC":
		xBytes, err := base64RawURLDecode(k.X)
		if err != nil {
			return nil, errors.New("EC x解析失败")
		}
		yBytes, err := base64RawURLDecode(k.Y)
		if err != nil {
			return nil, errors.New("EC y解析失败")
		}
		curve := curveFromCrv(k.Crv)
		if curve == nil {
			return nil, errors.New("不支持的曲线")
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, errors.New("仅支持Ed25519")
		}
		xBytes, err := base64RawURLDecode(k.X)
		if err != nil {
			return nil, errors.New("Ed25519公钥解析失败")
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, errors.New("不支持的JWK类型")
	}
}

func curveFromCrv(crv string) elliptic.Curve {
	switch crv {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

func base64RawURLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func prettyJSON(b []byte) string {
	var obj interface{}
	if err := json.Unmarshal(b, &obj); err != nil {
		return string(b)
	}
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return string(b)
	}
	return string(out)
}

func hashID(newHash func() hash.Hash) crypto.Hash {
	// 按摘要长度判定哈希算法, 不依赖具体类型名(Go 1.24+ fips140 重构后
	// crypto/sha512 返回类型为 *sha512.Digest, %T 字符串匹配会全部失效)。
	switch newHash().Size() {
	case 32:
		return crypto.SHA256
	case 48:
		return crypto.SHA384
	case 64:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}
