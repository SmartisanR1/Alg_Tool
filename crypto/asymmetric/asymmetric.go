package asymmetric

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/rand"

	"cryptokit/crypto/symmetric"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/curve25519"
)

type KeyPairResult struct {
	Success    bool   `json:"success"`
	PrivateKey string `json:"privateKey"` // PEM
	PublicKey  string `json:"publicKey"`  // PEM
	PrivHex    string `json:"privHex"`    // Raw Hex
	PubHex     string `json:"pubHex"`     // Raw Hex
	Error      string `json:"error"`
}

// ============================================================
// RSA
// ============================================================

type RSARequest struct {
	Key     string `json:"key"`     // PEM/Hex
	Data    string `json:"data"`    // hex
	Padding string `json:"padding"` // PKCS1v15 OAEP
	Hash    string `json:"hash"`    // SHA1 SHA256 SHA512
}

type RSASignRequest struct {
	PrivateKey string `json:"privateKey"` // PEM/Hex
	Data       string `json:"data"`       // hex (message hash)
	Hash       string `json:"hash"`       // SHA256 SHA384 SHA512
	Padding    string `json:"padding"`    // PKCS1v15 PSS
}

type RSAVerifyRequest struct {
	PublicKey string `json:"publicKey"` // PEM/Hex
	Data      string `json:"data"`      // hex (original data)
	Signature string `json:"signature"` // hex
	Hash      string `json:"hash"`
	Padding   string `json:"padding"`
}

func RSAGenerateKey(bits int) KeyPairResult {
	if bits == 0 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return KeyPairResult{Error: fmt.Sprintf("生成RSA密钥失败: %v", err)}
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Hex formats
	privHex := hexUpper(privBytes)
	pubHex := hexUpper(pubBytes)

	return KeyPairResult{
		Success:    true,
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		PrivHex:    privHex,
		PubHex:     pubHex,
	}
}

func RSAEncrypt(req RSARequest) symmetric.CryptoResult {
	rsaPub, err := parseRSAPublicKey(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	var ct []byte
	if req.Padding == "OAEP" {
		hashFunc := getHashFunc(req.Hash)
		ct, err = rsa.EncryptOAEP(hashFunc.New(), rand.Reader, rsaPub, dataBytes, nil)
	} else {
		ct, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPub, dataBytes)
	}
	if err != nil {
		return symmetric.CryptoResult{Error: "RSA加密失败，请检查密钥或数据"}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(ct)}
}

func RSADecrypt(req RSARequest) symmetric.CryptoResult {
	priv, err := parseRSAPrivateKey(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	var pt []byte
	if req.Padding == "OAEP" {
		hashFunc := getHashFunc(req.Hash)
		pt, err = rsa.DecryptOAEP(hashFunc.New(), rand.Reader, priv, dataBytes, nil)
	} else {
		pt, err = rsa.DecryptPKCS1v15(rand.Reader, priv, dataBytes)
	}
	if err != nil {
		return symmetric.CryptoResult{Error: "RSA解密失败，请检查密钥或密文"}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}
}

func RSASign(req RSASignRequest) symmetric.CryptoResult {
	priv, err := parseRSAPrivateKey(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	hashID := getHashID(req.Hash)
	hashFunc := getHashFunc(req.Hash)
	h := hashFunc.New()
	h.Write(dataBytes)
	digest := h.Sum(nil)

	var sig []byte
	if req.Padding == "PSS" {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hashID}
		sig, err = rsa.SignPSS(rand.Reader, priv, hashID, digest, opts)
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, hashID, digest)
	}
	if err != nil {
		return symmetric.CryptoResult{Error: "RSA签名失败，请检查密钥或数据"}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func RSAVerify(req RSAVerifyRequest) symmetric.CryptoResult {
	rsaPub, err := parseRSAPublicKey(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名(需要Hex)"}
	}

	hashID := getHashID(req.Hash)
	hashFunc := getHashFunc(req.Hash)
	h := hashFunc.New()
	h.Write(dataBytes)
	digest := h.Sum(nil)

	if req.Padding == "PSS" {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hashID}
		err = rsa.VerifyPSS(rsaPub, hashID, digest, sigBytes, opts)
	} else {
		err = rsa.VerifyPKCS1v15(rsaPub, hashID, digest, sigBytes)
	}
	if err != nil {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// ECC
// ============================================================

type ECCRequest struct {
	PrivateKey string `json:"privateKey"` // PEM/Hex
	Data       string `json:"data"`       // hex
	Hash       string `json:"hash"`
	Curve      string `json:"curve"` // P-256 P-384 P-521
}

type ECCVerifyRequest struct {
	PublicKey string `json:"publicKey"` // PEM/Hex
	Data      string `json:"data"`      // hex
	Signature string `json:"signature"` // hex (r||s, each coordinate length)
	Hash      string `json:"hash"`
	Curve     string `json:"curve"`
}

type ECDHRequest struct {
	PrivateKey    string `json:"privateKey"`    // PEM/Hex
	PeerPublicKey string `json:"peerPublicKey"` // PEM/Hex
	Curve         string `json:"curve"`
}

func ECCGenerateKey(curve string) KeyPairResult {
	var priv interface{}
	var pub interface{}
	var err error

	switch curve {
	case "SM2":
		p, e := sm2.GenerateKey(rand.Reader)
		if e != nil {
			err = e
		} else {
			priv = p
			pub = &p.PublicKey
		}
	case "P-224":
		p, e := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		priv, pub, err = p, &p.PublicKey, e
	case "P-256":
		p, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub, err = p, &p.PublicKey, e
	case "P-384":
		p, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		priv, pub, err = p, &p.PublicKey, e
	case "P-521":
		p, e := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		priv, pub, err = p, &p.PublicKey, e
	default:
		p, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub, err = p, &p.PublicKey, e
	}

	if err != nil {
		return KeyPairResult{Error: "生成ECC密钥失败: " + err.Error()}
	}

	var privPEM []byte
	var pubPEM []byte
	var privHex string
	var pubHex string

	if curve == "SM2" {
		sm2Priv := priv.(*sm2.PrivateKey)
		der, _ := smx509.MarshalSM2PrivateKey(sm2Priv)
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: der})
		privHex = hexUpper(sm2Priv.D.Bytes())

		pubDER, _ := smx509.MarshalPKIXPublicKey(&sm2Priv.PublicKey)
		pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		byteLen := 32
		xB := sm2Priv.PublicKey.X.Bytes()
		yB := sm2Priv.PublicKey.Y.Bytes()
		if len(xB) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(xB):], xB)
			xB = padded
		}
		if len(yB) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(yB):], yB)
			yB = padded
		}
		pubHex = hexUpper(append(xB, yB...))
	} else {
		p := priv.(*ecdsa.PrivateKey)
		privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		privHex = hexUpper(p.D.Bytes())

		pubDER, _ := x509.MarshalPKIXPublicKey(pub)
		pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		byteLen := (p.Curve.Params().BitSize + 7) / 8
		xBytes := p.PublicKey.X.Bytes()
		yBytes := p.PublicKey.Y.Bytes()
		if len(xBytes) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(xBytes):], xBytes)
			xBytes = padded
		}
		if len(yBytes) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(yBytes):], yBytes)
			yBytes = padded
		}
		pubHex = hexUpper(append(xBytes, yBytes...))
	}

	return KeyPairResult{
		Success:    true,
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		PrivHex:    privHex,
		PubHex:     pubHex,
	}
}

func ECCSign(req ECCRequest) symmetric.CryptoResult {
	priv, err := parseECPrivateKey(req.PrivateKey, req.Curve)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	hashFunc := getHashFunc(req.Hash)
	h := hashFunc.New()
	h.Write(dataBytes)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return symmetric.CryptoResult{Error: "ECDSA签名失败，请检查密钥或数据"}
	}

	keyLen := (priv.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*keyLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keyLen-len(rBytes):keyLen], rBytes)
	copy(sig[2*keyLen-len(sBytes):], sBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func ECCVerify(req ECCVerifyRequest) symmetric.CryptoResult {
	ecPub, err := parseECPublicKey(req.PublicKey, req.Curve)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名(需要Hex)"}
	}

	keyLen := (ecPub.Curve.Params().BitSize + 7) / 8
	if len(sigBytes) != 2*keyLen {
		return symmetric.CryptoResult{Error: "签名长度不正确"}
	}

	r := new(big.Int).SetBytes(sigBytes[:keyLen])
	s := new(big.Int).SetBytes(sigBytes[keyLen:])

	hashFunc := getHashFunc(req.Hash)
	h := hashFunc.New()
	h.Write(dataBytes)
	digest := h.Sum(nil)

	valid := ecdsa.Verify(ecPub, digest, r, s)
	if !valid {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

func ECDHCompute(req ECDHRequest) symmetric.CryptoResult {
	priv, err := parseECPrivateKey(req.PrivateKey, req.Curve)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	peerPub, err := parseECPublicKey(req.PeerPublicKey, req.Curve)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	x, _ := priv.Curve.ScalarMult(peerPub.X, peerPub.Y, priv.D.Bytes())
	if x == nil {
		return symmetric.CryptoResult{Error: "ECDH计算失败: 无效的密钥点"}
	}
	// 定长输出: x.Bytes() 会丢弃前导零导致短于曲线定长
	shared := make([]byte, (priv.Curve.Params().BitSize+7)/8)
	x.FillBytes(shared)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(shared)}
}

// ============================================================
// X25519 / Ed25519
// ============================================================

type X25519Request struct {
	PrivateKey    string `json:"privateKey"`    // hex 32 bytes
	PeerPublicKey string `json:"peerPublicKey"` // hex 32 bytes
}

type EdDSARequest struct {
	PrivateKey string `json:"privateKey"` // hex 64 bytes (seed+pub)
	Data       string `json:"data"`       // hex
}

type EdDSAVerifyRequest struct {
	PublicKey string `json:"publicKey"` // hex 32 bytes
	Data      string `json:"data"`      // hex
	Signature string `json:"signature"` // hex 64 bytes
}

func X25519KeyGen() KeyPairResult {
	privKey := make([]byte, 32)
	rand.Read(privKey)
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return KeyPairResult{Error: "生成X25519密钥失败: " + err.Error()}
	}
	return KeyPairResult{Success: true, PrivateKey: hexUpper(privKey), PublicKey: hexUpper(pubKey)}
}

func X25519Exchange(req X25519Request) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil || len(privBytes) != 32 {
		return symmetric.CryptoResult{Error: "X25519私钥需要32字节hex"}
	}
	peerBytes, err := hex.DecodeString(req.PeerPublicKey)
	if err != nil || len(peerBytes) != 32 {
		return symmetric.CryptoResult{Error: "对方公钥需要32字节hex"}
	}
	shared, err := curve25519.X25519(privBytes, peerBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "X25519密钥交换失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(shared)}
}

func Ed25519KeyGen() KeyPairResult {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPairResult{Error: "生成Ed25519密钥失败: " + err.Error()}
	}
	return KeyPairResult{Success: true, PrivateKey: hexUpper(priv), PublicKey: hexUpper(pub)}
}

func Ed25519Sign(req EdDSARequest) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return symmetric.CryptoResult{Error: "Ed25519私钥长度应为64字节(32字节seed+32字节公钥)"}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), dataBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func Ed25519Verify(req EdDSAVerifyRequest) symmetric.CryptoResult {
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的公钥: " + err.Error()}
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return symmetric.CryptoResult{Error: "Ed25519公钥长度应为32字节"}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名: " + err.Error()}
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return symmetric.CryptoResult{Error: "Ed25519签名长度应为64字节"}
	}
	valid := ed25519.Verify(ed25519.PublicKey(pubBytes), dataBytes, sigBytes)
	if !valid {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// Ed448
// ============================================================

type Ed448Request struct {
	PrivateKey string `json:"privateKey"` // hex 114 bytes
	Data       string `json:"data"`       // hex
	Context    string `json:"context"`    // optional
}

type Ed448VerifyRequest struct {
	PublicKey string `json:"publicKey"` // hex 57 bytes
	Data      string `json:"data"`      // hex
	Signature string `json:"signature"` // hex 114 bytes
	Context   string `json:"context"`   // optional
}

func Ed448KeyGen() KeyPairResult {
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPairResult{Error: "生成Ed448密钥失败: " + err.Error()}
	}
	return KeyPairResult{Success: true, PrivateKey: hexUpper(priv), PublicKey: hexUpper(pub)}
}

func Ed448Sign(req Ed448Request) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	if len(privBytes) != ed448.PrivateKeySize {
		return symmetric.CryptoResult{Error: "Ed448私钥长度应为114字节"}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	sig := ed448.Sign(ed448.PrivateKey(privBytes), dataBytes, req.Context)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func Ed448Verify(req Ed448VerifyRequest) symmetric.CryptoResult {
	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的公钥: " + err.Error()}
	}
	if len(pubBytes) != ed448.PublicKeySize {
		return symmetric.CryptoResult{Error: "Ed448公钥长度应为57字节"}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名: " + err.Error()}
	}
	valid := ed448.Verify(ed448.PublicKey(pubBytes), dataBytes, sigBytes, req.Context)
	if !valid {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// Helpers
// ============================================================

func isPEMKey(s string) bool {
	return strings.Contains(s, "-----BEGIN")
}

func cleanHexString(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func decodeHexKey(input string) ([]byte, error) {
	cleaned := cleanHexString(input)
	if cleaned == "" {
		return nil, fmt.Errorf("密钥为空")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("无效的Hex密钥")
	}
	return b, nil
}

func parseRSAPublicKey(input string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("公钥不能为空")
	}
	var der []byte
	if isPEMKey(input) {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("无效的PEM公钥")
		}
		der = block.Bytes
	} else {
		b, err := decodeHexKey(input)
		if err != nil {
			return nil, err
		}
		der = b
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}
	if rsaPub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rsaPub, nil
	}
	return nil, fmt.Errorf("公钥解析失败，请检查格式")
}

func parseRSAPrivateKey(input string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("私钥不能为空")
	}
	var der []byte
	if isPEMKey(input) {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("无效的PEM私钥")
		}
		der = block.Bytes
	} else {
		b, err := decodeHexKey(input)
		if err != nil {
			return nil, err
		}
		der = b
	}
	if priv, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return priv, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if priv, ok := key.(*rsa.PrivateKey); ok {
			return priv, nil
		}
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if _, ok := pub.(*rsa.PublicKey); ok {
			return nil, fmt.Errorf("请使用RSA私钥")
		}
	}
	return nil, fmt.Errorf("私钥解析失败，请检查格式")
}

func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	case "SM2":
		return sm2.P256()
	default:
		return elliptic.P256()
	}
}

func parseECPrivateKey(input string, curveName string) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("私钥不能为空")
	}
	if isPEMKey(input) {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("无效的PEM私钥")
		}
		if curveName == "SM2" {
			if sm2Priv, err := smx509.ParseSM2PrivateKey(block.Bytes); err == nil {
				return &ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{Curve: sm2Priv.Curve, X: sm2Priv.X, Y: sm2Priv.Y},
					D:         sm2Priv.D,
				}, nil
			}
		}
		if priv, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return priv, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if priv, ok := key.(*ecdsa.PrivateKey); ok {
				return priv, nil
			}
		}
		return nil, fmt.Errorf("私钥解析失败，请检查格式")
	}

	b, err := decodeHexKey(input)
	if err != nil {
		return nil, err
	}
	if curveName == "SM2" {
		if sm2Priv, err := smx509.ParseSM2PrivateKey(b); err == nil {
			return &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: sm2Priv.Curve, X: sm2Priv.X, Y: sm2Priv.Y},
				D:         sm2Priv.D,
			}, nil
		}
	}
	if priv, err := x509.ParseECPrivateKey(b); err == nil {
		return priv, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		if priv, ok := key.(*ecdsa.PrivateKey); ok {
			return priv, nil
		}
	}
	curve := curveByName(curveName)
	d := new(big.Int).SetBytes(b)
	if d.Sign() == 0 {
		return nil, fmt.Errorf("私钥无效")
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}

func parseECPublicKey(input string, curveName string) (*ecdsa.PublicKey, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("公钥不能为空")
	}
	if isPEMKey(input) {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("无效的PEM公钥")
		}
		if curveName == "SM2" {
			if pubIface, err := smx509.ParsePKIXPublicKey(block.Bytes); err == nil {
				if pub, ok := pubIface.(*ecdsa.PublicKey); ok {
					return pub, nil
				}
			}
		}
		if pubIface, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if pub, ok := pubIface.(*ecdsa.PublicKey); ok {
				return pub, nil
			}
		}
		return nil, fmt.Errorf("公钥解析失败，请检查格式")
	}

	b, err := decodeHexKey(input)
	if err != nil {
		return nil, err
	}
	if curveName == "SM2" {
		if pubIface, err := smx509.ParsePKIXPublicKey(b); err == nil {
			if pub, ok := pubIface.(*ecdsa.PublicKey); ok {
				return pub, nil
			}
		}
	} else {
		if pubIface, err := x509.ParsePKIXPublicKey(b); err == nil {
			if pub, ok := pubIface.(*ecdsa.PublicKey); ok {
				return pub, nil
			}
		}
	}
	curve := curveByName(curveName)
	if len(b) == 1+2*((curve.Params().BitSize+7)/8) && b[0] == 0x04 {
		x, y := elliptic.Unmarshal(curve, b)
		if x != nil && y != nil {
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
		}
	}
	return nil, fmt.Errorf("公钥解析失败，请检查格式")
}

func getHashFunc(name string) crypto.Hash {
	switch name {
	case "SHA384", "SHA-384":
		return crypto.SHA384
	case "SHA512", "SHA-512":
		return crypto.SHA512
	case "SHA1", "SHA-1":
		return crypto.SHA1
	case "SHA224", "SHA-224":
		return crypto.SHA224
	default:
		return crypto.SHA256
	}
}

func getHashID(name string) crypto.Hash {
	return getHashFunc(name)
}

// Suppress unused import warnings
var _ = sha256.New
var _ = sha512.New
