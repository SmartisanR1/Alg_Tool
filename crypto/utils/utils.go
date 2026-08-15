package utils

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emmansun/gmsm/rand"

	hashpkg "cryptokit/crypto/hash"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

type ToolResult struct {
	Success bool   `json:"success"`
	Data    string `json:"data"`
	Error   string `json:"error"`
}

// randInt generates a random big integer in [0, max) using the provided reader
// 使用拒绝采样消除模偏差: 直接取模会因 max 不整除 2^(8*字节数) 而产生偏差
func randInt(reader io.Reader, max *big.Int) (*big.Int, error) {
	if max == nil || max.Sign() <= 0 {
		return nil, errors.New("randInt: max 必须为正整数")
	}

	// Calculate number of bytes needed
	bits := max.BitLen()
	bytes := (bits + 7) / 8
	extra := bytes*8 - bits // 最高字节冗余位数

	buf := make([]byte, bytes)
	for {
		// Generate random bytes
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		// 清除最高字节的冗余高位, 使候选值 < 2^bits
		if extra > 0 {
			buf[0] &= byte(0xFF >> extra)
		}

		// Convert to big.Int and reject if >= max, 消除模偏差
		result := new(big.Int).SetBytes(buf)
		if result.Cmp(max) < 0 {
			return result, nil
		}
	}
}

// ============================================================
// Encoding utilities
// ============================================================

func HexToString(hexStr string) ToolResult {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "0x", "")
	hexStr = strings.ReplaceAll(hexStr, "0X", "")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return ToolResult{Error: "无效的Hex字符串: " + err.Error()}
	}
	if utf8.Valid(b) {
		return ToolResult{Success: true, Data: string(b)}
	}
	return ToolResult{Success: true, Data: string(b)}
}

func StringToHex(str string) ToolResult {
	return ToolResult{Success: true, Data: hexUpper([]byte(str))}
}

type Base64Request struct {
	Data   string `json:"data"`   // input data (string or hex)
	Format string `json:"format"` // Standard URL
	IsHex  bool   `json:"isHex"`  // if true, data is hex-encoded
}

func Base64Encode(req Base64Request) ToolResult {
	var dataBytes []byte
	if req.IsHex {
		var err error
		dataBytes, err = hex.DecodeString(req.Data)
		if err != nil {
			return ToolResult{Error: "无效的Hex数据: " + err.Error()}
		}
	} else {
		dataBytes = []byte(req.Data)
	}

	var encoded string
	if req.Format == "URL" {
		encoded = base64.URLEncoding.EncodeToString(dataBytes)
	} else if req.Format == "NoPadding" {
		encoded = base64.RawStdEncoding.EncodeToString(dataBytes)
	} else {
		encoded = base64.StdEncoding.EncodeToString(dataBytes)
	}
	return ToolResult{Success: true, Data: encoded}
}

func Base64Decode(req Base64Request) ToolResult {
	var dataBytes []byte
	var err error
	if req.Format == "URL" {
		dataBytes, err = base64.URLEncoding.DecodeString(req.Data)
		if err != nil {
			dataBytes, err = base64.RawURLEncoding.DecodeString(req.Data)
		}
	} else if req.Format == "NoPadding" {
		dataBytes, err = base64.RawStdEncoding.DecodeString(req.Data)
	} else {
		dataBytes, err = base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			dataBytes, err = base64.RawStdEncoding.DecodeString(req.Data)
		}
	}
	if err != nil {
		return ToolResult{Error: "Base64解码失败: " + err.Error()}
	}

	if req.IsHex {
		return ToolResult{Success: true, Data: hexUpper(dataBytes)}
	}
	if utf8.Valid(dataBytes) {
		return ToolResult{Success: true, Data: string(dataBytes)}
	}
	return ToolResult{Success: true, Data: hexUpper(dataBytes)}
}

// ============================================================
// XOR
// ============================================================

type XORRequest struct {
	A string `json:"a"` // hex
	B string `json:"b"` // hex
}

func XORCompute(req XORRequest) ToolResult {
	aBytes, err := hex.DecodeString(req.A)
	if err != nil {
		return ToolResult{Error: "无效的A (需要hex): " + err.Error()}
	}
	bBytes, err := hex.DecodeString(req.B)
	if err != nil {
		return ToolResult{Error: "无效的B (需要hex): " + err.Error()}
	}

	// If lengths differ, pad shorter with zeros
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}
	aPad := make([]byte, maxLen)
	bPad := make([]byte, maxLen)
	copy(aPad[maxLen-len(aBytes):], aBytes)
	copy(bPad[maxLen-len(bBytes):], bBytes)

	result := make([]byte, maxLen)
	for i := range result {
		result[i] = aPad[i] ^ bPad[i]
	}
	return ToolResult{Success: true, Data: hexUpper(result)}
}

// ============================================================
// URL Encode/Decode
// ============================================================

func URLEncode(str string) ToolResult {
	return ToolResult{Success: true, Data: url.QueryEscape(str)}
}

func URLDecode(str string) ToolResult {
	decoded, err := url.QueryUnescape(str)
	if err != nil {
		return ToolResult{Error: "URL解码失败: " + err.Error()}
	}
	return ToolResult{Success: true, Data: decoded}
}

// ============================================================
// Random generator
// ============================================================

type RandomRequest struct {
	Length int    `json:"length"` // bytes
	Format string `json:"format"` // hex base64 decimal
}

func GenerateRandom(req RandomRequest) ToolResult {
	length := req.Length
	if length == 0 {
		length = 32
	}
	if length > 4096 {
		length = 4096
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ToolResult{Error: "生成随机数失败: " + err.Error()}
	}

	switch req.Format {
	case "base64":
		return ToolResult{Success: true, Data: base64.StdEncoding.EncodeToString(b)}
	default:
		return ToolResult{Success: true, Data: hexUpper(b)}
	}
}

// ============================================================
// Padding
// ============================================================

type PaddingRequest struct {
	Data      string `json:"data"`
	Mode      string `json:"mode"`      // PKCS5 PKCS7 Zero ISO10126 ANSIX923
	BlockSize int    `json:"blockSize"` // 8 or 16
}

func PaddingApply(req PaddingRequest) ToolResult {
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return ToolResult{Error: "无效的数据: " + err.Error()}
	}
	bs := req.BlockSize
	if bs == 0 {
		bs = 16
	}

	var padded []byte
	switch req.Mode {
	case "PKCS5", "PKCS7":
		padLen := bs - len(dataBytes)%bs
		padded = make([]byte, len(dataBytes)+padLen)
		copy(padded, dataBytes)
		for i := len(dataBytes); i < len(padded); i++ {
			padded[i] = byte(padLen)
		}
	case "Zero":
		if len(dataBytes)%bs == 0 {
			padded = dataBytes
		} else {
			padLen := bs - len(dataBytes)%bs
			padded = make([]byte, len(dataBytes)+padLen)
			copy(padded, dataBytes)
		}
	case "ISO10126":
		padLen := bs - len(dataBytes)%bs
		padded = make([]byte, len(dataBytes)+padLen)
		copy(padded, dataBytes)
		rand.Read(padded[len(dataBytes) : len(padded)-1])
		padded[len(padded)-1] = byte(padLen)
	case "ANSIX923":
		padLen := bs - len(dataBytes)%bs
		padded = make([]byte, len(dataBytes)+padLen)
		copy(padded, dataBytes)
		padded[len(padded)-1] = byte(padLen)
	default:
		return ToolResult{Error: "不支持的填充模式: " + req.Mode}
	}
	return ToolResult{Success: true, Data: hexUpper(padded)}
}

func PaddingRemove(req PaddingRequest) ToolResult {
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return ToolResult{Error: "无效的数据: " + err.Error()}
	}
	if len(dataBytes) == 0 {
		return ToolResult{Success: true, Data: ""}
	}

	var result []byte
	switch req.Mode {
	case "PKCS5", "PKCS7", "ISO10126", "ANSIX923":
		padLen := int(dataBytes[len(dataBytes)-1])
		if padLen > 0 && padLen <= len(dataBytes) {
			result = dataBytes[:len(dataBytes)-padLen]
		} else {
			result = dataBytes
		}
	case "Zero":
		result = []byte(strings.TrimRight(string(dataBytes), "\x00"))
	default:
		return ToolResult{Error: "不支持的填充模式: " + req.Mode}
	}
	return ToolResult{Success: true, Data: hexUpper(result)}
}

// ============================================================
// JSON formatter
// ============================================================

func FormatJSON(str string) ToolResult {
	var obj interface{}
	if err := json.Unmarshal([]byte(str), &obj); err != nil {
		return ToolResult{Error: "JSON解析失败: " + err.Error()}
	}
	formatted, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return ToolResult{Error: "JSON格式化失败: " + err.Error()}
	}
	return ToolResult{Success: true, Data: string(formatted)}
}

// ============================================================
// Timestamp
// ============================================================

type TimestampRequest struct {
	Value    string `json:"value"`    // timestamp or datetime string
	From     string `json:"from"`     // unix10 unix13 rfc3339 datetime
	To       string `json:"to"`       // unix10 unix13 rfc3339 datetime
	Timezone string `json:"timezone"` // e.g. "Asia/Shanghai"
}

func TimestampConvert(req TimestampRequest) ToolResult {
	var t time.Time
	loc := time.UTC
	if req.Timezone != "" {
		l, err := time.LoadLocation(req.Timezone)
		if err == nil {
			loc = l
		}
	}

	switch req.From {
	case "unix10":
		ts, err := strconv.ParseInt(req.Value, 10, 64)
		if err != nil {
			return ToolResult{Error: "无效的时间戳: " + err.Error()}
		}
		t = time.Unix(ts, 0).In(loc)
	case "unix13":
		ts, err := strconv.ParseInt(req.Value, 10, 64)
		if err != nil {
			return ToolResult{Error: "无效的时间戳: " + err.Error()}
		}
		t = time.UnixMilli(ts).In(loc)
	case "rfc3339":
		var err error
		t, err = time.Parse(time.RFC3339, req.Value)
		if err != nil {
			return ToolResult{Error: "无效的RFC3339时间: " + err.Error()}
		}
		t = t.In(loc)
	case "datetime":
		var err error
		formats := []string{
			"2006-01-02 15:04:05",
			"2006/01/02 15:04:05",
			"2006-01-02T15:04:05",
			"2006-01-02",
		}
		for _, f := range formats {
			t, err = time.ParseInLocation(f, req.Value, loc)
			if err == nil {
				break
			}
		}
		if err != nil {
			return ToolResult{Error: "无效的时间格式: " + err.Error()}
		}
	default:
		t = time.Now().In(loc)
	}

	switch req.To {
	case "unix10":
		return ToolResult{Success: true, Data: strconv.FormatInt(t.Unix(), 10)}
	case "unix13":
		return ToolResult{Success: true, Data: strconv.FormatInt(t.UnixMilli(), 10)}
	case "rfc3339":
		return ToolResult{Success: true, Data: t.Format(time.RFC3339)}
	default:
		return ToolResult{Success: true, Data: t.Format("2006-01-02 15:04:05")}
	}
}

// ============================================================
// Unicode
// ============================================================

func UnicodeEncode(str string) ToolResult {
	var sb strings.Builder
	for _, r := range str {
		if r > 127 {
			sb.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return ToolResult{Success: true, Data: sb.String()}
}

func UnicodeDecode(str string) ToolResult {
	// Unquote unicode escapes
	result := strings.ReplaceAll(str, "\\u", "\\u")
	unquoted, err := strconv.Unquote(`"` + result + `"`)
	if err != nil {
		// Try simple replacement
		return ToolResult{Success: true, Data: str}
	}
	return ToolResult{Success: true, Data: unquoted}
}

// ============================================================
// Base conversion
// ============================================================

type BaseConvertRequest struct {
	Value string `json:"value"`
	From  int    `json:"from"` // 2 8 10 16
	To    int    `json:"to"`
}

func BaseConvert(req BaseConvertRequest) ToolResult {
	n, err := strconv.ParseInt(strings.TrimPrefix(req.Value, "0x"), req.From, 64)
	if err != nil {
		// Try unsigned
		un, err2 := strconv.ParseUint(strings.TrimPrefix(req.Value, "0x"), req.From, 64)
		if err2 != nil {
			return ToolResult{Error: fmt.Sprintf("无法从%d进制解析 %q: %v", req.From, req.Value, err)}
		}
		return ToolResult{Success: true, Data: strconv.FormatUint(un, req.To)}
	}
	return ToolResult{Success: true, Data: strconv.FormatInt(n, req.To)}
}

// ============================================================
// File operations
// ============================================================

type FileHashRequest struct {
	FilePath  string `json:"filePath"`
	Algorithm string `json:"algorithm"`
}

func HashFile(req FileHashRequest) ToolResult {
	result, err := hashpkg.HashFile(req.FilePath, req.Algorithm)
	if err != nil {
		return ToolResult{Error: err.Error()}
	}
	return ToolResult{Success: true, Data: result}
}

type FileEncryptRequest struct {
	InputPath  string `json:"inputPath"`
	OutputPath string `json:"outputPath"`
	Key        string `json:"key"`       // hex 32 bytes for AES-256-GCM
	Algorithm  string `json:"algorithm"` // AES-256-GCM SM4-GCM
}

type FileDecryptRequest struct {
	InputPath  string `json:"inputPath"`
	OutputPath string `json:"outputPath"`
	Key        string `json:"key"`
	Algorithm  string `json:"algorithm"`
}

// ============================================================
// BigInt Operations
// ============================================================

type BigIntRequest struct {
	A        string `json:"a"`
	B        string `json:"b"`
	N        string `json:"n"`
	Op       string `json:"op"` // add, sub, mul, exp, base
	BaseFrom int    `json:"baseFrom"`
	BaseTo   int    `json:"baseTo"`
}

func BigIntOperation(req BigIntRequest) ToolResult {
	if req.Op == "base" {
		val := new(big.Int)
		if _, ok := val.SetString(req.A, req.BaseFrom); !ok {
			return ToolResult{Error: "输入值不合法"}
		}
		return ToolResult{Success: true, Data: val.Text(req.BaseTo)}
	}

	a := new(big.Int)
	b := new(big.Int)
	n := new(big.Int)

	if _, ok := a.SetString(req.A, 0); !ok {
		return ToolResult{Error: "无效的 A"}
	}
	if _, ok := b.SetString(req.B, 0); !ok {
		return ToolResult{Error: "无效的 B"}
	}
	hasModulus := req.N != ""
	if hasModulus {
		if _, ok := n.SetString(req.N, 0); !ok {
			return ToolResult{Error: "无效的 N"}
		}
		if n.Sign() == 0 {
			return ToolResult{Error: "模数 N 不能为 0"}
		}
	}

	res := new(big.Int)
	switch req.Op {
	case "add":
		res.Add(a, b)
	case "sub":
		res.Sub(a, b)
	case "mul":
		res.Mul(a, b)
	case "exp":
		if hasModulus {
			res.Exp(a, b, n)
		} else {
			res.Exp(a, b, nil)
		}
	default:
		return ToolResult{Error: "不支持的操作: " + req.Op}
	}

	if hasModulus && req.Op != "exp" {
		res.Mod(res, n)
	}

	return ToolResult{Success: true, Data: res.String()}
}

// ============================================================
// Certificate Operations
// ============================================================

type CSRRequest struct {
	CN   string `json:"cn"`
	O    string `json:"o"`
	C    string `json:"c"`
	L    string `json:"l"`
	ST   string `json:"st"`
	OU   string `json:"ou"`
	Algo string `json:"algo"` // RSA2048, RSA4096, ECC-P256, SM2
	Type string `json:"type"` // both, sign, encrypt (for SM2/CSR usage hints)
}

type CertGenRequest struct {
	CSR         string   `json:"csr"`  // PEM
	Days        int      `json:"days"` // Validity
	Type        string   `json:"type"` // sign, encrypt, both
	Algo        string   `json:"algo"` // RSA, ECC, SM2
	SAN         []string `json:"san"`  // DNS names or IPs
	IsCA        bool     `json:"isCA"`
	PathLen     int      `json:"pathLen"`
	KeyUsage    []string `json:"keyUsage"`
	ExtKeyUsage []string `json:"extKeyUsage"`
	CRLPoints   []string `json:"crlPoints"`
	OCSPUrls    []string `json:"ocspUrls"`
	Policies    []string `json:"policies"`
}

type SelfSignedCertRequest struct {
	CN          string   `json:"cn"`
	O           string   `json:"o"`
	C           string   `json:"c"`
	L           string   `json:"l"`
	ST          string   `json:"st"`
	OU          string   `json:"ou"`
	Days        int      `json:"days"`
	Algo        string   `json:"algo"` // RSA, ECC, SM2
	IsCA        bool     `json:"isCA"`
	PathLen     int      `json:"pathLen"`
	KeyUsage    []string `json:"keyUsage"`
	ExtKeyUsage []string `json:"extKeyUsage"`
	SAN         []string `json:"san"`
	CRLPoints   []string `json:"crlPoints"`
	OCSPUrls    []string `json:"ocspUrls"`
	Policies    []string `json:"policies"`
}

type InternalCAResult struct {
	Success bool   `json:"success"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
	CSR     string `json:"csr"`
	Root    string `json:"root"` // Root CA cert for download
	Error   string `json:"error"`
}

type DualCertResult struct {
	Success      bool   `json:"success"`
	SignCert     string `json:"signCert"`
	SignKey      string `json:"signKey"`
	EncryptCert  string `json:"encryptCert"`
	EnwrappedKey string `json:"enwrappedKey"` // Private key in GM/T 0010 envelope (hex)
	RootCert     string `json:"rootCert"`
	Error        string `json:"error"`
}

var (
	internalSM2CAKey  *sm2.PrivateKey
	internalSM2CACert *smx509.Certificate
	internalRSACAKey  *rsa.PrivateKey
	internalRSACACert *x509.Certificate
)

func init() {
	// Initialize internal SM2 CA
	internalSM2CAKey, _ = sm2.GenerateKey(rand.Reader)
	serial, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &smx509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "CryptoKit SM2 Root CA",
			Organization: []string{"CryptoKit"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
	}
	certDer, _ := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &internalSM2CAKey.PublicKey, internalSM2CAKey)
	internalSM2CACert, _ = smx509.ParseCertificate(certDer)

	// Initialize internal RSA CA
	internalRSACAKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	serialRSA, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmplRSA := &x509.Certificate{
		SerialNumber: serialRSA,
		Subject: pkix.Name{
			CommonName:   "CryptoKit RSA Root CA",
			Organization: []string{"CryptoKit"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	certDerRSA, _ := x509.CreateCertificate(rand.Reader, tmplRSA, tmplRSA, &internalRSACAKey.PublicKey, internalRSACAKey)
	internalRSACACert, _ = x509.ParseCertificate(certDerRSA)
}

func GenerateDualCertificates(req SelfSignedCertRequest) DualCertResult {
	if req.Algo != "SM2" {
		return DualCertResult{Error: "双证书签发目前仅支持 SM2 国密算法"}
	}

	// 1. Generate Signing Key Pair & Cert
	signPriv, _ := sm2.GenerateKey(rand.Reader)
	signPub := &signPriv.PublicKey

	// 2. Generate Encryption Key Pair & Cert
	encPriv, _ := sm2.GenerateKey(rand.Reader)
	encPub := &encPriv.PublicKey

	serialSign, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serialEnc, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(req.Days) * 24 * time.Hour)

	subj := pkix.Name{
		CommonName:         req.CN,
		Organization:       []string{req.O},
		Country:            []string{req.C},
		Locality:           []string{req.L},
		Province:           []string{req.ST},
		OrganizationalUnit: []string{req.OU},
	}

	_, eku, dnsNames, ipAddresses := parseCertOptions(req.KeyUsage, req.ExtKeyUsage, req.SAN)
	policies := parsePolicyOIDs(req.Policies)

	// Signing Cert Template
	signTmpl := smx509.Certificate{
		SerialNumber:          serialSign,
		Subject:               subj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		CRLDistributionPoints: req.CRLPoints,
		OCSPServer:            req.OCSPUrls,
		PolicyIdentifiers:     policies,
	}
	for _, u := range eku {
		signTmpl.ExtKeyUsage = append(signTmpl.ExtKeyUsage, smx509.ExtKeyUsage(u))
	}

	// Encryption Cert Template
	encTmpl := smx509.Certificate{
		SerialNumber:          serialEnc,
		Subject:               subj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		CRLDistributionPoints: req.CRLPoints,
		OCSPServer:            req.OCSPUrls,
		PolicyIdentifiers:     policies,
	}
	for _, u := range eku {
		encTmpl.ExtKeyUsage = append(encTmpl.ExtKeyUsage, smx509.ExtKeyUsage(u))
	}

	// Sign both with Internal SM2 CA
	signCertDer, err := smx509.CreateCertificate(rand.Reader, &signTmpl, internalSM2CACert, signPub, internalSM2CAKey)
	if err != nil {
		return DualCertResult{Error: "签名证书签发失败: " + err.Error()}
	}
	encCertDer, err := smx509.CreateCertificate(rand.Reader, &encTmpl, internalSM2CACert, encPub, internalSM2CAKey)
	if err != nil {
		return DualCertResult{Error: "加密证书签发失败: " + err.Error()}
	}

	// 3. Wrap Encryption Private Key in GM/T 0010 Envelope
	// Standard: Envelope using Receiver's (User's) Signing Public Key
	encPrivDer, _ := smx509.MarshalSM2PrivateKey(encPriv)
	envelopeHex, err := makeGMT0010Envelope(encPrivDer, signPub, internalSM2CAKey)
	if err != nil {
		return DualCertResult{Error: "制作私钥信封失败: " + err.Error()}
	}

	signPrivDer, _ := smx509.MarshalSM2PrivateKey(signPriv)

	return DualCertResult{
		Success:      true,
		SignCert:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signCertDer})),
		SignKey:      string(pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: signPrivDer})),
		EncryptCert:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encCertDer})),
		EnwrappedKey: envelopeHex,
		RootCert:     GetInternalRootCert("SM2"),
	}
}

// makeGMT0010Envelope implements a basic GM/T 0010 digital envelope
// Logic: SM2 Sign (by CA) -> Generate SM4 Key -> SM4 Encrypt (Data+Sig) -> SM2 Wrap SM4 Key (by User Pub)
func makeGMT0010Envelope(data []byte, recipientPub *ecdsa.PublicKey, senderPriv *sm2.PrivateKey) (string, error) {
	// 1. SM2 Sign by CA
	sig, err := senderPriv.SignWithSM2(rand.Reader, nil, data)
	if err != nil {
		return "", err
	}

	// Payload = [len_data(4)][data][len_sig(4)][sig]
	payload := make([]byte, 4+len(data)+4+len(sig))
	i := 0
	payload[i], payload[i+1], payload[i+2], payload[i+3] = byte(len(data)>>24), byte(len(data)>>16), byte(len(data)>>8), byte(len(data))
	i += 4
	copy(payload[i:], data)
	i += len(data)
	payload[i], payload[i+1], payload[i+2], payload[i+3] = byte(len(sig)>>24), byte(len(sig)>>16), byte(len(sig)>>8), byte(len(sig))
	i += 4
	copy(payload[i:], sig)

	// 2. Generate SM4 Key
	sm4Key := make([]byte, 16)
	rand.Read(sm4Key)
	iv := make([]byte, 16)
	rand.Read(iv)

	// 3. SM4 Encrypt Payload
	block, _ := sm4.NewCipher(sm4Key)
	paddedPayload := pkcs7Pad(payload, 16)
	encPayload := make([]byte, len(paddedPayload))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encPayload, paddedPayload)

	// 4. Wrap SM4 Key with Recipient SM2 Pub
	encKey, err := sm2.EncryptASN1(rand.Reader, recipientPub, sm4Key)
	if err != nil {
		return "", err
	}

	// Result = [iv(16)][len_key(4)][encKey][encPayload]
	final := make([]byte, 16+4+len(encKey)+len(encPayload))
	copy(final[0:16], iv)
	final[16], final[17], final[18], final[19] = byte(len(encKey)>>24), byte(len(encKey)>>16), byte(len(encKey)>>8), byte(len(encKey))
	copy(final[20:20+len(encKey)], encKey)
	copy(final[20+len(encKey):], encPayload)

	return hexUpper(final), nil
}

func pkcs7Pad(b []byte, blocksize int) []byte {
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	for i := len(b); i < len(pb); i++ {
		pb[i] = byte(n)
	}
	return pb
}

func GetInternalRootCert(algo string) string {
	var der []byte
	if algo == "SM2" {
		der = internalSM2CACert.Raw
	} else {
		der = internalRSACACert.Raw
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func GenerateInternalSignedCert(req SelfSignedCertRequest) InternalCAResult {
	var priv interface{}
	var pubKey interface{}
	var err error

	if req.Algo == "SM2" {
		p, _ := sm2.GenerateKey(rand.Reader)
		priv = p
		pubKey = &p.PublicKey
	} else if req.Algo == "RSA" {
		p, _ := rsa.GenerateKey(rand.Reader, 2048)
		priv = p
		pubKey = &p.PublicKey
	} else {
		p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv = p
		pubKey = &p.PublicKey
	}

	serialNumber, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(req.Days) * 24 * time.Hour)

	subj := pkix.Name{
		CommonName:         req.CN,
		Organization:       []string{req.O},
		Country:            []string{req.C},
		Locality:           []string{req.L},
		Province:           []string{req.ST},
		OrganizationalUnit: []string{req.OU},
	}

	// 1. CSR
	var csrBytes []byte
	if req.Algo == "SM2" {
		csrTemplate := smx509.CertificateRequest{Subject: subj}
		csrBytes, _ = smx509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv.(*sm2.PrivateKey))
	} else {
		csrTemplate := x509.CertificateRequest{Subject: subj}
		csrBytes, _ = x509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// 2. Extensions
	ku, eku, dnsNames, ipAddresses := parseCertOptions(req.KeyUsage, req.ExtKeyUsage, req.SAN)
	policies := parsePolicyOIDs(req.Policies)

	var certBytes []byte
	if req.Algo == "SM2" {
		template := smx509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              smx509.KeyUsage(ku),
			BasicConstraintsValid: true,
			IsCA:                  req.IsCA,
			MaxPathLen:            req.PathLen,
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			CRLDistributionPoints: req.CRLPoints,
			OCSPServer:            req.OCSPUrls,
			PolicyIdentifiers:     policies,
		}
		for _, u := range eku {
			template.ExtKeyUsage = append(template.ExtKeyUsage, smx509.ExtKeyUsage(u))
		}
		certBytes, err = smx509.CreateCertificate(rand.Reader, &template, internalSM2CACert, pubKey, internalSM2CAKey)
	} else {
		template := x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              ku,
			ExtKeyUsage:           eku,
			BasicConstraintsValid: true,
			IsCA:                  req.IsCA,
			MaxPathLen:            req.PathLen,
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			CRLDistributionPoints: req.CRLPoints,
			OCSPServer:            req.OCSPUrls,
			PolicyIdentifiers:     policies,
		}
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, internalRSACACert, pubKey, internalRSACAKey)
	}

	if err != nil {
		return InternalCAResult{Error: "签发失败: " + err.Error()}
	}

	// Private Key PEM
	var privPEM []byte
	if req.Algo == "SM2" {
		der, _ := smx509.MarshalSM2PrivateKey(priv.(*sm2.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: der})
	} else if req.Algo == "RSA" {
		der := x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	} else {
		der, _ := x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}

	return InternalCAResult{
		Success: true,
		Cert:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})),
		Key:     string(privPEM),
		CSR:     string(csrPEM),
		Root:    GetInternalRootCert(req.Algo),
	}
}

// TranslateError translates internal crypto errors to user-friendly Chinese
func TranslateError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	// ASN.1 / DER Structure errors
	if strings.Contains(msg, "asn1: structure error") {
		if strings.Contains(msg, "tags don't match") {
			return "数据结构解析失败：ASN.1 标签不匹配 (可能是公钥/私钥格式选错，或数据不完整)"
		}
		return "数据结构错误：无法解析的 ASN.1 格式"
	}

	// PEM errors
	if strings.Contains(msg, "not a valid PEM") || strings.Contains(msg, "no PEM data") {
		return "无效的 PEM 格式：请确保包含正确的 BEGIN/END 边界"
	}

	// RSA Specific
	if strings.Contains(msg, "too message long") || strings.Contains(msg, "too large for modulus") {
		return "RSA 操作失败：待处理数据长度超过了密钥模长限制"
	}
	if strings.Contains(msg, "crypto/rsa: verification error") {
		return "RSA 签名验证失败：数据已被篡改或公钥不匹配"
	}
	if strings.Contains(msg, "crypto/rsa: decryption error") {
		return "RSA 解密失败：可能是填充模式不匹配或私钥错误"
	}

	// EC / SM2 Specific
	if strings.Contains(msg, "invalid elliptic curve") {
		return "无效的椭圆曲线：曲线类型不匹配"
	}
	if strings.Contains(msg, "square root does not exist") {
		return "计算失败：数据点不在椭圆曲线上"
	}

	// SM4 / AES Block errors
	if strings.Contains(msg, "input not full blocks") {
		return "分组加密失败：输入数据长度不是块大小的倍数 (请检查填充模式)"
	}
	if strings.Contains(msg, "cipher: message authentication failed") {
		return "解密认证失败：数据可能已被篡改或认证密钥错误"
	}

	// Hex errors
	if strings.Contains(msg, "encoding/hex: invalid byte") {
		return "无效的十六进制字符：输入包含非 Hex 字符"
	}
	if strings.Contains(msg, "encoding/hex: odd length hex string") {
		return "十六进制长度错误：Hex 字符串长度必须为偶数"
	}

	return msg
}

func parsePolicyOIDs(policies []string) []asn1.ObjectIdentifier {
	var result []asn1.ObjectIdentifier
	for _, p := range policies {
		parts := strings.Split(p, ".")
		var oid asn1.ObjectIdentifier
		valid := true
		for _, part := range parts {
			val, err := strconv.Atoi(part)
			if err != nil {
				valid = false
				break
			}
			oid = append(oid, val)
		}
		if valid && len(oid) > 0 {
			result = append(result, oid)
		}
	}
	return result
}

func parseCertOptions(kuStrs []string, ekuStrs []string, sanStrs []string) (x509.KeyUsage, []x509.ExtKeyUsage, []string, []net.IP) {
	var ku x509.KeyUsage
	for _, u := range kuStrs {
		switch u {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "nonRepudiation":
			ku |= x509.KeyUsageContentCommitment
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyCertSign":
			ku |= x509.KeyUsageCertSign
		case "crlSign":
			ku |= x509.KeyUsageCRLSign
		}
	}
	var eku []x509.ExtKeyUsage
	for _, u := range ekuStrs {
		switch u {
		case "serverAuth":
			eku = append(eku, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			eku = append(eku, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			eku = append(eku, x509.ExtKeyUsageEmailProtection)
		}
	}
	var dns []string
	var ips []net.IP
	for _, s := range sanStrs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, s)
		}
	}
	return ku, eku, dns, ips
}

type SelfSignedCertResult struct {
	Success bool   `json:"success"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
	CSR     string `json:"csr"`
	Error   string `json:"error"`
}

func GenerateSelfSignedCert(req SelfSignedCertRequest) SelfSignedCertResult {
	var priv interface{}
	var pubKey interface{}
	var err error

	if req.Algo == "SM2" {
		p, _ := sm2.GenerateKey(rand.Reader)
		priv = p
		pubKey = &p.PublicKey
	} else if req.Algo == "RSA" {
		p, _ := rsa.GenerateKey(rand.Reader, 2048)
		priv = p
		pubKey = &p.PublicKey
	} else {
		p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv = p
		pubKey = &p.PublicKey
	}

	serialNumber, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(req.Days) * 24 * time.Hour)

	subj := pkix.Name{
		CommonName:         req.CN,
		Organization:       []string{req.O},
		Country:            []string{req.C},
		Locality:           []string{req.L},
		Province:           []string{req.ST},
		OrganizationalUnit: []string{req.OU},
	}

	// 1. Generate CSR
	var csrBytes []byte
	if req.Algo == "SM2" {
		csrTemplate := smx509.CertificateRequest{Subject: subj}
		csrBytes, _ = smx509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv.(*sm2.PrivateKey))
	} else {
		csrTemplate := x509.CertificateRequest{Subject: subj}
		csrBytes, _ = x509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// 2. Generate Cert
	ku, eku, dnsNames, ipAddresses := parseCertOptions(req.KeyUsage, req.ExtKeyUsage, req.SAN)
	if ku == 0 {
		ku = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	var certBytes []byte
	if req.Algo == "SM2" {
		template := smx509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              smx509.KeyUsage(ku),
			BasicConstraintsValid: true,
			IsCA:                  req.IsCA,
			MaxPathLen:            req.PathLen,
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			CRLDistributionPoints: req.CRLPoints,
			OCSPServer:            req.OCSPUrls,
		}
		if req.IsCA {
			template.KeyUsage |= smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign
		}
		for _, u := range eku {
			template.ExtKeyUsage = append(template.ExtKeyUsage, smx509.ExtKeyUsage(u))
		}
		sm2Priv := priv.(*sm2.PrivateKey)
		certBytes, err = smx509.CreateCertificate(rand.Reader, &template, &template, pubKey, sm2Priv)
	} else {
		template := x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              ku,
			ExtKeyUsage:           eku,
			BasicConstraintsValid: true,
			IsCA:                  req.IsCA,
			MaxPathLen:            req.PathLen,
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			CRLDistributionPoints: req.CRLPoints,
			OCSPServer:            req.OCSPUrls,
		}
		if req.IsCA {
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
	}

	if err != nil {
		return SelfSignedCertResult{Error: "生成自签名证书失败: " + err.Error()}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// 3. Private Key PEM
	var privPEM []byte
	if req.Algo == "SM2" {
		der, _ := smx509.MarshalSM2PrivateKey(priv.(*sm2.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: der})
	} else if req.Algo == "RSA" {
		der := x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	} else {
		der, _ := x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}

	return SelfSignedCertResult{
		Success: true,
		Cert:    string(certPEM),
		Key:     string(privPEM),
		CSR:     string(csrPEM),
	}
}

func GenerateCertificate(req CertGenRequest) ToolResult {
	var subj pkix.Name
	var pubKey interface{}
	var err error

	// 1. If CSR is provided, parse it
	if req.CSR != "" {
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			return ToolResult{Error: "无效的 CSR PEM"}
		}

		if req.Algo == "SM2" {
			csr, err := smx509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return ToolResult{Error: "解析 SM2 CSR 失败: " + err.Error()}
			}
			subj = csr.Subject
			pubKey = csr.PublicKey
		} else {
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return ToolResult{Error: "解析 CSR 失败: " + err.Error()}
			}
			subj = csr.Subject
			pubKey = csr.PublicKey
		}
	} else {
		return ToolResult{Error: "未提供 CSR 内容"}
	}

	// 4. Template
	serialNumber, _ := randInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(req.Days) * 24 * time.Hour)

	// Adjust Usage based on Type
	ku, eku, dnsNames, ipAddresses := parseCertOptions(req.KeyUsage, req.ExtKeyUsage, req.SAN)
	policies := parsePolicyOIDs(req.Policies)
	if len(req.KeyUsage) == 0 {
		ku = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		if req.Type == "sign" {
			ku = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		} else if req.Type == "encrypt" {
			ku = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		}
	}

	var certBytes []byte
	if req.Algo == "SM2" {
		template := smx509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              smx509.KeyUsage(ku),
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			BasicConstraintsValid: true,
			IsCA:                  req.IsCA,
			MaxPathLen:            req.PathLen,
			CRLDistributionPoints: req.CRLPoints,
			OCSPServer:            req.OCSPUrls,
			PolicyIdentifiers:     policies,
		}
		if req.IsCA {
			template.KeyUsage |= smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign
		}
		for _, u := range eku {
			template.ExtKeyUsage = append(template.ExtKeyUsage, smx509.ExtKeyUsage(u))
		}
		certBytes, err = smx509.CreateCertificate(rand.Reader, &template, internalSM2CACert, pubKey, internalSM2CAKey)
	} else {
		template := x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              ku,
			ExtKeyUsage:           eku,
			DNSNames:              dnsNames,
			IPAddresses:           ipAddresses,
			BasicConstraintsValid: true,
			IsCA:                  req.IsCA,
			MaxPathLen:            req.PathLen,
			CRLDistributionPoints: req.CRLPoints,
			OCSPServer:            req.OCSPUrls,
			PolicyIdentifiers:     policies,
		}
		if req.IsCA {
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, internalRSACACert, pubKey, internalRSACAKey)
	}

	if err != nil {
		return ToolResult{Error: "生成证书失败: " + err.Error()}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return ToolResult{Success: true, Data: string(certPEM)}
}

func GenerateCSR(req CSRRequest) ToolResult {
	var priv interface{}
	var err error

	switch req.Algo {
	case "RSA4096":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ECC-P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "SM2":
		priv, err = sm2.GenerateKey(rand.Reader)
	default:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}

	if err != nil {
		return ToolResult{Error: "生成私钥失败: " + err.Error()}
	}

	subj := pkix.Name{
		CommonName:         req.CN,
		Organization:       []string{req.O},
		Country:            []string{req.C},
		Locality:           []string{req.L},
		Province:           []string{req.ST},
		OrganizationalUnit: []string{req.OU},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: 0, // Automatically choose
	}

	var csrBytes []byte
	if req.Algo == "SM2" {
		privKey, ok := priv.(*sm2.PrivateKey)
		if !ok {
			return ToolResult{Error: "内部错误: 无法获取 SM2 私钥"}
		}

		smxTemplate := smx509.CertificateRequest{
			Subject:            subj,
			SignatureAlgorithm: 0, // Automatically choose
		}
		csrBytes, err = smx509.CreateCertificateRequest(rand.Reader, &smxTemplate, privKey)
		if err != nil {
			return ToolResult{Error: "创建 SM2 CSR 失败: " + err.Error()}
		}
	} else {
		csrBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, priv)
		if err != nil {
			return ToolResult{Error: "创建 CSR 失败: " + err.Error()}
		}
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return ToolResult{Success: true, Data: string(pemBytes)}
}

func ParseCertificate(pemStr string) ToolResult {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return ToolResult{Error: "无效的 PEM 格式"}
	}

	// Try standard x509 first
	cert, err := x509.ParseCertificate(block.Bytes)
	var info string
	if err == nil {
		info = formatCertInfo(cert)
	} else {
		// Try SM2 x509
		smCert, err2 := smx509.ParseCertificate(block.Bytes)
		if err2 != nil {
			return ToolResult{Error: "解析证书失败 (尝试了国际和国密标准): " + err2.Error()}
		}
		info = formatSM2CertInfo(smCert)
	}

	return ToolResult{Success: true, Data: info}
}

func formatCertInfo(cert *x509.Certificate) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("版本: v%d\n", cert.Version))
	sb.WriteString(fmt.Sprintf("序列号: %s\n", cert.SerialNumber.Text(16)))
	sb.WriteString(fmt.Sprintf("签名算法: %s\n", cert.SignatureAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("发行者: %s\n", cert.Issuer.String()))
	sb.WriteString(fmt.Sprintf("使用者: %s\n", cert.Subject.String()))
	sb.WriteString(fmt.Sprintf("有效期自: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("有效期至: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("公钥算法: %s\n", cert.PublicKeyAlgorithm.String()))

	// OID and Extensions
	if len(cert.Extensions) > 0 {
		sb.WriteString("\n扩展项:\n")
		for _, ext := range cert.Extensions {
			sb.WriteString(fmt.Sprintf("  - %s (Critical: %v): %s\n", ext.Id.String(), ext.Critical, hexUpper(ext.Value)))
		}
	}

	return sb.String()
}

func formatSM2CertInfo(cert *smx509.Certificate) string {
	var sb strings.Builder
	sb.WriteString("类型: 国密 SM2 证书\n")
	sb.WriteString(fmt.Sprintf("版本: v%d\n", cert.Version))
	sb.WriteString(fmt.Sprintf("序列号: %s\n", cert.SerialNumber.Text(16)))
	sb.WriteString(fmt.Sprintf("签名算法: %s\n", cert.SignatureAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("发行者: %s\n", cert.Issuer.String()))
	sb.WriteString(fmt.Sprintf("使用者: %s\n", cert.Subject.String()))
	sb.WriteString(fmt.Sprintf("有效期自: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("有效期至: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05")))

	// OID and Extensions
	if len(cert.Extensions) > 0 {
		sb.WriteString("\n扩展项:\n")
		for _, ext := range cert.Extensions {
			sb.WriteString(fmt.Sprintf("  - %s (Critical: %v): %s\n", ext.Id.String(), ext.Critical, hexUpper(ext.Value)))
		}
	}

	return sb.String()
}
