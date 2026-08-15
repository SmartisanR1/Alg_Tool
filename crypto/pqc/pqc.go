package pqc

import (
	"encoding/hex"

	"github.com/emmansun/gmsm/rand"

	"cryptokit/crypto/symmetric"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/xwing"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

type PQCKeyResult struct {
	Success    bool   `json:"success"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	ParamSet   string `json:"paramSet"`
	Error      string `json:"error"`
}

type PQCEncapResult struct {
	Success      bool   `json:"success"`
	Ciphertext   string `json:"ciphertext"`
	SharedSecret string `json:"sharedSecret"`
	Error        string `json:"error"`
}

// ============================================================
// ML-KEM — FIPS 203
// ============================================================

type MLKEMRequest struct {
	PublicKey string `json:"publicKey"`
	ParamSet  string `json:"paramSet"`
}

type MLKEMDecapRequest struct {
	PrivateKey string `json:"privateKey"`
	Ciphertext string `json:"ciphertext"`
	ParamSet   string `json:"paramSet"`
}

func MLKEMKeyGen(paramSet string) PQCKeyResult {
	switch paramSet {
	case "ML-KEM-512":
		pub, priv, err := mlkem512.GenerateKeyPair(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-KEM-512 密钥生成失败: " + err.Error()}
		}
		pb, _ := pub.MarshalBinary()
		sb, _ := priv.MarshalBinary()
		return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "ML-KEM-512"}
	case "ML-KEM-768":
		pub, priv, err := mlkem768.GenerateKeyPair(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-KEM-768 密钥生成失败: " + err.Error()}
		}
		pb, _ := pub.MarshalBinary()
		sb, _ := priv.MarshalBinary()
		return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "ML-KEM-768"}
	default:
		pub, priv, err := mlkem1024.GenerateKeyPair(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-KEM-1024 密钥生成失败: " + err.Error()}
		}
		pb, _ := pub.MarshalBinary()
		sb, _ := priv.MarshalBinary()
		return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "ML-KEM-1024"}
	}
}

func MLKEMEncapsulate(req MLKEMRequest) PQCEncapResult {
	pb, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return PQCEncapResult{Error: "无效的公钥: " + err.Error()}
	}
	switch req.ParamSet {
	case "ML-KEM-512":
		s := mlkem512.Scheme()
		pub, e := s.UnmarshalBinaryPublicKey(pb)
		if e != nil {
			return PQCEncapResult{Error: "解析公钥失败: " + e.Error()}
		}
		ct, ss, e := s.Encapsulate(pub)
		if e != nil {
			return PQCEncapResult{Error: "封装失败: " + e.Error()}
		}
		return PQCEncapResult{Success: true, Ciphertext: hexUpper(ct), SharedSecret: hexUpper(ss)}
	case "ML-KEM-768":
		s := mlkem768.Scheme()
		pub, e := s.UnmarshalBinaryPublicKey(pb)
		if e != nil {
			return PQCEncapResult{Error: "解析公钥失败: " + e.Error()}
		}
		ct, ss, e := s.Encapsulate(pub)
		if e != nil {
			return PQCEncapResult{Error: "封装失败: " + e.Error()}
		}
		return PQCEncapResult{Success: true, Ciphertext: hexUpper(ct), SharedSecret: hexUpper(ss)}
	default:
		s := mlkem1024.Scheme()
		pub, e := s.UnmarshalBinaryPublicKey(pb)
		if e != nil {
			return PQCEncapResult{Error: "解析公钥失败: " + e.Error()}
		}
		ct, ss, e := s.Encapsulate(pub)
		if e != nil {
			return PQCEncapResult{Error: "封装失败: " + e.Error()}
		}
		return PQCEncapResult{Success: true, Ciphertext: hexUpper(ct), SharedSecret: hexUpper(ss)}
	}
}

func MLKEMDecapsulate(req MLKEMDecapRequest) symmetric.CryptoResult {
	sb, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	ct, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密文: " + err.Error()}
	}
	switch req.ParamSet {
	case "ML-KEM-512":
		s := mlkem512.Scheme()
		priv, e := s.UnmarshalBinaryPrivateKey(sb)
		if e != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + e.Error()}
		}
		ss, e := s.Decapsulate(priv, ct)
		if e != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + e.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}
	case "ML-KEM-768":
		s := mlkem768.Scheme()
		priv, e := s.UnmarshalBinaryPrivateKey(sb)
		if e != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + e.Error()}
		}
		ss, e := s.Decapsulate(priv, ct)
		if e != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + e.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}
	default:
		s := mlkem1024.Scheme()
		priv, e := s.UnmarshalBinaryPrivateKey(sb)
		if e != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + e.Error()}
		}
		ss, e := s.Decapsulate(priv, ct)
		if e != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + e.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}
	}
}

// ============================================================
// ML-DSA — FIPS 204
// ============================================================

type MLDSARequest struct {
	PrivateKey string `json:"privateKey"`
	Data       string `json:"data"`
	ParamSet   string `json:"paramSet"`
}

type MLDSAVerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
	ParamSet  string `json:"paramSet"`
}

func MLDSAKeyGen(paramSet string) PQCKeyResult {
	switch paramSet {
	case "ML-DSA-44":
		pub, priv, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-DSA-44 密钥生成失败: " + err.Error()}
		}
		pb, _ := pub.MarshalBinary()
		sb, _ := priv.MarshalBinary()
		return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "ML-DSA-44"}
	case "ML-DSA-65":
		pub, priv, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-DSA-65 密钥生成失败: " + err.Error()}
		}
		pb, _ := pub.MarshalBinary()
		sb, _ := priv.MarshalBinary()
		return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "ML-DSA-65"}
	default:
		pub, priv, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return PQCKeyResult{Error: "ML-DSA-87 密钥生成失败: " + err.Error()}
		}
		pb, _ := pub.MarshalBinary()
		sb, _ := priv.MarshalBinary()
		return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "ML-DSA-87"}
	}
}

func MLDSASign(req MLDSARequest) symmetric.CryptoResult {
	sb, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	msg, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	switch req.ParamSet {
	case "ML-DSA-44":
		var priv mldsa44.PrivateKey
		if err := priv.UnmarshalBinary(sb); err != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&priv, msg, nil, true, sig); err != nil {
			return symmetric.CryptoResult{Error: "签名失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
	case "ML-DSA-65":
		var priv mldsa65.PrivateKey
		if err := priv.UnmarshalBinary(sb); err != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&priv, msg, nil, true, sig); err != nil {
			return symmetric.CryptoResult{Error: "签名失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
	default:
		var priv mldsa87.PrivateKey
		if err := priv.UnmarshalBinary(sb); err != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(&priv, msg, nil, true, sig); err != nil {
			return symmetric.CryptoResult{Error: "签名失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
	}
}

func MLDSAVerify(req MLDSAVerifyRequest) symmetric.CryptoResult {
	pb, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的公钥: " + err.Error()}
	}
	msg, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名: " + err.Error()}
	}
	var valid bool
	switch req.ParamSet {
	case "ML-DSA-44":
		var pub mldsa44.PublicKey
		if err := pub.UnmarshalBinary(pb); err != nil {
			return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
		}
		valid = mldsa44.Verify(&pub, msg, nil, sig)
	case "ML-DSA-65":
		var pub mldsa65.PublicKey
		if err := pub.UnmarshalBinary(pb); err != nil {
			return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
		}
		valid = mldsa65.Verify(&pub, msg, nil, sig)
	default:
		var pub mldsa87.PublicKey
		if err := pub.UnmarshalBinary(pb); err != nil {
			return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
		}
		valid = mldsa87.Verify(&pub, msg, nil, sig)
	}
	if !valid {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// SLH-DSA (SPHINCS+) — FIPS 205
// ============================================================

type SLHDSARequest struct {
	PrivateKey string `json:"privateKey"`
	Data       string `json:"data"`
	ParamSet   string `json:"paramSet"`
}

type SLHDSAVerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
	ParamSet  string `json:"paramSet"`
}

func SLHDSAKeyGen(paramSet string) PQCKeyResult {
	id, err := slhdsa.IDByName(paramSet)
	if err != nil {
		return PQCKeyResult{Error: "不支持的 SLH-DSA 参数集: " + err.Error(), ParamSet: paramSet}
	}
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
	if err != nil {
		return PQCKeyResult{Error: "SLH-DSA 密钥生成失败: " + err.Error(), ParamSet: paramSet}
	}
	pb, _ := pub.MarshalBinary()
	sb, _ := priv.MarshalBinary()
	return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: paramSet}
}

func SLHDSASign(req SLHDSARequest) symmetric.CryptoResult {
	sb, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	msg, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	id, err := slhdsa.IDByName(req.ParamSet)
	if err != nil {
		return symmetric.CryptoResult{Error: "不支持的参数集: " + err.Error()}
	}
	priv := slhdsa.PrivateKey{ID: id}
	if err := priv.UnmarshalBinary(sb); err != nil {
		return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
	}
	sig, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		return symmetric.CryptoResult{Error: "签名失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func SLHDSAVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	pb, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效公钥: " + err.Error()}
	}
	msg, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效数据: " + err.Error()}
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效签名: " + err.Error()}
	}
	id, err := slhdsa.IDByName(req.ParamSet)
	if err != nil {
		return symmetric.CryptoResult{Error: "不支持的参数集: " + err.Error()}
	}
	pub := slhdsa.PublicKey{ID: id}
	if err := pub.UnmarshalBinary(pb); err != nil {
		return symmetric.CryptoResult{Error: "解析公钥失败: " + err.Error()}
	}
	if !slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig, nil) {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// X-Wing — PQ/T Hybrid KEM (ML-KEM-768 + X25519)
// ============================================================

type XWingRequest struct {
	PublicKey  string `json:"publicKey"`
	Ciphertext string `json:"ciphertext"`
	PrivateKey string `json:"privateKey"`
}

func XWingKeyGen() PQCKeyResult {
	priv, pub, err := xwing.GenerateKeyPair(rand.Reader)
	if err != nil {
		return PQCKeyResult{Error: "X-Wing 密钥生成失败: " + err.Error()}
	}
	pb, _ := pub.MarshalBinary()
	sb, _ := priv.MarshalBinary()
	return PQCKeyResult{Success: true, PublicKey: hexUpper(pb), PrivateKey: hexUpper(sb), ParamSet: "X-Wing"}
}

func XWingEncapsulate(req XWingRequest) PQCEncapResult {
	pb, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return PQCEncapResult{Error: "无效的公钥: " + err.Error()}
	}
	ss, ct, err := xwing.Encapsulate(pb, nil)
	if err != nil {
		return PQCEncapResult{Error: "X-Wing封装失败: " + err.Error()}
	}
	return PQCEncapResult{Success: true, Ciphertext: hexUpper(ct), SharedSecret: hexUpper(ss)}
}

func XWingDecapsulate(req XWingRequest) symmetric.CryptoResult {
	sb, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	ct, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密文: " + err.Error()}
	}
	ss := xwing.Decapsulate(ct, sb)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}
}
