package pqc

import (
	"encoding/hex"

	"cryptokit/crypto/symmetric"

	falcon "github.com/lattice-safe/falcon-go"
)

func falconLogN(paramSet string) (uint, bool) {
	switch paramSet {
	case "Falcon-512":
		return 9, true
	case "Falcon-1024":
		return 10, true
	default:
		return 0, false
	}
}

// FalconKeyGen generates an FN-DSA/Falcon key pair.
func FalconKeyGen(paramSet string) PQCKeyResult {
	logn, ok := falconLogN(paramSet)
	if !ok {
		return PQCKeyResult{Error: "不支持的参数集: " + paramSet + " (支持 Falcon-512, Falcon-1024)", ParamSet: paramSet}
	}

	kp, err := falcon.Generate(logn)
	if err != nil {
		return PQCKeyResult{Error: "Falcon 密钥生成失败: " + err.Error(), ParamSet: paramSet}
	}

	return PQCKeyResult{
		Success:    true,
		PrivateKey: hexUpper(kp.PrivateKey()),
		PublicKey:  hexUpper(kp.PublicKey()),
		ParamSet:   paramSet,
	}
}

// FalconSign signs hex-encoded data with a hex-encoded Falcon private key.
func FalconSign(req SLHDSARequest) symmetric.CryptoResult {
	if _, ok := falconLogN(req.ParamSet); !ok {
		return symmetric.CryptoResult{Error: "不支持的参数集: " + req.ParamSet}
	}

	sk, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	msg, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	kp, err := falcon.FromPrivateKey(sk)
	if err != nil {
		return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
	}
	if kp.LogN() != mustFalconLogN(req.ParamSet) {
		return symmetric.CryptoResult{Error: "私钥与参数集不匹配"}
	}

	sig, err := kp.Sign(msg, falcon.DomainNone())
	if err != nil {
		return symmetric.CryptoResult{Error: "签名失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig.Bytes())}
}

// FalconVerify verifies a hex-encoded Falcon signature over hex-encoded data.
func FalconVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	logn, ok := falconLogN(req.ParamSet)
	if !ok {
		return symmetric.CryptoResult{Error: "不支持的参数集: " + req.ParamSet}
	}

	pk, err := hex.DecodeString(req.PublicKey)
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
	if pkLogN, err := falconPublicLogN(pk); err != nil || pkLogN != logn {
		return symmetric.CryptoResult{Error: "公钥与参数集不匹配"}
	}

	if err := falcon.Verify(sig, pk, msg, falcon.DomainNone()); err != nil {
		return symmetric.CryptoResult{Success: false, Error: "签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

func mustFalconLogN(paramSet string) uint {
	logn, _ := falconLogN(paramSet)
	return logn
}

func falconPublicLogN(pk []byte) (uint, error) {
	if len(pk) == 0 || pk[0]&0xF0 != 0 {
		return 0, falcon.ErrFormat
	}
	return uint(pk[0] & 0x0F), nil
}
