//go:build !oqs
// +build !oqs

package pqc

import (
	"encoding/hex"
	"fmt"

	"cryptokit/crypto/symmetric"

	hqc "github.com/shurlinet/go-hqc"
)

// HQC — Hamming Quasi-Cyclic code-based KEM.
// This uses go-hqc, which tracks the pre-FIPS HQC v5.0.0 reference.
func HQCKeyGen(paramSet string) PQCKeyResult {
	switch paramSet {
	case "HQC-128":
		dk, err := hqc.GenerateKey128()
		if err != nil {
			return PQCKeyResult{Error: "HQC-128 密钥生成失败: " + err.Error(), ParamSet: paramSet}
		}
		defer dk.Destroy()
		return PQCKeyResult{Success: true, PrivateKey: hexUpper(dk.Bytes()), PublicKey: hexUpper(dk.EncapsulationKey().Bytes()), ParamSet: paramSet}
	case "HQC-192":
		dk, err := hqc.GenerateKey192()
		if err != nil {
			return PQCKeyResult{Error: "HQC-192 密钥生成失败: " + err.Error(), ParamSet: paramSet}
		}
		defer dk.Destroy()
		return PQCKeyResult{Success: true, PrivateKey: hexUpper(dk.Bytes()), PublicKey: hexUpper(dk.EncapsulationKey().Bytes()), ParamSet: paramSet}
	case "HQC-256":
		dk, err := hqc.GenerateKey256()
		if err != nil {
			return PQCKeyResult{Error: "HQC-256 密钥生成失败: " + err.Error(), ParamSet: paramSet}
		}
		defer dk.Destroy()
		return PQCKeyResult{Success: true, PrivateKey: hexUpper(dk.Bytes()), PublicKey: hexUpper(dk.EncapsulationKey().Bytes()), ParamSet: paramSet}
	default:
		return PQCKeyResult{Error: "不支持的 HQC 参数集: " + paramSet + " (支持 HQC-128, HQC-192, HQC-256)", ParamSet: paramSet}
	}
}

func HQCEncapsulate(req MLKEMRequest) PQCEncapResult {
	pb, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return PQCEncapResult{Error: "无效的公钥: " + err.Error()}
	}

	var ss, ct []byte
	switch req.ParamSet {
	case "HQC-128":
		ek, err := hqc.ParseEncapsulationKey128(pb)
		if err != nil {
			return PQCEncapResult{Error: "解析公钥失败: " + err.Error()}
		}
		ss, ct = ek.Encapsulate()
	case "HQC-192":
		ek, err := hqc.ParseEncapsulationKey192(pb)
		if err != nil {
			return PQCEncapResult{Error: "解析公钥失败: " + err.Error()}
		}
		ss, ct = ek.Encapsulate()
	case "HQC-256":
		ek, err := hqc.ParseEncapsulationKey256(pb)
		if err != nil {
			return PQCEncapResult{Error: "解析公钥失败: " + err.Error()}
		}
		ss, ct = ek.Encapsulate()
	default:
		return PQCEncapResult{Error: "不支持的 HQC 参数集: " + req.ParamSet + " (支持 HQC-128, HQC-192, HQC-256)"}
	}

	return PQCEncapResult{Success: true, Ciphertext: hexUpper(ct), SharedSecret: hexUpper(ss)}
}

func HQCDecapsulate(req MLKEMDecapRequest) symmetric.CryptoResult {
	sb, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的私钥: " + err.Error()}
	}
	ct, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密文: " + err.Error()}
	}

	var ss []byte
	switch req.ParamSet {
	case "HQC-128":
		dk, err := hqc.ParseDecapsulationKey128(sb)
		if err != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
		}
		defer dk.Destroy()
		ss, err = dk.Decapsulate(ct)
		if err != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + err.Error()}
		}
	case "HQC-192":
		dk, err := hqc.ParseDecapsulationKey192(sb)
		if err != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
		}
		defer dk.Destroy()
		ss, err = dk.Decapsulate(ct)
		if err != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + err.Error()}
		}
	case "HQC-256":
		dk, err := hqc.ParseDecapsulationKey256(sb)
		if err != nil {
			return symmetric.CryptoResult{Error: "解析私钥失败: " + err.Error()}
		}
		defer dk.Destroy()
		ss, err = dk.Decapsulate(ct)
		if err != nil {
			return symmetric.CryptoResult{Error: "解封装失败: " + err.Error()}
		}
	default:
		return symmetric.CryptoResult{Error: fmt.Sprintf("不支持的 HQC 参数集: %s", req.ParamSet)}
	}

	return symmetric.CryptoResult{Success: true, Data: hexUpper(ss)}
}
