package gm

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/rand"

	"cryptokit/crypto/symmetric"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/gmsm/zuc"
)

// ============================================================
// SM2  (GM/T 0003-2012)
// ============================================================

type SM2KeyResult struct {
	Success    bool   `json:"success"`
	PrivateKey string `json:"privateKey"` // PEM
	PublicKey  string `json:"publicKey"`  // PEM
	PrivHex    string `json:"privHex"`    // DER 私钥 Hex
	PubHex     string `json:"pubHex"`     // DER 公钥 Hex
	RawPriv    string `json:"rawPriv"`    // 裸私钥 32字节 Hex
	RawPub     string `json:"rawPub"`     // 裸公钥 64字节 Hex (X||Y)
	Error      string `json:"error"`
}

type SM2Request struct {
	Key  string `json:"key"`  // PEM/Hex
	Data string `json:"data"` // hex
	Mode string `json:"mode"` // C1C3C2(default) or C1C2C3
}

type SM2SignRequest struct {
	PrivateKey string `json:"privateKey"` // PEM/Hex
	Data       string `json:"data"`       // hex (raw message, SM2Sign will hash internally)
	ID         string `json:"id"`         // user ID, default "1234567812345678"
}

type SM2VerifyRequest struct {
	PublicKey string `json:"publicKey"` // PEM/Hex
	Data      string `json:"data"`      // hex
	Signature string `json:"signature"` // hex (ASN.1 DER)
	ID        string `json:"id"`
}

type SM2KeyAgreementRequest struct {
	PrivateKey    string `json:"privateKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	MyID          string `json:"myId"`
	PeerID        string `json:"peerId"`
	KeyLen        int    `json:"keyLen"`
	Initiator     bool   `json:"initiator"`
}

// SM2GenerateKey generates an SM2 key pair (GM/T 0003.1)
// Uses sm2p256v1 curve per GB/T 32918.5
func SM2GenerateKey() SM2KeyResult {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return SM2KeyResult{Error: "生成SM2密钥失败: " + err.Error()}
	}

	// ✅ Marshal private key (SEC1/PKCS8 with OID 1.2.156.10197.1.301)
	privDER, err := smx509.MarshalSM2PrivateKey(priv)
	if err != nil {
		return SM2KeyResult{Error: "序列化SM2私钥失败: " + err.Error()}
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: privDER})

	// ✅ Marshal public key (SubjectPublicKeyInfo per RFC 5480)
	pubDER, err := smx509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return SM2KeyResult{Error: "序列化SM2公钥失败: " + err.Error()}
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return SM2KeyResult{
		Success:    true,
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		PrivHex:    hexUpper(privDER),
		PubHex:     hexUpper(pubDER),
	}
}

// SM2GenerateRawKey generates SM2 key pair with raw values
// Private key: 32 bytes (d), Public key: 64 bytes (X || Y)
func SM2GenerateRawKey() SM2KeyResult {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return SM2KeyResult{Error: "生成SM2密钥失败: " + err.Error()}
	}

	curve := sm2.P256()
	byteLen := (curve.Params().BitSize + 7) / 8

	privRaw := priv.D.Bytes()
	if len(privRaw) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(privRaw):], privRaw)
		privRaw = padded
	}

	xRaw := priv.PublicKey.X.Bytes()
	if len(xRaw) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xRaw):], xRaw)
		xRaw = padded
	}
	yRaw := priv.PublicKey.Y.Bytes()
	if len(yRaw) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(yRaw):], yRaw)
		yRaw = padded
	}

	pubRaw := append(xRaw, yRaw...)

	privDER, _ := smx509.MarshalSM2PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: privDER})
	pubDER, _ := smx509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return SM2KeyResult{
		Success:    true,
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		PrivHex:    hexUpper(privDER),
		PubHex:     hexUpper(pubDER),
		RawPriv:    hexUpper(privRaw),
		RawPub:     hexUpper(pubRaw),
	}
}

// SM2Encrypt encrypts data using SM2 public key (GM/T 0003.4)
// Output: ASN.1 encoded C1||C3||C2 (default, GM/T 0003 Rev.2)
func SM2Encrypt(req SM2Request) symmetric.CryptoResult {
	sm2Pub, err := parseSM2PublicKey(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	// EncryptASN1 默认输出 ASN.1 封装的 C1||C3||C2 (GM/T 0003 最新规范)
	ct, err := sm2.EncryptASN1(rand.Reader, sm2Pub, dataBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM2加密失败，请检查公钥或数据"}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(ct)}
}

// SM2Decrypt decrypts SM2 ciphertext using private key (GM/T 0003.4)
func SM2Decrypt(req SM2Request) symmetric.CryptoResult {
	priv, err := parseSM2PrivateKey(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	// gmsm v0.27.2 中没有包级的 DecryptASN1，推荐使用 sm2.Decrypt，
	// 默认支持解析 ASN.1 格式密文并按 C1C3C2 进行处理。
	pt, err := sm2.Decrypt(priv, dataBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM2解密失败，请检查私钥或密文"}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}
}

// SM2Sign signs data using SM2 private key (GM/T 0003.2)
// Implements ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
// then e = H256(ZA || M), signs e
func SM2Sign(req SM2SignRequest) symmetric.CryptoResult {
	priv, err := parseSM2PrivateKey(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}

	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex)"}
	}

	uid := req.ID
	if uid == "" {
		uid = "1234567812345678" // GM/T 0009-2012 推荐默认ID
	}

	// SignWithSM2: 内部完成 ZA 计算 + SM3 摘要 + ECDSA签名
	// 符合 GM/T 0003.2-2012 §6
	sig, err := priv.SignWithSM2(rand.Reader, []byte(uid), dataBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM2签名失败，请检查私钥或数据"}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

// SM2Verify verifies an SM2 signature (GM/T 0003.2)
func SM2Verify(req SM2VerifyRequest) symmetric.CryptoResult {
	sm2Pub, err := parseSM2PublicKey(req.PublicKey)
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

	uid := req.ID
	if uid == "" {
		uid = "1234567812345678"
	}

	valid := sm2.VerifyASN1WithSM2(sm2Pub, []byte(uid), dataBytes, sigBytes)
	if !valid {
		return symmetric.CryptoResult{
			Success: true,
			Data:    "false",
			Error:   "SM2签名验证失败",
		}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// SM2KeyAgreement: GM/T 0003.3 密钥协商协议说明
// 完整协议需要双方交互，此处提供协议流程展示
func SM2KeyAgreement(req SM2KeyAgreementRequest) symmetric.CryptoResult {
	return symmetric.CryptoResult{
		Success: true,
		Data: "GM/T 0003.3 SM2密钥协商协议流程:\n" +
			"1. 发起方A 生成临时密钥对 (rA, RA=rA*G)\n" +
			"2. A 发送 RA 给 响应方B\n" +
			"3. B 生成临时密钥对 (rB, RB=rB*G)\n" +
			"4. B 计算共享密钥: KB = KDF(x||y||ZA||ZB)\n" +
			"   其中 (x,y) = h*(rB+w*tB)*( RA + w*TA )\n" +
			"5. B 发送 RB 及可选确认值 SB 给 A\n" +
			"6. A 用 RA,RB,tA 计算相同的共享密钥\n" +
			"gmsm库支持: sm2.NewKeyExchange() 实现完整流程",
		Error: "",
	}
}

// ============================================================
// SM3  (GM/T 0004-2012)
// ============================================================

type SM3Request struct {
	Data string `json:"data"` // hex
}

type SM3WithIDRequest struct {
	ID        string `json:"id"`        // user ID, default "1234567812345678"
	PublicKey string `json:"publicKey"` // SM2 public key (PEM/Hex)
	Data      string `json:"data"`      // hex (raw message)
}

type SM3HMACRequest struct {
	Key  string `json:"key"`  // hex
	Data string `json:"data"` // hex
}

// SM3Hash computes SM3 hash (GM/T 0004)
// Standard test vector: SM3("abc") = 66c7f0f4...
func SM3Hash(req SM3Request) symmetric.CryptoResult {
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	h := sm3.New()
	h.Write(dataBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
}

// SM3HashWithID computes SM3 hash with ID and public key (GM/T 0003.2)
// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
// e = H256(ZA || M)
func SM3HashWithID(req SM3WithIDRequest) symmetric.CryptoResult {
	sm2Pub, err := parseSM2PublicKey(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "公钥解析失败: " + err.Error()}
	}

	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据(需要Hex): " + err.Error()}
	}

	uid := req.ID
	if uid == "" {
		uid = "1234567812345678"
	}

	hashVal, err := sm2.CalculateSM2Hash(sm2Pub, dataBytes, []byte(uid))
	if err != nil {
		return symmetric.CryptoResult{Error: "SM3(WithID)计算失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(hashVal)}
}

// SM3HMAC computes HMAC-SM3
func SM3HMAC(req SM3HMACRequest) symmetric.CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	h := hmac.New(sm3.New, keyBytes)
	h.Write(dataBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
}

// ============================================================
// SM4  (GM/T 0002-2012 / GB/T 32907-2016)
// ============================================================

type SM4Request struct {
	Key     string `json:"key"`     // hex 16 bytes
	IV      string `json:"iv"`      // hex 16 bytes
	Nonce   string `json:"nonce"`   // hex 12 bytes for GCM
	AAD     string `json:"aad"`     // hex, additional authenticated data
	Data    string `json:"data"`    // hex
	Mode    string `json:"mode"`    // ECB CBC CFB OFB CTR GCM
	Padding string `json:"padding"` // PKCS7 Zero NoPadding
}

// SM4Encrypt encrypts using SM4 block cipher (GM/T 0002)
// Standard test vector:
//
//	Key:        0123456789ABCDEFFEDCBA9876543210
//	Plaintext:  0123456789ABCDEFFEDCBA9876543210
//	ECB Result: 681EDF34D206965E86B3E94F536E4246
func SM4Encrypt(req SM4Request) symmetric.CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil || len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须是128位(16字节 / 32位hex)"}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	// ✅ 使用 sm4.NewCipher 获取 cipher.Block，然后套标准模式
	block, err := sm4.NewCipher(keyBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}

	switch req.Mode {
	case "ECB":
		result, err := sm4ECBEncrypt(block, dataBytes, req.Padding)
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(result)}

	case "CBC":
		ivBytes, err := getOrGenBytes(req.IV, sm4.BlockSize)
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		padded := applyPadding(dataBytes, sm4.BlockSize, req.Padding)
		if len(padded) == 0 || len(padded)%sm4.BlockSize != 0 {
			return symmetric.CryptoResult{Error: "CBC模式: 明文填充后长度必须是16字节的倍数(可改用PKCS7/Zero填充)"}
		}
		ct := make([]byte, len(padded))
		// ✅ 标准 cipher.NewCBCEncrypter 适用于任何 cipher.Block
		cipher.NewCBCEncrypter(block, ivBytes).CryptBlocks(ct, padded)
		// CBC模式：加密后IV变为最后一个密文块
		newIV := ct[len(ct)-sm4.BlockSize:]
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(ct),
			Extra:   hexUpper(newIV),
		}

	case "CFB":
		ivBytes, err := getOrGenBytes(req.IV, sm4.BlockSize)
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		ct := make([]byte, len(dataBytes))
		cipher.NewCFBEncrypter(block, ivBytes).XORKeyStream(ct, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ct), Extra: hexUpper(ivBytes)}

	case "OFB":
		ivBytes, err := getOrGenBytes(req.IV, sm4.BlockSize)
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		ct := make([]byte, len(dataBytes))
		cipher.NewOFB(block, ivBytes).XORKeyStream(ct, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ct), Extra: hexUpper(ivBytes)}

	case "CTR":
		ivBytes, err := getOrGenBytes(req.IV, sm4.BlockSize)
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		ct := make([]byte, len(dataBytes))
		stream := cipher.NewCTR(block, ivBytes)
		stream.XORKeyStream(ct, dataBytes)
		// CTR模式：计算加密后的计数器值
		blocks := (len(dataBytes) + sm4.BlockSize - 1) / sm4.BlockSize
		newIV := make([]byte, len(ivBytes))
		copy(newIV, ivBytes)
		for i := 0; i < blocks; i++ {
			for j := len(newIV) - 1; j >= 0; j-- {
				newIV[j]++
				if newIV[j] != 0 {
					break
				}
			}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(ct), Extra: hexUpper(newIV)}

	case "GCM":
		// ✅ SM4-GCM: cipher.NewGCM 对任何 128位 block cipher 有效
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return symmetric.CryptoResult{Error: "SM4-GCM init失败: " + err.Error()}
		}
		nonceBytes, err := getOrGenBytes(req.Nonce, gcm.NonceSize())
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		var aad []byte
		if req.AAD != "" {
			var err error
			aad, err = hex.DecodeString(req.AAD)
			if err != nil {
				return symmetric.CryptoResult{Error: "无效的AAD: " + err.Error()}
			}
		}
		ct := gcm.Seal(nil, nonceBytes, dataBytes, aad)
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(ct),
			Extra:   hexUpper(nonceBytes),
		}

	default:
		return symmetric.CryptoResult{Error: "SM4不支持的模式: " + req.Mode + " (支持: ECB CBC CFB OFB CTR GCM)"}
	}
}

// SM4Decrypt decrypts SM4 ciphertext (GM/T 0002)
func SM4Decrypt(req SM4Request) symmetric.CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil || len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须是128位(16字节)"}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	block, err := sm4.NewCipher(keyBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}

	switch req.Mode {
	case "ECB":
		result, err := sm4ECBDecrypt(block, dataBytes, req.Padding)
		if err != nil {
			return symmetric.CryptoResult{Error: err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(result)}

	case "CBC":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil || len(ivBytes) != sm4.BlockSize {
			return symmetric.CryptoResult{Error: "CBC模式需要16字节IV"}
		}
		if len(dataBytes) == 0 || len(dataBytes)%sm4.BlockSize != 0 {
			return symmetric.CryptoResult{Error: "CBC解密: 密文长度必须是16字节的倍数"}
		}
		pt := make([]byte, len(dataBytes))
		cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(pt, dataBytes)
		pt = removePadding(pt, req.Padding)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}

	case "CFB":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return symmetric.CryptoResult{Error: "CFB需要IV: " + err.Error()}
		}
		if len(ivBytes) != sm4.BlockSize {
			return symmetric.CryptoResult{Error: "CFB需要16字节IV"}
		}
		pt := make([]byte, len(dataBytes))
		cipher.NewCFBDecrypter(block, ivBytes).XORKeyStream(pt, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}

	case "OFB":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return symmetric.CryptoResult{Error: "OFB需要IV: " + err.Error()}
		}
		if len(ivBytes) != sm4.BlockSize {
			return symmetric.CryptoResult{Error: "OFB需要16字节IV"}
		}
		pt := make([]byte, len(dataBytes))
		cipher.NewOFB(block, ivBytes).XORKeyStream(pt, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}

	case "CTR":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return symmetric.CryptoResult{Error: "CTR需要IV: " + err.Error()}
		}
		if len(ivBytes) != sm4.BlockSize {
			return symmetric.CryptoResult{Error: "CTR需要16字节IV"}
		}
		pt := make([]byte, len(dataBytes))
		cipher.NewCTR(block, ivBytes).XORKeyStream(pt, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}

	case "GCM":
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return symmetric.CryptoResult{Error: "SM4-GCM init失败: " + err.Error()}
		}
		nonceBytes, err := hex.DecodeString(req.Nonce)
		if err != nil || len(nonceBytes) != gcm.NonceSize() {
			return symmetric.CryptoResult{Error: "GCM需要12字节Nonce"}
		}
		var aad []byte
		if req.AAD != "" {
			var err error
			aad, err = hex.DecodeString(req.AAD)
			if err != nil {
				return symmetric.CryptoResult{Error: "无效的AAD: " + err.Error()}
			}
		}
		pt, err := gcm.Open(nil, nonceBytes, dataBytes, aad)
		if err != nil {
			return symmetric.CryptoResult{Error: "SM4-GCM解密失败(认证错误): " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}

	default:
		return symmetric.CryptoResult{Error: "SM4不支持的模式: " + req.Mode}
	}
}

// ============================================================
// SM9  (GM/T 0044-2016)
// ============================================================

type SM9KeyResult struct {
	Success    bool   `json:"success"`
	PrivateKey string `json:"privateKey"` // hex
	PublicKey  string `json:"publicKey"`  // hex
	Error      string `json:"error"`
}

type SM9MasterKeyResult struct {
	Success          bool   `json:"success"`
	MasterPrivateKey string `json:"masterPrivateKey"` // hex
	MasterPublicKey  string `json:"masterPublicKey"`  // hex
	Error            string `json:"error"`
}

type SM9Request struct {
	MasterPublicKey string `json:"masterPublicKey"` // hex
	UserPrivateKey  string `json:"userPrivateKey"`  // hex
	UID             string `json:"uid"`
	Data            string `json:"data"` // hex
}

type SM9SignRequest struct {
	UserPrivateKey string `json:"userPrivateKey"` // hex
	Data           string `json:"data"`           // hex
}

type SM9VerifyRequest struct {
	MasterPublicKey string `json:"masterPublicKey"` // hex
	UID             string `json:"uid"`
	Data            string `json:"data"`      // hex
	Signature       string `json:"signature"` // hex
}

// SM9GenerateMasterKey generates SM9 signature master key pair (GM/T 0044.1)
func SM9GenerateMasterKey() SM9MasterKeyResult {
	masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		return SM9MasterKeyResult{Error: "生成SM9签名主密钥失败: " + err.Error()}
	}
	privBytes, err := masterKey.MarshalASN1()
	if err != nil {
		return SM9MasterKeyResult{Error: "序列化SM9主私钥失败: " + err.Error()}
	}
	pubBytes, err := masterKey.PublicKey().MarshalASN1()
	if err != nil {
		return SM9MasterKeyResult{Error: "序列化SM9主公钥失败: " + err.Error()}
	}
	return SM9MasterKeyResult{
		Success:          true,
		MasterPrivateKey: hexUpper(privBytes),
		MasterPublicKey:  hexUpper(pubBytes),
	}
}

// SM9GenerateEncMasterKey generates SM9 encryption master key pair (GM/T 0044.1)
func SM9GenerateEncMasterKey() SM9MasterKeyResult {
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		return SM9MasterKeyResult{Error: "生成SM9加密主密钥失败: " + err.Error()}
	}
	privBytes, err := masterKey.MarshalASN1()
	if err != nil {
		return SM9MasterKeyResult{Error: "序列化SM9加密主私钥失败: " + err.Error()}
	}
	pubBytes, err := masterKey.PublicKey().MarshalASN1()
	if err != nil {
		return SM9MasterKeyResult{Error: "序列化SM9加密主公钥失败: " + err.Error()}
	}
	return SM9MasterKeyResult{
		Success:          true,
		MasterPrivateKey: hexUpper(privBytes),
		MasterPublicKey:  hexUpper(pubBytes),
	}
}

// SM9GenerateEncKey generates SM9 encryption user key pair
func SM9GenerateEncKey(masterPrivHex string, uid string) SM9KeyResult {
	masterPrivBytes, err := hex.DecodeString(masterPrivHex)
	if err != nil {
		return SM9KeyResult{Error: "无效的主私钥: " + err.Error()}
	}
	masterKey, err := sm9.UnmarshalEncryptMasterPrivateKeyASN1(masterPrivBytes)
	if err != nil {
		return SM9KeyResult{Error: "解析SM9加密主私钥失败: " + err.Error()}
	}
	// 根据 gmsm 最新 API，GenerateUserKey 接收 (uid []byte, hid byte)
	const hidEncrypt byte = 0x02
	userKey, err := masterKey.GenerateUserKey([]byte(uid), hidEncrypt)
	if err != nil {
		return SM9KeyResult{Error: "生成SM9用户加密密钥失败: " + err.Error()}
	}
	privBytes, err := userKey.MarshalASN1()
	if err != nil {
		return SM9KeyResult{Error: "序列化用户密钥失败: " + err.Error()}
	}
	pubBytes, err := masterKey.PublicKey().MarshalASN1()
	if err != nil {
		return SM9KeyResult{Error: "序列化主公钥失败: " + err.Error()}
	}
	return SM9KeyResult{
		Success:    true,
		PrivateKey: hexUpper(privBytes),
		PublicKey:  hexUpper(pubBytes),
	}
}

// SM9Encrypt encrypts data using SM9 (GM/T 0044.4)
func SM9Encrypt(req SM9Request) symmetric.CryptoResult {
	pubBytes, err := hex.DecodeString(req.MasterPublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的主公钥: " + err.Error()}
	}
	masterPub, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(pubBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "解析SM9加密主公钥失败: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	// EncryptASN1 使用 SM4-CBC + SM3 KDF，hid=0x02 为加密标识
	const hidEncrypt byte = 0x02
	ct, err := sm9.EncryptASN1(rand.Reader, masterPub, []byte(req.UID), hidEncrypt, dataBytes, nil)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM9加密失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(ct)}
}

// SM9Decrypt decrypts SM9 ciphertext (GM/T 0044.4)
func SM9Decrypt(req SM9Request) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.UserPrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的用户私钥: " + err.Error()}
	}
	userPriv, err := sm9.UnmarshalEncryptPrivateKeyASN1(privBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "解析SM9用户私钥失败: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	pt, err := sm9.DecryptASN1(userPriv, []byte(req.UID), dataBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM9解密失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}
}

// SM9Sign signs data using SM9 user signing key (GM/T 0044.2)
func SM9Sign(req SM9SignRequest) symmetric.CryptoResult {
	privBytes, err := hex.DecodeString(req.UserPrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的用户私钥: " + err.Error()}
	}
	userPriv, err := sm9.UnmarshalSignPrivateKeyASN1(privBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "解析SM9签名私钥失败: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	// 直接使用 ASN.1 编码签名接口，避免手动处理 (h,s) 对
	sigBytes, err := sm9.SignASN1(rand.Reader, userPriv, dataBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "序列化签名失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sigBytes)}
}

// SM9Verify verifies an SM9 signature (GM/T 0044.2)
func SM9Verify(req SM9VerifyRequest) symmetric.CryptoResult {
	pubBytes, err := hex.DecodeString(req.MasterPublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的主公钥: " + err.Error()}
	}
	masterPub, err := sm9.UnmarshalSignMasterPublicKeyASN1(pubBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "解析SM9签名主公钥失败: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的签名: " + err.Error()}
	}
	// 使用 VerifyASN1 / Verify，hid=0x01 为签名标识
	const hidSign byte = 0x01
	valid := sm9.VerifyASN1(masterPub, []byte(req.UID), hidSign, dataBytes, sigBytes)
	if !valid {
		return symmetric.CryptoResult{Success: false, Data: "false", Error: "SM9签名验证失败"}
	}
	return symmetric.CryptoResult{Success: true, Data: "true"}
}

// ============================================================
// ZUC (祖冲之序列密码) — GM/T 0001-2012
// ============================================================

type ZUCRequest struct {
	Key  string `json:"key"`  // hex: ZUC-128=16B, ZUC-256=32B
	IV   string `json:"iv"`   // hex: ZUC-128=16B, ZUC-256=25B
	Data string `json:"data"` // hex
	Type string `json:"type"` // ZUC-128 or ZUC-256
}

// ============================================================
// 数字信封 (GM/T 0010-2012) - 基于 SM2 + SM4 的简单实现
// ============================================================

type GMEnvelopeRequest struct {
	SenderPriv  string `json:"senderPriv"`  // 发送方 SM2 私钥 (PEM/Hex)，用于签名
	ReceiverPub string `json:"receiverPub"` // 接收方 SM2 公钥 (PEM/Hex)，用于加密
	Data        string `json:"data"`        // 待封装数据 (Hex，明文)
}

type GMEnvelopeOpenRequest struct {
	ReceiverPriv string `json:"receiverPriv"` // 接收方 SM2 私钥 (PEM/Hex)，用于解密
	SenderPub    string `json:"senderPub"`    // 发送方 SM2 公钥 (PEM/Hex)，用于验签
	EnvelopeData string `json:"envelopeData"` // 信封数据 (Hex)，内部为 JSON
}

type gmEnvelopePayload struct {
	Ciphertext string `json:"ciphertext"` // SM2 加密后的密文 (Hex)
	Signature  string `json:"signature"`  // SM2 签名 (Hex, ASN.1 DER)
}

// ZUCEncrypt encrypts/decrypts using ZUC stream cipher (GM/T 0001)
// ZUC is a stream cipher: encrypt = decrypt (XOR with keystream)
func ZUCEncrypt(req ZUCRequest) symmetric.CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	ivBytes, err := hex.DecodeString(req.IV)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的IV: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	// ✅ zuc.NewCipher 支持 ZUC-128 (key=16B, iv=16B) 和 ZUC-256 (key=32B, iv=25B)
	stream, err := zuc.NewCipher(keyBytes, ivBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "ZUC初始化失败 (检查Key/IV长度): " + err.Error()}
	}

	ct := make([]byte, len(dataBytes))
	stream.XORKeyStream(ct, dataBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(ct)}
}

// ZUCDecrypt is identical to ZUCEncrypt (stream cipher property)
func ZUCDecrypt(req ZUCRequest) symmetric.CryptoResult {
	return ZUCEncrypt(req)
}

// MakeGMEnvelope 生成数字信封:
// 1. 使用接收方公钥对明文做 SM2 加密
// 2. 使用发送方私钥对明文做 SM2 签名
// 3. 将 {ciphertext, signature} JSON 后再 Hex 编码作为信封数据
func MakeGMEnvelope(req GMEnvelopeRequest) symmetric.CryptoResult {
	// 1) 加密
	encRes := SM2Encrypt(SM2Request{
		Key:  req.ReceiverPub,
		Data: req.Data,
	})
	if !encRes.Success {
		if encRes.Error == "" {
			encRes.Error = "SM2 加密失败"
		}
		return encRes
	}

	// 2) 签名
	sigRes := SM2Sign(SM2SignRequest{
		PrivateKey: req.SenderPriv,
		Data:       req.Data,
	})
	if !sigRes.Success {
		if sigRes.Error == "" {
			sigRes.Error = "SM2 签名失败"
		}
		return sigRes
	}

	payload := gmEnvelopePayload{
		Ciphertext: encRes.Data,
		Signature:  sigRes.Data,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return symmetric.CryptoResult{Error: "编码信封数据失败: " + err.Error()}
	}
	return symmetric.CryptoResult{
		Success: true,
		Data:    hexUpper(b),
	}
}

// OpenGMEnvelope 拆解数字信封:
// 1. 解码 Hex -> JSON 得到密文与签名
// 2. 使用接收方私钥解密出明文
// 3. 使用发送方公钥验证签名
func OpenGMEnvelope(req GMEnvelopeOpenRequest) symmetric.CryptoResult {
	envBytes, err := hex.DecodeString(req.EnvelopeData)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的信封数据(需要Hex)"}
	}
	var payload gmEnvelopePayload
	if err := json.Unmarshal(envBytes, &payload); err != nil {
		return symmetric.CryptoResult{Error: "信封数据解析失败"}
	}

	// 1) 解密
	decRes := SM2Decrypt(SM2Request{
		Key:  req.ReceiverPriv,
		Data: payload.Ciphertext,
	})
	if !decRes.Success {
		if decRes.Error == "" {
			decRes.Error = "SM2 解密失败"
		}
		return decRes
	}

	// 2) 验签
	verifyRes := SM2Verify(SM2VerifyRequest{
		PublicKey: req.SenderPub,
		Data:      decRes.Data,
		Signature: payload.Signature,
	})
	if !verifyRes.Success || verifyRes.Data != "true" {
		if verifyRes.Error == "" {
			verifyRes.Error = "SM2 签名验证失败"
		}
		return verifyRes
	}

	return symmetric.CryptoResult{
		Success: true,
		Data:    decRes.Data,
	}
}

// ============================================================
// Internal helpers
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

func parseSM2PrivateKey(input string) (*sm2.PrivateKey, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("私钥不能为空")
	}
	if isPEMKey(input) {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("无效的PEM私钥")
		}
		priv, err := smx509.ParseSM2PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败，请检查格式")
		}
		return priv, nil
	}
	b, err := decodeHexKey(input)
	if err != nil {
		return nil, err
	}
	if priv, err := smx509.ParseSM2PrivateKey(b); err == nil {
		return priv, nil
	}
	if priv, err := sm2.NewPrivateKey(b); err == nil {
		return priv, nil
	}
	d := new(big.Int).SetBytes(b)
	if d.Sign() == 0 {
		return nil, fmt.Errorf("私钥无效")
	}
	if priv, err := sm2.NewPrivateKeyFromInt(d); err == nil {
		return priv, nil
	}
	return nil, fmt.Errorf("私钥解析失败，请检查格式")
}

func parseSM2PublicKey(input string) (*ecdsa.PublicKey, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("公钥不能为空")
	}
	if isPEMKey(input) {
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return nil, fmt.Errorf("无效的PEM公钥")
		}
		pubIface, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("公钥解析失败，请检查格式")
		}
		pub, ok := pubIface.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("公钥类型不匹配")
		}
		return pub, nil
	}
	b, err := decodeHexKey(input)
	if err != nil {
		return nil, err
	}
	if pubIface, err := smx509.ParsePKIXPublicKey(b); err == nil {
		if pub, ok := pubIface.(*ecdsa.PublicKey); ok {
			return pub, nil
		}
	}
	if pub, err := sm2.NewPublicKey(b); err == nil {
		return pub, nil
	}
	curve := sm2.P256()
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(b) == 1+2*byteLen && b[0] == 0x04 {
		x, y := elliptic.Unmarshal(curve, b)
		if x != nil && y != nil {
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
		}
	}
	if len(b) == 2*byteLen {
		x := new(big.Int).SetBytes(b[:byteLen])
		y := new(big.Int).SetBytes(b[byteLen:])
		if x.Sign() > 0 && y.Sign() > 0 {
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
		}
	}
	return nil, fmt.Errorf("公钥解析失败，请检查格式")
}

func getOrGenBytes(hexStr string, size int) ([]byte, error) {
	if hexStr != "" {
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("无效的参数: %v", err)
		}
		if len(b) != size {
			return nil, fmt.Errorf("长度错误: 需要%d字节, 实际%d字节", size, len(b))
		}
		return b, nil
	}
	b := make([]byte, size)
	rand.Read(b)
	return b, nil
}

func sm4ECBEncrypt(block cipher.Block, data []byte, padding string) ([]byte, error) {
	bs := block.BlockSize()
	padded := applyPadding(data, bs, padding)
	if len(padded)%bs != 0 {
		return nil, fmt.Errorf("数据填充后长度 %d 不是块大小 %d 的倍数", len(padded), bs)
	}
	ct := make([]byte, len(padded))
	for i := 0; i < len(padded); i += bs {
		block.Encrypt(ct[i:i+bs], padded[i:i+bs])
	}
	return ct, nil
}

func sm4ECBDecrypt(block cipher.Block, data []byte, padding string) ([]byte, error) {
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, fmt.Errorf("密文长度 %d 不是块大小 %d 的倍数", len(data), bs)
	}
	pt := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(pt[i:i+bs], data[i:i+bs])
	}
	return removePadding(pt, padding), nil
}

func applyPadding(data []byte, blockSize int, padding string) []byte {
	switch padding {
	case "PKCS7", "PKCS5":
		padLen := blockSize - len(data)%blockSize
		padded := make([]byte, len(data)+padLen)
		copy(padded, data)
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(padLen)
		}
		return padded
	case "Zero":
		if len(data)%blockSize == 0 {
			return data
		}
		padLen := blockSize - len(data)%blockSize
		return append(data, make([]byte, padLen)...)
	default:
		return data
	}
}

func removePadding(data []byte, padding string) []byte {
	if len(data) == 0 {
		return data
	}
	switch padding {
	case "PKCS7", "PKCS5":
		padLen := int(data[len(data)-1])
		if padLen > 0 && padLen <= 16 && padLen <= len(data) {
			return data[:len(data)-padLen]
		}
	case "Zero":
		i := len(data) - 1
		for i >= 0 && data[i] == 0 {
			i--
		}
		return data[:i+1]
	}
	return data
}
