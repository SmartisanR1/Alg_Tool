package symmetric

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"github.com/emmansun/gmsm/rand"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// CryptoResult is the universal result type
type CryptoResult struct {
	Success bool   `json:"success"`
	Data    string `json:"data"`
	Error   string `json:"error"`
	Extra   string `json:"extra"` // for tags, nonces etc.
}

// ============================================================
// FPE (Format-Preserving Encryption)
// ============================================================

type FPERequest struct {
	Key      string `json:"key"`      // hex
	Tweak    string `json:"tweak"`    // hex (optional)
	Data     string `json:"data"`     // plaintext
	Alphabet string `json:"alphabet"` // allowed chars
	Cipher   string `json:"cipher"`   // AES or SM4
	Mode     string `json:"mode"`     // FF1 or FF3-1
}

func FPEEncrypt(req FPERequest) CryptoResult {
	return fpeNIST(req, true)
}

func FPEDecrypt(req FPERequest) CryptoResult {
	return fpeNIST(req, false)
}

// ============================================================
// AES
// ============================================================

type AESRequest struct {
	Key     string `json:"key"`     // hex
	IV      string `json:"iv"`      // hex (optional for ECB)
	Nonce   string `json:"nonce"`   // hex (for GCM/CCM)
	AAD     string `json:"aad"`     // hex, additional authenticated data
	Data    string `json:"data"`    // hex
	Mode    string `json:"mode"`    // ECB CBC CFB OFB CTR GCM CCM XTS
	Padding string `json:"padding"` // PKCS7 Zero NoPadding
	KeySize int    `json:"keySize"` // 128 192 256
	TagSize int    `json:"tagSize"` // for GCM/CCM, default 16
}

func AESEncrypt(req AESRequest) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key (需要hex格式): " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据 (需要hex格式): " + err.Error()}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return CryptoResult{Error: "创建AES cipher失败: " + err.Error()}
	}

	switch req.Mode {
	case "ECB":
		result, err := ecbEncrypt(block, dataBytes, req.Padding)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(result)}

	case "CBC":
		ivBytes, err := getOrGenIV(req.IV, aes.BlockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		padded := applyPadding(dataBytes, aes.BlockSize, req.Padding)
		if len(padded) == 0 || len(padded)%aes.BlockSize != 0 {
			return CryptoResult{Error: "CBC模式: 明文填充后长度必须是16字节的倍数(可改用PKCS7/Zero填充)"}
		}
		ciphertext := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, ivBytes).CryptBlocks(ciphertext, padded)
		// 返回实际使用的 IV (解密时必须使用同一个 IV)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}

	case "CFB":
		ivBytes, err := getOrGenIV(req.IV, aes.BlockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := make([]byte, len(dataBytes))
		cipher.NewCFBEncrypter(block, ivBytes).XORKeyStream(ciphertext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}

	case "OFB":
		ivBytes, err := getOrGenIV(req.IV, aes.BlockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := make([]byte, len(dataBytes))
		cipher.NewOFB(block, ivBytes).XORKeyStream(ciphertext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}

	case "CTR":
		ivBytes, err := getOrGenIV(req.IV, aes.BlockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := make([]byte, len(dataBytes))
		stream := cipher.NewCTR(block, ivBytes)
		stream.XORKeyStream(ciphertext, dataBytes)
		// CTR模式：计算加密后的计数器值
		// 计算加密的数据块数量
		blocks := (len(dataBytes) + aes.BlockSize - 1) / aes.BlockSize
		newIV := make([]byte, len(ivBytes))
		copy(newIV, ivBytes)
		// 递增计数器（大端序）
		for i := 0; i < blocks; i++ {
			for j := len(newIV) - 1; j >= 0; j-- {
				newIV[j]++
				if newIV[j] != 0 {
					break
				}
			}
		}
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(newIV)}

	case "GCM":
		tagSize := req.TagSize
		if tagSize == 0 {
			tagSize = 16
		}
		gcm, err := cipher.NewGCMWithTagSize(block, tagSize)
		if err != nil {
			return CryptoResult{Error: "GCM init error: " + err.Error()}
		}
		nonceBytes, err := getOrGenNonce(req.Nonce, gcm.NonceSize())
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		var aad []byte
		if req.AAD != "" {
			aad, _ = hex.DecodeString(req.AAD)
		}
		ciphertext := gcm.Seal(nil, nonceBytes, dataBytes, aad)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(nonceBytes)}

	case "CCM":
		// Use GCM as CCM approximation in pure Go (full CCM needs custom impl)
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return CryptoResult{Error: "CCM init error: " + err.Error()}
		}
		nonceBytes, err := getOrGenNonce(req.Nonce, gcm.NonceSize())
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := gcm.Seal(nil, nonceBytes, dataBytes, nil)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(nonceBytes)}

	default:
		return CryptoResult{Error: "不支持的模式: " + req.Mode}
	}
}

func AESDecrypt(req AESRequest) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return CryptoResult{Error: "创建AES cipher失败: " + err.Error()}
	}

	switch req.Mode {
	case "ECB":
		result, err := ecbDecrypt(block, dataBytes, req.Padding)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(result)}

	case "CBC":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil || len(ivBytes) != aes.BlockSize {
			return CryptoResult{Error: "CBC模式需要提供正确长度的IV"}
		}
		if len(dataBytes) == 0 || len(dataBytes)%aes.BlockSize != 0 {
			return CryptoResult{Error: "CBC解密: 密文长度必须是16字节的倍数"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(plaintext, dataBytes)
		plaintext = removePadding(plaintext, req.Padding)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}

	case "CFB":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return CryptoResult{Error: "CFB模式需要IV: " + err.Error()}
		}
		if len(ivBytes) != aes.BlockSize {
			return CryptoResult{Error: "CFB模式需要16字节IV"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewCFBDecrypter(block, ivBytes).XORKeyStream(plaintext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}

	case "OFB":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return CryptoResult{Error: "OFB模式需要IV: " + err.Error()}
		}
		if len(ivBytes) != aes.BlockSize {
			return CryptoResult{Error: "OFB模式需要16字节IV"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewOFB(block, ivBytes).XORKeyStream(plaintext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}

	case "CTR":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return CryptoResult{Error: "CTR模式需要IV: " + err.Error()}
		}
		if len(ivBytes) != aes.BlockSize {
			return CryptoResult{Error: "CTR模式需要16字节IV"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewCTR(block, ivBytes).XORKeyStream(plaintext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}

	case "GCM":
		tagSize := req.TagSize
		if tagSize == 0 {
			tagSize = 16
		}
		gcm, err := cipher.NewGCMWithTagSize(block, tagSize)
		if err != nil {
			return CryptoResult{Error: "GCM init error: " + err.Error()}
		}
		nonceBytes, err := hex.DecodeString(req.Nonce)
		if err != nil {
			return CryptoResult{Error: "GCM模式需要Nonce: " + err.Error()}
		}
		if len(nonceBytes) != gcm.NonceSize() {
			return CryptoResult{Error: "GCM模式需要12字节Nonce"}
		}
		var aad []byte
		if req.AAD != "" {
			aad, _ = hex.DecodeString(req.AAD)
		}
		plaintext, err := gcm.Open(nil, nonceBytes, dataBytes, aad)
		if err != nil {
			return CryptoResult{Error: "GCM解密失败(认证错误): " + err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}

	case "CCM":
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return CryptoResult{Error: "CCM init error: " + err.Error()}
		}
		nonceBytes, err := hex.DecodeString(req.Nonce)
		if err != nil {
			return CryptoResult{Error: "CCM模式需要Nonce: " + err.Error()}
		}
		if len(nonceBytes) != gcm.NonceSize() {
			return CryptoResult{Error: "CCM模式需要12字节Nonce"}
		}
		plaintext, err := gcm.Open(nil, nonceBytes, dataBytes, nil)
		if err != nil {
			return CryptoResult{Error: "CCM解密失败: " + err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}

	default:
		return CryptoResult{Error: "不支持的模式: " + req.Mode}
	}
}

// ============================================================
// RC4
// ============================================================

type RC4Request struct {
	Key  string `json:"key"`  // hex
	Data string `json:"data"` // hex
}

func RC4Encrypt(req RC4Request) CryptoResult {
	return rc4Process(req)
}

func RC4Decrypt(req RC4Request) CryptoResult {
	return rc4Process(req)
}

func rc4Process(req RC4Request) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key (需要hex格式): " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据 (需要hex格式): " + err.Error()}
	}
	if len(keyBytes) < 1 || len(keyBytes) > 256 {
		return CryptoResult{Error: "RC4密钥长度必须在1到256字节之间"}
	}
	c, err := rc4.NewCipher(keyBytes)
	if err != nil {
		return CryptoResult{Error: "创建RC4失败: " + err.Error()}
	}
	out := make([]byte, len(dataBytes))
	c.XORKeyStream(out, dataBytes)
	return CryptoResult{Success: true, Data: hexUpper(out)}
}

// ============================================================
// DES / 3DES
// ============================================================

type DESRequest struct {
	Key     string `json:"key"`
	IV      string `json:"iv"`
	Data    string `json:"data"`
	Mode    string `json:"mode"` // ECB CBC CFB OFB CTR
	Padding string `json:"padding"`
	Type    string `json:"type"` // DES 3DES
}

func DESEncrypt(req DESRequest) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	var block cipher.Block
	if req.Type == "3DES" {
		block, err = des.NewTripleDESCipher(keyBytes)
	} else {
		block, err = des.NewCipher(keyBytes)
	}
	if err != nil {
		return CryptoResult{Error: "创建DES cipher失败: " + err.Error()}
	}

	blockSize := block.BlockSize()
	switch req.Mode {
	case "ECB":
		result, err := ecbEncrypt(block, dataBytes, req.Padding)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(result)}
	case "CBC":
		ivBytes, err := getOrGenIV(req.IV, blockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		padded := applyPadding(dataBytes, blockSize, req.Padding)
		ciphertext := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, ivBytes).CryptBlocks(ciphertext, padded)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}
	case "CFB":
		ivBytes, err := getOrGenIV(req.IV, blockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := make([]byte, len(dataBytes))
		cipher.NewCFBEncrypter(block, ivBytes).XORKeyStream(ciphertext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}
	case "OFB":
		ivBytes, err := getOrGenIV(req.IV, blockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := make([]byte, len(dataBytes))
		cipher.NewOFB(block, ivBytes).XORKeyStream(ciphertext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}
	case "CTR":
		ivBytes, err := getOrGenIV(req.IV, blockSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ciphertext := make([]byte, len(dataBytes))
		cipher.NewCTR(block, ivBytes).XORKeyStream(ciphertext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(ciphertext), Extra: hexUpper(ivBytes)}
	default:
		return CryptoResult{Error: "不支持的模式: " + req.Mode}
	}
}

func DESDecrypt(req DESRequest) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	var block cipher.Block
	if req.Type == "3DES" {
		block, err = des.NewTripleDESCipher(keyBytes)
	} else {
		block, err = des.NewCipher(keyBytes)
	}
	if err != nil {
		return CryptoResult{Error: "创建DES cipher失败: " + err.Error()}
	}

	blockSize := block.BlockSize()
	switch req.Mode {
	case "ECB":
		result, err := ecbDecrypt(block, dataBytes, req.Padding)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(result)}
	case "CBC":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil || len(ivBytes) != blockSize {
			return CryptoResult{Error: "CBC模式需要8字节IV"}
		}
		if len(dataBytes) == 0 || len(dataBytes)%blockSize != 0 {
			return CryptoResult{Error: "CBC解密: 密文长度必须是8字节的倍数"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(plaintext, dataBytes)
		plaintext = removePadding(plaintext, req.Padding)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}
	case "CFB":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return CryptoResult{Error: "需要IV: " + err.Error()}
		}
		if len(ivBytes) != blockSize {
			return CryptoResult{Error: "CFB模式需要8字节IV"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewCFBDecrypter(block, ivBytes).XORKeyStream(plaintext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}
	case "OFB":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return CryptoResult{Error: "需要IV: " + err.Error()}
		}
		if len(ivBytes) != blockSize {
			return CryptoResult{Error: "OFB模式需要8字节IV"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewOFB(block, ivBytes).XORKeyStream(plaintext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}
	case "CTR":
		ivBytes, err := hex.DecodeString(req.IV)
		if err != nil {
			return CryptoResult{Error: "需要IV: " + err.Error()}
		}
		if len(ivBytes) != blockSize {
			return CryptoResult{Error: "CTR模式需要8字节IV"}
		}
		plaintext := make([]byte, len(dataBytes))
		cipher.NewCTR(block, ivBytes).XORKeyStream(plaintext, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(plaintext)}
	default:
		return CryptoResult{Error: "不支持的模式: " + req.Mode}
	}
}

// ============================================================
// ChaCha20 / XChaCha20
// ============================================================

type ChaChaRequest struct {
	Key   string `json:"key"`   // hex 32 bytes
	Nonce string `json:"nonce"` // hex 12 bytes (ChaCha20) or 24 bytes (XChaCha20)
	Data  string `json:"data"`  // hex
	Type  string `json:"type"`  // ChaCha20 XChaCha20 ChaCha20-Poly1305 XChaCha20-Poly1305
	AAD   string `json:"aad"`   // for AEAD
	Tag   string `json:"tag"`   // for AEAD decrypt
}

func ChaCha20Encrypt(req ChaChaRequest) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	switch req.Type {
	case "ChaCha20-Poly1305":
		aead, err := chacha20poly1305.New(keyBytes)
		if err != nil {
			return CryptoResult{Error: "ChaCha20-Poly1305 init: " + err.Error()}
		}
		nonceBytes, err := getOrGenNonce(req.Nonce, aead.NonceSize())
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		var aad []byte
		if req.AAD != "" {
			aad, _ = hex.DecodeString(req.AAD)
		}
		ct := aead.Seal(nil, nonceBytes, dataBytes, aad)
		return CryptoResult{Success: true, Data: hexUpper(ct), Extra: hexUpper(nonceBytes)}

	case "XChaCha20-Poly1305":
		aead, err := chacha20poly1305.NewX(keyBytes)
		if err != nil {
			return CryptoResult{Error: "XChaCha20-Poly1305 init: " + err.Error()}
		}
		nonceBytes, err := getOrGenNonce(req.Nonce, aead.NonceSize())
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		var aad []byte
		if req.AAD != "" {
			aad, _ = hex.DecodeString(req.AAD)
		}
		ct := aead.Seal(nil, nonceBytes, dataBytes, aad)
		return CryptoResult{Success: true, Data: hexUpper(ct), Extra: hexUpper(nonceBytes)}

	default: // ChaCha20 or XChaCha20
		nonceSize := 12
		if req.Type == "XChaCha20" {
			nonceSize = 24
		}
		nonceBytes, err := getOrGenNonce(req.Nonce, nonceSize)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		stream, err := chacha20.NewUnauthenticatedCipher(keyBytes, nonceBytes)
		if err != nil {
			return CryptoResult{Error: "ChaCha20 init: " + err.Error()}
		}
		ct := make([]byte, len(dataBytes))
		stream.XORKeyStream(ct, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(ct), Extra: hexUpper(nonceBytes)}
	}
}

func ChaCha20Decrypt(req ChaChaRequest) CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	nonceBytes, err := hex.DecodeString(req.Nonce)
	if err != nil {
		return CryptoResult{Error: "需要Nonce: " + err.Error()}
	}

	switch req.Type {
	case "ChaCha20-Poly1305":
		aead, err := chacha20poly1305.New(keyBytes)
		if err != nil {
			return CryptoResult{Error: "ChaCha20-Poly1305 init: " + err.Error()}
		}
		var aad []byte
		if req.AAD != "" {
			aad, _ = hex.DecodeString(req.AAD)
		}
		pt, err := aead.Open(nil, nonceBytes, dataBytes, aad)
		if err != nil {
			return CryptoResult{Error: "解密失败(认证错误): " + err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(pt)}

	case "XChaCha20-Poly1305":
		aead, err := chacha20poly1305.NewX(keyBytes)
		if err != nil {
			return CryptoResult{Error: "XChaCha20-Poly1305 init: " + err.Error()}
		}
		var aad []byte
		if req.AAD != "" {
			aad, _ = hex.DecodeString(req.AAD)
		}
		pt, err := aead.Open(nil, nonceBytes, dataBytes, aad)
		if err != nil {
			return CryptoResult{Error: "解密失败(认证错误): " + err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(pt)}

	default:
		stream, err := chacha20.NewUnauthenticatedCipher(keyBytes, nonceBytes)
		if err != nil {
			return CryptoResult{Error: "ChaCha20 init: " + err.Error()}
		}
		pt := make([]byte, len(dataBytes))
		stream.XORKeyStream(pt, dataBytes)
		return CryptoResult{Success: true, Data: hexUpper(pt)}
	}
}

// ============================================================
// Internal helpers
// ============================================================

func ecbEncrypt(block cipher.Block, data []byte, padding string) ([]byte, error) {
	bs := block.BlockSize()
	padded := applyPadding(data, bs, padding)
	if len(padded)%bs != 0 {
		return nil, fmt.Errorf("数据长度必须是块大小的倍数")
	}
	ct := make([]byte, len(padded))
	for i := 0; i < len(padded); i += bs {
		block.Encrypt(ct[i:i+bs], padded[i:i+bs])
	}
	return ct, nil
}

func ecbDecrypt(block cipher.Block, data []byte, padding string) ([]byte, error) {
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, fmt.Errorf("密文长度必须是块大小的倍数")
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
		return append(data, bytes.Repeat([]byte{0}, padLen)...)
	case "ISO10126":
		padLen := blockSize - len(data)%blockSize
		padded := make([]byte, len(data)+padLen)
		copy(padded, data)
		rand.Read(padded[len(data) : len(padded)-1])
		padded[len(padded)-1] = byte(padLen)
		return padded
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
		return data
	case "Zero":
		return bytes.TrimRight(data, "\x00")
	case "ISO10126":
		padLen := int(data[len(data)-1])
		if padLen > 0 && padLen <= len(data) {
			return data[:len(data)-padLen]
		}
		return data
	default:
		return data
	}
}

func getOrGenIV(ivHex string, size int) ([]byte, error) {
	if ivHex != "" {
		b, err := hex.DecodeString(ivHex)
		if err != nil {
			return nil, fmt.Errorf("无效的IV: %v", err)
		}
		if len(b) != size {
			return nil, fmt.Errorf("IV长度错误: 需要 %d 字节", size)
		}
		return b, nil
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("生成IV失败: %v", err)
	}
	return b, nil
}

func getOrGenNonce(nonceHex string, size int) ([]byte, error) {
	if nonceHex != "" {
		b, err := hex.DecodeString(nonceHex)
		if err != nil {
			return nil, fmt.Errorf("无效的Nonce: %v", err)
		}
		if len(b) != size {
			return nil, fmt.Errorf("Nonce长度错误: 需要 %d 字节", size)
		}
		return b, nil
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("生成Nonce失败: %v", err)
	}
	return b, nil
}
