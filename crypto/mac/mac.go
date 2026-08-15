package mac

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"

	"cryptokit/crypto/symmetric"

	"github.com/emmansun/gmsm/cbcmac"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/poly1305"
)

type MACRequest struct {
	Algorithm string `json:"algorithm"` // CMAC-AES GMAC Poly1305 SipHash-2-4 CBC-MAC-SM4 CBC-MAC-AES
	Key       string `json:"key"`       // hex
	Data      string `json:"data"`      // hex
	IV        string `json:"iv"`        // hex, for GMAC
}

func Compute(req MACRequest) symmetric.CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	switch req.Algorithm {
	case "CMAC-AES":
		result, err := cmacAES(keyBytes, dataBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "CMAC-AES失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(result)}

	case "GMAC":
		nonceHex := req.IV
		if nonceHex == "" {
			nonceHex = hexUpper(make([]byte, 12))
		}
		nonceBytes, err := hex.DecodeString(nonceHex)
		if err != nil {
			return symmetric.CryptoResult{Error: "无效的Nonce: " + err.Error()}
		}
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "GMAC init失败: " + err.Error()}
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return symmetric.CryptoResult{Error: "GMAC GCM init失败: " + err.Error()}
		}
		if len(nonceBytes) != gcm.NonceSize() {
			return symmetric.CryptoResult{Error: fmt.Sprintf("无效的Nonce: GCM nonce必须为 %d 字节(%d位hex)", gcm.NonceSize(), gcm.NonceSize()*2)}
		}
		// GMAC = GCM with empty plaintext, AAD = data
		tag := gcm.Seal(nil, nonceBytes, nil, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(tag)}

	case "Poly1305":
		if len(keyBytes) != 32 {
			return symmetric.CryptoResult{Error: "Poly1305 key需要32字节(64位hex)"}
		}
		var key [32]byte
		copy(key[:], keyBytes)
		var tag [poly1305.TagSize]byte
		poly1305.Sum(&tag, dataBytes, &key)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(tag[:])}

	case "SipHash-2-4":
		if len(keyBytes) < 16 {
			padded := make([]byte, 16)
			copy(padded, keyBytes)
			keyBytes = padded
		}
		result := sipHash24(keyBytes[:16], dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(result)}

	case "CBC-MAC-SM4":
		// GB/T 15821.1-2020 — MAC scheme 1 using SM4
		if len(keyBytes) != 16 {
			return symmetric.CryptoResult{Error: "SM4 密钥必须为 16 字节 (32位hex)"}
		}
		block, err := sm4.NewCipher(keyBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "SM4 cipher 初始化失败: " + err.Error()}
		}
		mac := cbcmac.NewCBCMAC(block, sm4.BlockSize)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(mac.MAC(dataBytes))}

	case "CBC-MAC-AES":
		// GB/T 15821.1-2020 — MAC scheme 1 using AES
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "AES cipher 初始化失败: " + err.Error()}
		}
		mac := cbcmac.NewCBCMAC(block, block.BlockSize())
		return symmetric.CryptoResult{Success: true, Data: hexUpper(mac.MAC(dataBytes))}

	default:
		return symmetric.CryptoResult{Error: "不支持的MAC算法: " + req.Algorithm}
	}
}

// ============================================================
// CMAC-AES — NIST SP 800-38B
// ============================================================

func cmacAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	// Generate subkeys K1, K2
	L := make([]byte, bs)
	block.Encrypt(L, L)
	k1 := generateSubkey(L)
	k2 := generateSubkey(k1)

	// Determine number of blocks
	n := (len(data) + bs - 1) / bs
	if n == 0 {
		n = 1
	}

	M := make([]byte, n*bs)
	copy(M, data)

	if len(data) == 0 || len(data)%bs != 0 {
		// Incomplete last block: apply ISO/IEC 9797-1 padding and XOR with K2
		M[len(data)] = 0x80
		xorBlock(M[(n-1)*bs:n*bs], k2)
	} else {
		// Complete last block: XOR with K1
		xorBlock(M[(n-1)*bs:n*bs], k1)
	}

	// CBC-MAC
	X := make([]byte, bs)
	for i := 0; i < n; i++ {
		xorBlock(X, M[i*bs:(i+1)*bs])
		block.Encrypt(X, X)
	}
	return X, nil
}

func generateSubkey(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	msb := out[0]&0x80 != 0
	for i := 0; i < len(out)-1; i++ {
		out[i] = (out[i] << 1) | (out[i+1] >> 7)
	}
	out[len(out)-1] <<= 1
	if msb {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xorBlock(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// ============================================================
// SipHash-2-4 — RFC 7693 / Aumasson & Bernstein 2012
// ============================================================

func sipHash24(key []byte, data []byte) []byte {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	sipRound := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}

	// Process full 8-byte blocks
	length := len(data)
	blocks := length / 8
	for i := 0; i < blocks; i++ {
		m := binary.LittleEndian.Uint64(data[i*8 : i*8+8])
		v3 ^= m
		sipRound()
		sipRound()
		v0 ^= m
	}

	// Process remaining bytes + length byte
	last := uint64(length) << 56
	tail := data[blocks*8:]
	for i, b := range tail {
		last |= uint64(b) << (uint(i) * 8)
	}
	v3 ^= last
	sipRound()
	sipRound()
	v0 ^= last

	// Finalization
	v2 ^= 0xff
	sipRound()
	sipRound()
	sipRound()
	sipRound()

	hash := v0 ^ v1 ^ v2 ^ v3
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, hash)
	return result
}
