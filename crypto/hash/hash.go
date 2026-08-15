package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"cryptokit/crypto/symmetric"

	"github.com/emmansun/gmsm/sm3"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

type HashRequest struct {
	Algorithm string `json:"algorithm"` // MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA512-224 SHA512-256
	// SHA3-224 SHA3-256 SHA3-384 SHA3-512 SHAKE128 SHAKE256
	// BLAKE2b-256 BLAKE2b-384 BLAKE2b-512 BLAKE2s-256 BLAKE3
	// RIPEMD160 SM3
	Data       string `json:"data"`       // hex
	OutputSize int    `json:"outputSize"` // for SHAKE
}

type HMACRequest struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`  // hex
	Data      string `json:"data"` // hex
}

func Compute(req HashRequest) symmetric.CryptoResult {
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	switch req.Algorithm {
	case "MD4":
		h := md4.New()
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "MD5":
		h := md5.Sum(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA1", "SHA-1":
		h := sha1.Sum(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA224", "SHA-224":
		h := sha256.Sum224(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA256", "SHA-256":
		h := sha256.Sum256(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA384", "SHA-384":
		h := sha512.Sum384(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA512", "SHA-512":
		h := sha512.Sum512(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA512-224", "SHA-512/224":
		h := sha512.Sum512_224(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA512-256", "SHA-512/256":
		h := sha512.Sum512_256(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA3-224":
		h := sha3.Sum224(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA3-256":
		h := sha3.Sum256(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA3-384":
		h := sha3.Sum384(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHA3-512":
		h := sha3.Sum512(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h[:])}
	case "SHAKE128":
		outSize := req.OutputSize
		if outSize == 0 {
			outSize = 32
		}
		out := make([]byte, outSize)
		sha3.ShakeSum128(out, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	case "SHAKE256":
		outSize := req.OutputSize
		if outSize == 0 {
			outSize = 64
		}
		out := make([]byte, outSize)
		sha3.ShakeSum256(out, dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	case "BLAKE2b-256":
		h, _ := blake2b.New256(nil)
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "BLAKE2b-384":
		h, _ := blake2b.New384(nil)
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "BLAKE2b-512":
		h, _ := blake2b.New512(nil)
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "BLAKE2s-256":
		h, _ := blake2s.New256(nil)
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "BLAKE3":
		h := blake3.New()
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "RIPEMD160", "RIPEMD-160":
		h := ripemd160.New()
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	case "SM3":
		h := sm3.New()
		h.Write(dataBytes)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
	default:
		return symmetric.CryptoResult{Error: "不支持的算法: " + req.Algorithm}
	}
}

func ComputeHMAC(req HMACRequest) symmetric.CryptoResult {
	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的Key: " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	var h hash.Hash
	switch req.Algorithm {
	case "HMAC-MD5":
		h = hmac.New(md5.New, keyBytes)
	case "HMAC-SHA1":
		h = hmac.New(sha1.New, keyBytes)
	case "HMAC-SHA224":
		h = hmac.New(sha256.New224, keyBytes)
	case "HMAC-SHA256":
		h = hmac.New(sha256.New, keyBytes)
	case "HMAC-SHA384":
		h = hmac.New(sha512.New384, keyBytes)
	case "HMAC-SHA512":
		h = hmac.New(sha512.New, keyBytes)
	case "HMAC-SHA3-256":
		h = hmac.New(sha3.New256, keyBytes)
	case "HMAC-SHA3-512":
		h = hmac.New(sha3.New512, keyBytes)
	case "HMAC-BLAKE2b-256":
		h, err = blake2b.New256(keyBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "HMAC-BLAKE2b init: " + err.Error()}
		}
	case "HMAC-BLAKE2b-512":
		h, err = blake2b.New512(keyBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "HMAC-BLAKE2b-512 init: " + err.Error()}
		}
	case "HMAC-SM3":
		h = hmac.New(sm3.New, keyBytes)
	default:
		return symmetric.CryptoResult{Error: "不支持的HMAC算法: " + req.Algorithm}
	}

	h.Write(dataBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(h.Sum(nil))}
}

// HashFile computes hash of a file
func HashFile(filePath string, algorithm string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %v", err)
	}
	defer f.Close()

	var h hash.Hash
	switch algorithm {
	case "MD5":
		h = md5.New()
	case "SHA1":
		h = sha1.New()
	case "SHA224":
		h = sha256.New224()
	case "SHA256":
		h = sha256.New()
	case "SHA384":
		h = sha512.New384()
	case "SHA512":
		h = sha512.New()
	case "RIPEMD160":
		h = ripemd160.New()
	case "SHA3-224":
		h = sha3.New224()
	case "SHA3-256":
		h = sha3.New256()
	case "SHA3-384":
		h = sha3.New384()
	case "SHA3-512":
		h = sha3.New512()
	case "SM3":
		h = sm3.New()
	case "BLAKE3":
		h = blake3.New()
	default:
		return "", fmt.Errorf("不支持的哈希算法: %s", algorithm)
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("计算哈希失败: %v", err)
	}
	return hexUpper(h.Sum(nil)), nil
}
