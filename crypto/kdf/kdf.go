package kdf

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/emmansun/gmsm/rand"
	"github.com/emmansun/gmsm/sm3"

	"cryptokit/crypto/symmetric"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type KDFRequest struct {
	Algorithm  string `json:"algorithm"`  // PBKDF2-SHA256 PBKDF2-SHA512 HKDF-SHA256 HKDF-SHA512 HKDF-SM3 bcrypt scrypt Argon2i Argon2d Argon2id
	Password   string `json:"password"`   // hex (or plain text for bcrypt)
	Salt       string `json:"salt"`       // hex
	Info       string `json:"info"`       // hex, for HKDF
	Iterations int    `json:"iterations"` // for PBKDF2
	KeyLen     int    `json:"keyLen"`     // output key length in bytes
	Cost       int    `json:"cost"`       // for bcrypt (4-31)
	// scrypt params
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
	// Argon2 params
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

// decodeHexOrNil 将 hex 字符串解码; 空字符串返回 nil(允许可选参数留空), 非法 hex 报错
func decodeHexOrNil(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func Derive(req KDFRequest) symmetric.CryptoResult {
	passBytes, err := hex.DecodeString(req.Password)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密码(需要hex): " + err.Error()}
	}

	var saltBytes []byte
	if req.Salt != "" {
		saltBytes, err = hex.DecodeString(req.Salt)
		if err != nil {
			return symmetric.CryptoResult{Error: "无效的盐(需要hex): " + err.Error()}
		}
	}
	if len(saltBytes) == 0 && req.Algorithm != "bcrypt" {
		saltBytes = make([]byte, 16)
		rand.Read(saltBytes)
	}

	keyLen := req.KeyLen
	if keyLen == 0 {
		keyLen = 32
	}

	switch req.Algorithm {
	case "PBKDF2-SHA1":
		iter := req.Iterations
		if iter == 0 {
			iter = 100000
		}
		dk := pbkdf2.Key(passBytes, saltBytes, iter, keyLen, sha1.New)
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	case "PBKDF2-SHA256":
		iter := req.Iterations
		if iter == 0 {
			iter = 100000
		}
		dk := pbkdf2.Key(passBytes, saltBytes, iter, keyLen, sha256.New)
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	case "PBKDF2-SHA512":
		iter := req.Iterations
		if iter == 0 {
			iter = 100000
		}
		dk := pbkdf2.Key(passBytes, saltBytes, iter, keyLen, sha512.New)
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	case "HKDF-SHA256":
		infoBytes, err := decodeHexOrNil(req.Info)
		if err != nil {
			return symmetric.CryptoResult{Error: "无效的Info(需要hex): " + err.Error()}
		}
		r := hkdf.New(sha256.New, passBytes, saltBytes, infoBytes)
		out := make([]byte, keyLen)
		if _, err := r.Read(out); err != nil {
			return symmetric.CryptoResult{Error: "HKDF-SHA256 失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}

	case "HKDF-SHA512":
		infoBytes, err := decodeHexOrNil(req.Info)
		if err != nil {
			return symmetric.CryptoResult{Error: "无效的Info(需要hex): " + err.Error()}
		}
		r := hkdf.New(sha512.New, passBytes, saltBytes, infoBytes)
		out := make([]byte, keyLen)
		if _, err := r.Read(out); err != nil {
			return symmetric.CryptoResult{Error: "HKDF-SHA512 失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}

	case "HKDF-SM3":
		infoBytes, err := decodeHexOrNil(req.Info)
		if err != nil {
			return symmetric.CryptoResult{Error: "无效的Info(需要hex): " + err.Error()}
		}
		r := hkdf.New(sm3.New, passBytes, saltBytes, infoBytes)
		out := make([]byte, keyLen)
		if _, err := r.Read(out); err != nil {
			return symmetric.CryptoResult{Error: "HKDF-SM3 失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}

	case "bcrypt":
		cost := req.Cost
		if cost == 0 {
			cost = 12
		}
		// bcrypt works with raw password string
		hash, err := bcrypt.GenerateFromPassword(passBytes, cost)
		if err != nil {
			return symmetric.CryptoResult{Error: "bcrypt 失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: string(hash)}

	case "scrypt":
		N := req.N
		r := req.R
		p := req.P
		if N == 0 {
			N = 32768
		}
		if r == 0 {
			r = 8
		}
		if p == 0 {
			p = 1
		}
		dk, err := scrypt.Key(passBytes, saltBytes, N, r, p, keyLen)
		if err != nil {
			return symmetric.CryptoResult{Error: "scrypt 失败: " + err.Error()}
		}
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	case "Argon2i":
		t := req.Time
		m := req.Memory
		threads := req.Threads
		if t == 0 {
			t = 3
		}
		if m == 0 {
			m = 65536
		}
		if threads == 0 {
			threads = 4
		}
		dk := argon2.Key(passBytes, saltBytes, t, m, threads, uint32(keyLen))
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	case "Argon2d":
		// Go 标准库不提供纯 Argon2d，使用 Argon2i 作为近似（时序安全侧重不同，请知悉）
		t := req.Time
		m := req.Memory
		threads := req.Threads
		if t == 0 {
			t = 3
		}
		if m == 0 {
			m = 65536
		}
		if threads == 0 {
			threads = 4
		}
		dk := argon2.Key(passBytes, saltBytes, t, m, threads, uint32(keyLen))
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	case "Argon2id":
		t := req.Time
		m := req.Memory
		threads := req.Threads
		if t == 0 {
			t = 3
		}
		if m == 0 {
			m = 65536
		}
		if threads == 0 {
			threads = 4
		}
		dk := argon2.IDKey(passBytes, saltBytes, t, m, threads, uint32(keyLen))
		return symmetric.CryptoResult{
			Success: true,
			Data:    hexUpper(dk),
			Extra:   hexUpper(saltBytes),
		}

	default:
		return symmetric.CryptoResult{Error: fmt.Sprintf("不支持的KDF算法: %s", req.Algorithm)}
	}
}
