package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/emmansun/gmsm/sm4"
)

func fpeNIST(req FPERequest, encrypt bool) CryptoResult {
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "FF1"
	}

	alphabet := req.Alphabet
	if alphabet == "" {
		alphabet = "0123456789"
	}
	alpha, err := NewAlphabet(alphabet)
	if err != nil {
		return CryptoResult{Error: "字符集错误: " + err.Error()}
	}

	dataRunes := []rune(req.Data)
	keyBytes, err := hex.DecodeString(strings.TrimSpace(req.Key))
	if err != nil {
		return CryptoResult{Error: "无效的密钥(需要Hex): " + err.Error()}
	}

	var tweak []byte
	if strings.TrimSpace(req.Tweak) != "" {
		tweak, err = hex.DecodeString(strings.TrimSpace(req.Tweak))
		if err != nil {
			return CryptoResult{Error: "无效的Tweak(需要Hex): " + err.Error()}
		}
	}

	radix := alpha.Len()
	minLen := int(math.Ceil(6 / math.Log10(float64(radix))))
	maxLen := int64(1 << 32)
	if mode == "FF3-1" || mode == "FF3_1" || mode == "FF3" {
		maxLen = int64(math.Floor(192 / math.Log2(float64(radix))))
	}
	if len(dataRunes) < minLen || int64(len(dataRunes)) > maxLen {
		return CryptoResult{Error: fmt.Sprintf("输入长度必须在%d~%d之间", minLen, maxLen)}
	}
	if err := validateAlphabetData(&alpha, dataRunes); err != nil {
		return CryptoResult{Error: err.Error()}
	}

	switch mode {
	case "FF1":
		block, err := fpeBlock(req.Cipher, keyBytes)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ff1, err := newFF1WithBlock(block, tweak, 0, 0, radix, alphabet)
		if err != nil {
			return CryptoResult{Error: translateFPEError(err)}
		}
		var out []rune
		if encrypt {
			out, err = ff1.EncryptRunes(dataRunes, tweak)
		} else {
			out, err = ff1.DecryptRunes(dataRunes, tweak)
		}
		if err != nil {
			return CryptoResult{Error: translateFPEError(err)}
		}
		return CryptoResult{Success: true, Data: string(out)}

	case "FF3-1", "FF3_1", "FF3":
		if len(tweak) == 0 {
			tweak = make([]byte, 7)
		} else if len(tweak) != 7 {
			return CryptoResult{Error: "FF3-1 的 Tweak 必须是 7 字节(14位Hex)"}
		}
		block, err := fpeBlock(req.Cipher, keyBytes)
		if err != nil {
			return CryptoResult{Error: err.Error()}
		}
		ff3, err := newFF3_1WithBlock(block, tweak, radix, alphabet)
		if err != nil {
			return CryptoResult{Error: translateFPEError(err)}
		}
		var out []rune
		if encrypt {
			out, err = ff3.EncryptRunes(dataRunes, tweak)
		} else {
			out, err = ff3.DecryptRunes(dataRunes, tweak)
		}
		if err != nil {
			return CryptoResult{Error: translateFPEError(err)}
		}
		return CryptoResult{Success: true, Data: string(out)}
	default:
		return CryptoResult{Error: "不支持的FPE模式: " + req.Mode}
	}
}

func fpeBlock(name string, key []byte) (cipher.Block, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "", "AES":
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, fmt.Errorf("AES密钥长度必须是16/24/32字节")
		}
		return aes.NewCipher(key)
	case "SM4":
		if len(key) != 16 {
			return nil, fmt.Errorf("SM4密钥长度必须是16字节")
		}
		return sm4.NewCipher(key)
	default:
		return nil, fmt.Errorf("不支持的算法")
	}
}

func validateAlphabetData(alpha *Alphabet, data []rune) error {
	for _, r := range data {
		if alpha.PosOf(r) < 0 {
			return fmt.Errorf("数据包含非法字符: %q", r)
		}
	}
	return nil
}

func translateFPEError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unsupported radix"):
		return "不支持的基数/字符集"
	case strings.Contains(msg, "unsupported radix/maximum text length combination"):
		return "字符集长度与文本长度不符合标准要求"
	case strings.Contains(msg, "invalid text length"):
		return "文本长度不符合标准要求"
	case strings.Contains(msg, "invalid tweak length"):
		return "Tweak长度不符合标准要求"
	default:
		return msg
	}
}
