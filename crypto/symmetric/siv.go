package symmetric

import (
	"encoding/hex"
	"strings"

	siv "github.com/secure-io/siv-go"
)

type SIVRequest struct {
	Mode  string `json:"mode"`  // AES-SIV | AES-GCM-SIV
	Key   string `json:"key"`   // hex
	Nonce string `json:"nonce"` // hex (optional for AES-SIV, required for AES-GCM-SIV)
	AAD   string `json:"aad"`   // hex optional
	Data  string `json:"data"`  // hex
}

func SIVEncrypt(req SIVRequest) CryptoResult {
	return sivProcess(req, true)
}

func SIVDecrypt(req SIVRequest) CryptoResult {
	return sivProcess(req, false)
}

func sivProcess(req SIVRequest, encrypt bool) CryptoResult {
	keyBytes, err := hex.DecodeString(strings.TrimSpace(req.Key))
	if err != nil {
		return CryptoResult{Error: "无效的Key (需要hex格式): " + err.Error()}
	}
	dataBytes, err := hex.DecodeString(strings.TrimSpace(req.Data))
	if err != nil {
		return CryptoResult{Error: "无效的数据 (需要hex格式): " + err.Error()}
	}
	var aad []byte
	if strings.TrimSpace(req.AAD) != "" {
		aad, err = hex.DecodeString(strings.TrimSpace(req.AAD))
		if err != nil {
			return CryptoResult{Error: "无效的AAD (需要hex格式): " + err.Error()}
		}
	}
	var nonce []byte
	if strings.TrimSpace(req.Nonce) != "" {
		nonce, err = hex.DecodeString(strings.TrimSpace(req.Nonce))
		if err != nil {
			return CryptoResult{Error: "无效的Nonce (需要hex格式): " + err.Error()}
		}
	}

	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	switch mode {
	case "AES-SIV":
		if len(keyBytes) != 32 && len(keyBytes) != 48 && len(keyBytes) != 64 {
			return CryptoResult{Error: "AES-SIV密钥长度必须是32/48/64字节"}
		}
		aead, err := siv.NewCMAC(keyBytes)
		if err != nil {
			return CryptoResult{Error: "AES-SIV初始化失败: " + err.Error()}
		}
		if len(nonce) != 0 && len(nonce) != aead.NonceSize() {
			return CryptoResult{Error: "AES-SIV Nonce 必须为16字节(或留空)"}
		}
		if encrypt {
			ct := aead.Seal(nil, nonce, dataBytes, aad)
			return CryptoResult{Success: true, Data: hexUpper(ct)}
		}
		pt, err := aead.Open(nil, nonce, dataBytes, aad)
		if err != nil {
			return CryptoResult{Error: "解密失败: " + err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(pt)}

	case "AES-GCM-SIV":
		if len(keyBytes) != 16 && len(keyBytes) != 32 {
			return CryptoResult{Error: "AES-GCM-SIV密钥长度必须是16/32字节"}
		}
		aead, err := siv.NewGCM(keyBytes)
		if err != nil {
			return CryptoResult{Error: "AES-GCM-SIV初始化失败: " + err.Error()}
		}
		if len(nonce) != aead.NonceSize() {
			return CryptoResult{Error: "AES-GCM-SIV Nonce 必须为12字节"}
		}
		if encrypt {
			ct := aead.Seal(nil, nonce, dataBytes, aad)
			return CryptoResult{Success: true, Data: hexUpper(ct)}
		}
		pt, err := aead.Open(nil, nonce, dataBytes, aad)
		if err != nil {
			return CryptoResult{Error: "解密失败: " + err.Error()}
		}
		return CryptoResult{Success: true, Data: hexUpper(pt)}
	default:
		return CryptoResult{Error: "不支持的模式"}
	}
}
