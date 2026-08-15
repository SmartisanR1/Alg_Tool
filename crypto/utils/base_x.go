package utils

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/bech32"
)

type Base32Request struct {
	Data      string `json:"data"`
	IsHex     bool   `json:"isHex"`
	NoPadding bool   `json:"noPadding"`
	Variant   string `json:"variant"` // Standard | Hex
}

type Base58Request struct {
	Data  string `json:"data"`
	IsHex bool   `json:"isHex"`
}

type Bech32EncodeRequest struct {
	HRP   string `json:"hrp"`
	Data  string `json:"data"`
	IsHex bool   `json:"isHex"`
}

type Bech32DecodeResult struct {
	Success bool   `json:"success"`
	HRP     string `json:"hrp"`
	Data    string `json:"data"` // hex
	Error   string `json:"error"`
}

func Base32Encode(req Base32Request) ToolResult {
	b, err := decodeMaybeHex(req.Data, req.IsHex)
	if err != nil {
		return ToolResult{Error: "无效的输入: " + err.Error()}
	}

	var enc *base32.Encoding
	switch strings.ToLower(strings.TrimSpace(req.Variant)) {
	case "hex":
		enc = base32.HexEncoding
	default:
		enc = base32.StdEncoding
	}
	if req.NoPadding {
		enc = enc.WithPadding(base32.NoPadding)
	}

	return ToolResult{Success: true, Data: enc.EncodeToString(b)}
}

func Base32Decode(req Base32Request) ToolResult {
	var enc *base32.Encoding
	switch strings.ToLower(strings.TrimSpace(req.Variant)) {
	case "hex":
		enc = base32.HexEncoding
	default:
		enc = base32.StdEncoding
	}
	if req.NoPadding {
		enc = enc.WithPadding(base32.NoPadding)
	}

	b, err := enc.DecodeString(strings.TrimSpace(req.Data))
	if err != nil {
		return ToolResult{Error: "Base32解码失败: " + err.Error()}
	}

	if req.IsHex {
		return ToolResult{Success: true, Data: hexUpper(b)}
	}
	if utf8.Valid(b) {
		return ToolResult{Success: true, Data: string(b)}
	}
	return ToolResult{Success: true, Data: hexUpper(b)}
}

func Base58Encode(req Base58Request) ToolResult {
	b, err := decodeMaybeHex(req.Data, req.IsHex)
	if err != nil {
		return ToolResult{Error: "无效的输入: " + err.Error()}
	}
	return ToolResult{Success: true, Data: base58.Encode(b)}
}

func Base58Decode(req Base58Request) ToolResult {
	input := strings.TrimSpace(req.Data)
	if input == "" {
		return ToolResult{Error: "输入为空"}
	}
	b := base58.Decode(input)
	if len(b) == 0 {
		return ToolResult{Error: "Base58解码失败"}
	}
	if req.IsHex {
		return ToolResult{Success: true, Data: hexUpper(b)}
	}
	if utf8.Valid(b) {
		return ToolResult{Success: true, Data: string(b)}
	}
	return ToolResult{Success: true, Data: hexUpper(b)}
}

func Bech32Encode(req Bech32EncodeRequest) ToolResult {
	if strings.TrimSpace(req.HRP) == "" {
		return ToolResult{Error: "HRP不能为空"}
	}
	b, err := decodeMaybeHex(req.Data, req.IsHex)
	if err != nil {
		return ToolResult{Error: "无效的输入: " + err.Error()}
	}
	conv, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return ToolResult{Error: "Bech32转换失败: " + err.Error()}
	}
	encoded, err := bech32.Encode(strings.ToLower(req.HRP), conv)
	if err != nil {
		return ToolResult{Error: "Bech32编码失败: " + err.Error()}
	}
	return ToolResult{Success: true, Data: encoded}
}

func Bech32Decode(input string) Bech32DecodeResult {
	input = strings.TrimSpace(input)
	if input == "" {
		return Bech32DecodeResult{Error: "输入为空"}
	}
	hrp, data, err := bech32.Decode(input)
	if err != nil {
		return Bech32DecodeResult{Error: "Bech32解码失败: " + err.Error()}
	}
	conv, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return Bech32DecodeResult{Error: "Bech32数据转换失败: " + err.Error()}
	}
	return Bech32DecodeResult{Success: true, HRP: hrp, Data: hexUpper(conv)}
}

func decodeMaybeHex(input string, isHex bool) ([]byte, error) {
	if isHex {
		clean := strings.ReplaceAll(input, " ", "")
		clean = strings.ReplaceAll(clean, "\n", "")
		clean = strings.ReplaceAll(clean, "\t", "")
		clean = strings.ReplaceAll(clean, "0x", "")
		clean = strings.ReplaceAll(clean, "0X", "")
		if len(clean)%2 != 0 {
			return nil, hex.ErrLength
		}
		return hex.DecodeString(clean)
	}
	return []byte(input), nil
}
