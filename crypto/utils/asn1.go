package utils

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
	"unicode"
)

type ASN1Request struct {
	Data   string `json:"data"`
	Format string `json:"format"` // auto | hex | base64 | pem | text
}

const (
	tagVisibleString   = 26
	tagUniversalString = 28
)

func ParseASN1(req ASN1Request) ToolResult {
	b, err := decodeASN1Input(req.Data, req.Format)
	if err != nil {
		return ToolResult{Error: "ASN.1解析失败: " + err.Error()}
	}
	out, err := formatASN1(b)
	if err != nil {
		return ToolResult{Error: "ASN.1解析失败: " + err.Error()}
	}
	return ToolResult{Success: true, Data: out}
}

func ParseASN1File(path string) ToolResult {
	b, err := readFileBytes(path)
	if err != nil {
		return ToolResult{Error: "读取文件失败: " + err.Error()}
	}
	out, err := formatASN1(b)
	if err != nil {
		return ToolResult{Error: "ASN.1解析失败: " + err.Error()}
	}
	return ToolResult{Success: true, Data: out}
}

func decodeASN1Input(input string, format string) ([]byte, error) {
	fmtLower := strings.ToLower(strings.TrimSpace(format))
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("输入为空")
	}

	switch fmtLower {
	case "pem":
		b, err := pemToBytes(trimmed)
		if err != nil {
			return nil, err
		}
		return b, nil
	case "hex":
		return hexToBytes(trimmed)
	case "base64":
		return base64ToBytes(trimmed)
	case "text":
		return []byte(input), nil
	case "", "auto":
		return autoDetectASN1(trimmed)
	default:
		return nil, errors.New("不支持的输入格式")
	}
}

func autoDetectASN1(trimmed string) ([]byte, error) {
	if strings.Contains(trimmed, "BEGIN") {
		if b, err := pemToBytes(trimmed); err == nil {
			return b, nil
		}
	}

	if isHexLike(trimmed) {
		if b, err := hexToBytes(trimmed); err == nil {
			if canParseASN1(b) {
				return b, nil
			}
		}
	}

	if b, err := base64ToBytes(trimmed); err == nil {
		if canParseASN1(b) {
			return b, nil
		}
	}

	b := []byte(trimmed)
	if canParseASN1(b) {
		return b, nil
	}

	return nil, errors.New("无法识别输入格式")
}

func pemToBytes(s string) ([]byte, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("无效的PEM内容")
	}
	return block.Bytes, nil
}

func hexToBytes(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, " ", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\t", "")
	clean = strings.ReplaceAll(clean, "0x", "")
	clean = strings.ReplaceAll(clean, "0X", "")
	if len(clean)%2 != 0 {
		return nil, errors.New("Hex长度必须为偶数")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func base64ToBytes(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "\t", "")
	clean = strings.ReplaceAll(clean, " ", "")
	if clean == "" {
		return nil, errors.New("Base64内容为空")
	}
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	return nil, errors.New("Base64解码失败")
}

func canParseASN1(b []byte) bool {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return false
	}
	return len(raw.FullBytes) > 0 && len(rest) == 0
}

func formatASN1(b []byte) (string, error) {
	var sb strings.Builder
	if err := dumpASN1(&sb, b, 0); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func dumpASN1(sb *strings.Builder, b []byte, depth int) error {
	for len(b) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(b, &raw)
		if err != nil {
			return err
		}
		line := formatASN1Line(&raw, depth)
		sb.WriteString(line)
		sb.WriteString("\n")

		if raw.IsCompound {
			if err := dumpASN1(sb, raw.Bytes, depth+1); err != nil {
				return err
			}
		} else if raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagOctetString {
			if canParseASN1(raw.Bytes) {
				indent(sb, depth+1)
				sb.WriteString("嵌套ASN.1:\n")
				if err := dumpASN1(sb, raw.Bytes, depth+2); err != nil {
					return err
				}
			}
		}

		b = rest
	}
	return nil
}

func indent(sb *strings.Builder, depth int) {
	for i := 0; i < depth; i++ {
		sb.WriteString("  ")
	}
}

func formatASN1Line(raw *asn1.RawValue, depth int) string {
	var sb strings.Builder
	indent(&sb, depth)

	typeName := asn1TypeName(raw)
	className := asn1ClassName(raw.Class)

	sb.WriteString(fmt.Sprintf("%s (class=%s tag=%d len=%d)", typeName, className, raw.Tag, len(raw.Bytes)))

	value := asn1ValueString(raw)
	if value != "" {
		sb.WriteString(": ")
		sb.WriteString(value)
	}

	return sb.String()
}

func asn1ClassName(class int) string {
	switch class {
	case asn1.ClassUniversal:
		return "Universal"
	case asn1.ClassApplication:
		return "Application"
	case asn1.ClassContextSpecific:
		return "Context"
	case asn1.ClassPrivate:
		return "Private"
	default:
		return "Unknown"
	}
}

func asn1TypeName(raw *asn1.RawValue) string {
	if raw.Class != asn1.ClassUniversal {
		if raw.IsCompound {
			return "CONSTRUCTED"
		}
		return "PRIMITIVE"
	}
	switch raw.Tag {
	case asn1.TagBoolean:
		return "BOOLEAN"
	case asn1.TagInteger:
		return "INTEGER"
	case asn1.TagBitString:
		return "BIT STRING"
	case asn1.TagOctetString:
		return "OCTET STRING"
	case asn1.TagNull:
		return "NULL"
	case asn1.TagOID:
		return "OBJECT IDENTIFIER"
	case asn1.TagEnum:
		return "ENUMERATED"
	case asn1.TagUTF8String:
		return "UTF8 STRING"
	case asn1.TagSequence:
		return "SEQUENCE"
	case asn1.TagSet:
		return "SET"
	case asn1.TagNumericString:
		return "NUMERIC STRING"
	case asn1.TagPrintableString:
		return "PRINTABLE STRING"
	case asn1.TagT61String:
		return "T61 STRING"
	case asn1.TagIA5String:
		return "IA5 STRING"
	case asn1.TagUTCTime:
		return "UTC TIME"
	case asn1.TagGeneralizedTime:
		return "GENERALIZED TIME"
	case asn1.TagGeneralString:
		return "GENERAL STRING"
	case asn1.TagBMPString:
		return "BMP STRING"
	case tagVisibleString:
		return "VISIBLE STRING"
	case tagUniversalString:
		return "UNIVERSAL STRING"
	default:
		if raw.IsCompound {
			return "CONSTRUCTED"
		}
		return "PRIMITIVE"
	}
}

func asn1ValueString(raw *asn1.RawValue) string {
	if raw.IsCompound {
		return ""
	}
	if raw.Class != asn1.ClassUniversal {
		return ""
	}

	switch raw.Tag {
	case asn1.TagBoolean:
		var v bool
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			if v {
				return "TRUE"
			}
			return "FALSE"
		}
	case asn1.TagInteger:
		var v *big.Int
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			return v.String()
		}
	case asn1.TagBitString:
		var v asn1.BitString
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			return fmt.Sprintf("%d bits %s", v.BitLength, hexUpper(v.Bytes))
		}
	case asn1.TagOctetString:
		var v []byte
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			return formatBytesPreview(v)
		}
	case asn1.TagNull:
		return "NULL"
	case asn1.TagOID:
		var v asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			return v.String()
		}
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagT61String, asn1.TagIA5String, asn1.TagNumericString, asn1.TagGeneralString, tagVisibleString, tagUniversalString, asn1.TagBMPString:
		var v string
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			return v
		}
	case asn1.TagUTCTime, asn1.TagGeneralizedTime:
		var v time.Time
		if _, err := asn1.Unmarshal(raw.FullBytes, &v); err == nil {
			return v.Format(time.RFC3339)
		}
	}

	return formatBytesPreview(raw.Bytes)
}

func formatBytesPreview(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const maxLen = 64
	preview := b
	truncated := false
	if len(b) > maxLen {
		preview = b[:maxLen]
		truncated = true
	}
	hexStr := hexUpper(preview)
	if truncated {
		hexStr = hexStr + "..."
	}
	text := printablePreview(preview)
	if text != "" {
		return fmt.Sprintf("%s (%s)", hexStr, text)
	}
	return hexStr
}

func printablePreview(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		}
	}
	out := strings.TrimSpace(sb.String())
	if out == "" {
		return ""
	}
	if len(out) > 64 {
		return out[:64] + "..."
	}
	return out
}

func readFileBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("文件路径为空")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func isHexLike(s string) bool {
	clean := strings.ReplaceAll(s, " ", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\t", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "0x", "")
	clean = strings.ReplaceAll(clean, "0X", "")
	if len(clean)%2 != 0 {
		return false
	}
	for _, r := range clean {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
