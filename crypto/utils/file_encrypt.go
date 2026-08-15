package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/emmansun/gmsm/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return hex.DecodeString(s)
}

// EncryptFile encrypts a file using AES-256-GCM
func EncryptFile(req FileEncryptRequest) ToolResult {
	keyBytes, err := hexDecode(req.Key)
	if err != nil {
		return ToolResult{Error: "无效的密钥: " + err.Error()}
	}

	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return ToolResult{Error: fmt.Sprintf("AES密钥长度必须为 16, 24 或 32 字节 (当前为 %d 字节)", len(keyBytes))}
	}

	inputData, err := os.ReadFile(req.InputPath)
	if err != nil {
		return ToolResult{Error: "读取输入文件失败: " + err.Error()}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return ToolResult{Error: "创建AES cipher失败: " + err.Error()}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ToolResult{Error: "GCM初始化失败: " + err.Error()}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ToolResult{Error: "生成Nonce失败: " + err.Error()}
	}

	// Output format: nonce + ciphertext+tag
	ct := gcm.Seal(nonce, nonce, inputData, nil)

	if err := os.WriteFile(req.OutputPath, ct, 0644); err != nil {
		return ToolResult{Error: "写入输出文件失败: " + err.Error()}
	}

	return ToolResult{
		Success: true,
		Data:    fmt.Sprintf("✅ 加密完成: %s → %s (%d bytes)", req.InputPath, req.OutputPath, len(ct)),
	}
}

// DecryptFile decrypts a file using AES-256-GCM
func DecryptFile(req FileDecryptRequest) ToolResult {
	keyBytes, err := hexDecode(req.Key)
	if err != nil {
		return ToolResult{Error: "无效的密钥: " + err.Error()}
	}

	ctData, err := os.ReadFile(req.InputPath)
	if err != nil {
		return ToolResult{Error: "读取输入文件失败: " + err.Error()}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return ToolResult{Error: "创建AES cipher失败: " + err.Error()}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ToolResult{Error: "GCM初始化失败: " + err.Error()}
	}

	nonceSize := gcm.NonceSize()
	if len(ctData) < nonceSize+gcm.Overhead() {
		return ToolResult{Error: "密文太短，文件可能已损坏"}
	}

	nonce, ct := ctData[:nonceSize], ctData[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return ToolResult{Error: "解密失败(密钥错误或文件损坏): " + err.Error()}
	}

	if err := os.WriteFile(req.OutputPath, pt, 0644); err != nil {
		return ToolResult{Error: "写入输出文件失败: " + err.Error()}
	}

	return ToolResult{
		Success: true,
		Data:    fmt.Sprintf("✅ 解密完成: %s → %s (%d bytes)", req.InputPath, req.OutputPath, len(pt)),
	}
}
