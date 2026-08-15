package finance

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/rand"

	"cryptokit/crypto/symmetric"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

type RetailMACRequest struct {
	Key     string `json:"key"`     // hex, 16/24 bytes
	Data    string `json:"data"`    // hex
	Padding string `json:"padding"` // ISO9797-1-P1 | ISO9797-1-P2
}

type SM4MACRequest struct {
	Key     string `json:"key"`     // hex, 16 bytes
	Data    string `json:"data"`    // hex
	Padding string `json:"padding"` // ISO9797-1-P1 | ISO9797-1-P2
}

type PINBlockRequest struct {
	Format string `json:"format"` // ISO-0 | ISO-3
	PIN    string `json:"pin"`    // 4-12 digits
	PAN    string `json:"pan"`    // PAN digits
	Random string `json:"random"` // for ISO-3 optional, digits
}

type PINBlockResult struct {
	Success bool   `json:"success"`
	Block   string `json:"block"`
	Random  string `json:"random"`
	Error   string `json:"error"`
}

type PINBlockParseRequest struct {
	Format string `json:"format"` // ISO-0 | ISO-3
	Block  string `json:"block"`  // hex 16 nibbles
	PAN    string `json:"pan"`
}

type PINParseResult struct {
	Success bool   `json:"success"`
	PIN     string `json:"pin"`
	Error   string `json:"error"`
}

type PINEncryptRequest struct {
	Key   string `json:"key"`   // hex 16/24 bytes
	Block string `json:"block"` // hex 8 bytes
}

type PVVRequest struct {
	PVK      string `json:"pvk"`      // hex 16/24 bytes
	PVKI     string `json:"pvki"`     // 0-9
	PIN      string `json:"pin"`      // 4 digits
	PAN11    string `json:"pan11"`    // rightmost 11 digits (excluding check digit)
	DecTable string `json:"decTable"` // 16 digits, optional
}

type PVVResult struct {
	Success bool   `json:"success"`
	PVV     string `json:"pvv"`
	Error   string `json:"error"`
}

type CVVRequest struct {
	CVK      string `json:"cvk"`      // hex 16/24 bytes
	PAN      string `json:"pan"`      // digits
	Exp      string `json:"exp"`      // YYMM
	Service  string `json:"service"`  // 3 digits
	DecTable string `json:"decTable"` // 16 digits, optional
	Length   int    `json:"length"`   // 3 or 4
}

type CVVResult struct {
	Success bool   `json:"success"`
	CVV     string `json:"cvv"`
	Error   string `json:"error"`
}

type UDKRequest struct {
	MDK string `json:"mdk"` // hex 16/24 bytes
	PAN string `json:"pan"` // digits
	PSN string `json:"psn"` // 2 digits
}

type UDKResult struct {
	Success bool   `json:"success"`
	UDK     string `json:"udk"`
	Left    string `json:"left"`
	Right   string `json:"right"`
	Error   string `json:"error"`
}

type DOWRequest struct {
	Key  string `json:"key"`  // hex 16/24 bytes
	Data string `json:"data"` // hex 8 bytes
}

type DOWResult struct {
	Success bool   `json:"success"`
	Out     string `json:"out"`
	Left    string `json:"left"`
	Right   string `json:"right"`
	Error   string `json:"error"`
}

type EMVACRequest struct {
	Key     string `json:"key"`     // hex 16/24 bytes
	Data    string `json:"data"`    // hex
	Padding string `json:"padding"` // ISO9797-1-P2
}

type TDESRequest struct {
	Key     string `json:"key"`     // hex 16/24 bytes
	Data    string `json:"data"`    // hex
	Mode    string `json:"mode"`    // ECB | CBC
	IV      string `json:"iv"`      // hex, for CBC
	Padding string `json:"padding"` // ISO9797-1-P1 | ISO9797-1-P2
}

type SM4FinanceRequest struct {
	Key     string `json:"key"`     // hex 16 bytes
	Data    string `json:"data"`    // hex
	Mode    string `json:"mode"`    // ECB | CBC
	IV      string `json:"iv"`      // hex 16 bytes, for CBC
	Padding string `json:"padding"` // ISO9797-1-P1 | ISO9797-1-P2 | PKCS7 | Zero | NoPadding
}

type SM2PINRequest struct {
	Key   string `json:"key"`   // PEM or Hex
	Block string `json:"block"` // hex 8 bytes PIN block
}

type SM4PINRequest struct {
	Key   string `json:"key"`   // hex 16 bytes
	Block string `json:"block"` // hex 8 bytes PIN block
}

type SM4CMACRequest struct {
	Key     string `json:"key"`     // hex 16 bytes
	Data    string `json:"data"`    // hex
	Padding string `json:"padding"` // ISO9797-1-P1 | ISO9797-1-P2
}

type SM4UDKRequest struct {
	MDK string `json:"mdk"` // hex 16 bytes
	PAN string `json:"pan"` // digits
	PSN string `json:"psn"` // 2 digits
}

// ============================================================
// Retail MAC (ANSI X9.19 / ISO 9797-1 Alg 3)
// ============================================================

func RetailMAC(req RetailMACRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	padMethod := normalizePad(req.Padding)
	if padMethod == "" {
		padMethod = "ISO9797-1-P2"
	}

	mac, err := retailMAC(keyBytes, dataBytes, padMethod)
	if err != nil {
		return symmetric.CryptoResult{Error: "MAC计算失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(mac)}
}

// SM4-CBC-MAC (GB/T 15852.1-2020 / GM/T 0002)
// ============================================================
func SM4MAC(req SM4MACRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	if len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须为16字节"}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	padMethod := normalizePad(req.Padding)
	if padMethod == "" {
		padMethod = "ISO9797-1-P2"
	}

	mac, err := sm4CBCMAC(keyBytes, dataBytes, padMethod)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4-CBC-MAC计算失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(mac)}
}

func sm4CBCMAC(key, data []byte, padding string) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := padDataSM4(data, 16, padding)

	x := make([]byte, 16)
	for i := 0; i < len(padded); i += 16 {
		for j := 0; j < 16; j++ {
			x[j] ^= padded[i+j]
		}
		block.Encrypt(x, x)
	}
	return x, nil
}

// SM4-CMAC (GB/T 15852.1-2020 Section 6.2 / GM/T 0002)
// ============================================================
func SM4CMAC(req SM4CMACRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	if len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须为16字节"}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	padMethod := normalizePad(req.Padding)
	if padMethod == "" {
		padMethod = "ISO9797-1-P2"
	}

	mac, err := sm4CMAC(keyBytes, dataBytes, padMethod)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4-CMAC计算失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(mac)}
}

func sm4CMAC(key, data []byte, padding string) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	// Generate subkeys K1, K2 per NIST SP 800-38B
	L := make([]byte, bs)
	block.Encrypt(L, L)
	k1 := generateSM4Subkey(L)
	k2 := generateSM4Subkey(k1)

	// Determine number of blocks
	n := (len(data) + bs - 1) / bs
	if n == 0 {
		n = 1
	}

	M := make([]byte, n*bs)
	copy(M, data)

	if len(data) == 0 || len(data)%bs != 0 {
		// Incomplete last block: apply padding and XOR with K2
		M[len(data)] = 0x80
		for j := 0; j < 16; j++ {
			M[(n-1)*bs+j] ^= k2[j]
		}
	} else {
		// Complete last block: XOR with K1
		for j := 0; j < 16; j++ {
			M[(n-1)*bs+j] ^= k1[j]
		}
	}

	// CBC-MAC
	x := make([]byte, bs)
	for i := 0; i < n; i++ {
		for j := 0; j < bs; j++ {
			x[j] ^= M[i*bs+j]
		}
		block.Encrypt(x, x)
	}
	return x, nil
}

func generateSM4Subkey(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	msb := out[0]&0x80 != 0
	for i := 0; i < len(out)-1; i++ {
		out[i] = (out[i] << 1) | (out[i+1] >> 7)
	}
	out[len(out)-1] <<= 1
	if msb {
		out[len(out)-1] ^= 0x87 // 0x87 = 0x80 << 1 | 1 (for 128-bit)
	}
	return out
}

func padDataSM4(data []byte, blockSize int, padding string) []byte {
	switch padding {
	case "ISO9797-1-P1":
		padded := make([]byte, ((len(data)+blockSize-1)/blockSize)*blockSize)
		copy(padded, data)
		return padded
	default:
		padded := make([]byte, ((len(data)+blockSize-1)/blockSize)*blockSize)
		copy(padded, data)
		if len(data) == 0 || len(data)%blockSize != 0 {
			padded[len(data)] = 0x80
		}
		return padded
	}
}

// ============================================================
// PIN Block
// ============================================================

func GeneratePINBlock(req PINBlockRequest) PINBlockResult {
	format := strings.ToUpper(strings.TrimSpace(req.Format))
	if format == "" {
		format = "ISO-0"
	}
	pin := strings.TrimSpace(req.PIN)
	if !isDigits(pin) || len(pin) < 4 || len(pin) > 12 {
		return PINBlockResult{Error: "PIN长度必须为4-12位数字"}
	}
	pan12, err := pan12FromPAN(req.PAN)
	if err != nil {
		return PINBlockResult{Error: err.Error()}
	}

	pinField, randUsed, err := buildPINField(format, pin, req.Random)
	if err != nil {
		return PINBlockResult{Error: err.Error()}
	}
	panField := "0000" + pan12
	block := xorHex(pinField, panField)
	return PINBlockResult{Success: true, Block: strings.ToUpper(block), Random: randUsed}
}

func ParsePINBlock(req PINBlockParseRequest) PINParseResult {
	format := strings.ToUpper(strings.TrimSpace(req.Format))
	if format == "" {
		format = "ISO-0"
	}
	block := strings.ToUpper(cleanHex(req.Block))
	if len(block) != 16 {
		return PINParseResult{Error: "PIN Block长度必须为16位Hex"}
	}
	pan12, err := pan12FromPAN(req.PAN)
	if err != nil {
		return PINParseResult{Error: err.Error()}
	}
	panField := "0000" + pan12
	pinField := xorHex(block, panField)
	if len(pinField) != 16 {
		return PINParseResult{Error: "PIN Block解析失败"}
	}
	prefix := pinField[0:1]
	if format == "ISO-0" && prefix != "0" {
		return PINParseResult{Error: "PIN Block格式不匹配(应为ISO-0)"}
	}
	if format == "ISO-3" && prefix != "3" {
		return PINParseResult{Error: "PIN Block格式不匹配(应为ISO-3)"}
	}
	pinLenNibble := pinField[1:2]
	pinLen, err := hexDigitToInt(pinLenNibble)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return PINParseResult{Error: "PIN长度解析失败"}
	}
	pin := pinField[2 : 2+pinLen]
	if !isDigits(pin) {
		return PINParseResult{Error: "PIN解析失败"}
	}
	return PINParseResult{Success: true, PIN: pin}
}

func EncryptPINBlock(req PINEncryptRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	blockBytes, err := decodeHex(req.Block)
	if err != nil || len(blockBytes) != 8 {
		return symmetric.CryptoResult{Error: "PIN Block必须为8字节Hex"}
	}
	out, err := tdesECBEncrypt(keyBytes, blockBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "PIN加密失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
}

func DecryptPINBlock(req PINEncryptRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	blockBytes, err := decodeHex(req.Block)
	if err != nil || len(blockBytes) != 8 {
		return symmetric.CryptoResult{Error: "PIN Block必须为8字节Hex"}
	}
	out, err := tdesECBDecrypt(keyBytes, blockBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "PIN解密失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
}

// SM2 PIN 加解密 (GMT 0045-2016)
// ============================================================
func SM2EncryptPIN(req SM2PINRequest) symmetric.CryptoResult {
	sm2Pub, err := parseSM2PublicKeyPIN(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	blockBytes, err := decodeHex(req.Block)
	if err != nil || len(blockBytes) != 8 {
		return symmetric.CryptoResult{Error: "PIN Block必须为8字节Hex"}
	}
	ct, err := sm2.EncryptASN1(rand.Reader, sm2Pub, blockBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM2 PIN加密失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(ct)}
}

func SM2DecryptPIN(req SM2PINRequest) symmetric.CryptoResult {
	priv, err := parseSM2PrivateKeyPIN(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	blockBytes, err := decodeHex(req.Block)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密文: " + err.Error()}
	}
	pt, err := sm2.Decrypt(priv, blockBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM2 PIN解密失败: " + err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(pt)}
}

func parseSM2PublicKeyPIN(key string) (*ecdsa.PublicKey, error) {
	key = strings.TrimSpace(key)
	if strings.Contains(key, "-----BEGIN") {
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, errors.New("无效的PEM格式")
		}
		pubIface, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("PEM解析公钥失败: " + err.Error())
		}
		pub, ok := pubIface.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("不是有效的SM2公钥")
		}
		return pub, nil
	}
	return nil, errors.New("SM2公钥需要PEM格式")
}

func parseSM2PrivateKeyPIN(key string) (*sm2.PrivateKey, error) {
	key = strings.TrimSpace(key)
	if strings.Contains(key, "-----BEGIN") {
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, errors.New("无效的PEM格式")
		}
		priv, err := smx509.ParseSM2PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("PEM解析私钥失败: " + err.Error())
		}
		return priv, nil
	}
	return nil, errors.New("SM2私钥需要PEM格式")
}

// SM4 PIN 加解密 (GMT 0045-2016)
// ============================================================
func SM4EncryptPIN(req SM4PINRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	if len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须为16字节"}
	}
	blockBytes, err := decodeHex(req.Block)
	if err != nil || len(blockBytes) != 8 {
		return symmetric.CryptoResult{Error: "PIN Block必须为8字节Hex"}
	}
	block, err := sm4.NewCipher(keyBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}
	out := make([]byte, 8)
	block.Encrypt(out, blockBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
}

func SM4DecryptPIN(req SM4PINRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	if len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须为16字节"}
	}
	blockBytes, err := decodeHex(req.Block)
	if err != nil || len(blockBytes) != 8 {
		return symmetric.CryptoResult{Error: "PIN Block必须为8字节Hex"}
	}
	block, err := sm4.NewCipher(keyBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}
	out := make([]byte, 8)
	block.Decrypt(out, blockBytes)
	return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
}

// ============================================================
// PVV (Visa PIN Verification Value)
// ============================================================

func ComputePVV(req PVVRequest) PVVResult {
	pvk, err := decodeHex(req.PVK)
	if err != nil {
		return PVVResult{Error: "无效的PVK: " + err.Error()}
	}
	pvki := strings.TrimSpace(req.PVKI)
	if pvki == "" || !isDigits(pvki) || len(pvki) != 1 {
		return PVVResult{Error: "PVKI必须为1位数字"}
	}
	pin := strings.TrimSpace(req.PIN)
	if !isDigits(pin) || len(pin) != 4 {
		return PVVResult{Error: "PIN必须为4位数字"}
	}
	pan11 := strings.TrimSpace(req.PAN11)
	if !isDigits(pan11) || len(pan11) != 11 {
		return PVVResult{Error: "PAN11必须为11位数字(右起11位, 去校验位)"}
	}

	dataDigits := pvki + pin + pan11
	b, err := bcdEncode(dataDigits)
	if err != nil {
		return PVVResult{Error: "输入编码失败: " + err.Error()}
	}
	enc, err := tdesECBEncrypt(pvk, b)
	if err != nil {
		return PVVResult{Error: "PVV计算失败: " + err.Error()}
	}
	decTable := normalizeDecTable(req.DecTable)
	dec, err := decimalize(enc, decTable)
	if err != nil {
		return PVVResult{Error: "十进制化失败: " + err.Error()}
	}
	return PVVResult{Success: true, PVV: dec[:4]}
}

// ============================================================
// CVV / CVC / CVN / CSC
// ============================================================

func ComputeCVV(req CVVRequest) CVVResult {
	cvk, err := decodeHex(req.CVK)
	if err != nil {
		return CVVResult{Error: "无效的CVK: " + err.Error()}
	}
	pan := strings.TrimSpace(req.PAN)
	exp := strings.TrimSpace(req.Exp)
	svc := strings.TrimSpace(req.Service)
	if !isDigits(pan) || len(pan) < 13 || len(pan) > 19 {
		return CVVResult{Error: "PAN长度应为13-19位数字"}
	}
	if !isDigits(exp) || len(exp) != 4 {
		return CVVResult{Error: "有效期必须为YYMM(4位数字)"}
	}
	if !isDigits(svc) || len(svc) != 3 {
		return CVVResult{Error: "服务代码必须为3位数字"}
	}
	length := req.Length
	if length == 0 {
		length = 3
	}
	if length != 3 && length != 4 {
		return CVVResult{Error: "长度仅支持3或4"}
	}

	dataDigits := pan + exp + svc
	if len(dataDigits) > 32 {
		return CVVResult{Error: "输入数据过长"}
	}
	for len(dataDigits) < 32 {
		dataDigits += "0"
	}
	b, err := bcdEncode(dataDigits)
	if err != nil {
		return CVVResult{Error: "输入编码失败: " + err.Error()}
	}
	out, err := tdesCBCEncrypt(cvk, b, make([]byte, 8))
	if err != nil {
		return CVVResult{Error: "CVV计算失败: " + err.Error()}
	}
	last := out[len(out)-8:]
	decTable := normalizeDecTable(req.DecTable)
	dec, err := decimalize(last, decTable)
	if err != nil {
		return CVVResult{Error: "十进制化失败: " + err.Error()}
	}
	return CVVResult{Success: true, CVV: dec[:length]}
}

// ============================================================
// EMV UDK (PAN + PSN) / Double-One-Way
// ============================================================

func DeriveEMVUDK(req UDKRequest) UDKResult {
	mdk, err := decodeHex(req.MDK)
	if err != nil {
		return UDKResult{Error: "无效的MDK: " + err.Error()}
	}
	pan := strings.TrimSpace(req.PAN)
	psn := strings.TrimSpace(req.PSN)
	if !isDigits(psn) || len(psn) != 2 {
		return UDKResult{Error: "PSN必须为2位数字"}
	}
	panClean := digitsOnly(pan)
	if len(panClean) < 13 {
		return UDKResult{Error: "PAN长度不足"}
	}
	// 标准(EMV Book 2 A1.4.1 Option A): 派生数据 Y = (PAN || PSN) 右起16位
	dataDigits := panClean + psn
	if len(dataDigits) > 16 {
		dataDigits = dataDigits[len(dataDigits)-16:]
	}
	if len(dataDigits) < 16 {
		return UDKResult{Error: "PAN+PSN长度不足16位"}
	}
	dataBytes, err := bcdEncode(dataDigits)
	if err != nil {
		return UDKResult{Error: "分散数据编码失败: " + err.Error()}
	}
	left, err := tdesECBEncrypt(mdk, dataBytes)
	if err != nil {
		return UDKResult{Error: "分散计算失败: " + err.Error()}
	}
	xor := xorBytes(dataBytes, bytesRepeat(0xFF, 8))
	right, err := tdesECBEncrypt(mdk, xor)
	if err != nil {
		return UDKResult{Error: "分散计算失败: " + err.Error()}
	}
	return UDKResult{
		Success: true,
		Left:    hexUpper(left),
		Right:   hexUpper(right),
		UDK:     hexUpper(append(left, right...)),
	}
}

// SM4 UDK 分散 (GMT 0045-2016)
// ============================================================
func DeriveSM4UDK(req SM4UDKRequest) UDKResult {
	mdk, err := decodeHex(req.MDK)
	if err != nil {
		return UDKResult{Error: "无效的MDK: " + err.Error()}
	}
	if len(mdk) != 16 {
		return UDKResult{Error: "SM4 MDK必须为16字节"}
	}
	pan := strings.TrimSpace(req.PAN)
	psn := strings.TrimSpace(req.PSN)
	if !isDigits(psn) || len(psn) != 2 {
		return UDKResult{Error: "PSN必须为2位数字"}
	}
	panClean := digitsOnly(pan)
	if len(panClean) < 13 {
		return UDKResult{Error: "PAN长度不足"}
	}
	// 取右起16位(不含校验位)
	core := panClean[:len(panClean)-1]
	if len(core) > 16 {
		core = core[len(core)-16:]
	}
	if len(core) < 16 {
		return UDKResult{Error: "PAN长度不足16位(去校验位后)"}
	}
	// 填充到16字节: 前14位PAN + PSN + 0xF
	dataDigits := core[:14] + psn + "F"
	dataBytes, err := bcdEncode(dataDigits)
	if err != nil {
		return UDKResult{Error: "分散数据编码失败: " + err.Error()}
	}
	// 不足16字节用0xFF填充
	if len(dataBytes) < 16 {
		padded := make([]byte, 16)
		copy(padded, dataBytes)
		for i := len(dataBytes); i < 16; i++ {
			padded[i] = 0xFF
		}
		dataBytes = padded
	}

	block, err := sm4.NewCipher(mdk)
	if err != nil {
		return UDKResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}

	// Left: Encrypt(dataBytes)
	left := make([]byte, 16)
	block.Encrypt(left, dataBytes)

	// Right: Encrypt(dataBytes XOR 0xFF)
	xorData := make([]byte, 16)
	for i := 0; i < 16; i++ {
		xorData[i] = dataBytes[i] ^ 0xFF
	}
	right := make([]byte, 16)
	block.Encrypt(right, xorData)

	return UDKResult{
		Success: true,
		Left:    hexUpper(left),
		Right:   hexUpper(right),
		UDK:     hexUpper(append(left, right...)),
	}
}

func DoubleOneWay(req DOWRequest) DOWResult {
	key, err := decodeHex(req.Key)
	if err != nil {
		return DOWResult{Error: "无效的密钥: " + err.Error()}
	}
	data, err := decodeHex(req.Data)
	if err != nil || len(data) != 8 {
		return DOWResult{Error: "数据必须为8字节Hex"}
	}
	left, err := tdesECBEncrypt(key, data)
	if err != nil {
		return DOWResult{Error: "DOW计算失败: " + err.Error()}
	}
	xor := xorBytes(data, bytesRepeat(0xFF, 8))
	right, err := tdesECBEncrypt(key, xor)
	if err != nil {
		return DOWResult{Error: "DOW计算失败: " + err.Error()}
	}
	return DOWResult{
		Success: true,
		Left:    hexUpper(left),
		Right:   hexUpper(right),
		Out:     hexUpper(append(left, right...)),
	}
}

// ============================================================
// EMV AC / ARQC / Script MAC
// ============================================================

func ComputeARQC(req EMVACRequest) symmetric.CryptoResult {
	return RetailMAC(RetailMACRequest{Key: req.Key, Data: req.Data, Padding: req.Padding})
}

// ============================================================
// 3DES Data Encrypt/Decrypt (Finance)
// ============================================================

func TDESEncrypt(req TDESRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	padMethod := normalizePad(req.Padding)
	if padMethod == "" {
		padMethod = "ISO9797-1-P2"
	}
	dataBytes = padData(dataBytes, 8, padMethod)
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "ECB"
	}
	switch mode {
	case "ECB":
		out, err := tdesECBEncrypt(keyBytes, dataBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "3DES加密失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	case "CBC":
		iv := make([]byte, 8)
		if strings.TrimSpace(req.IV) != "" {
			iv, err = decodeHex(req.IV)
			if err != nil || len(iv) != 8 {
				return symmetric.CryptoResult{Error: "IV必须为8字节Hex"}
			}
		}
		out, err := tdesCBCEncrypt(keyBytes, dataBytes, iv)
		if err != nil {
			return symmetric.CryptoResult{Error: "3DES加密失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out), Extra: hexUpper(iv)}
	default:
		return symmetric.CryptoResult{Error: "不支持的模式: " + mode}
	}
}

func TDESDecrypt(req TDESRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "ECB"
	}
	switch mode {
	case "ECB":
		out, err := tdesECBDecrypt(keyBytes, dataBytes)
		if err != nil {
			return symmetric.CryptoResult{Error: "3DES解密失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	case "CBC":
		iv, err := decodeHex(req.IV)
		if err != nil || len(iv) != 8 {
			return symmetric.CryptoResult{Error: "IV必须为8字节Hex"}
		}
		out, err := tdesCBCDecrypt(keyBytes, dataBytes, iv)
		if err != nil {
			return symmetric.CryptoResult{Error: "3DES解密失败: " + err.Error()}
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	default:
		return symmetric.CryptoResult{Error: "不支持的模式: " + mode}
	}
}

// SM4 金融加解密 (GMT 0045-2016 / GM/T 0002-2012)
// ============================================================

func SM4EncryptFinance(req SM4FinanceRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	if len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须为16字节"}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	block, err := sm4.NewCipher(keyBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}

	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "ECB"
	}
	padding := normalizeFinancePad(req.Padding)

	switch mode {
	case "ECB":
		padded := padDataSM4Finance(dataBytes, 16, padding)
		if len(padded) == 0 || len(padded)%16 != 0 {
			return symmetric.CryptoResult{Error: "ECB模式: 明文填充后长度必须是16字节的倍数(可改用PKCS7/Zero/ISO9797填充)"}
		}
		out := make([]byte, len(padded))
		for i := 0; i < len(padded); i += 16 {
			block.Encrypt(out[i:i+16], padded[i:i+16])
		}
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	case "CBC":
		var iv []byte
		if req.IV == "" {
			// 未提供 IV 时随机生成, 通过 Extra 返回, 与解密端保持一致
			iv = make([]byte, 16)
			rand.Read(iv)
		} else {
			var err error
			iv, err = decodeHex(req.IV)
			if err != nil || len(iv) != 16 {
				return symmetric.CryptoResult{Error: "CBC模式需要16字节IV"}
			}
		}
		padded := padDataSM4Finance(dataBytes, 16, padding)
		if len(padded) == 0 || len(padded)%16 != 0 {
			return symmetric.CryptoResult{Error: "CBC模式: 明文填充后长度必须是16字节的倍数(可改用PKCS7/Zero/ISO9797填充)"}
		}
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out), Extra: hexUpper(iv)}
	default:
		return symmetric.CryptoResult{Error: "不支持的模式: " + mode}
	}
}

func SM4DecryptFinance(req SM4FinanceRequest) symmetric.CryptoResult {
	keyBytes, err := decodeHex(req.Key)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的密钥: " + err.Error()}
	}
	if len(keyBytes) != 16 {
		return symmetric.CryptoResult{Error: "SM4密钥必须为16字节"}
	}
	dataBytes, err := decodeHex(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效的数据: " + err.Error()}
	}

	block, err := sm4.NewCipher(keyBytes)
	if err != nil {
		return symmetric.CryptoResult{Error: "SM4 cipher初始化失败: " + err.Error()}
	}

	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "ECB"
	}
	padding := normalizeFinancePad(req.Padding)

	switch mode {
	case "ECB":
		if len(dataBytes) == 0 || len(dataBytes)%16 != 0 {
			return symmetric.CryptoResult{Error: "ECB解密: 密文长度必须是16字节的倍数"}
		}
		out := make([]byte, len(dataBytes))
		for i := 0; i < len(dataBytes); i += 16 {
			block.Decrypt(out[i:i+16], dataBytes[i:i+16])
		}
		out = unpadDataSM4(out, padding)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	case "CBC":
		iv, err := decodeHex(req.IV)
		if err != nil || len(iv) != 16 {
			return symmetric.CryptoResult{Error: "CBC模式需要16字节IV"}
		}
		if len(dataBytes) == 0 || len(dataBytes)%16 != 0 {
			return symmetric.CryptoResult{Error: "CBC解密: 密文长度必须是16字节的倍数"}
		}
		out := make([]byte, len(dataBytes))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, dataBytes)
		out = unpadDataSM4(out, padding)
		return symmetric.CryptoResult{Success: true, Data: hexUpper(out)}
	default:
		return symmetric.CryptoResult{Error: "不支持的模式: " + mode}
	}
}

func padDataSM4Finance(data []byte, blockSize int, padding string) []byte {
	switch padding {
	case "NoPadding":
		return data
	case "PKCS7":
		padLen := blockSize - (len(data) % blockSize)
		padded := make([]byte, len(data)+padLen)
		copy(padded, data)
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(padLen)
		}
		return padded
	case "ISO9797-1-P1", "Zero":
		// ISO 9797-1 method 1: 补全零
		padded := make([]byte, ((len(data)+blockSize-1)/blockSize)*blockSize)
		copy(padded, data)
		return padded
	default:
		padded := make([]byte, ((len(data)+blockSize-1)/blockSize)*blockSize)
		copy(padded, data)
		if len(data) == 0 || len(data)%blockSize != 0 {
			padded[len(data)] = 0x80
		}
		return padded
	}
}

func unpadDataSM4(data []byte, padding string) []byte {
	switch padding {
	case "NoPadding":
		return data
	case "PKCS7":
		if len(data) == 0 {
			return data
		}
		padLen := int(data[len(data)-1])
		if padLen > 16 || padLen > len(data) {
			return data
		}
		return data[:len(data)-padLen]
	case "ISO9797-1-P1", "Zero":
		i := len(data) - 1
		for i >= 0 && data[i] == 0 {
			i--
		}
		return data[:i+1]
	default:
		i := len(data) - 1
		for i >= 0 && data[i] == 0 {
			i--
		}
		if i >= 0 && data[i] == 0x80 {
			return data[:i]
		}
		return data
	}
}

func normalizeFinancePad(padding string) string {
	p := strings.ToUpper(strings.TrimSpace(padding))
	switch p {
	case "ISO9797-1-P1":
		return "ISO9797-1-P1"
	case "ISO9797-1-P2":
		return "ISO9797-1-P2"
	case "PKCS7", "PKCS5":
		return "PKCS7"
	default:
		return "ISO9797-1-P2"
	}
}

// ============================================================
// Helpers
// ============================================================

func retailMAC(key, data []byte, padding string) ([]byte, error) {
	k1, k2, k3, err := splitTDESKeys(key)
	if err != nil {
		return nil, err
	}
	padded := padData(data, 8, padding)
	mac, err := cbcMACDES(k1, padded)
	if err != nil {
		return nil, err
	}
	dec, err := desECBDecrypt(k2, mac)
	if err != nil {
		return nil, err
	}
	enc, err := desECBEncrypt(k3, dec)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func cbcMACDES(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	x := make([]byte, 8)
	for i := 0; i < len(data); i += 8 {
		for j := 0; j < 8; j++ {
			x[j] ^= data[i+j]
		}
		block.Encrypt(x, x)
	}
	return x, nil
}

func desECBEncrypt(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Encrypt(out[i:i+8], data[i:i+8])
	}
	return out, nil
}

func desECBDecrypt(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Decrypt(out[i:i+8], data[i:i+8])
	}
	return out, nil
}

func tdesECBEncrypt(key, data []byte) ([]byte, error) {
	k, err := expandTDESKey(key)
	if err != nil {
		return nil, err
	}
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return nil, err
	}
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Encrypt(out[i:i+8], data[i:i+8])
	}
	return out, nil
}

func tdesECBDecrypt(key, data []byte) ([]byte, error) {
	k, err := expandTDESKey(key)
	if err != nil {
		return nil, err
	}
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return nil, err
	}
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Decrypt(out[i:i+8], data[i:i+8])
	}
	return out, nil
}

func tdesCBCEncrypt(key, data []byte, iv []byte) ([]byte, error) {
	k, err := expandTDESKey(key)
	if err != nil {
		return nil, err
	}
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return nil, err
	}
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	if len(iv) != 8 {
		return nil, errors.New("IV长度必须为8字节")
	}
	out := make([]byte, len(data))
	prev := make([]byte, 8)
	copy(prev, iv)
	for i := 0; i < len(data); i += 8 {
		blockIn := xorBytes(data[i:i+8], prev)
		block.Encrypt(out[i:i+8], blockIn)
		copy(prev, out[i:i+8])
	}
	return out, nil
}

func tdesCBCDecrypt(key, data []byte, iv []byte) ([]byte, error) {
	k, err := expandTDESKey(key)
	if err != nil {
		return nil, err
	}
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return nil, err
	}
	if len(data)%8 != 0 {
		return nil, errors.New("数据长度必须为8字节倍数")
	}
	if len(iv) != 8 {
		return nil, errors.New("IV长度必须为8字节")
	}
	out := make([]byte, len(data))
	prev := make([]byte, 8)
	copy(prev, iv)
	for i := 0; i < len(data); i += 8 {
		block.Decrypt(out[i:i+8], data[i:i+8])
		for j := 0; j < 8; j++ {
			out[i+j] ^= prev[j]
		}
		copy(prev, data[i:i+8])
	}
	return out, nil
}

func splitTDESKeys(key []byte) ([]byte, []byte, []byte, error) {
	switch len(key) {
	case 16:
		return key[:8], key[8:16], key[:8], nil
	case 24:
		return key[:8], key[8:16], key[16:24], nil
	default:
		return nil, nil, nil, errors.New("密钥长度必须为16或24字节")
	}
}

func expandTDESKey(key []byte) ([]byte, error) {
	if len(key) == 16 {
		return append(append([]byte{}, key...), key[:8]...), nil
	}
	if len(key) == 24 {
		return key, nil
	}
	return nil, errors.New("密钥长度必须为16或24字节")
}

func padData(data []byte, blockSize int, method string) []byte {
	switch method {
	case "ISO9797-1-P1":
		if len(data)%blockSize == 0 {
			return data
		}
		pad := blockSize - (len(data) % blockSize)
		return append(data, bytesRepeat(0x00, pad)...)
	case "ISO9797-1-P2":
		pad := blockSize - (len(data) % blockSize)
		if pad == 0 {
			pad = blockSize
		}
		out := append([]byte{}, data...)
		out = append(out, 0x80)
		out = append(out, bytesRepeat(0x00, pad-1)...)
		return out
	default:
		return data
	}
}

func normalizePad(p string) string {
	up := strings.ToUpper(strings.TrimSpace(p))
	switch up {
	case "ISO9797-1-P1", "P1":
		return "ISO9797-1-P1"
	case "ISO9797-1-P2", "P2", "":
		return "ISO9797-1-P2"
	default:
		return up
	}
}

func cleanHex(s string) string {
	out := strings.TrimSpace(s)
	out = strings.ReplaceAll(out, " ", "")
	out = strings.ReplaceAll(out, "\n", "")
	out = strings.ReplaceAll(out, "\t", "")
	out = strings.ReplaceAll(out, "0x", "")
	out = strings.ReplaceAll(out, "0X", "")
	return out
}

func decodeHex(s string) ([]byte, error) {
	clean := cleanHex(s)
	if clean == "" {
		return nil, errors.New("输入为空")
	}
	if len(clean)%2 != 0 {
		return nil, hex.ErrLength
	}
	return hex.DecodeString(clean)
}

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func xorHex(a, b string) string {
	ab, _ := hex.DecodeString(a)
	bb, _ := hex.DecodeString(b)
	out := xorBytes(ab, bb)
	return hex.EncodeToString(out)
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		if i < len(b) {
			out[i] = a[i] ^ b[i]
		} else {
			out[i] = a[i]
		}
	}
	return out
}

func bytesRepeat(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func pan12FromPAN(pan string) (string, error) {
	p := digitsOnly(pan)
	if len(p) < 13 {
		return "", errors.New("PAN长度不足，至少13位")
	}
	core := p[:len(p)-1]
	if len(core) < 12 {
		return "", errors.New("PAN长度不足")
	}
	return core[len(core)-12:], nil
}

func buildPINField(format, pin, rand string) (string, string, error) {
	pinLen := len(pin)
	lenNibble := fmt.Sprintf("%X", pinLen)
	switch format {
	case "ISO-0":
		out := "0" + lenNibble + pin
		for len(out) < 16 {
			out += "F"
		}
		return out, "", nil
	case "ISO-3":
		out := "3" + lenNibble + pin
		randDigits := strings.TrimSpace(rand)
		if randDigits != "" && !isDigits(randDigits) {
			return "", "", errors.New("随机填充必须为数字")
		}
		if randDigits == "" {
			randDigits = randomDigits(16 - len(out))
		}
		for len(out) < 16 {
			if randDigits != "" {
				out += randDigits[:1]
				randDigits = randDigits[1:]
			} else {
				out += "0"
			}
		}
		return out, out[2+pinLen:], nil
	default:
		return "", "", errors.New("不支持的PIN Block格式")
	}
}

func hexDigitToInt(h string) (int, error) {
	if len(h) != 1 {
		return 0, errors.New("长度错误")
	}
	v, err := hex.DecodeString("0" + h)
	if err != nil || len(v) == 0 {
		return 0, errors.New("解析失败")
	}
	return int(v[0]), nil
}

func bcdEncode(digits string) ([]byte, error) {
	if len(digits)%2 != 0 {
		return nil, errors.New("数字长度必须为偶数")
	}
	out := make([]byte, len(digits)/2)
	for i := 0; i < len(digits); i += 2 {
		hi := digits[i]
		lo := digits[i+1]
		if hi < '0' || hi > '9' || lo < '0' || lo > '9' {
			return nil, errors.New("仅支持数字")
		}
		out[i/2] = (hi-'0')<<4 | (lo - '0')
	}
	return out, nil
}

func normalizeDecTable(table string) string {
	t := strings.TrimSpace(table)
	if t == "" {
		return "0123456789012345"
	}
	if len(t) != 16 || !isDigits(t) {
		return "0123456789012345"
	}
	return t
}

func decimalize(data []byte, table string) (string, error) {
	if len(table) != 16 {
		return "", errors.New("十进制化表长度必须为16")
	}
	var b strings.Builder
	for _, v := range data {
		hi := table[(v>>4)&0x0F]
		lo := table[v&0x0F]
		b.WriteByte(hi)
		b.WriteByte(lo)
	}
	out := b.String()
	if len(out) < 4 {
		return "", errors.New("十进制化失败")
	}
	return out, nil
}

func randomDigits(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	for i := range buf {
		buf[i] = '0' + (buf[i] % 10)
	}
	return string(buf)
}
