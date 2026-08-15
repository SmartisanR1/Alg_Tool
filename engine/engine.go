// Package engine 是 CryptoKit 的密码计算引擎，由 C# WinUI3 前端以子进程方式
// 拉起，通过 stdio JSON-RPC 调用。
//
// 引擎只保留纯计算 / 以文件路径为输入的方法，不承担任何 UI 职责
// （窗口、主题、强调色、文件对话框等均由 WinUI3 原生 API 处理）。
// 所有方法均返回单一结果结构体（JSON 可直接序列化），便于反射分发。
package engine

import (
	"os"

	"cryptokit/crypto/asymmetric"
	"cryptokit/crypto/finance"
	"cryptokit/crypto/gm"
	"cryptokit/crypto/hash"
	"cryptokit/crypto/kdf"
	"cryptokit/crypto/mac"
	"cryptokit/crypto/pqc"
	"cryptokit/crypto/symmetric"
	"cryptokit/crypto/utils"
)

// Engine 聚合所有密码计算能力。方法签名与旧 App 完全一致，
// 仅接收器名从 *App 改为 *Engine。
type Engine struct{}

// NewEngine 返回一个空引擎（无状态，所有方法均为纯函数）。
func NewEngine() *Engine {
	return &Engine{}
}

// ============================================================
// 对称加密 API
// ============================================================

func (e *Engine) AESEncrypt(req symmetric.AESRequest) symmetric.CryptoResult {
	return symmetric.AESEncrypt(req)
}

func (e *Engine) AESDecrypt(req symmetric.AESRequest) symmetric.CryptoResult {
	return symmetric.AESDecrypt(req)
}

func (e *Engine) DESEncrypt(req symmetric.DESRequest) symmetric.CryptoResult {
	return symmetric.DESEncrypt(req)
}

func (e *Engine) DESDecrypt(req symmetric.DESRequest) symmetric.CryptoResult {
	return symmetric.DESDecrypt(req)
}

func (e *Engine) ChaCha20Encrypt(req symmetric.ChaChaRequest) symmetric.CryptoResult {
	return symmetric.ChaCha20Encrypt(req)
}

func (e *Engine) ChaCha20Decrypt(req symmetric.ChaChaRequest) symmetric.CryptoResult {
	return symmetric.ChaCha20Decrypt(req)
}

func (e *Engine) RC4Encrypt(req symmetric.RC4Request) symmetric.CryptoResult {
	return symmetric.RC4Encrypt(req)
}

func (e *Engine) RC4Decrypt(req symmetric.RC4Request) symmetric.CryptoResult {
	return symmetric.RC4Decrypt(req)
}

func (e *Engine) SIVEncrypt(req symmetric.SIVRequest) symmetric.CryptoResult {
	return symmetric.SIVEncrypt(req)
}

func (e *Engine) SIVDecrypt(req symmetric.SIVRequest) symmetric.CryptoResult {
	return symmetric.SIVDecrypt(req)
}

func (e *Engine) FPEEncrypt(req symmetric.FPERequest) symmetric.CryptoResult {
	return symmetric.FPEEncrypt(req)
}

func (e *Engine) FPEDecrypt(req symmetric.FPERequest) symmetric.CryptoResult {
	return symmetric.FPEDecrypt(req)
}

// ============================================================
// 非对称加密 API
// ============================================================

func (e *Engine) RSAGenerateKey(bits int) asymmetric.KeyPairResult {
	return asymmetric.RSAGenerateKey(bits)
}

func (e *Engine) RSAEncrypt(req asymmetric.RSARequest) symmetric.CryptoResult {
	return asymmetric.RSAEncrypt(req)
}

func (e *Engine) RSADecrypt(req asymmetric.RSARequest) symmetric.CryptoResult {
	return asymmetric.RSADecrypt(req)
}

func (e *Engine) RSASign(req asymmetric.RSASignRequest) symmetric.CryptoResult {
	return asymmetric.RSASign(req)
}

func (e *Engine) RSAVerify(req asymmetric.RSAVerifyRequest) symmetric.CryptoResult {
	return asymmetric.RSAVerify(req)
}

func (e *Engine) ECCGenerateKey(curve string) asymmetric.KeyPairResult {
	return asymmetric.ECCGenerateKey(curve)
}

func (e *Engine) ECCSign(req asymmetric.ECCRequest) symmetric.CryptoResult {
	return asymmetric.ECCSign(req)
}

func (e *Engine) ECCVerify(req asymmetric.ECCVerifyRequest) symmetric.CryptoResult {
	return asymmetric.ECCVerify(req)
}

func (e *Engine) ECDHCompute(req asymmetric.ECDHRequest) symmetric.CryptoResult {
	return asymmetric.ECDHCompute(req)
}

func (e *Engine) X25519KeyGen() asymmetric.KeyPairResult {
	return asymmetric.X25519KeyGen()
}

func (e *Engine) X25519Exchange(req asymmetric.X25519Request) symmetric.CryptoResult {
	return asymmetric.X25519Exchange(req)
}

func (e *Engine) Ed25519KeyGen() asymmetric.KeyPairResult {
	return asymmetric.Ed25519KeyGen()
}

func (e *Engine) Ed25519Sign(req asymmetric.EdDSARequest) symmetric.CryptoResult {
	return asymmetric.Ed25519Sign(req)
}

func (e *Engine) Ed25519Verify(req asymmetric.EdDSAVerifyRequest) symmetric.CryptoResult {
	return asymmetric.Ed25519Verify(req)
}

func (e *Engine) Ed448KeyGen() asymmetric.KeyPairResult {
	return asymmetric.Ed448KeyGen()
}

func (e *Engine) Ed448Sign(req asymmetric.Ed448Request) symmetric.CryptoResult {
	return asymmetric.Ed448Sign(req)
}

func (e *Engine) Ed448Verify(req asymmetric.Ed448VerifyRequest) symmetric.CryptoResult {
	return asymmetric.Ed448Verify(req)
}

// ============================================================
// 哈希 / HMAC API
// ============================================================

func (e *Engine) Hash(req hash.HashRequest) symmetric.CryptoResult {
	return hash.Compute(req)
}

func (e *Engine) HMAC(req hash.HMACRequest) symmetric.CryptoResult {
	return hash.ComputeHMAC(req)
}

// ============================================================
// MAC API
// ============================================================

func (e *Engine) ComputeMAC(req mac.MACRequest) symmetric.CryptoResult {
	return mac.Compute(req)
}

// ============================================================
// 金融密码 API
// ============================================================

func (e *Engine) RetailMAC(req finance.RetailMACRequest) symmetric.CryptoResult {
	return finance.RetailMAC(req)
}

func (e *Engine) GeneratePINBlock(req finance.PINBlockRequest) finance.PINBlockResult {
	return finance.GeneratePINBlock(req)
}

func (e *Engine) ParsePINBlock(req finance.PINBlockParseRequest) finance.PINParseResult {
	return finance.ParsePINBlock(req)
}

func (e *Engine) EncryptPINBlock(req finance.PINEncryptRequest) symmetric.CryptoResult {
	return finance.EncryptPINBlock(req)
}

func (e *Engine) DecryptPINBlock(req finance.PINEncryptRequest) symmetric.CryptoResult {
	return finance.DecryptPINBlock(req)
}

func (e *Engine) ComputePVV(req finance.PVVRequest) finance.PVVResult {
	return finance.ComputePVV(req)
}

func (e *Engine) ComputeCVV(req finance.CVVRequest) finance.CVVResult {
	return finance.ComputeCVV(req)
}

func (e *Engine) DeriveEMVUDK(req finance.UDKRequest) finance.UDKResult {
	return finance.DeriveEMVUDK(req)
}

func (e *Engine) DoubleOneWay(req finance.DOWRequest) finance.DOWResult {
	return finance.DoubleOneWay(req)
}

func (e *Engine) ComputeARQC(req finance.EMVACRequest) symmetric.CryptoResult {
	return finance.ComputeARQC(req)
}

func (e *Engine) TDESEncrypt(req finance.TDESRequest) symmetric.CryptoResult {
	return finance.TDESEncrypt(req)
}

func (e *Engine) TDESDecrypt(req finance.TDESRequest) symmetric.CryptoResult {
	return finance.TDESDecrypt(req)
}

func (e *Engine) SM4MAC(req finance.SM4MACRequest) symmetric.CryptoResult {
	return finance.SM4MAC(req)
}

func (e *Engine) SM4EncryptFinance(req finance.SM4FinanceRequest) symmetric.CryptoResult {
	return finance.SM4EncryptFinance(req)
}

func (e *Engine) SM4DecryptFinance(req finance.SM4FinanceRequest) symmetric.CryptoResult {
	return finance.SM4DecryptFinance(req)
}

func (e *Engine) SM4CMAC(req finance.SM4CMACRequest) symmetric.CryptoResult {
	return finance.SM4CMAC(req)
}

func (e *Engine) SM2EncryptPIN(req finance.SM2PINRequest) symmetric.CryptoResult {
	return finance.SM2EncryptPIN(req)
}

func (e *Engine) SM2DecryptPIN(req finance.SM2PINRequest) symmetric.CryptoResult {
	return finance.SM2DecryptPIN(req)
}

func (e *Engine) SM4EncryptPIN(req finance.SM4PINRequest) symmetric.CryptoResult {
	return finance.SM4EncryptPIN(req)
}

func (e *Engine) SM4DecryptPIN(req finance.SM4PINRequest) symmetric.CryptoResult {
	return finance.SM4DecryptPIN(req)
}

func (e *Engine) DeriveSM4UDK(req finance.SM4UDKRequest) finance.UDKResult {
	return finance.DeriveSM4UDK(req)
}

// ============================================================
// KDF API
// ============================================================

func (e *Engine) DeriveKey(req kdf.KDFRequest) symmetric.CryptoResult {
	return kdf.Derive(req)
}

// ============================================================
// 国密算法 API
// ============================================================

func (e *Engine) SM2GenerateKey() gm.SM2KeyResult {
	return gm.SM2GenerateKey()
}

func (e *Engine) SM2GenerateRawKey() gm.SM2KeyResult {
	return gm.SM2GenerateRawKey()
}

func (e *Engine) SM2Encrypt(req gm.SM2Request) symmetric.CryptoResult {
	return gm.SM2Encrypt(req)
}

func (e *Engine) SM2Decrypt(req gm.SM2Request) symmetric.CryptoResult {
	return gm.SM2Decrypt(req)
}

func (e *Engine) SM2Sign(req gm.SM2SignRequest) symmetric.CryptoResult {
	return gm.SM2Sign(req)
}

func (e *Engine) SM2Verify(req gm.SM2VerifyRequest) symmetric.CryptoResult {
	return gm.SM2Verify(req)
}

func (e *Engine) SM2KeyAgreement(req gm.SM2KeyAgreementRequest) symmetric.CryptoResult {
	return gm.SM2KeyAgreement(req)
}

func (e *Engine) SM3Hash(req gm.SM3Request) symmetric.CryptoResult {
	return gm.SM3Hash(req)
}

func (e *Engine) SM3HashWithID(req gm.SM3WithIDRequest) symmetric.CryptoResult {
	return gm.SM3HashWithID(req)
}

func (e *Engine) SM3HMAC(req gm.SM3HMACRequest) symmetric.CryptoResult {
	return gm.SM3HMAC(req)
}

func (e *Engine) SM4Encrypt(req gm.SM4Request) symmetric.CryptoResult {
	return gm.SM4Encrypt(req)
}

func (e *Engine) SM4Decrypt(req gm.SM4Request) symmetric.CryptoResult {
	return gm.SM4Decrypt(req)
}

func (e *Engine) SM9GenerateEncMasterKey() gm.SM9MasterKeyResult {
	return gm.SM9GenerateEncMasterKey()
}

func (e *Engine) SM9GenerateEncKey(masterPriv string, uid string) gm.SM9KeyResult {
	return gm.SM9GenerateEncKey(masterPriv, uid)
}

func (e *Engine) SM9Encrypt(req gm.SM9Request) symmetric.CryptoResult {
	return gm.SM9Encrypt(req)
}

func (e *Engine) SM9Decrypt(req gm.SM9Request) symmetric.CryptoResult {
	return gm.SM9Decrypt(req)
}

func (e *Engine) SM9GenerateMasterKey() gm.SM9MasterKeyResult {
	return gm.SM9GenerateMasterKey()
}

func (e *Engine) SM9Sign(req gm.SM9SignRequest) symmetric.CryptoResult {
	return gm.SM9Sign(req)
}

func (e *Engine) SM9Verify(req gm.SM9VerifyRequest) symmetric.CryptoResult {
	return gm.SM9Verify(req)
}

func (e *Engine) ZUCEncrypt(req gm.ZUCRequest) symmetric.CryptoResult {
	return gm.ZUCEncrypt(req)
}

func (e *Engine) ZUCDecrypt(req gm.ZUCRequest) symmetric.CryptoResult {
	return gm.ZUCDecrypt(req)
}

func (e *Engine) MakeGMEnvelope(req gm.GMEnvelopeRequest) symmetric.CryptoResult {
	return gm.MakeGMEnvelope(req)
}

func (e *Engine) OpenGMEnvelope(req gm.GMEnvelopeOpenRequest) symmetric.CryptoResult {
	return gm.OpenGMEnvelope(req)
}

// ============================================================
// 后量子密码 API
// ============================================================

func (e *Engine) MLKEMKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.MLKEMKeyGen(paramSet)
}

func (e *Engine) MLKEMEncapsulate(req pqc.MLKEMRequest) pqc.PQCEncapResult {
	return pqc.MLKEMEncapsulate(req)
}

func (e *Engine) MLKEMDecapsulate(req pqc.MLKEMDecapRequest) symmetric.CryptoResult {
	return pqc.MLKEMDecapsulate(req)
}

func (e *Engine) MLDSAKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.MLDSAKeyGen(paramSet)
}

func (e *Engine) MLDSASign(req pqc.MLDSARequest) symmetric.CryptoResult {
	return pqc.MLDSASign(req)
}

func (e *Engine) MLDSAVerify(req pqc.MLDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.MLDSAVerify(req)
}

func (e *Engine) SLHDSAKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.SLHDSAKeyGen(paramSet)
}

func (e *Engine) SLHDSASign(req pqc.SLHDSARequest) symmetric.CryptoResult {
	return pqc.SLHDSASign(req)
}

func (e *Engine) SLHDSAVerify(req pqc.SLHDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.SLHDSAVerify(req)
}

// ============================================================
// 工具 API
// ============================================================

func (e *Engine) HexToString(hex string) utils.ToolResult {
	return utils.HexToString(hex)
}

func (e *Engine) StringToHex(str string) utils.ToolResult {
	return utils.StringToHex(str)
}

func (e *Engine) Base64Encode(req utils.Base64Request) utils.ToolResult {
	return utils.Base64Encode(req)
}

func (e *Engine) Base64Decode(req utils.Base64Request) utils.ToolResult {
	return utils.Base64Decode(req)
}

func (e *Engine) XORCompute(req utils.XORRequest) utils.ToolResult {
	return utils.XORCompute(req)
}

func (e *Engine) URLEncode(str string) utils.ToolResult {
	return utils.URLEncode(str)
}

func (e *Engine) URLDecode(str string) utils.ToolResult {
	return utils.URLDecode(str)
}

func (e *Engine) GenerateRandom(req utils.RandomRequest) utils.ToolResult {
	return utils.GenerateRandom(req)
}

func (e *Engine) PaddingApply(req utils.PaddingRequest) utils.ToolResult {
	return utils.PaddingApply(req)
}

func (e *Engine) PaddingRemove(req utils.PaddingRequest) utils.ToolResult {
	return utils.PaddingRemove(req)
}

func (e *Engine) FormatJSON(str string) utils.ToolResult {
	return utils.FormatJSON(str)
}

func (e *Engine) TimestampConvert(req utils.TimestampRequest) utils.ToolResult {
	return utils.TimestampConvert(req)
}

func (e *Engine) UnicodeEncode(str string) utils.ToolResult {
	return utils.UnicodeEncode(str)
}

func (e *Engine) UnicodeDecode(str string) utils.ToolResult {
	return utils.UnicodeDecode(str)
}

func (e *Engine) BaseConvert(req utils.BaseConvertRequest) utils.ToolResult {
	return utils.BaseConvert(req)
}

func (e *Engine) ParseASN1(req utils.ASN1Request) utils.ToolResult {
	return utils.ParseASN1(req)
}

func (e *Engine) ParseASN1File(path string) utils.ToolResult {
	return utils.ParseASN1File(path)
}

func (e *Engine) Base32Encode(req utils.Base32Request) utils.ToolResult {
	return utils.Base32Encode(req)
}

func (e *Engine) Base32Decode(req utils.Base32Request) utils.ToolResult {
	return utils.Base32Decode(req)
}

func (e *Engine) Base58Encode(req utils.Base58Request) utils.ToolResult {
	return utils.Base58Encode(req)
}

func (e *Engine) Base58Decode(req utils.Base58Request) utils.ToolResult {
	return utils.Base58Decode(req)
}

func (e *Engine) Bech32Encode(req utils.Bech32EncodeRequest) utils.ToolResult {
	return utils.Bech32Encode(req)
}

func (e *Engine) Bech32Decode(input string) utils.Bech32DecodeResult {
	return utils.Bech32Decode(input)
}

func (e *Engine) ParseJWT(req utils.JWTRequest) utils.JWTResult {
	return utils.ParseJWT(req)
}

func (e *Engine) ConvertKey(req utils.KeyConvertRequest) utils.KeyConvertResult {
	return utils.ConvertKey(req)
}

func (e *Engine) VerifyCertChain(req utils.CertChainRequest) utils.CertChainResult {
	return utils.VerifyCertChain(req)
}

func (e *Engine) ParsePKCS12(req utils.PKCS12Request) utils.PKCS12Result {
	return utils.ParsePKCS12(req)
}

func (e *Engine) ParsePKCS12File(path string, password string) utils.PKCS12Result {
	return utils.ParsePKCS12File(path, password)
}

func (e *Engine) SendPacket(req utils.PacketIORequest) utils.PacketIOResult {
	return utils.SendPacket(req)
}

// PacketPerfTest 报文发送性能测试（真·多线程并发往返）
func (e *Engine) PacketPerfTest(req utils.PacketPerfRequest) utils.PacketPerfResult {
	return utils.PacketPerfTest(req)
}

func (e *Engine) HashFile(req utils.FileHashRequest) utils.ToolResult {
	return utils.HashFile(req)
}

func (e *Engine) EncryptFile(req utils.FileEncryptRequest) utils.ToolResult {
	return utils.EncryptFile(req)
}

func (e *Engine) DecryptFile(req utils.FileDecryptRequest) utils.ToolResult {
	return utils.DecryptFile(req)
}

// ============================================================
// 大数运算 & 证书 API
// ============================================================

func (e *Engine) BigIntOperation(req utils.BigIntRequest) utils.ToolResult {
	return utils.BigIntOperation(req)
}

func (e *Engine) GenerateCSR(req utils.CSRRequest) utils.ToolResult {
	return utils.GenerateCSR(req)
}

func (e *Engine) GenerateCertificate(req utils.CertGenRequest) utils.ToolResult {
	return utils.GenerateCertificate(req)
}

func (e *Engine) GenerateSelfSignedCert(req utils.SelfSignedCertRequest) utils.SelfSignedCertResult {
	return utils.GenerateSelfSignedCert(req)
}

func (e *Engine) GenerateInternalSignedCert(req utils.SelfSignedCertRequest) utils.InternalCAResult {
	return utils.GenerateInternalSignedCert(req)
}

func (e *Engine) GenerateDualCertificates(req utils.SelfSignedCertRequest) utils.DualCertResult {
	return utils.GenerateDualCertificates(req)
}

func (e *Engine) GetInternalRootCert(algo string) string {
	return utils.GetInternalRootCert(algo)
}

func (e *Engine) ParseCertificate(pemStr string) utils.ToolResult {
	return utils.ParseCertificate(pemStr)
}

// ReadFile 读取文件内容为字符串（供证书/ASN.1/PKCS12 等需要文件路径的界面使用）。
// 选择文件由 C# 原生 FileOpenPicker 完成，Go 引擎只负责读。
func (e *Engine) ReadFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// ============================================================
// 额外 PQC API
// ============================================================

func (e *Engine) FalconKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.FalconKeyGen(paramSet)
}

func (e *Engine) FalconSign(req pqc.SLHDSARequest) symmetric.CryptoResult {
	return pqc.FalconSign(req)
}

func (e *Engine) FalconVerify(req pqc.SLHDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.FalconVerify(req)
}

func (e *Engine) HQCKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.HQCKeyGen(paramSet)
}

func (e *Engine) AigisKeyGen(paramSet string) pqc.PQCKeyResult {
	return pqc.AigisKeyGen(paramSet)
}

func (e *Engine) AigisSign(req pqc.SLHDSARequest) symmetric.CryptoResult {
	return pqc.AigisSign(req)
}

func (e *Engine) AigisVerify(req pqc.SLHDSAVerifyRequest) symmetric.CryptoResult {
	return pqc.AigisVerify(req)
}

func (e *Engine) HQCEncapsulate(req pqc.MLKEMRequest) pqc.PQCEncapResult {
	return pqc.HQCEncapsulate(req)
}

func (e *Engine) HQCDecapsulate(req pqc.MLKEMDecapRequest) symmetric.CryptoResult {
	return pqc.HQCDecapsulate(req)
}

func (e *Engine) XWingKeyGen() pqc.PQCKeyResult {
	return pqc.XWingKeyGen()
}

func (e *Engine) XWingEncapsulate(req pqc.XWingRequest) pqc.PQCEncapResult {
	return pqc.XWingEncapsulate(req)
}

func (e *Engine) XWingDecapsulate(req pqc.XWingRequest) symmetric.CryptoResult {
	return pqc.XWingDecapsulate(req)
}

// ============================================================
// TLS/TLCP 连接测试 API
// ============================================================

func (e *Engine) TLSConnect(req utils.TLSConnectRequest) utils.TLSConnectResult {
	return utils.TLSConnect(req)
}

func (e *Engine) ListTLSCipherSuites() utils.ToolResult {
	return utils.ListTLSCipherSuites()
}

func (e *Engine) ListTLCPCipherSuites() utils.ToolResult {
	return utils.ListTLCPCipherSuites()
}

// TLS/TLCP 双向连接演示（左侧服务端 / 右侧客户端）
func (e *Engine) TLSDemoServerStart(req utils.TLSDemoStartRequest) utils.TLSDemoResult {
	return utils.TLSDemoServerStart(req)
}

func (e *Engine) TLSDemoClientConnect(req utils.TLSDemoSessionRequest) utils.TLSDemoResult {
	return utils.TLSDemoClientConnect(req)
}

func (e *Engine) TLSDemoSend(req utils.TLSDemoSendRequest) utils.TLSDemoResult {
	return utils.TLSDemoSend(req)
}

func (e *Engine) TLSDemoGetState(req utils.TLSDemoSessionRequest) utils.TLSDemoResult {
	return utils.TLSDemoGetState(req)
}

func (e *Engine) TLSDemoClose(req utils.TLSDemoSessionRequest) utils.TLSDemoResult {
	return utils.TLSDemoClose(req)
}
