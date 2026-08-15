# CryptoKit — 密码算法工具箱

> 基于 **Go + WinUI3 (C#)** 的桌面密码工具，覆盖国密 / 国际 / 后量子 / 金融密码算法。
> 所有计算在本地完成，数据不离开本机（无网络、无 HTTP API）。

---

## ✨ 功能特性

### 🌐 国际标准算法
- **对称加密**: AES-128/192/256 (ECB/CBC/CFB/OFB/CTR/GCM/CCM), DES/3DES, ChaCha20/XChaCha20, ChaCha20-Poly1305, RC4, AES-SIV/AES-GCM-SIV
- **格式保留加密 (FPE)**: FF1, FF3-1 (NIST SP 800-38G), FFX
- **非对称加密**: RSA-1024/2048/4096 (PKCS1/OAEP/PSS), ECDSA/ECDH (P-256/384/521)
- **现代椭圆曲线**: X25519, Ed25519, X448, Ed448
- **哈希**: MD5, SHA-1, SHA-2 全系列, SHA-3 全系列, SHAKE128/256, BLAKE2b/2s, BLAKE3, RIPEMD-160
- **HMAC**: HMAC-MD5/SHA1/SHA256/SHA512/SHA3/BLAKE2/SM3
- **MAC**: CMAC-AES, GMAC, Poly1305, SipHash-2-4, CBC-MAC (AES/SM4)
- **KDF**: PBKDF2, HKDF (SHA256/SHA512/SM3), bcrypt, scrypt, Argon2i/d/id

### 🇨🇳 国密算法 (GM/T 标准)
- **SM2**: 加解密、数字签名/验签、密钥协商、PIN 加密 (GM/T 0003)
- **SM3**: 哈希、HMAC-SM3、带 ID 哈希 (GM/T 0004)
- **SM4**: ECB/CBC/CFB/OFB/CTR/GCM 全模式 (GM/T 0006)
- **SM9**: 标识密码 (IBC): 加密、签名、密钥封装 (GM/T 0044)
- **ZUC**: 祖冲之流密码 ZUC-128/256 (GM/T 0001)

### 🔮 后量子密码 (NIST 标准)
- **ML-KEM** (Kyber): 512/768/1024 — FIPS 203
- **ML-DSA** (Dilithium): 44/65/87 — FIPS 204
- **SLH-DSA** (SPHINCS+): FIPS 205
- **Falcon**: 512/1024
- **HQC**: 128/192/256
- **AIGIS-sig**: III/V（国密 PQC 竞赛算法）
- **X-Wing**: 混合 KEM (X25519 + ML-KEM-768)

### 🏦 金融密码工具
- **PIN Block**: 生成/解析 (ISO 9564 Format 0/1/3), SM2/SM4 PIN 加解密
- **CVV/CVV2**: 卡验证值生成
- **PVV**: PIN 验证值 (IBM 3624 方法)
- **EMV**: UDK 派生 (3DES/SM4), ARQC/TC/AAC 生成, 双重单向派生
- **TDES**: 金融 3DES 加解密
- **SM4 金融**: SM4 加解密/CMAC/Retain MAC
- **Retail MAC**: ISO 9797-1 (方法 1/2)

### 🔧 工具箱
- 编解码: Hex ↔ 字符串, Base64/32/58, Bech32, URL 编解码, Unicode 转义, JSON 格式化
- XOR 异或, 进制转换 (2/8/10/16/36), 随机密钥/IV/Nonce 生成
- 数据填充 (PKCS7/PKCS5/Zero/ISO10126/ANSIX923/ISO9797-1)
- 时间戳转换, 文件哈希, 文件加解密 (AES-256-GCM)
- ASN.1 解析, 大整数运算, JWT 解析
- 证书工具: CSR/自签名/内部 CA 签发/SM2 双证书/解析/链校验/PKCS12
- TLS/TLCP 连接测试, 密码套件列表, 数据包收发 (TCP/UDP), 多线程性能测试

---

## 🏗️ 架构

```
┌─────────────────────────┐     stdio JSON-RPC    ┌──────────────────────┐
│  C# WinUI3 前端           │ ──────────────────▶ │  Go 密码引擎           │
│  Mica / 系统强调色 / 标题栏  │ ◀────────────────── │  （纯静态、零残留）      │
└─────────────────────────┘                       └──────────────────────┘
```

- **UI 层**：原生 WinUI3（C# / XAML）。Mica 毛玻璃、系统强调色、原生标题栏均为系统级能力，无 WebView2、无 Web 前端。
- **引擎层**：Go 独立子进程，纯静态编译（无 cgo、无运行时依赖），通过 stdio 逐行 JSON-RPC 通信。引擎不落盘、不创建临时文件。

---

## 🚀 构建（Windows）

### 环境依赖
- Go 1.26+
- .NET 10 SDK
- Windows 11

### 一键构建
```powershell
.\winui3\build.ps1                         # win-x64（需 .NET 10 桌面运行时）
.\winui3\build.ps1 -Runtime win-arm64      # ARM64
.\winui3\build.ps1 -SelfContainedDotNet    # 连 .NET 运行时一起打包，完全免安装
```

产物在 `dist\winui3\`，**整目录复制到任意位置即可运行**（免 WebView2、关闭零残留）。

> **运行依赖**（各安装一次，不再打进包）：
> - .NET 10 桌面运行时：https://dotnet.microsoft.com/download/dotnet/10.0
> - Windows App SDK 运行时：https://learn.microsoft.com/windows/apps/windows-app-sdk/downloads
>
> 首次构建会从 NuGet 下载 Windows App SDK 包，需联网。

---

## 📁 项目结构

```
crypto/<pkg>/           # Go 算法实现（symmetric/asymmetric/hash/mac/kdf/gm/pqc/finance/utils）
engine/                 # Go 密码引擎（全部计算 API + JSON-RPC 分发）
cmd/engine/             # 引擎进程入口
winui3/CryptoKit/       # C# WinUI3 项目（App / MainWindow / Services / Pages）
winui3/build.ps1        # 一键构建脚本
winui3/BUILD.md         # 构建与引擎协议细节
```

---

## 🔑 核心依赖

| 依赖 | 用途 |
|------|------|
| `github.com/emmansun/gmsm` | SM2/SM3/SM4/SM9/ZUC 国密算法 |
| `github.com/cloudflare/circl` | ML-KEM/ML-DSA/SLH-DSA/Falcon/HQC (PQC) |
| `gitee.com/Trisia/gotlcp` | TLCP/TLS 1.3 连接测试 |
| `golang.org/x/crypto` | ChaCha20/Ed25519/X25519/bcrypt/scrypt/Argon2 |
| `github.com/zeebo/blake3` | BLAKE3 哈希 |
| `github.com/secure-io/siv-go` | AES-SIV / AES-GCM-SIV |
| `github.com/btcsuite/btcutil` | Base58 编解码 |
| `software.sslmate.com/src/go-pkcs12` | PKCS12 解析 |
| `Microsoft.WindowsAppSDK` | WinUI3 运行时与控件 |

---

## ⚠️ 安全说明

- 所有计算在本地进行，**数据不离开本机**
- **仅供学习/测试使用**，生产环境请参考正式密码工程规范
- ECB 模式存在安全缺陷，不推荐在生产中使用
- RSA-1024 已不满足安全需求，建议使用 RSA-2048+
- AIGIS-sig 为实验性实现，参数基于公开论文，尚待官方标准测试向量验证

---

## 📜 License

MIT License
