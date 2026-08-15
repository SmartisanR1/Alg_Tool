# AGENTS.md — CryptoKit 项目指南

> 面向 AI 编码代理的代码库导航与约定。完整功能列表、环境搭建、安全说明见 [README.md](./README.md)。

## 项目概览

**CryptoKit** 是 Go + WinUI3 (C#) 的桌面密码算法工具箱，覆盖国密（SM2/SM3/SM4/SM9/ZUC）、国际算法（AES/RSA/ECC/哈希/MAC/KDF/FPE）、后量子（ML-KEM/ML-DSA/SLH-DSA/Falcon/HQC/AIGIS）与金融密码工具。所有计算本地完成。

- **UI**：原生 WinUI3（C# / XAML），Mica 毛玻璃、系统强调色、原生标题栏。
- **引擎**：Go 独立子进程，stdio JSON-RPC 通信，纯静态、零残留。

## 常用命令

```bash
go build ./...                    # 编译全部 Go 包（crypto + engine + cmd/engine）
go vet ./...                      # 静态检查
go test ./crypto/pqc/...          # 运行 PQC 测试（全项目唯一有测试的包）
go run ./cmd/engine               # 本地跑引擎（stdin 输入 JSON 行）

# 构建 WinUI3（在 Windows 上）
.\winui3\build.ps1                # 产物 dist\winui3\
```

**版本约束**：Go 1.26、.NET 10 SDK（WinUI3 目标框架 `net10.0-windows10.0.19041.0`）。发布流程见 `.github/workflows/release.yml`（push `v*` tag 触发）。

## 架构总览

```
crypto/<pkg>/           # 算法实现（symmetric/asymmetric/hash/mac/kdf/gm/pqc/finance/utils）
engine/engine.go        # Engine 结构体：全部计算 API（每方法一行转发 + 分组注释）
engine/dispatch.go      # 反射式 JSON-RPC 分发器 + stdio 服务循环
cmd/engine/main.go      # 引擎进程入口（stdin/stdout 通信）
winui3/CryptoKit/       # C# WinUI3 项目
  App.xaml(.cs)         # 入口：加载设置、拉起引擎、展示主窗口
  MainWindow.xaml(.cs)  # Mica 后层 + 延伸标题栏 + NavigationView
  Services/             # ThemeService / EngineClient / AppSettings
  Pages/                # 功能页（HomePage 已实现、HashPage 参考、其余占位）
```

### 数据流

1. C# 页面调用 `_engine.CallAsync<T>("Method", args)`（`Services/EngineClient.cs`）。
2. EngineClient 向引擎进程 stdin 写入一行 JSON-RPC，从 stdout 读回结果。
3. Go 端 `dispatch.go` 按方法名反射调用 `Engine` 的对应方法 → `crypto/<pkg>` 实现。
4. 结果结构体（如 `CryptoResult`）序列化回 C#，读 `Success/Data/Error/Extra`。

## Go 引擎约定（新增/修改算法必读）

- **结果类型**：多数算法返回 `symmetric.CryptoResult{Success, Data, Error, Extra}`；密钥生成返回 `asymmetric.KeyPairResult` / `gm.SM2KeyResult` / `pqc.PQCKeyResult`；工具类返回 `utils.ToolResult{Success, Data, Error}`；finance 有各自结果类型。
- **错误处理**：**不返回 Go error**。失败写结果结构体 `Error` 字段（**中文消息**，格式 `"前缀: " + err.Error()`），`Success: false`。
- **输入/输出**：请求结构体字段全为 `string`（hex/PEM），内部 `hex.DecodeString`；输出统一大写 hex（`hexUpper`）。IV/Nonce 留空自动生成并回填 `Extra`。
- **每包复制一份 `hex.go`**：`hexUpper(b []byte) string` 无法跨包共享，8 个算法包各一份逐字相同副本（finance 内联在 `finance.go`）。新增算法包复制此惯例。
- **引擎薄封装**：`engine/engine.go` 的 `Engine` 方法每行只转发到 `crypto/<pkg>`，带 `// ====` 分组注释。**新增 API 三步**：① 在 `crypto/<pkg>` 实现；② 在 `engine/engine.go` 加一行 `Engine` 转发方法；③ C# 端 `CallAsync<T>("方法名", args)` 调用即可（反射分发，无需注册表）。
- **随机源**：统一 `github.com/emmansun/gmsm/rand` 的 `rand.Reader`（非 `crypto/rand`）。
- **tag 拆分**：`pqc_stub.go`（`//go:build !oqs`）默认纯 Go 实现，`-tags oqs` 可裁剪。
- **已知近似实现**（注释已明示，非 bug）：AES-CCM 用 GCM 近似；Argon2d 用 Argon2i 近似；`SM2KeyAgreement` 只返回协议流程占位文本。
- **PQC 测试**：`crypto/pqc/*_test.go`，向量在 `crypto/pqc/testdata/`，命名 `TestXxxKAT` / `TestXxxSelfConsistency` / `TestXxxParamSet`。

## 引擎 JSON-RPC 协议

```
请求   {"id":1,"method":"Hash","params":[{"algorithm":"SHA256","data":"48656c6c6f"}]}
成功   {"id":1,"result":{"success":true,"data":"185F8DB3...","error":"","extra":""}}
失败   {"id":1,"error":"unknown method: \"X\""}
```

- `params` 恒为数组，元素与 Go 方法形参一一对应（单参 `[obj]`、双参 `[a,b]`、无参 `[]`）。
- 引擎 `stdout` 只输出 JSON 行，**禁止**向 stdout 打印任何日志（会污染协议）。

## C# WinUI3 约定（新增页面必读）

- **页面模板**：参照 `Pages/HashPage.xaml(.cs)` —— 构造函数注入 `EngineClient`，按钮点击里 `await _engine.CallAsync<T>("方法名", 请求对象)`。
- **请求/结果字段名**：与 Go 端 JSON tag 完全一致（`Models/EngineModels.cs` 已定义 `CryptoResult`/`ToolResult`，其余结果类型按需补充）。
- **文件选择**：用 WinUI3 原生 `FileOpenPicker` / `FileSavePicker`（**不再经 Go**），拿到路径后传给引擎的文件类方法。
- **主题/强调色**：无需手动处理——WinUI3 的 Fluent 2 资源自动跟随系统深浅色与强调色；三态主题切换见 `Services/ThemeService.cs` + `MainWindow.OnThemeClick`。
- **新增页面后**：在 `MainWindow.xaml` 的 `NavigationView.MenuItems` 加一项（`Tag`），并在 `MainWindow.Navigate` 的 switch 里映射到新页面。

## 构建/打包注意

- **WinUI3 需显式平台**：`dotnet publish` 带 `-p:Platform=x64`（或 x86/ARM64），`build.ps1` 已自动映射；框架依赖 WinAppSDK 由引导器自动初始化（运行时一次安装）。
- **零残留**：引擎纯静态不落盘；主窗口关闭时 `EngineClient.Dispose()` 结束子进程；设置写 exe 同目录 `settings.json`（只读时回退 `%LOCALAPPDATA%`）。
- 产物 `dist\winui3\` 整目录复制即可运行，无 MSIX、无 WebView2。

## 相关文档（链接，勿重复）

- 功能列表 / 环境搭建 / 安全说明：**[README.md](./README.md)**
- 构建与引擎协议细节：**[winui3/BUILD.md](./winui3/BUILD.md)**
