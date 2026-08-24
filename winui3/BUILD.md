# CryptoKit WinUI3 构建与运行

## 架构

- **UI**：原生 WinUI3（C# / XAML），Mica 毛玻璃、系统强调色、标题栏均为系统原生。
- **密码引擎**：Go 独立子进程（纯静态、无运行时依赖），通过 stdio JSON-RPC 与前端通信。

```
engine/            # Go 密码引擎（全部计算 API + 反射式 JSON-RPC 分发）
cmd/engine/        # 引擎进程入口
winui3/CryptoKit/  # C# WinUI3 项目（App / MainWindow / Services / Pages）
winui3/build.ps1   # 一键构建脚本
```

## 构建（Windows）

构建依赖：Go 1.26+、.NET 10 SDK。最终用户**无需安装** .NET、Windows App SDK 或其他运行时。

```powershell
.\winui3\build.ps1                     # win-x64 免安装便携版
.\winui3\build.ps1 -Runtime win-arm64
```

产物在 `dist\winui3\`，包含主程序、Windows App SDK 原生运行时与密码引擎：

```
CryptoKit.exe          # WinUI3 主程序
Microsoft.UI.Xaml.dll  # Windows App SDK 原生运行时（自包含部署）
*.dll                  # 其余 Windows App SDK / .NET 运行时文件
resources.pri          # MRT 资源表（XAML 加载必需）
CryptoKitEngine.exe    # 本地 Go 密码引擎
README.txt             # 使用说明
```

**整目录复制到任意位置即可运行**，双击 `CryptoKit.exe`。不要单独移动或删除
`CryptoKitEngine.exe` 及任何运行时 DLL，主程序依赖同目录文件完成启动。

> ⚠️ **不要启用 `PublishSingleFile`（单文件发布）**。WinUI3 自包含 + 单文件模式存在
> 已知 bug：应用进程启动后不显示窗口（microsoft/WindowsAppSDK#6248、#3718），且
> 官方自包含部署指南明确要求 WinUI3 的原生运行时必须保留为独立文件。本项目采用
> 官方推荐的目录级 xcopy 部署：解压 zip 后整目录即为可运行程序，无需安装任何运行时。

> 首次 `dotnet publish` 会从 NuGet 下载 Windows App SDK 包，需联网；
> 若 csproj 中的 `Microsoft.WindowsAppSDK` 版本无法还原，升级到最新稳定版即可。

## 零残留设计（关闭即清理）

1. **Go 引擎**：纯静态二进制，stdio 通信，不落盘、无临时目录、无缓存。
2. **WinUI3**：无 WebView2；以自包含目录部署（非单文件），不依赖机器预装的 Windows App SDK。
3. **进程清理**：主窗口关闭时 `EngineClient.Dispose()` 关闭 stdin 并 `Kill`，杜绝孤儿进程。
4. **设置**：默认写 exe 同目录 `settings.json`（几 KB，便携）；exe 目录只读时才回退 `%LOCALAPPDATA%\CryptoKit\settings.json`。

## 引擎 JSON-RPC 协议

```
请求   {"id":1,"method":"Hash","params":[{"algorithm":"SHA256","data":"48656c6c6f"}]}
成功   {"id":1,"result":{"success":true,"data":"185F8DB3...","error":"","extra":""}}
失败   {"id":1,"error":"unknown method: \"X\""}
```

`params` 恒为数组，元素与 Go 方法形参一一对应（单参 `[obj]`、双参 `[a,b]`、无参 `[]`）。

## 功能页状态

| 页面 Tag | 状态 |
|---|---|
| home | ✅ 已实现（工作台与快捷入口） |
| hash | ✅ 已实现（本地文本哈希） |
| keys | ✅ 已实现（RSA 密钥对生成） |
| tools | ✅ 已实现（文本 / Hex 转换） |
| symmetric | ✅ 已实现（AES / SM4 CBC 加解密） |
| asymmetric | ✅ 已实现（RSA/ECC/Ed25519/SM2/SM3/SM4/SM9/ZUC） |
| pqc | ✅ 已实现（ML-KEM/ML-DSA/SLH-DSA/Falcon/HQC/AIGIS-sig） |
| packet | ✅ 已实现（TLS 连接/报文收发/TLS·TLCP 演示） |

补齐页面时参照 `Pages/HashPage.xaml(.cs)`：`_engine.CallAsync<T>("方法名", 请求对象)`，
请求/结果字段名与 Go 端 JSON tag 一致。文件选择用 WinUI3 原生 `FileOpenPicker` / `FileSavePicker`。
