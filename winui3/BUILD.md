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

依赖：Go 1.26+、.NET 10 SDK。运行时需装 .NET 10 桌面运行时 + Windows App SDK 运行时（各一次）。

```powershell
.\winui3\build.ps1                     # win-x64（.NET 框架依赖，需装 .NET 10 桌面运行时）
.\winui3\build.ps1 -Runtime win-arm64
.\winui3\build.ps1 -SelfContainedDotNet   # 连 .NET 运行时一起打包，免装
```

产物在 `dist\winui3\`，**整目录复制到任意位置即可运行**。

> 首次 `dotnet publish` 会从 NuGet 下载 Windows App SDK 包，需联网；
> 若 csproj 中的 `Microsoft.WindowsAppSDK` 版本无法还原，升级到最新稳定版即可。

## 零残留设计（关闭即清理）

1. **Go 引擎**：纯静态二进制，stdio 通信，不落盘、无临时目录、无缓存。
2. **WinUI3**：无 WebView2，不存在缓存目录；框架依赖 WinAppSDK（运行时仅一次安装，应用目录无残留）。
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
| home | ✅ 已实现 |
| hash | ✅ 已实现（参考页） |
| symmetric / asymmetric / pqc / finance / mac / cert / tools / bigint / file / packet / tls | ⬜ 待实现 |

补齐页面时参照 `Pages/HashPage.xaml(.cs)`：`_engine.CallAsync<T>("方法名", 请求对象)`，
请求/结果字段名与 Go 端 JSON tag 一致。文件选择用 WinUI3 原生 `FileOpenPicker` / `FileSavePicker`。
