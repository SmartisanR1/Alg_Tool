# CryptoKit WinUI3 构建脚本（在 Windows 上运行）
# 产物：dist/winui3/ 目录，仅保留 CryptoKit.exe + CryptoKitEngine.exe + README.txt。
#       整目录复制即可运行（绿色便携，无安装、无 MSIX、无 WebView2）。
#
# 用法：
#   .\winui3\build.ps1                          # 默认 win-x64，免安装便携版
#   .\winui3\build.ps1 -Runtime win-arm64       # ARM64
#   .\winui3\build.ps1 -SelfContainedDotNet     # 兼容旧参数；便携版始终自包含
param(
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release",
    [switch]$SelfContainedDotNet
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot          # 仓库根目录
$out = Join-Path $root "dist\winui3"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "未找到 go，请先安装 Go 1.26+" }
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "未找到 dotnet，请先安装 .NET 10 SDK" }

# 不能在旧目录上叠加发布：否则上一次发布留下的 DLL 会破坏“两个可执行文件”的便携交付。
if (Test-Path $out) { Remove-Item -Recurse -Force -Path $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

# 1. 编译 C# WinUI3 前端
Write-Host "==> 编译 C# WinUI3 ($Runtime) ..."
$proj = Join-Path $PSScriptRoot "CryptoKit\CryptoKit.csproj"
# 原生 WinUI3 需显式平台（非 AnyCPU），须由 Runtime 映射出 Platform
$platform = if ($Runtime -like "*arm64*") { "ARM64" } elseif ($Runtime -like "*x86*") { "x86" } else { "x64" }
dotnet publish $proj -c $Configuration -r $Runtime "-p:Platform=$platform" --self-contained true -o $out
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败" }

# 2. 编译 Go 密码引擎（纯静态，无 cgo，无运行时依赖）
Write-Host "==> 编译 Go 密码引擎 ($Runtime) ..."
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = if ($Runtime -like "*arm64*") { "arm64" } elseif ($Runtime -like "*x86*") { "386" } else { "amd64" }
Push-Location $root
& go build -trimpath -ldflags "-s -w" -o (Join-Path $out "CryptoKitEngine.exe") ./cmd/engine
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "go build 失败" }
Pop-Location

@"
CryptoKit 便携版

双击 CryptoKit.exe 即可使用，无需安装 .NET 或 Windows App SDK。
CryptoKitEngine.exe 是本地密码计算组件，请与主程序放在同一目录。
"@ | Set-Content -Path (Join-Path $out "README.txt") -Encoding utf8

Write-Host "==> 完成！产物目录: $out"
Write-Host "    目录仅含主程序、密码引擎和说明；复制整个目录后双击 CryptoKit.exe 即可运行。"
