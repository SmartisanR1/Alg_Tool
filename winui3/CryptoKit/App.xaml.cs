using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using CryptoKit.Services;
using System.Runtime.InteropServices;

namespace CryptoKit;

/// <summary>
/// 应用入口：拉起随程序提供的 Go 密码引擎、加载便携设置、应用主题，然后展示主窗口。
/// 前端以便携目录方式发布，密码引擎是唯一需要保留在同目录的协作程序。
///
/// 健壮性设计：任何启动阶段异常都会写入 startup-error.log 并用原生 MessageBox 告知
/// 用户后退出——绝不静默进入「进程在运行但没有窗口」的状态。
/// </summary>
public partial class App : Application
{
    public static Window? MainAppWindow { get; private set; }

    private readonly AppSettings _settings = new();
    private readonly EngineClient _engine = new();

    public App()
    {
        InitializeComponent();

        // 捕获未处理异常：先落盘日志（即使界面已经无法渲染），避免无声崩溃
        UnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // 主窗口创建/激活必须成功；失败则记录并退出，绝不留下无窗口的僵尸进程
        try
        {
            _settings.Load();

            MainAppWindow = new MainWindow(_engine, _settings);
            MainAppWindow.Activate();
        }
        catch (Exception ex)
        {
            CrashLog.Write(ex, "OnLaunched 创建主窗口");
            ShowFatalError($"程序启动失败，无法创建主窗口。\n\n{ex.Message}\n\n详细信息已写入 startup-error.log。");
            Environment.Exit(1);
        }

        // 拉起密码引擎（CryptoKitEngine.exe，与主程序同目录）。启动失败时仍展示窗口，
        // 明确告知用户缺失的文件，避免未处理异常造成「点击没有反应」。
        try
        {
            _engine.Start();
        }
        catch (Exception ex)
        {
            _ = ShowEngineStartErrorAsync(ex.Message);
        }
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        CrashLog.Write(e.Exception, "UI 未处理异常");
        e.Handled = true; // 单个页面错误不拖垮整个应用
    }

    private static void OnAppDomainUnhandledException(object sender, System.UnhandledExceptionEventArgs e)
    {
        CrashLog.Write(e.ExceptionObject as Exception, "AppDomain 未处理异常");
    }

    private static async Task ShowEngineStartErrorAsync(string detail)
    {
        if (MainAppWindow?.Content is not FrameworkElement root) return;
        var dialog = new ContentDialog
        {
            XamlRoot = root.XamlRoot,
            Title = "无法启动本地密码引擎",
            Content = "请确认 CryptoKitEngine.exe 与 CryptoKit.exe 位于同一目录，然后重新打开应用。\n\n" + detail,
            CloseButtonText = "知道了",
        };
        await dialog.ShowAsync();
    }

    private static void ShowFatalError(string message)
    {
        try
        {
            _ = MessageBoxW(IntPtr.Zero, message, "CryptoKit 启动失败", 0x10 /* MB_ICONERROR */);
        }
        catch { /* 忽略 */ }
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
