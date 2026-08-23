using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using CryptoKit.Services;

namespace CryptoKit;

/// <summary>
/// 应用入口：拉起随程序提供的 Go 密码引擎、加载便携设置、应用主题，然后展示主窗口。
/// 前端以单文件便携模式发布，密码引擎是唯一需要保留在同目录的协作程序。
/// </summary>
public partial class App : Application
{
    public static Window? MainAppWindow { get; private set; }

    private readonly AppSettings _settings = new();
    private readonly EngineClient _engine = new();

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _settings.Load();

        MainAppWindow = new MainWindow(_engine, _settings);
        MainAppWindow.Activate();

        // 拉起密码引擎（CryptoKitEngine.exe，与主程序同目录）。启动失败时仍展示窗口，
        // 明确告知用户缺失的文件，避免未处理异常造成“点击没有反应”。
        try
        {
            _engine.Start();
        }
        catch (Exception ex)
        {
            _ = ShowEngineStartErrorAsync(ex.Message);
        }
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
}
