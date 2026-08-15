using Microsoft.UI.Xaml;
using CryptoKit.Services;

namespace CryptoKit;

/// <summary>
/// 应用入口：拉起 Go 密码引擎子进程、加载便携设置、应用主题，然后展示主窗口。
/// 关闭窗口时引擎随进程退出（见 MainWindow.Closed），不留任何临时文件。
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

        // 拉起密码引擎（CryptoKitEngine.exe，与主程序同目录）
        // 主题（system/light/dark）由 MainWindow 在构造时应用；强调色无需处理——
        // WinUI3 控件通过 Fluent 2 主题资源自动跟随系统强调色。
        _engine.Start();

        MainAppWindow = new MainWindow(_engine, _settings);
        MainAppWindow.Activate();
    }
}
