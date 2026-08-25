using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using CryptoKit.Pages;
using CryptoKit.Services;
using Windows.Graphics;

namespace CryptoKit;

/// <summary>
/// 主窗口：WinUI3 原生 Mica 后层 + 延伸标题栏 + NavigationView 导航。
/// 关闭时保存设置并释放引擎进程，不残留任何临时文件。
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly EngineClient _engine;
    private readonly AppSettings _settings;
    private ElementTheme _theme;

    public MainWindow(EngineClient engine, AppSettings settings)
    {
        _engine = engine;
        _settings = settings;
        _theme = settings.Theme;

        InitializeComponent();

        Title = "CryptoKit";

        // 应用初始主题到窗口根元素
        ThemeService.Apply(_theme, Content as FrameworkElement);
        UpdateThemeButton();

        // Mica 后层：WinUI3 原生，自动跟随系统主题采样桌面壁纸。
        // 个别环境（远程桌面/精简显卡/不支持合成器）可能抛错，失败则退回普通背景，不影响窗口显示。
        try
        {
            SystemBackdrop = new MicaBackdrop { Kind = MicaKind.Base };
        }
        catch { /* 忽略：降级为普通窗口背景 */ }

        // 标题栏延伸到内容区。失败则退回系统默认标题栏，绝不因此丢掉窗口。
        try
        {
            AppWindow.TitleBar.ExtendsContentIntoTitleBar = true;
            AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
            SetTitleBar(AppTitleBar);

            // 为主题按钮让出右侧系统标题栏按钮（最小化/最大化/关闭）的空间
            var rightInset = Math.Max(AppWindow.TitleBar.RightInset, 138);
            ThemeButton.Margin = new Thickness(0, 0, rightInset + 8, 0);
        }
        catch { /* 忽略：退回系统默认标题栏 */ }

        // 恢复窗口：上次最大化则继续最大化（首次启动默认最大化，铺满屏幕）；
        // 否则恢复保存的尺寸，并钳制在当前显示器工作区内（分辨率变小/设置残留不导致窗口开不全）
        if (_settings.IsMaximized)
        {
            try { AppWindow.SetPresenter(AppWindowPresenterKind.Maximized); }
            catch { /* 忽略：最大化失败则用默认尺寸 */ }
        }
        else
        {
            var (w, h) = (_settings.WindowWidth, _settings.WindowHeight);
            try
            {
                var work = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Nearest).WorkArea;
                w = Math.Min(w, work.Width);
                h = Math.Min(h, work.Height);
            }
            catch { /* 忽略：钳制失败则按原尺寸 */ }
            if (w > 0 && h > 0)
                AppWindow.Resize(new SizeInt32((int)w, (int)h));
        }

        Closed += OnClosed;

        // 默认选中「首页」
        NavView.SelectedItem = NavView.MenuItems[0];
        Navigate("home");
    }

    private void OnNavSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem { Tag: string tag })
            Navigate(tag);
    }

    private void Navigate(string tag)
    {
        ContentFrame.Content = tag switch
        {
            "home" => new HomePage(Navigate),
            "hash" => new HashPage(_engine),
            "keys" => new KeyGeneratorPage(_engine),
            "symmetric" => new SymmetricPage(_engine),
            "asymmetric" => new AsymmetricPage(_engine),
            "pqc" => new PQCPage(_engine),
            "packet" => new PacketPage(_engine),
            "tools" => new ConverterPage(_engine),
            _ => new PlaceholderPage(TitleFor(tag)),
        };
    }

    private static string TitleFor(string tag) => tag switch
    {
        "packet" => "报文 · 协议联调",
        "symmetric" => "对称算法",
        "asymmetric" => "公钥算法 / 国密",
        "pqc" => "后量子",
        _ => tag,
    };

    private void OnThemeClick(object sender, RoutedEventArgs e)
    {
        _theme = ThemeService.Cycle(_theme);
        _settings.Theme = _theme;
        ThemeService.Apply(_theme, Content as FrameworkElement);
        UpdateThemeButton();
        _settings.Save();
    }

    private void UpdateThemeButton()
    {
        var label = _theme switch
        {
            ElementTheme.Default => "跟随系统主题（点击切换）",
            ElementTheme.Light => "浅色模式（点击切换）",
            _ => "深色模式（点击切换）",
        };
        ToolTipService.SetToolTip(ThemeButton, label);
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        // 记录窗口几何供下次恢复（失败不影响退出）。
        // 最大化时保存最大化状态、保留上一份普通尺寸；普通尺寸时保存当前尺寸。
        try
        {
            var isMaximized = AppWindow.Presenter.Kind == AppWindowPresenterKind.Maximized;
            _settings.IsMaximized = isMaximized;
            if (!isMaximized)
            {
                var size = AppWindow.Size;
                _settings.WindowWidth = size.Width;
                _settings.WindowHeight = size.Height;
            }
            _settings.Save();
        }
        catch { /* 忽略 */ }

        // 释放引擎子进程：关闭 stdin 让引擎 EOF 退出并兜底 Kill，杜绝孤儿进程
        _engine.Dispose();
    }
}
