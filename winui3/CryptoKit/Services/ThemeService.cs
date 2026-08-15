using Microsoft.UI.Xaml;

namespace CryptoKit.Services;

/// <summary>
/// 主题辅助：WinUI3 的 Fluent 2 主题资源（颜色/字体/圆角）与系统强调色
/// 均由内置 ResourceDictionary 自动跟随，这里只需管理「浅/深/跟随系统」三态。
/// </summary>
public static class ThemeService
{
    /// <summary>把主题应用到窗口根元素（ElementTheme.Default = 跟随系统）。</summary>
    public static void Apply(ElementTheme mode, FrameworkElement? root)
    {
        if (root is not null)
            root.RequestedTheme = mode;
    }

    /// <summary>三态循环：跟随系统 → 浅色 → 深色 → 跟随系统。</summary>
    public static ElementTheme Cycle(ElementTheme current) => current switch
    {
        ElementTheme.Default => ElementTheme.Light,
        ElementTheme.Light => ElementTheme.Dark,
        _ => ElementTheme.Default,
    };
}
