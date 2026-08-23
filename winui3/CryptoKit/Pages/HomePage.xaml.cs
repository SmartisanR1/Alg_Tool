using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

/// <summary>首页：静态概览。</summary>
public sealed partial class HomePage : Page
{
    private readonly Action<string> _navigate;

    public HomePage(Action<string> navigate)
    {
        _navigate = navigate;
        InitializeComponent();
    }

    private void OnToolClick(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag }) _navigate(tag);
    }
}
