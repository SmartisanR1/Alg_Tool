using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

/// <summary>工作区占位页：保持新版工作台的统一信息层级。</summary>
public sealed partial class PlaceholderPage : Page
{
    public PlaceholderPage(string title)
    {
        InitializeComponent();
        TitleText.Text = title;
    }
}
