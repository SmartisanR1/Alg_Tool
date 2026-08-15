using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

/// <summary>占位页：显示功能名，提示待移植。</summary>
public sealed partial class PlaceholderPage : Page
{
    public PlaceholderPage(string title)
    {
        InitializeComponent();
        TitleText.Text = title;
    }
}
