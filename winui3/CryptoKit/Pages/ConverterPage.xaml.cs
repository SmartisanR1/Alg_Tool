using CryptoKit.Models;
using CryptoKit.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

public sealed partial class ConverterPage : Page
{
    private readonly EngineClient _engine;
    public ConverterPage(EngineClient engine) { _engine = engine; InitializeComponent(); }

    private Task ConvertAsync(string method) => ConvertCoreAsync(method);

    private async Task ConvertCoreAsync(string method)
    {
        if (string.IsNullOrEmpty(InputBox.Text)) { ResultBox.Text = "请输入要转换的内容"; return; }
        try
        {
            var result = await _engine.CallAsync<ToolResult>(method, InputBox.Text);
            ResultBox.Text = result.Success ? result.Data : "转换失败：" + result.Error;
        }
        catch (EngineException ex) { ResultBox.Text = "引擎错误：" + ex.Message; }
    }

    private async void OnTextToHexClick(object sender, RoutedEventArgs e) => await ConvertAsync("StringToHex");
    private async void OnHexToTextClick(object sender, RoutedEventArgs e) => await ConvertAsync("HexToString");
    private void OnClearClick(object sender, RoutedEventArgs e) { InputBox.Text = string.Empty; ResultBox.Text = string.Empty; }
}
