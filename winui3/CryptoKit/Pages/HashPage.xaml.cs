using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using CryptoKit.Models;
using CryptoKit.Services;

namespace CryptoKit.Pages;

/// <summary>
/// 哈希摘要页：演示完整的「UI → 引擎 JSON-RPC → 展示结果」链路。
/// 输入文本 → StringToHex → Hash → 展示十六进制摘要。
/// 其余 12 个功能页可参照此页的调用模式逐一移植。
/// </summary>
public sealed partial class HashPage : Page
{
    private readonly EngineClient _engine;

    public HashPage(EngineClient engine)
    {
        _engine = engine;
        InitializeComponent();
    }

    private async void OnComputeClick(object sender, RoutedEventArgs e)
    {
        var text = InputBox.Text;
        if (string.IsNullOrEmpty(text))
        {
            ResultBox.Text = "请输入内容";
            return;
        }

        ComputeButton.IsEnabled = false;
        ComputeButton.Content = "计算中…";
        try
        {
            // 1) 文本 → hex
            var hex = await _engine.CallAsync<ToolResult>("StringToHex", text);
            if (!hex.Success)
            {
                ResultBox.Text = "编码失败：" + hex.Error;
                return;
            }

            var algo = (AlgoBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "SHA256";

            // 2) 计算哈希
            var result = await _engine.CallAsync<CryptoResult>("Hash", new
            {
                algorithm = algo,
                data = hex.Data,
                outputSize = 256,
            });

            ResultBox.Text = result.Success
                ? result.Data
                : "计算失败：" + result.Error;
        }
        catch (EngineException ex)
        {
            ResultBox.Text = "引擎错误：" + ex.Message;
        }
        finally
        {
            ComputeButton.IsEnabled = true;
            ComputeButton.Content = "计算哈希";
        }
    }

    private void OnClearClick(object sender, RoutedEventArgs e)
    {
        InputBox.Text = string.Empty;
        ResultBox.Text = string.Empty;
    }
}
