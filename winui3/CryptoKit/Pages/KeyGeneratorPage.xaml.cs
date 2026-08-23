using CryptoKit.Models;
using CryptoKit.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

public sealed partial class KeyGeneratorPage : Page
{
    private readonly EngineClient _engine;

    public KeyGeneratorPage(EngineClient engine)
    {
        _engine = engine;
        InitializeComponent();
    }

    private async void OnGenerateClick(object sender, RoutedEventArgs e)
    {
        var bits = int.Parse((BitsBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "3072");
        GenerateButton.IsEnabled = false;
        GenerateButton.Content = "正在生成…";
        try
        {
            var result = await _engine.CallAsync<KeyPairResult>("RSAGenerateKey", bits);
            if (result.Success)
            {
                PublicKeyBox.Text = result.PublicKey;
                PrivateKeyBox.Text = result.PrivateKey;
            }
            else
            {
                PublicKeyBox.Text = "生成失败：" + result.Error;
                PrivateKeyBox.Text = string.Empty;
            }
        }
        catch (EngineException ex)
        {
            PublicKeyBox.Text = "引擎错误：" + ex.Message;
        }
        finally
        {
            GenerateButton.IsEnabled = true;
            GenerateButton.Content = "生成密钥对";
        }
    }
}
