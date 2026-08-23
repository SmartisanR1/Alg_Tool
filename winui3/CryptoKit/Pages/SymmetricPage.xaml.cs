using CryptoKit.Models;
using CryptoKit.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

public sealed partial class SymmetricPage : Page
{
    private readonly EngineClient _engine;
    public SymmetricPage(EngineClient engine) { _engine = engine; InitializeComponent(); }

    private async Task ProcessAsync(bool encrypt)
    {
        var algorithm = (AlgorithmBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "AES";
        var method = algorithm == "SM4" ? (encrypt ? "SM4Encrypt" : "SM4Decrypt") : (encrypt ? "AESEncrypt" : "AESDecrypt");
        var keySize = KeyBox.Text.Trim().Length / 2 * 8;
        var request = new { key = KeyBox.Text.Trim(), iv = IvBox.Text.Trim(), nonce = "", aad = "", data = DataBox.Text.Trim(), mode = "CBC", padding = "PKCS7", keySize, tagSize = 16 };
        EncryptButton.IsEnabled = DecryptButton.IsEnabled = false;
        try
        {
            var result = await _engine.CallAsync<CryptoResult>(method, request);
            ResultBox.Text = result.Success ? result.Data : "计算失败：" + result.Error;
            ExtraText.Text = result.Success && !string.IsNullOrEmpty(result.Extra) ? "本次使用的 IV：" + result.Extra : string.Empty;
        }
        catch (EngineException ex) { ResultBox.Text = "引擎错误：" + ex.Message; ExtraText.Text = string.Empty; }
        finally { EncryptButton.IsEnabled = DecryptButton.IsEnabled = true; }
    }

    private async void OnEncryptClick(object sender, RoutedEventArgs e) => await ProcessAsync(true);
    private async void OnDecryptClick(object sender, RoutedEventArgs e) => await ProcessAsync(false);
    private void OnClearClick(object sender, RoutedEventArgs e) { KeyBox.Text = IvBox.Text = DataBox.Text = ResultBox.Text = ExtraText.Text = string.Empty; }
}
