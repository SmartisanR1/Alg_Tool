using CryptoKit.Models;
using CryptoKit.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

/// <summary>后量子工作区：ML-KEM / ML-DSA / SLH-DSA / Falcon / HQC / AIGIS-sig。</summary>
public sealed partial class PQCPage : Page
{
    private readonly EngineClient _engine;
    public PQCPage(EngineClient engine) { _engine = engine; InitializeComponent(); }

    private static string CurTag(ComboBox box) => (box.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
    private static string TagOr(ComboBox box, string def)
    {
        var t = CurTag(box);
        return string.IsNullOrEmpty(t) ? def : t;
    }

    // 文本转 hex，失败把消息写入 sigBox 并返回 null
    private async Task<string?> ToHexAsync(string text, TextBox sigBox)
    {
        if (string.IsNullOrEmpty(text)) { sigBox.Text = "请输入要签名的内容"; return null; }
        var r = await _engine.CallAsync<ToolResult>("StringToHex", text);
        if (!r.Success) { sigBox.Text = "编码失败：" + r.Error; return null; }
        return r.Data;
    }

    // ============================================================
    // ML-KEM
    // ============================================================

    private async void OnMlkemGen(object s, RoutedEventArgs e)
    {
        MlkemGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCKeyResult>("MLKEMKeyGen", TagOr(MlkemParamBox, "ML-KEM-512"));
            if (r.Success) { MlkemPubBox.Text = r.PublicKey; MlkemPrivBox.Text = r.PrivateKey; }
            else { MlkemPubBox.Text = "生成失败：" + r.Error; MlkemPrivBox.Text = ""; }
        }
        catch (EngineException ex) { MlkemPubBox.Text = "引擎错误：" + ex.Message; }
        finally { MlkemGenBtn.IsEnabled = true; }
    }

    private async void OnMlkemEncap(object s, RoutedEventArgs e)
    {
        MlkemEncapBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCEncapResult>("MLKEMEncapsulate", new { publicKey = MlkemPubBox.Text.Trim(), paramSet = TagOr(MlkemParamBox, "ML-KEM-512") });
            if (r.Success) { MlkemCipherBox.Text = r.Ciphertext; MlkemSecretBox.Text = r.SharedSecret; }
            else { MlkemCipherBox.Text = "封装失败：" + r.Error; }
        }
        catch (EngineException ex) { MlkemCipherBox.Text = "引擎错误：" + ex.Message; }
        finally { MlkemEncapBtn.IsEnabled = true; }
    }

    private async void OnMlkemDecap(object s, RoutedEventArgs e)
    {
        MlkemDecapBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<CryptoResult>("MLKEMDecapsulate", new { privateKey = MlkemPrivBox.Text.Trim(), ciphertext = MlkemCipherBox.Text.Trim(), paramSet = TagOr(MlkemParamBox, "ML-KEM-512") });
            MlkemSecretBox.Text = r.Success ? r.Data : "解封装失败：" + r.Error;
        }
        catch (EngineException ex) { MlkemSecretBox.Text = "引擎错误：" + ex.Message; }
        finally { MlkemDecapBtn.IsEnabled = true; }
    }

    // ============================================================
    // ML-DSA
    // ============================================================

    private async void OnMldsaGen(object s, RoutedEventArgs e)
    {
        MldsaGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCKeyResult>("MLDSAKeyGen", TagOr(MldsaParamBox, "ML-DSA-44"));
            if (r.Success) { MldsaPubBox.Text = r.PublicKey; MldsaPrivBox.Text = r.PrivateKey; }
            else { MldsaPubBox.Text = "生成失败：" + r.Error; MldsaPrivBox.Text = ""; }
        }
        catch (EngineException ex) { MldsaPubBox.Text = "引擎错误：" + ex.Message; }
        finally { MldsaGenBtn.IsEnabled = true; }
    }

    private async Task MldsaSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(MldsaDataInput.Text, MldsaSigBox); if (data is null) return;
        MldsaSignBtn.IsEnabled = MldsaVerifyBtn.IsEnabled = false;
        try
        {
            var ps = TagOr(MldsaParamBox, "ML-DSA-44");
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("MLDSASign", new { privateKey = MldsaPrivBox.Text.Trim(), data, paramSet = ps });
                MldsaSigBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("MLDSAVerify", new { publicKey = MldsaPubBox.Text.Trim(), data, signature = MldsaSigBox.Text.Trim(), paramSet = ps });
                MldsaSigBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { MldsaSigBox.Text = "引擎错误：" + ex.Message; }
        finally { MldsaSignBtn.IsEnabled = MldsaVerifyBtn.IsEnabled = true; }
    }

    private void OnMldsaSign(object s, RoutedEventArgs e) => _ = MldsaSignVerifyAsync(true);
    private void OnMldsaVerify(object s, RoutedEventArgs e) => _ = MldsaSignVerifyAsync(false);

    // ============================================================
    // SLH-DSA
    // ============================================================

    private async void OnSlhdsaGen(object s, RoutedEventArgs e)
    {
        SlhdsaGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCKeyResult>("SLHDSAKeyGen", TagOr(SlhdsaParamBox, "SLH-DSA-SHA2-128s"));
            if (r.Success) { SlhdsaPubBox.Text = r.PublicKey; SlhdsaPrivBox.Text = r.PrivateKey; }
            else { SlhdsaPubBox.Text = "生成失败：" + r.Error; SlhdsaPrivBox.Text = ""; }
        }
        catch (EngineException ex) { SlhdsaPubBox.Text = "引擎错误：" + ex.Message; }
        finally { SlhdsaGenBtn.IsEnabled = true; }
    }

    private async Task SlhdsaSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(SlhdsaDataInput.Text, SlhdsaSigBox); if (data is null) return;
        SlhdsaSignBtn.IsEnabled = SlhdsaVerifyBtn.IsEnabled = false;
        try
        {
            var ps = TagOr(SlhdsaParamBox, "SLH-DSA-SHA2-128s");
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("SLHDSASign", new { privateKey = SlhdsaPrivBox.Text.Trim(), data, paramSet = ps });
                SlhdsaSigBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("SLHDSAVerify", new { publicKey = SlhdsaPubBox.Text.Trim(), data, signature = SlhdsaSigBox.Text.Trim(), paramSet = ps });
                SlhdsaSigBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { SlhdsaSigBox.Text = "引擎错误：" + ex.Message; }
        finally { SlhdsaSignBtn.IsEnabled = SlhdsaVerifyBtn.IsEnabled = true; }
    }

    private void OnSlhdsaSign(object s, RoutedEventArgs e) => _ = SlhdsaSignVerifyAsync(true);
    private void OnSlhdsaVerify(object s, RoutedEventArgs e) => _ = SlhdsaSignVerifyAsync(false);

    // ============================================================
    // Falcon
    // ============================================================

    private async void OnFalconGen(object s, RoutedEventArgs e)
    {
        FalconGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCKeyResult>("FalconKeyGen", TagOr(FalconParamBox, "Falcon-512"));
            if (r.Success) { FalconPubBox.Text = r.PublicKey; FalconPrivBox.Text = r.PrivateKey; }
            else { FalconPubBox.Text = "生成失败：" + r.Error; FalconPrivBox.Text = ""; }
        }
        catch (EngineException ex) { FalconPubBox.Text = "引擎错误：" + ex.Message; }
        finally { FalconGenBtn.IsEnabled = true; }
    }

    private async Task FalconSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(FalconDataInput.Text, FalconSigBox); if (data is null) return;
        FalconSignBtn.IsEnabled = FalconVerifyBtn.IsEnabled = false;
        try
        {
            var ps = TagOr(FalconParamBox, "Falcon-512");
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("FalconSign", new { privateKey = FalconPrivBox.Text.Trim(), data, paramSet = ps });
                FalconSigBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("FalconVerify", new { publicKey = FalconPubBox.Text.Trim(), data, signature = FalconSigBox.Text.Trim(), paramSet = ps });
                FalconSigBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { FalconSigBox.Text = "引擎错误：" + ex.Message; }
        finally { FalconSignBtn.IsEnabled = FalconVerifyBtn.IsEnabled = true; }
    }

    private void OnFalconSign(object s, RoutedEventArgs e) => _ = FalconSignVerifyAsync(true);
    private void OnFalconVerify(object s, RoutedEventArgs e) => _ = FalconSignVerifyAsync(false);

    // ============================================================
    // HQC
    // ============================================================

    private async void OnHqcGen(object s, RoutedEventArgs e)
    {
        HqcGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCKeyResult>("HQCKeyGen", TagOr(HqcParamBox, "HQC-128"));
            if (r.Success) { HqcPubBox.Text = r.PublicKey; HqcPrivBox.Text = r.PrivateKey; }
            else { HqcPubBox.Text = "生成失败：" + r.Error; HqcPrivBox.Text = ""; }
        }
        catch (EngineException ex) { HqcPubBox.Text = "引擎错误：" + ex.Message; }
        finally { HqcGenBtn.IsEnabled = true; }
    }

    private async void OnHqcEncap(object s, RoutedEventArgs e)
    {
        HqcEncapBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCEncapResult>("HQCEncapsulate", new { publicKey = HqcPubBox.Text.Trim(), paramSet = TagOr(HqcParamBox, "HQC-128") });
            if (r.Success) { HqcCipherBox.Text = r.Ciphertext; HqcSecretBox.Text = r.SharedSecret; }
            else { HqcCipherBox.Text = "封装失败：" + r.Error; }
        }
        catch (EngineException ex) { HqcCipherBox.Text = "引擎错误：" + ex.Message; }
        finally { HqcEncapBtn.IsEnabled = true; }
    }

    private async void OnHqcDecap(object s, RoutedEventArgs e)
    {
        HqcDecapBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<CryptoResult>("HQCDecapsulate", new { privateKey = HqcPrivBox.Text.Trim(), ciphertext = HqcCipherBox.Text.Trim(), paramSet = TagOr(HqcParamBox, "HQC-128") });
            HqcSecretBox.Text = r.Success ? r.Data : "解封装失败：" + r.Error;
        }
        catch (EngineException ex) { HqcSecretBox.Text = "引擎错误：" + ex.Message; }
        finally { HqcDecapBtn.IsEnabled = true; }
    }

    // ============================================================
    // AIGIS-sig
    // ============================================================

    private async void OnAigisGen(object s, RoutedEventArgs e)
    {
        AigisGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<PQCKeyResult>("AigisKeyGen", TagOr(AigisParamBox, "AIGIS-sig-1"));
            if (r.Success) { AigisPubBox.Text = r.PublicKey; AigisPrivBox.Text = r.PrivateKey; }
            else { AigisPubBox.Text = "生成失败：" + r.Error; AigisPrivBox.Text = ""; }
        }
        catch (EngineException ex) { AigisPubBox.Text = "引擎错误：" + ex.Message; }
        finally { AigisGenBtn.IsEnabled = true; }
    }

    private async Task AigisSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(AigisDataInput.Text, AigisSigBox); if (data is null) return;
        AigisSignBtn.IsEnabled = AigisVerifyBtn.IsEnabled = false;
        try
        {
            var ps = TagOr(AigisParamBox, "AIGIS-sig-1");
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("AigisSign", new { privateKey = AigisPrivBox.Text.Trim(), data, paramSet = ps });
                AigisSigBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("AigisVerify", new { publicKey = AigisPubBox.Text.Trim(), data, signature = AigisSigBox.Text.Trim(), paramSet = ps });
                AigisSigBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { AigisSigBox.Text = "引擎错误：" + ex.Message; }
        finally { AigisSignBtn.IsEnabled = AigisVerifyBtn.IsEnabled = true; }
    }

    private void OnAigisSign(object s, RoutedEventArgs e) => _ = AigisSignVerifyAsync(true);
    private void OnAigisVerify(object s, RoutedEventArgs e) => _ = AigisSignVerifyAsync(false);
}
