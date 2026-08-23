using CryptoKit.Models;
using CryptoKit.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

/// <summary>公钥/国密工作区：RSA / ECC / Ed25519·X25519 / SM2 / SM3 / SM4 / SM9 / ZUC。</summary>
public sealed partial class AsymmetricPage : Page
{
    private readonly EngineClient _engine;
    public AsymmetricPage(EngineClient engine) { _engine = engine; InitializeComponent(); }

    private static string CurTag(ComboBox box) => (box.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
    private static string CurText(ComboBox box) => (box.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "";
    private static string TagOr(ComboBox box, string def)
    {
        var t = CurTag(box);
        return string.IsNullOrEmpty(t) ? def : t;
    }
    private static string TextOr(ComboBox box, string def)
    {
        var t = CurText(box);
        return string.IsNullOrEmpty(t) ? def : t;
    }

    // 文本转 hex（用于需要原始数据的方法），失败时把消息写入 output 并返回 null
    private async Task<string?> ToHexAsync(string text, TextBox output)
    {
        if (string.IsNullOrEmpty(text)) { output.Text = "请输入内容"; return null; }
        var r = await _engine.CallAsync<ToolResult>("StringToHex", text);
        if (!r.Success) { output.Text = "编码失败：" + r.Error; return null; }
        return r.Data;
    }

    // ============================================================
    // RSA
    // ============================================================

    private async void OnRsaGenerate(object s, RoutedEventArgs e)
    {
        var bits = int.TryParse(CurTag(RsaBitsBox), out var b) ? b : 2048;
        RsaGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<KeyPairResult>("RSAGenerateKey", bits);
            if (r.Success) { RsaPubBox.Text = r.PublicKey; RsaPrivBox.Text = r.PrivateKey; }
            else { RsaPubBox.Text = "生成失败：" + r.Error; RsaPrivBox.Text = ""; }
        }
        catch (EngineException ex) { RsaPubBox.Text = "引擎错误：" + ex.Message; }
        finally { RsaGenBtn.IsEnabled = true; }
    }

    private async Task RsaCryptAsync(bool encrypt)
    {
        var key = encrypt ? RsaPubKeyInput.Text.Trim() : RsaPrivKeyInput.Text.Trim();
        var data = await ToHexAsync(RsaDataInput.Text, RsaResultBox); if (data is null) return;
        RsaEncBtn.IsEnabled = RsaDecBtn.IsEnabled = false;
        try
        {
            var req = new
            {
                key,
                data,
                padding = TagOr(RsaPaddingBox, "PKCS1v15"),
                hash = TextOr(RsaHashBox, "SHA256"),
            };
            var r = await _engine.CallAsync<CryptoResult>(encrypt ? "RSAEncrypt" : "RSADecrypt", req);
            RsaResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { RsaResultBox.Text = "引擎错误：" + ex.Message; }
        finally { RsaEncBtn.IsEnabled = RsaDecBtn.IsEnabled = true; }
    }

    private async Task RsaSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(RsaSignDataInput.Text, RsaSignResultBox); if (data is null) return;
        RsaSignBtn.IsEnabled = RsaVerifyBtn.IsEnabled = false;
        try
        {
            var hash = TextOr(RsaSignHashBox, "SHA256");
            var padding = TagOr(RsaSignPaddingBox, "PKCS1v15");
            if (sign)
            {
                var req = new { privateKey = RsaSignPrivInput.Text.Trim(), data, hash, padding };
                var r = await _engine.CallAsync<CryptoResult>("RSASign", req);
                RsaSignResultBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var req = new { publicKey = RsaVerifyPubInput.Text.Trim(), data, signature = RsaVerifySigInput.Text.Trim(), hash, padding };
                var r = await _engine.CallAsync<CryptoResult>("RSAVerify", req);
                RsaSignResultBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败：" + r.Data) : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { RsaSignResultBox.Text = "引擎错误：" + ex.Message; }
        finally { RsaSignBtn.IsEnabled = RsaVerifyBtn.IsEnabled = true; }
    }

    private void OnRsaEncrypt(object s, RoutedEventArgs e) => _ = RsaCryptAsync(true);
    private void OnRsaDecrypt(object s, RoutedEventArgs e) => _ = RsaCryptAsync(false);
    private void OnRsaSign(object s, RoutedEventArgs e) => _ = RsaSignVerifyAsync(true);
    private void OnRsaVerify(object s, RoutedEventArgs e) => _ = RsaSignVerifyAsync(false);

    // ============================================================
    // ECC
    // ============================================================

    private async void OnEccGenerate(object s, RoutedEventArgs e)
    {
        EccGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<KeyPairResult>("ECCGenerateKey", TagOr(EccCurveBox, "P-256"));
            if (r.Success) { EccPubBox.Text = r.PublicKey; EccPrivBox.Text = r.PrivateKey; }
            else { EccPubBox.Text = "生成失败：" + r.Error; EccPrivBox.Text = ""; }
        }
        catch (EngineException ex) { EccPubBox.Text = "引擎错误：" + ex.Message; }
        finally { EccGenBtn.IsEnabled = true; }
    }

    private async Task EccSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(EccDataInput.Text, EccResultBox); if (data is null) return;
        EccSignBtn.IsEnabled = EccVerifyBtn.IsEnabled = false;
        try
        {
            var curve = TagOr(EccCurveBox, "P-256");
            var hash = TextOr(EccHashBox, "SHA256");
            if (sign)
            {
                var req = new { privateKey = EccPrivKeyInput.Text.Trim(), data, hash, curve };
                var r = await _engine.CallAsync<CryptoResult>("ECCSign", req);
                EccResultBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var req = new { publicKey = EccPubKeyInput.Text.Trim(), data, signature = EccSigInput.Text.Trim(), hash, curve };
                var r = await _engine.CallAsync<CryptoResult>("ECCVerify", req);
                EccResultBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { EccResultBox.Text = "引擎错误：" + ex.Message; }
        finally { EccSignBtn.IsEnabled = EccVerifyBtn.IsEnabled = true; }
    }

    private async void OnEcdh(object s, RoutedEventArgs e)
    {
        EcdhBtn.IsEnabled = false;
        try
        {
            var req = new { privateKey = EcdhPrivInput.Text.Trim(), peerPublicKey = EcdhPeerInput.Text.Trim(), curve = TagOr(EccCurveBox, "P-256") };
            var r = await _engine.CallAsync<CryptoResult>("ECDHCompute", req);
            EcdhResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { EcdhResultBox.Text = "引擎错误：" + ex.Message; }
        finally { EcdhBtn.IsEnabled = true; }
    }

    private void OnEccSign(object s, RoutedEventArgs e) => _ = EccSignVerifyAsync(true);
    private void OnEccVerify(object s, RoutedEventArgs e) => _ = EccSignVerifyAsync(false);

    // ============================================================
    // Ed25519 / X25519
    // ============================================================

    private async void OnEdGenerate(object s, RoutedEventArgs e)
    {
        var method = TagOr(EdAlgoBox, "Ed25519") == "X25519" ? "X25519KeyGen" : "Ed25519KeyGen";
        EdGenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<KeyPairResult>(method);
            if (r.Success) { EdPubBox.Text = r.PublicKey; EdPrivBox.Text = r.PrivateKey; }
            else { EdPubBox.Text = "生成失败：" + r.Error; EdPrivBox.Text = ""; }
        }
        catch (EngineException ex) { EdPubBox.Text = "引擎错误：" + ex.Message; }
        finally { EdGenBtn.IsEnabled = true; }
    }

    private async Task EdSignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(EdDataInput.Text, EdResultBox); if (data is null) return;
        EdSignBtn.IsEnabled = EdVerifyBtn.IsEnabled = false;
        try
        {
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("Ed25519Sign", new { privateKey = EdPrivKeyInput.Text.Trim(), data });
                EdResultBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("Ed25519Verify", new { publicKey = EdPubKeyInput.Text.Trim(), data, signature = EdSigInput.Text.Trim() });
                EdResultBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { EdResultBox.Text = "引擎错误：" + ex.Message; }
        finally { EdSignBtn.IsEnabled = EdVerifyBtn.IsEnabled = true; }
    }

    private async void OnX25519Exchange(object s, RoutedEventArgs e)
    {
        X25519Btn.IsEnabled = false;
        try
        {
            var req = new { privateKey = X25519PrivInput.Text.Trim(), peerPublicKey = X25519PeerInput.Text.Trim() };
            var r = await _engine.CallAsync<CryptoResult>("X25519Exchange", req);
            X25519ResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { X25519ResultBox.Text = "引擎错误：" + ex.Message; }
        finally { X25519Btn.IsEnabled = true; }
    }

    private void OnEdSign(object s, RoutedEventArgs e) => _ = EdSignVerifyAsync(true);
    private void OnEdVerify(object s, RoutedEventArgs e) => _ = EdSignVerifyAsync(false);

    // ============================================================
    // SM2
    // ============================================================

    private async void OnSm2Generate(object s, RoutedEventArgs e)
    {
        Sm2GenBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<SM2KeyResult>("SM2GenerateKey");
            if (r.Success) { Sm2PubBox.Text = r.PublicKey; Sm2PrivBox.Text = r.PrivateKey; }
            else { Sm2PubBox.Text = "生成失败：" + r.Error; Sm2PrivBox.Text = ""; }
        }
        catch (EngineException ex) { Sm2PubBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm2GenBtn.IsEnabled = true; }
    }

    private async Task Sm2CryptAsync(bool encrypt)
    {
        var key = encrypt ? Sm2PubKeyInput.Text.Trim() : Sm2PrivKeyInput.Text.Trim();
        var data = await ToHexAsync(Sm2DataInput.Text, Sm2ResultBox); if (data is null) return;
        Sm2EncBtn.IsEnabled = Sm2DecBtn.IsEnabled = false;
        try
        {
            var req = new { key, data, mode = TagOr(Sm2ModeBox, "C1C3C2") };
            var r = await _engine.CallAsync<CryptoResult>(encrypt ? "SM2Encrypt" : "SM2Decrypt", req);
            Sm2ResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { Sm2ResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm2EncBtn.IsEnabled = Sm2DecBtn.IsEnabled = true; }
    }

    private async Task Sm2SignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(Sm2SignDataInput.Text, Sm2SignResultBox); if (data is null) return;
        Sm2SignBtn.IsEnabled = Sm2VerifyBtn.IsEnabled = false;
        try
        {
            var id = string.IsNullOrEmpty(Sm2IdInput.Text.Trim()) ? "1234567812345678" : Sm2IdInput.Text.Trim();
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("SM2Sign", new { privateKey = Sm2SignPrivInput.Text.Trim(), data, id });
                Sm2SignResultBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("SM2Verify", new { publicKey = Sm2VerifyPubInput.Text.Trim(), data, signature = Sm2VerifySigInput.Text.Trim(), id });
                Sm2SignResultBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { Sm2SignResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm2SignBtn.IsEnabled = Sm2VerifyBtn.IsEnabled = true; }
    }

    private void OnSm2Encrypt(object s, RoutedEventArgs e) => _ = Sm2CryptAsync(true);
    private void OnSm2Decrypt(object s, RoutedEventArgs e) => _ = Sm2CryptAsync(false);
    private void OnSm2Sign(object s, RoutedEventArgs e) => _ = Sm2SignVerifyAsync(true);
    private void OnSm2Verify(object s, RoutedEventArgs e) => _ = Sm2SignVerifyAsync(false);

    // ============================================================
    // SM3
    // ============================================================

    private async void OnSm3Hash(object s, RoutedEventArgs e)
    {
        var data = await ToHexAsync(Sm3DataInput.Text, Sm3ResultBox); if (data is null) return;
        Sm3HashBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<CryptoResult>("SM3Hash", new { data });
            Sm3ResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { Sm3ResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm3HashBtn.IsEnabled = true; }
    }

    private async void OnSm3Hmac(object s, RoutedEventArgs e)
    {
        var data = await ToHexAsync(Sm3HmacDataInput.Text, Sm3HmacResultBox); if (data is null) return;
        Sm3HmacBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<CryptoResult>("SM3HMAC", new { key = Sm3HmacKeyInput.Text.Trim(), data });
            Sm3HmacResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { Sm3HmacResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm3HmacBtn.IsEnabled = true; }
    }

    // ============================================================
    // SM4
    // ============================================================

    private async Task Sm4CryptAsync(bool encrypt)
    {
        Sm4EncBtn.IsEnabled = Sm4DecBtn.IsEnabled = false;
        try
        {
            var req = new
            {
                key = Sm4KeyInput.Text.Trim(),
                iv = Sm4IvInput.Text.Trim(),
                nonce = "",
                aad = "",
                data = Sm4DataInput.Text.Trim(),
                mode = TagOr(Sm4ModeBox, "CBC"),
                padding = TagOr(Sm4PaddingBox, "PKCS7"),
            };
            var r = await _engine.CallAsync<CryptoResult>(encrypt ? "SM4Encrypt" : "SM4Decrypt", req);
            Sm4ResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { Sm4ResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm4EncBtn.IsEnabled = Sm4DecBtn.IsEnabled = true; }
    }

    private void OnSm4Encrypt(object s, RoutedEventArgs e) => _ = Sm4CryptAsync(true);
    private void OnSm4Decrypt(object s, RoutedEventArgs e) => _ = Sm4CryptAsync(false);

    // ============================================================
    // SM9
    // ============================================================

    private async void OnSm9MasterKey(object s, RoutedEventArgs e)
    {
        Sm9MasterBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<SM9MasterKeyResult>("SM9GenerateMasterKey");
            if (r.Success) { Sm9MasterPrivBox.Text = r.MasterPrivateKey; Sm9MasterPubBox.Text = r.MasterPublicKey; }
            else { Sm9MasterPrivBox.Text = "生成失败：" + r.Error; Sm9MasterPubBox.Text = ""; }
        }
        catch (EngineException ex) { Sm9MasterPrivBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm9MasterBtn.IsEnabled = true; }
    }

    private async void OnSm9UserKey(object s, RoutedEventArgs e)
    {
        Sm9UserBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<SM9KeyResult>("SM9GenerateEncKey", Sm9MasterPrivBox.Text.Trim(), Sm9UidInput.Text.Trim());
            if (r.Success) { Sm9UserPrivBox.Text = r.PrivateKey; Sm9UserPubBox.Text = r.PublicKey; }
            else { Sm9UserPrivBox.Text = "生成失败：" + r.Error; Sm9UserPubBox.Text = ""; }
        }
        catch (EngineException ex) { Sm9UserPrivBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm9UserBtn.IsEnabled = true; }
    }

    private async Task Sm9CryptAsync(bool encrypt)
    {
        var data = await ToHexAsync(Sm9DataInput.Text, Sm9ResultBox); if (data is null) return;
        Sm9EncBtn.IsEnabled = Sm9DecBtn.IsEnabled = false;
        try
        {
            var req = new { masterPublicKey = Sm9MasterPubBox.Text.Trim(), userPrivateKey = Sm9UserPrivBox.Text.Trim(), uid = Sm9UidInput.Text.Trim(), data };
            var r = await _engine.CallAsync<CryptoResult>(encrypt ? "SM9Encrypt" : "SM9Decrypt", req);
            Sm9ResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { Sm9ResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm9EncBtn.IsEnabled = Sm9DecBtn.IsEnabled = true; }
    }

    private async Task Sm9SignVerifyAsync(bool sign)
    {
        var data = await ToHexAsync(Sm9SignDataInput.Text, Sm9SignResultBox); if (data is null) return;
        Sm9SignBtn.IsEnabled = Sm9VerifyBtn.IsEnabled = false;
        try
        {
            if (sign)
            {
                var r = await _engine.CallAsync<CryptoResult>("SM9Sign", new { userPrivateKey = Sm9SignPrivInput.Text.Trim(), data });
                Sm9SignResultBox.Text = r.Success ? r.Data : "签名失败：" + r.Error;
            }
            else
            {
                var r = await _engine.CallAsync<CryptoResult>("SM9Verify", new { masterPublicKey = Sm9SignMasterPubInput.Text.Trim(), uid = Sm9SignUidInput.Text.Trim(), data, signature = Sm9SignSigInput.Text.Trim() });
                Sm9SignResultBox.Text = r.Success ? (r.Data == "true" ? "验签通过" : "验签失败") : "验签失败：" + r.Error;
            }
        }
        catch (EngineException ex) { Sm9SignResultBox.Text = "引擎错误：" + ex.Message; }
        finally { Sm9SignBtn.IsEnabled = Sm9VerifyBtn.IsEnabled = true; }
    }

    private void OnSm9Encrypt(object s, RoutedEventArgs e) => _ = Sm9CryptAsync(true);
    private void OnSm9Decrypt(object s, RoutedEventArgs e) => _ = Sm9CryptAsync(false);
    private void OnSm9Sign(object s, RoutedEventArgs e) => _ = Sm9SignVerifyAsync(true);
    private void OnSm9Verify(object s, RoutedEventArgs e) => _ = Sm9SignVerifyAsync(false);

    // ============================================================
    // ZUC
    // ============================================================

    private async Task ZucCryptAsync(bool encrypt)
    {
        ZucEncBtn.IsEnabled = ZucDecBtn.IsEnabled = false;
        try
        {
            var req = new { key = ZucKeyInput.Text.Trim(), iv = ZucIvInput.Text.Trim(), data = ZucDataInput.Text.Trim(), type = TagOr(ZucTypeBox, "ZUC-128") };
            var r = await _engine.CallAsync<CryptoResult>(encrypt ? "ZUCEncrypt" : "ZUCDecrypt", req);
            ZucResultBox.Text = r.Success ? r.Data : "计算失败：" + r.Error;
        }
        catch (EngineException ex) { ZucResultBox.Text = "引擎错误：" + ex.Message; }
        finally { ZucEncBtn.IsEnabled = ZucDecBtn.IsEnabled = true; }
    }

    private void OnZucEncrypt(object s, RoutedEventArgs e) => _ = ZucCryptAsync(true);
    private void OnZucDecrypt(object s, RoutedEventArgs e) => _ = ZucCryptAsync(false);
}
