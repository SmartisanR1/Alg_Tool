using System.Text;
using CryptoKit.Models;
using CryptoKit.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace CryptoKit.Pages;

/// <summary>协议联调：TLS 连接测试、报文收发、TLS/TLCP 本地演示。</summary>
public sealed partial class PacketPage : Page
{
    private readonly EngineClient _engine;
    public PacketPage(EngineClient engine) { _engine = engine; InitializeComponent(); }

    private static string CurTag(ComboBox box) => (box.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
    private static string TagOr(ComboBox box, string def)
    {
        var t = CurTag(box);
        return string.IsNullOrEmpty(t) ? def : t;
    }

    private static int IntOr(string text, int def) => int.TryParse(text, out var v) ? v : def;

    private async void OnTlsConnect(object s, RoutedEventArgs e)
    {
        TlsConnectBtn.IsEnabled = false;
        try
        {
            var req = new
            {
                host = TlsHostInput.Text.Trim(),
                port = IntOr(TlsPortInput.Text, 443),
                protocol = TagOr(TlsProtoBox, "tls1.2"),
                serverName = TlsServerNameInput.Text.Trim(),
                insecureSkipVerify = TlsInsecureCheck.IsChecked == true,
                caCertPEM = "",
                clientCertPEM = "",
                clientKeyPEM = "",
                clientEncCertPEM = "",
                clientEncKeyPEM = "",
                timeoutMs = 10000,
                enablePQC = false,
            };
            var r = await _engine.CallAsync<TLSConnectResult>("TLSConnect", req);
            var sb = new StringBuilder();
            if (r.Success)
            {
                sb.AppendLine($"协议：{r.Protocol}    版本：{r.TlsVersion}");
                sb.AppendLine($"CipherSuite：{r.CipherSuite} ({r.CipherSuiteId})");
                sb.AppendLine($"ServerName：{r.ServerName}    ALPN：{r.AlpnProtocol}    曲线：{r.CurveUsed}");
                sb.AppendLine($"握手耗时：{r.HandshakeTimeMs} ms    会话复用：{r.SessionReused}");
                foreach (var c in r.PeerCertificates)
                {
                    sb.AppendLine("—");
                    sb.AppendLine($"证书主题：{c.Subject}");
                    sb.AppendLine($"颁发者：{c.Issuer}");
                    sb.AppendLine($"序列号：{c.SerialNumber}");
                    sb.AppendLine($"有效期：{c.NotBefore} ~ {c.NotAfter}");
                    sb.AppendLine($"指纹：{c.Fingerprint}");
                }
            }
            else sb.AppendLine("连接失败：" + r.Error);
            TlsResultBox.Text = sb.ToString();
        }
        catch (EngineException ex) { TlsResultBox.Text = "引擎错误：" + ex.Message; }
        finally { TlsConnectBtn.IsEnabled = true; }
    }

    private async void OnListCiphers(object s, RoutedEventArgs e)
    {
        ListCiphersBtn.IsEnabled = false;
        try
        {
            var tls = await _engine.CallAsync<ToolResult>("ListTLSCipherSuites");
            var tlcp = await _engine.CallAsync<ToolResult>("ListTLCPCipherSuites");
            var sb = new StringBuilder();
            sb.AppendLine("— TLS 支持的密码套件 —");
            sb.AppendLine(tls.Success ? tls.Data : "读取失败：" + tls.Error);
            sb.AppendLine();
            sb.AppendLine("— TLCP 支持的密码套件 —");
            sb.AppendLine(tlcp.Success ? tlcp.Data : "读取失败：" + tlcp.Error);
            TlsResultBox.Text = sb.ToString();
        }
        catch (EngineException ex) { TlsResultBox.Text = "引擎错误：" + ex.Message; }
        finally { ListCiphersBtn.IsEnabled = true; }
    }

    private async void OnSendPacket(object s, RoutedEventArgs e)
    {
        SendPacketBtn.IsEnabled = false;
        try
        {
            var req = new
            {
                host = PktHostInput.Text.Trim(),
                port = IntOr(PktPortInput.Text, 443),
                network = TagOr(PktNetworkBox, "auto"),
                transport = TagOr(PktTransportBox, "plain"),
                serverName = PktServerNameInput.Text.Trim(),
                insecureSkipVerify = PktInsecureCheck.IsChecked == true,
                headerLength = IntOr(PktHeaderLenInput.Text, 0),
                timeoutSec = IntOr(PktTimeoutInput.Text, 5),
                payload = PktPayloadInput.Text.Trim(),
                payloadFormat = TagOr(PktPayloadFmtBox, "text"),
                responseFormat = TagOr(PktRespFmtBox, "text"),
                filePath = "",
                caCertPEM = "",
                clientCertPEM = "",
                clientKeyPEM = "",
                clientEncCertPEM = "",
                clientEncKeyPEM = "",
            };
            var r = await _engine.CallAsync<PacketIOResult>("SendPacket", req);
            var sb = new StringBuilder();
            if (r.Success)
            {
                sb.AppendLine($"请求 {r.RequestBytes} 字节，响应 {r.ResponseBytes} 字节，耗时 {r.DurationMs} ms");
                if (!string.IsNullOrEmpty(r.HeaderHex)) sb.AppendLine("响应头(Hex)：" + r.HeaderHex);
                sb.AppendLine("响应(Hex)：" + r.ResponseHex);
                sb.AppendLine("响应(文本)：" + r.Response);
            }
            else sb.AppendLine("发送失败：" + r.Error);
            PktResultBox.Text = sb.ToString();
        }
        catch (EngineException ex) { PktResultBox.Text = "引擎错误：" + ex.Message; }
        finally { SendPacketBtn.IsEnabled = true; }
    }

    private string _demoSession = "";

    private async void OnDemoStart(object s, RoutedEventArgs e)
    {
        DemoStartBtn.IsEnabled = false;
        try
        {
            var req = new { protocol = TagOr(DemoProtoBox, "tls1.2"), enablePQC = false };
            var r = await _engine.CallAsync<TLSDemoResult>("TLSDemoServerStart", req);
            if (r.Success)
            {
                _demoSession = r.SessionId;
                DemoPortText.Text = "监听端口：" + r.Port + "（会话 " + r.SessionId + "）";
            }
            DemoLogBox.Text = r.Success ? FormatDemo(r) : "启动失败：" + r.Error;
        }
        catch (EngineException ex) { DemoLogBox.Text = "引擎错误：" + ex.Message; }
        finally { DemoStartBtn.IsEnabled = true; }
    }

    private async void OnDemoConnect(object s, RoutedEventArgs e)
    {
        DemoConnectBtn.IsEnabled = false;
        try
        {
            var r = await _engine.CallAsync<TLSDemoResult>("TLSDemoClientConnect", new { sessionId = _demoSession });
            DemoLogBox.Text = r.Success ? FormatDemo(r) : "连接失败：" + r.Error;
        }
        catch (EngineException ex) { DemoLogBox.Text = "引擎错误：" + ex.Message; }
        finally { DemoConnectBtn.IsEnabled = true; }
    }

    private async void OnDemoSend(object s, RoutedEventArgs e)
    {
        DemoSendBtn.IsEnabled = false;
        try
        {
            var side = TagOr(DemoSideBox, "client");
            var r = await _engine.CallAsync<TLSDemoResult>("TLSDemoSend", new { sessionId = _demoSession, side, message = DemoMsgInput.Text.Trim() });
            DemoLogBox.Text = r.Success ? FormatDemo(r) : "发送失败：" + r.Error;
        }
        catch (EngineException ex) { DemoLogBox.Text = "引擎错误：" + ex.Message; }
        finally { DemoSendBtn.IsEnabled = true; }
    }

    private async void OnDemoRefresh(object s, RoutedEventArgs e)
    {
        try
        {
            var r = await _engine.CallAsync<TLSDemoResult>("TLSDemoGetState", new { sessionId = _demoSession });
            DemoLogBox.Text = r.Success ? FormatDemo(r) : "读取失败：" + r.Error;
        }
        catch (EngineException ex) { DemoLogBox.Text = "引擎错误：" + ex.Message; }
    }

    private async void OnDemoClose(object s, RoutedEventArgs e)
    {
        try
        {
            var r = await _engine.CallAsync<TLSDemoResult>("TLSDemoClose", new { sessionId = _demoSession });
            DemoLogBox.Text = r.Success ? "已关闭会话。" : "关闭失败：" + r.Error;
        }
        catch (EngineException ex) { DemoLogBox.Text = "引擎错误：" + ex.Message; }
    }

    private static string FormatDemo(TLSDemoResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"会话 {r.SessionId}    服务端：{r.ServerStatus}    客户端：{r.ClientStatus}");
        sb.AppendLine("— 服务端时间线 —");
        foreach (var x in r.ServerTimeline) sb.AppendLine(x);
        sb.AppendLine("— 客户端时间线 —");
        foreach (var x in r.ClientTimeline) sb.AppendLine(x);
        if (r.ServerMessages.Count > 0) { sb.AppendLine("— 服务端收到 —"); foreach (var x in r.ServerMessages) sb.AppendLine(x); }
        if (r.ClientMessages.Count > 0) { sb.AppendLine("— 客户端收到 —"); foreach (var x in r.ClientMessages) sb.AppendLine(x); }
        return sb.ToString();
    }
}
