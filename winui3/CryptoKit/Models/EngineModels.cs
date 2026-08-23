namespace CryptoKit.Models;

/// <summary>通用结果类型：与 Go 端 symmetric.CryptoResult 的 JSON 字段一致。</summary>
public sealed class CryptoResult
{
    public bool Success { get; set; }
    public string Data { get; set; } = "";
    public string Error { get; set; } = "";
    public string Extra { get; set; } = "";
}

/// <summary>工具类结果：与 Go 端 utils.ToolResult 一致。</summary>
public sealed class ToolResult
{
    public bool Success { get; set; }
    public string Data { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 asymmetric.KeyPairResult 的 JSON 字段一致。</summary>
public sealed class KeyPairResult
{
    public bool Success { get; set; }
    public string PrivateKey { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string PrivHex { get; set; } = "";
    public string PubHex { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 gm.SM2KeyResult 一致。</summary>
public sealed class SM2KeyResult
{
    public bool Success { get; set; }
    public string PrivateKey { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string PrivHex { get; set; } = "";
    public string PubHex { get; set; } = "";
    public string RawPriv { get; set; } = "";
    public string RawPub { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 gm.SM9KeyResult 一致。</summary>
public sealed class SM9KeyResult
{
    public bool Success { get; set; }
    public string PrivateKey { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 gm.SM9MasterKeyResult 一致。</summary>
public sealed class SM9MasterKeyResult
{
    public bool Success { get; set; }
    public string MasterPrivateKey { get; set; } = "";
    public string MasterPublicKey { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 pqc.PQCKeyResult 一致。</summary>
public sealed class PQCKeyResult
{
    public bool Success { get; set; }
    public string PrivateKey { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string ParamSet { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 pqc.PQCEncapResult 一致。</summary>
public sealed class PQCEncapResult
{
    public bool Success { get; set; }
    public string Ciphertext { get; set; } = "";
    public string SharedSecret { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 utils.TLSConnectResult 中的证书信息一致。</summary>
public sealed class CertInfo
{
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public string NotBefore { get; set; } = "";
    public string NotAfter { get; set; } = "";
    public List<string> DnsNames { get; set; } = new();
    public List<string> IpAddresses { get; set; } = new();
    public bool IsCa { get; set; }
    public string KeyAlgorithm { get; set; } = "";
    public string SigAlgorithm { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string RawPem { get; set; } = "";
}

/// <summary>与 Go 端 utils.TLSConnectResult 一致。</summary>
public sealed class TLSConnectResult
{
    public bool Success { get; set; }
    public string Protocol { get; set; } = "";
    public string CipherSuite { get; set; } = "";
    public string CipherSuiteId { get; set; } = "";
    public string ServerName { get; set; } = "";
    public string TlsVersion { get; set; } = "";
    public long HandshakeTimeMs { get; set; }
    public List<CertInfo> PeerCertificates { get; set; } = new();
    public string AlpnProtocol { get; set; } = "";
    public bool SessionReused { get; set; }
    public string CurveUsed { get; set; } = "";
    public string Error { get; set; } = "";
}

/// <summary>与 Go 端 utils.PacketIOResult 一致。</summary>
public sealed class PacketIOResult
{
    public bool Success { get; set; }
    public string Error { get; set; } = "";
    public string Response { get; set; } = "";
    public string ResponseHex { get; set; } = "";
    public int RequestBytes { get; set; }
    public int ResponseBytes { get; set; }
    public string HeaderHex { get; set; } = "";
    public long DurationMs { get; set; }
}

/// <summary>与 Go 端 utils.TLSDemoResult 一致。</summary>
public sealed class TLSDemoResult
{
    public bool Success { get; set; }
    public string Error { get; set; } = "";
    public string SessionId { get; set; } = "";
    public int Port { get; set; }
    public string ServerStatus { get; set; } = "";
    public string ClientStatus { get; set; } = "";
    public List<string> ServerTimeline { get; set; } = new();
    public List<string> ClientTimeline { get; set; } = new();
    public List<string> ServerMessages { get; set; } = new();
    public List<string> ClientMessages { get; set; } = new();
}
