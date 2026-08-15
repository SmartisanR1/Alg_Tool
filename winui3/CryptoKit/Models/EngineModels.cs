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
