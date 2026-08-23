using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace CryptoKit.Services;

/// <summary>
/// 密码引擎客户端：拉起 CryptoKitEngine.exe 子进程，通过 stdin/stdout
/// 用「每行一条 JSON-RPC」协议通信。引擎为无状态纯计算进程，不落盘、
/// 不创建临时目录；本类 Dispose 时结束子进程，保证零残留。
///
/// 协议（与 Go 端 engine/dispatch.go 对应）：
///   请求  {"id":1,"method":"Hash","params":[{"algorithm":"SHA256","data":"..."}]}
///   成功  {"id":1,"result":{...}}
///   失败  {"id":1,"error":"..."}
/// </summary>
public sealed class EngineClient : IDisposable
{
    private const string EngineExe = "CryptoKitEngine.exe";

    private Process? _process;
    private StreamWriter? _stdin;
    private readonly object _writeLock = new();
    private long _nextId;

    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> _pending = new();

    public bool IsRunning => _process is { HasExited: false };

    /// <summary>启动引擎子进程。引擎必须与本程序位于同一目录。</summary>
    public void Start()
    {
        var exe = Path.Combine(AppContext.BaseDirectory, EngineExe);
        if (!File.Exists(exe))
            throw new FileNotFoundException($"未找到密码引擎 {EngineExe}，请先运行构建脚本。", exe);

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        _process = new Process { StartInfo = psi };
        if (!_process.Start())
            throw new InvalidOperationException("无法启动密码引擎进程。");

        _stdin = _process.StandardInput;

        // 读取响应循环 + stderr 排空（防止缓冲区填满导致死锁）
        _ = Task.Run(ReadLoopAsync);
        _ = Task.Run(DrainStderrAsync);
    }

    /// <summary>调用引擎方法，返回 result 的原始 JSON 元素。</summary>
    public Task<JsonElement> CallAsync(string method, params object?[] args)
    {
        EnsureStarted();

        var id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        var payload = JsonSerializer.Serialize(new { id, method, @params = args });
        lock (_writeLock)
        {
            _stdin!.WriteLine(payload);
            _stdin.Flush();
        }

        return tcs.Task;
    }

    /// <summary>调用引擎方法并反序列化为指定结果类型。</summary>
    public async Task<T> CallAsync<T>(string method, params object?[] args)
    {
        var element = await CallAsync(method, args).ConfigureAwait(false);
        return element.Deserialize<T>() ?? throw new JsonException($"无法反序列化 {method} 的返回值为 {typeof(T).Name}");
    }

    private async Task ReadLoopAsync()
    {
        var reader = _process!.StandardOutput;
        while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            HandleLine(line);
        }
    }

    private void HandleLine(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            if (!root.TryGetProperty("id", out var idEl) || !idEl.TryGetInt64(out var id))
                return; // 协议错误响应（无 id），忽略

            if (!_pending.TryRemove(id, out var tcs))
                return;

            if (root.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.String)
            {
                tcs.TrySetException(new EngineException(err.GetString() ?? "未知引擎错误"));
                return;
            }

            if (root.TryGetProperty("result", out var result))
                tcs.TrySetResult(result.Clone());
            else
                tcs.TrySetException(new EngineException("引擎响应缺少 result 字段"));
        }
        catch (JsonException ex)
        {
            // 单行解析失败不拖垮整个读取循环
            System.Diagnostics.Debug.WriteLine($"[EngineClient] 解析失败: {ex.Message}");
        }
    }

    private void DrainStderrAsync()
    {
        var reader = _process!.StandardError;
        while (reader.ReadLine() is { } line)
        {
            System.Diagnostics.Debug.WriteLine($"[engine] {line}");
        }
    }

    private void EnsureStarted()
    {
        if (!IsRunning)
            throw new InvalidOperationException("密码引擎未运行。");
    }

    public void Dispose()
    {
        // 关闭 stdin 让引擎读到 EOF 自行退出；再兜底 Kill，确保不留孤儿进程
        try { _stdin?.Close(); } catch { /* ignore */ }

        try
        {
            if (_process is { HasExited: false })
            {
                if (!_process.WaitForExit(1500))
                    _process.Kill(entireProcessTree: true);
            }
        }
        catch { /* ignore */ }

        _process?.Dispose();
        _process = null;
        _stdin = null;

        foreach (var tcs in _pending.Values)
            tcs.TrySetCanceled();
        _pending.Clear();
    }
}

public sealed class EngineException : Exception
{
    public EngineException(string message) : base(message) { }
}
