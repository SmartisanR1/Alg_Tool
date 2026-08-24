using System.Text;

namespace CryptoKit.Services;

/// <summary>
/// 启动失败 / 未处理异常日志：写入 exe 同目录 startup-error.log（目录只读时回退
/// %LOCALAPPDATA%\CryptoKit）。目的：即使界面无法渲染，也能让用户拿到失败原因，
/// 杜绝「点开没反应 / 进程在但没窗口」这种无法定位的故障。
/// </summary>
public static class CrashLog
{
    /// <summary>追加一条错误记录。日志失败绝不再引发新异常。</summary>
    public static void Write(Exception? ex, string phase)
    {
        try
        {
            var dir = ResolveDir();
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var sb = new StringBuilder();
            sb.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {phase} 失败");
            sb.AppendLine(ex?.ToString() ?? "(无异常对象)");
            sb.AppendLine(new string('-', 60));
            File.AppendAllText(Path.Combine(dir, "startup-error.log"), sb.ToString());
        }
        catch { /* 忽略 */ }
    }

    private static string ResolveDir()
    {
        try
        {
            var exeDir = AppContext.BaseDirectory;
            if (!string.IsNullOrEmpty(exeDir) && CanWrite(exeDir)) return exeDir;
        }
        catch { /* 忽略 */ }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoKit");
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, ".cryptokit-log-probe");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch { return false; }
    }
}
