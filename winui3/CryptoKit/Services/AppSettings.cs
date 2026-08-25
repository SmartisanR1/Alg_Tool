using System.Text.Json;
using Microsoft.UI.Xaml;

namespace CryptoKit.Services;

/// <summary>
/// 便携设置：主题模式 + 窗口几何。默认写入 exe 同目录 settings.json（绿色便携，
/// 不占 C 盘）；当 exe 所在目录只读（如放在 Program Files）时回退到
/// %LOCALAPPDATA%\CryptoKit\settings.json（仅几 KB，非临时垃圾）。
/// </summary>
public sealed class AppSettings
{
    private const string FileName = "settings.json";

    public ElementTheme Theme { get; set; } = ElementTheme.Default;
    public double WindowWidth { get; set; } = 1440;
    public double WindowHeight { get; set; } = 900;

    /// <summary>窗口是否最大化。默认 true：首次启动即以最大化铺满屏幕，之后记住用户的选择。</summary>
    public bool IsMaximized { get; set; } = true;

    private string? _path;

    public void Load()
    {
        _path = ResolvePath();
        if (!File.Exists(_path)) return;

        try
        {
            var json = File.ReadAllText(_path);
            var data = JsonSerializer.Deserialize<AppSettings>(json);
            if (data is null) return;
            Theme = data.Theme;
            WindowWidth = data.WindowWidth > 0 ? data.WindowWidth : 1440;
            WindowHeight = data.WindowHeight > 0 ? data.WindowHeight : 900;
            IsMaximized = data.IsMaximized;
        }
        catch
        {
            // 设置损坏则回退默认，绝不因设置文件崩溃
        }
    }

    public void Save()
    {
        try
        {
            _path ??= ResolvePath();
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // 只读目录等场景静默失败，不影响功能
        }
    }

    private static string ResolvePath()
    {
        var exeDir = AppContext.BaseDirectory;
        try
        {
            // 可写则便携（exe 同目录）
            if (!string.IsNullOrEmpty(exeDir) && CanWrite(exeDir))
                return Path.Combine(exeDir, FileName);
        }
        catch { /* fall through */ }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoKit", FileName);
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, ".cryptokit-write-probe");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
