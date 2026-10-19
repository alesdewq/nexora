using System.Diagnostics;

namespace Nexora.Cleanup.Tests;

/// <summary>Изолированный временный каталог для тестов очистки. Удаляется после теста; ссылки удаляются без перехода по ним.</summary>
internal sealed class TempTree : IDisposable
{
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "nexora-cleanup-test-" + Guid.NewGuid().ToString("N"));

    public TempTree() => Directory.CreateDirectory(Root);

    public string File(string relative, int bytes = 100, TimeSpan? age = null)
    {
        var path = Path.Combine(Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllBytes(path, new byte[bytes]);
        System.IO.File.SetLastWriteTimeUtc(path, DateTime.UtcNow - (age ?? TimeSpan.FromDays(3)));
        return path;
    }

    /// <summary>Junction (mklink /J) не требует прав администратора.</summary>
    public static void Junction(string link, string target)
    {
        using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true })!;
        p.WaitForExit();
        if (p.ExitCode != 0 || !Directory.Exists(link)) throw new InvalidOperationException("не удалось создать junction");
    }

    public void Dispose()
    {
        // Сначала убираем ссылки (Directory.Delete на junction удаляет только ссылку), затем остальное.
        foreach (var d in Directory.EnumerateDirectories(Root, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 })
                     .Where(d => new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)).ToList())
            Directory.Delete(d);
        Directory.Delete(Root, true);
    }
}

internal sealed class RecordingRemover : IFileRemover
{
    public List<string> Removed { get; } = [];
    public void Remove(string path, bool toRecycleBin) { System.IO.File.Delete(path); Removed.Add(path); }
}
