using System.Runtime.InteropServices;
using Nexora.Cleanup;

namespace Nexora.Platform;

/// <summary>Предпросмотр кандидатов на очистку на реальной системе (этап 7). Только чтение.</summary>
public static partial class CleanupCollector
{
    public static string UserTemp => Path.TrimEndingDirectorySeparator(Path.GetTempPath());
    public static string WindowsTemp => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
    public static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static CleanupPreview Collect(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        return new CleanupPreview(now,
        [
            PreviewScanner.ScanTemp(CleanupCategory.UserTemp, UserTemp, now, ct),
            PreviewScanner.ScanTemp(CleanupCategory.WindowsTemp, WindowsTemp, now, ct),
            RecycleBin(),
            PreviewScanner.ScanLargeFiles(UserProfile, ct),
        ]);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SHQUERYRBINFO { public int cbSize; public long i64Size; public long i64NumItems; }

    [LibraryImport("shell32.dll", EntryPoint = "SHQueryRecycleBinW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SHQueryRecycleBin(string? rootPath, ref SHQUERYRBINFO info);

    public static CategoryPreview RecycleBin()
    {
        const string title = "Корзина";
        const string consequences = "Очистка корзины необратима: удалённые файлы нельзя будет восстановить средствами Windows.";
        var info = new SHQUERYRBINFO { cbSize = Marshal.SizeOf<SHQUERYRBINFO>() };
        var hr = SHQueryRecycleBin(null, ref info);
        if (hr != 0)
            return new(CleanupCategory.RecycleBin, title, "", null, 0, 0, [], false, consequences, $"Shell не вернул сведения о корзине (0x{hr:X8})");
        // Корзина очищается целиком штатной функцией Windows, а не по файлам — поэтому CanClean=false для пофайлового плана.
        return new(CleanupCategory.RecycleBin, title, "Файлы, которые вы удалили, но ещё можете восстановить.", null,
            (int)info.i64NumItems, info.i64Size, [], false, consequences);
    }
}
