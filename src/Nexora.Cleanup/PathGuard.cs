namespace Nexora.Cleanup;

/// <summary>
/// Повторная проверка объекта непосредственно перед действием: путь внутри разрешённого корня, без ссылок на всём пути,
/// без «..», устройств, альтернативных потоков; файл тот же, что был показан в предпросмотре (размер и время изменения).
/// </summary>
public static class PathGuard
{
    public static string? Validate(string candidate, string allowedRoot, long expectedSize, DateTimeOffset expectedLastWriteUtc)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(allowedRoot)) return "пустой путь";
        if (candidate.StartsWith(@"\\", StringComparison.Ordinal) || candidate.StartsWith("//", StringComparison.Ordinal))
            return "сетевые и аппаратные пути (\\\\…) не допускаются";
        if (candidate.Split('\\', '/').Any(seg => seg == ".."))
            return "путь содержит «..»";
        if (candidate.IndexOf(':', 2) >= 0) return "альтернативные потоки данных и нестандартные пути не допускаются";
        if (candidate.TrimEnd().EndsWith('.') || candidate.EndsWith(' ')) return "путь оканчивается точкой или пробелом";

        string full, root;
        try
        {
            full = Path.GetFullPath(candidate);
            root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(allowedRoot));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return "некорректный путь";
        }
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return "файл находится вне разрешённой папки";

        // Ни корень, ни один промежуточный каталог, ни сам файл не должны быть ссылкой (symlink, junction).
        var current = root;
        if (IsLink(current)) return "разрешённая папка является ссылкой";
        foreach (var part in full[(root.Length + 1)..].Split(Path.DirectorySeparatorChar))
        {
            current = Path.Combine(current, part);
            if (IsLink(current)) return $"на пути есть ссылка: {current}";
        }

        var fi = new FileInfo(full);
        if (!fi.Exists) return "файл уже не существует";
        if (fi.Attributes.HasFlag(FileAttributes.System)) return "системный файл";
        if (fi.Length != expectedSize || fi.LastWriteTimeUtc != expectedLastWriteUtc.UtcDateTime)
            return "файл изменился после предпросмотра";
        return null;
    }

    private static bool IsLink(string path)
    {
        try
        {
            var attrs = File.GetAttributes(path);
            return attrs.HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return false; }
    }
}
