namespace Nexora.Cleanup;

/// <summary>Поиск кандидатов на очистку. Только чтение: файлы не открываются на запись и не удаляются.</summary>
public static class PreviewScanner
{
    public static readonly TimeSpan TempMinAge = TimeSpan.FromHours(24);
    public const long LargeFileBytes = 500L << 20;
    public const int LargeFilesMax = 30;

    /// <summary>Ссылки (symlink/junction) и системные файлы пропускаются: обход не выходит за пределы каталога.</summary>
    public static EnumerationOptions SafeEnumeration => new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System | FileAttributes.Device,
        ReturnSpecialDirectories = false,
    };

    public static CategoryPreview ScanTemp(CleanupCategory category, string root, DateTimeOffset now, CancellationToken ct = default)
    {
        var (title, explanation) = category == CleanupCategory.WindowsTemp
            ? ("Временные файлы Windows", "Временные файлы установщиков и служб Windows.")
            : ("Временные файлы пользователя", "Программы складывают сюда промежуточные файлы и часто не удаляют их за собой.");
        const string consequences = "Удаляются только файлы старше 24 часов. Файлы, занятые запущенными программами, будут пропущены. Обычно удаление безопасно; изредка программа может заново создать свои временные данные.";
        if (!Directory.Exists(root))
            return new(category, title, explanation, root, 0, 0, [], false, consequences, "папка не существует");
        if (new DirectoryInfo(root).Attributes.HasFlag(FileAttributes.ReparsePoint))
            return new(category, title, explanation, root, 0, 0, [], false, consequences, "папка является ссылкой — обход отключён для безопасности");

        var items = new List<CleanupCandidate>();
        var skipped = 0;
        try
        {
            foreach (var path in Directory.EnumerateFiles(root, "*", SafeEnumeration))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var fi = new FileInfo(path);
                    if (now - fi.LastWriteTimeUtc < TempMinAge) continue;
                    items.Add(new CleanupCandidate(fi.FullName, fi.Length, fi.LastWriteTimeUtc));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { skipped++; }
            }
        }
        catch (UnauthorizedAccessException)
        {
            return new(category, title, explanation, root, 0, 0, [], false, consequences, "нет доступа к папке (нужны права администратора)");
        }
        return new(category, title, explanation, root, items.Count, items.Sum(i => i.SizeBytes), items,
            category == CleanupCategory.UserTemp, consequences, null, skipped);
    }

    public static CategoryPreview ScanLargeFiles(string root, CancellationToken ct = default)
    {
        const string consequences = "NEXORA не предлагает удалять эти файлы: размер и возраст не говорят о том, что файл не нужен. Решение — только за вами.";
        if (!Directory.Exists(root))
            return new(CleanupCategory.LargeFiles, "Крупные файлы", "", root, 0, 0, [], false, consequences, "папка не существует");
        var top = new List<CleanupCandidate>();
        var count = 0;
        long total = 0;
        foreach (var path in Directory.EnumerateFiles(root, "*", SafeEnumeration))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length < LargeFileBytes) continue;
                count++; total += fi.Length;
                top.Add(new CleanupCandidate(fi.FullName, fi.Length, fi.LastWriteTimeUtc));
                if (top.Count > LargeFilesMax * 2) top = top.OrderByDescending(x => x.SizeBytes).Take(LargeFilesMax).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return new(CleanupCategory.LargeFiles, "Крупные файлы",
            $"Файлы от {LargeFileBytes >> 20} МБ в папке пользователя — для информации.", root, count, total,
            top.OrderByDescending(x => x.SizeBytes).Take(LargeFilesMax).ToList(), false, consequences);
    }
}
