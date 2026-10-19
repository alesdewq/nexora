using System.Globalization;

namespace Nexora.Cleanup;

public static class CleanupAnalyzer
{
    public const long NoticeBytes = 1L << 30;

    public static IReadOnlyList<CheckResult> Analyze(CleanupPreview p)
    {
        var results = new List<CheckResult>();
        foreach (var c in p.Categories)
        {
            var id = c.Category switch
            {
                CleanupCategory.UserTemp => "files.temp.user",
                CleanupCategory.WindowsTemp => "files.temp.windows",
                CleanupCategory.RecycleBin => "files.recycle-bin",
                _ => "files.large",
            };
            var ev = new Evidence(c.Root ?? c.Title, $"файлов: {c.FileCount}, объём: {Size(c.TotalBytes)}");
            if (c.Unavailable is not null)
            {
                results.Add(CheckResult.Unavailable(id, c.Title, Section.FilesAndPrograms, c.Root ?? c.Title, c.Unavailable));
                continue;
            }
            if (c.Category == CleanupCategory.LargeFiles)
            {
                results.Add(c.FileCount == 0
                    ? CheckResult.Ok(id, c.Title, Section.FilesAndPrograms, $"Файлов крупнее {PreviewScanner.LargeFileBytes >> 20} МБ в папке пользователя нет.", ev)
                    : CheckResult.Finding(id, c.Title, Section.FilesAndPrograms, Severity.Info, FindingKind.Fact, Confidence.High,
                        $"Крупных файлов: {c.FileCount}, всего {Size(c.TotalBytes)}. Самые большие: " +
                        string.Join("; ", c.Items.Take(3).Select(i => $"{Path.GetFileName(i.Path)} ({Size(i.SizeBytes)})")) + ".",
                        "Крупные файлы — первое, что стоит посмотреть, если не хватает места.",
                        "Просмотрите список и решите сами; NEXORA не считает эти файлы ненужными и не удаляет их.", ev)
                        with { Limitations = ["Ищутся только файлы в папке профиля; ссылки и системные файлы пропускаются."] });
                continue;
            }
            var big = c.TotalBytes >= NoticeBytes;
            results.Add(big
                ? CheckResult.Finding(id, c.Title, Section.FilesAndPrograms, Severity.Info, FindingKind.Recommendation, Confidence.High,
                    $"{c.Title}: {Size(c.TotalBytes)} ({c.FileCount} файлов).",
                    c.Explanation, c.CanClean ? "Можно очистить в разделе «Файлы и программы» — NEXORA покажет список и попросит подтверждение." : "Очистите средствами Windows («Параметры → Система → Память»).", ev)
                    with { AutomatedActionAvailable = c.CanClean, Consequences = c.Consequences }
                : CheckResult.Ok(id, c.Title, Section.FilesAndPrograms, $"{c.Title}: {Size(c.TotalBytes)} ({c.FileCount} файлов) — немного.", ev));
        }
        return results;
    }

    public static string Size(long bytes) => bytes switch
    {
        >= 1L << 30 => (bytes / (double)(1L << 30)).ToString("0.##", CultureInfo.GetCultureInfo("ru-RU")) + " ГБ",
        >= 1L << 20 => (bytes / (double)(1L << 20)).ToString("0.#", CultureInfo.GetCultureInfo("ru-RU")) + " МБ",
        _ => (bytes / 1024.0).ToString("0", CultureInfo.GetCultureInfo("ru-RU")) + " КБ",
    };
}
