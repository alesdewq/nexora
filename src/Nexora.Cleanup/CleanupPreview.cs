namespace Nexora.Cleanup;

public enum CleanupCategory { UserTemp, WindowsTemp, RecycleBin, LargeFiles }

public sealed record CleanupCandidate(string Path, long SizeBytes, DateTimeOffset LastWriteUtc);

/// <param name="Root">Каталог категории; удаление возможно только внутри него.</param>
/// <param name="CanClean">Разрешена ли автоматическая очистка этой категории в NEXORA (с подтверждением).</param>
public sealed record CategoryPreview(
    CleanupCategory Category, string Title, string Explanation, string? Root, int FileCount, long TotalBytes,
    IReadOnlyList<CleanupCandidate> Items, bool CanClean, string Consequences, string? Unavailable = null, int SkippedInaccessible = 0);

public sealed record CleanupPreview(DateTimeOffset At, IReadOnlyList<CategoryPreview> Categories);

public static class CategoryText
{
    public static string ToDisplay(this CleanupCategory c) => c switch
    {
        CleanupCategory.UserTemp => "Временные файлы пользователя",
        CleanupCategory.WindowsTemp => "Временные файлы Windows",
        CleanupCategory.RecycleBin => "Корзина",
        CleanupCategory.LargeFiles => "Крупные файлы",
        _ => c.ToString(),
    };
}
