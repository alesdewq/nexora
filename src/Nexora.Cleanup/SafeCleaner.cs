using System.Text.Json;

namespace Nexora.Cleanup;

/// <summary>Способ удаления файла. Реализация для Windows — в Nexora.Platform (корзина или окончательное удаление).</summary>
public interface IFileRemover
{
    void Remove(string path, bool toRecycleBin);
}

/// <summary>План очистки, который пользователь явно подтвердил. Без подтверждения выполнить нельзя.</summary>
public sealed class CleanupPlan
{
    private CleanupPlan(CategoryPreview category, IReadOnlyList<CleanupCandidate> items, bool toRecycleBin, DateTimeOffset confirmedAt)
    {
        Category = category; Items = items; ToRecycleBin = toRecycleBin; ConfirmedAt = confirmedAt;
    }

    public CategoryPreview Category { get; }
    public IReadOnlyList<CleanupCandidate> Items { get; }
    public bool ToRecycleBin { get; }
    public DateTimeOffset ConfirmedAt { get; }

    /// <summary>Создать план после подтверждения. Можно выбрать только элементы из предпросмотра этой категории.</summary>
    public static CleanupPlan Confirm(CategoryPreview category, IEnumerable<CleanupCandidate> selected, bool toRecycleBin, DateTimeOffset now)
    {
        if (!category.CanClean) throw new InvalidOperationException($"Категория «{category.Title}» не поддерживает очистку.");
        if (category.Root is null) throw new InvalidOperationException("У категории нет корневой папки.");
        var allowed = category.Items.ToHashSet();
        var items = selected.ToList();
        if (items.Any(i => !allowed.Contains(i))) throw new InvalidOperationException("План содержит элементы не из предпросмотра.");
        return new CleanupPlan(category, items, toRecycleBin, now);
    }
}

public sealed record CleanupItemResult(string Path, bool Removed, string? Reason);

public sealed record CleanupReport(int Removed, long FreedBytes, int Skipped, IReadOnlyList<CleanupItemResult> Items);

public sealed record JournalEntry(DateTimeOffset At, string Action, string Target, string Result, string? Details);

/// <summary>Локальный журнал действий, меняющих систему (JSON Lines).</summary>
public sealed class ActionJournal(string file)
{
    public string File { get; } = file;

    public static string DefaultFile =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NEXORA", "logs", "actions.jsonl");

    public void Write(JournalEntry e)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(File)!);
        System.IO.File.AppendAllText(File, JsonSerializer.Serialize(e) + Environment.NewLine);
    }

    public IReadOnlyList<JournalEntry> Read() => !System.IO.File.Exists(File) ? [] :
        System.IO.File.ReadLines(File).Select(l => { try { return JsonSerializer.Deserialize<JournalEntry>(l); } catch (JsonException) { return null; } })
            .OfType<JournalEntry>().ToList();
}

public static class SafeCleaner
{
    public static CleanupReport Execute(CleanupPlan plan, IFileRemover remover, ActionJournal journal, Func<DateTimeOffset> clock,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var results = new List<CleanupItemResult>();
        long freed = 0;
        journal.Write(new JournalEntry(clock(), "cleanup.start", plan.Category.Root!, "started",
            $"{plan.Category.Title}: {plan.Items.Count} файлов, {(plan.ToRecycleBin ? "в корзину" : "окончательно")}, подтверждено {plan.ConfirmedAt:O}"));
        for (var i = 0; i < plan.Items.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var item = plan.Items[i];
            var reason = PathGuard.Validate(item.Path, plan.Category.Root!, item.SizeBytes, item.LastWriteUtc);
            if (reason is null)
            {
                try
                {
                    remover.Remove(item.Path, plan.ToRecycleBin);
                    freed += item.SizeBytes;
                    results.Add(new(item.Path, true, null));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
                {
                    results.Add(new(item.Path, false, ex is UnauthorizedAccessException ? "нет доступа" : $"файл занят или ошибка: {ex.Message}"));
                }
            }
            else
            {
                results.Add(new(item.Path, false, reason));
            }
            var r = results[^1];
            journal.Write(new JournalEntry(clock(), plan.ToRecycleBin ? "cleanup.recycle" : "cleanup.delete", item.Path, r.Removed ? "ok" : "skipped", r.Reason));
            progress?.Report((i + 1) / (double)plan.Items.Count);
        }
        var report = new CleanupReport(results.Count(r => r.Removed), freed, results.Count(r => !r.Removed), results);
        journal.Write(new JournalEntry(clock(), "cleanup.end", plan.Category.Root!, "finished", $"удалено {report.Removed}, пропущено {report.Skipped}, освобождено {freed} байт"));
        return report;
    }
}
