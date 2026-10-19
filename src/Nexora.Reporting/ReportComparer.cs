namespace Nexora.Reporting;

public sealed record SeverityChange(ReportedFinding Before, ReportedFinding After);

public sealed record ReportComparison(
    IReadOnlyList<ReportedFinding> New,
    IReadOnlyList<ReportedFinding> Resolved,
    IReadOnlyList<SeverityChange> Changed,
    IReadOnlyList<ReportedFinding> Persisting,
    IReadOnlyList<ReportedFinding> NoLongerChecked);

/// <summary>Сравнение двух отчётов по идентификаторам проверок.</summary>
public static class ReportComparer
{
    public static ReportComparison Compare(ReportDocument older, ReportDocument newer)
    {
        static bool Issue(ReportedFinding f) => f.Status == CheckStatus.Finding;
        var before = older.Findings.ToDictionary(f => f.Id, StringComparer.Ordinal);
        var after = newer.Findings.ToDictionary(f => f.Id, StringComparer.Ordinal);

        var added = new List<ReportedFinding>();
        var resolved = new List<ReportedFinding>();
        var changed = new List<SeverityChange>();
        var persisting = new List<ReportedFinding>();
        var unchecked_ = new List<ReportedFinding>();

        foreach (var (id, a) in after)
        {
            before.TryGetValue(id, out var b);
            if (Issue(a))
            {
                if (b is null || !Issue(b)) added.Add(a);
                else if (b.Severity != a.Severity) changed.Add(new SeverityChange(b, a));
                else persisting.Add(a);
            }
            else if (b is not null && Issue(b))
            {
                // Было замечание, а теперь проверка не выполнилась — это не «устранено».
                if (a.Status is CheckStatus.Unavailable or CheckStatus.Failed) unchecked_.Add(b);
                else resolved.Add(b);
            }
        }
        foreach (var (id, b) in before)
        {
            if (after.ContainsKey(id) || !Issue(b)) continue;
            // Проверка исчезла из нового отчёта (модуль не запускался или запись автозапуска удалена).
            if (newer.SkippedModules.Count > 0 || !newer.ExecutedModules.Any()) unchecked_.Add(b); else resolved.Add(b);
        }
        return new ReportComparison(Sort(added), Sort(resolved), changed.OrderByDescending(c => c.After.Severity).ToList(), Sort(persisting), Sort(unchecked_));
    }

    private static List<ReportedFinding> Sort(IEnumerable<ReportedFinding> f) => f.OrderByDescending(x => x.Severity).ThenBy(x => x.Title, StringComparer.CurrentCulture).ToList();
}
