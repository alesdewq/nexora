namespace Nexora.Core;

/// <summary>Итог по набору проверок. Никогда не утверждает, что система «безопасна».</summary>
public sealed record Assessment(
    int Total,
    int Ok,
    int NotChecked,
    IReadOnlyDictionary<Severity, int> FindingsBySeverity,
    Severity? Highest,
    string Summary)
{
    public static Assessment From(IEnumerable<CheckResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var list = results.ToList();

        var dupe = list.GroupBy(r => r.Id, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (dupe is not null)
            throw new ArgumentException($"Повторяющийся идентификатор проверки: {dupe.Key}", nameof(results));

        var findings = list.Where(r => r.Status == CheckStatus.Finding).ToList();
        var bySeverity = findings.GroupBy(r => r.Severity).ToDictionary(g => g.Key, g => g.Count());
        Severity? highest = findings.Count == 0 ? null : findings.Max(r => r.Severity);
        int ok = list.Count(r => r.Status == CheckStatus.Ok);
        int notChecked = list.Count(r => r.Status is CheckStatus.Unavailable or CheckStatus.Failed);

        return new Assessment(list.Count, ok, notChecked, bySeverity, highest, Summarize(list.Count, findings.Count, notChecked, highest));
    }

    private static string Summarize(int total, int findings, int notChecked, Severity? highest)
    {
        if (total == 0)
            return "Проверки не выполнялись.";

        var head = findings == 0
            ? $"Выполненные проверки ({total - notChecked} из {total}) замечаний не выявили. Это не гарантирует, что система безопасна или исправна."
            : $"Замечаний: {findings}, наивысший уровень — {highest!.Value.ToDisplay()}.";

        return notChecked == 0 ? head : $"{head} Не удалось проверить: {notChecked}.";
    }
}
