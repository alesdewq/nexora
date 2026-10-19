using System.Diagnostics.Eventing.Reader;
using Nexora.Diagnostics.Performance;

namespace Nexora.Platform;

/// <summary>Чтение журнала «Система» за последние дни. Журнал не очищается и не изменяется.</summary>
public static class EventLogScanner
{
    public const int MaxEvents = 5000;
    private const string Source = "Журнал событий «Система»";

    private static readonly HashSet<string> DiskProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        "disk", "Ntfs", "Microsoft-Windows-Ntfs", "stornvme", "storahci", "iaStorA", "iaStorAC", "iaStorAVC", "volmgr",
        "Microsoft-Windows-StorPort", "Microsoft-Windows-Disk",
    };

    public static Measured<EventLogSummary> Scan(int days)
    {
        try
        {
            var ms = (long)TimeSpan.FromDays(days).TotalMilliseconds;
            var query = new EventLogQuery("System", PathType.LogName,
                $"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= {ms}]]]") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            var raw = new List<(string Provider, int Id, int Level, DateTimeOffset Time)>();
            var truncated = false;
            for (var e = reader.ReadEvent(); e is not null; e = reader.ReadEvent())
            {
                using (e)
                {
                    if (raw.Count >= MaxEvents) { truncated = true; break; }
                    raw.Add((e.ProviderName ?? "?", e.Id, e.Level ?? 4, e.TimeCreated is { } t ? new DateTimeOffset(t) : DateTimeOffset.MinValue));
                }
            }
            return Measured<EventLogSummary>.Of(Summarize(raw, days, truncated), Source);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            return Measured<EventLogSummary>.Unavailable(Source, Probe.Describe(ex));
        }
    }

    public static EventCategory Classify(string provider, int id, int level)
    {
        if (provider.Equals("Microsoft-Windows-WHEA-Logger", StringComparison.OrdinalIgnoreCase)) return EventCategory.Hardware;
        if ((provider.Equals("Microsoft-Windows-Kernel-Power", StringComparison.OrdinalIgnoreCase) && id == 41)
            || (provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) && id == 6008)) return EventCategory.UnexpectedShutdown;
        // Диск: ошибки и известные предупреждения (7 — сбойный блок, 51 — ошибка страничного обмена, 129 — сброс контроллера, 153 — повтор операции).
        if (DiskProviders.Contains(provider) && (level <= 2 || id is 7 or 51 or 129 or 153)) return EventCategory.Disk;
        return EventCategory.Other;
    }

    public static EventLogSummary Summarize(IReadOnlyList<(string Provider, int Id, int Level, DateTimeOffset Time)> raw, int days, bool truncated)
    {
        var groups = raw
            .Select(r => (r.Provider, r.Id, r.Level, r.Time, Cat: Classify(r.Provider, r.Id, r.Level)))
            .Where(r => r.Cat != EventCategory.Other || r.Level <= 2)
            .GroupBy(r => (r.Provider, r.Id, r.Cat))
            .Select(g => new EventGroup(g.Key.Provider, g.Key.Id, g.Key.Cat, g.Count(), g.Min(x => x.Level), g.Max(x => x.Time)))
            .OrderBy(g => g.Category).ThenByDescending(g => g.Count)
            .ToList();
        return new EventLogSummary(days, raw.Count(r => r.Level <= 2), groups, truncated);
    }
}
