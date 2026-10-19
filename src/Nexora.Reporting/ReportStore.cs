using System.Globalization;
using System.Text.Json;

namespace Nexora.Reporting;

public sealed record StoredReport(string Path, DateTimeOffset Started, string ComputerName, int Issues, int NotChecked, string Summary);

/// <summary>Локальная история отчётов (по умолчанию %LOCALAPPDATA%\NEXORA\reports). Отчёты никуда не отправляются.</summary>
public sealed class ReportStore(string directory)
{
    public string Directory { get; } = directory;

    public static string DefaultDirectory =>
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NEXORA", "reports");

    public string Save(ReportDocument doc)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var name = $"report-{doc.Meta.Started.ToLocalTime().ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}.json";
        var path = System.IO.Path.Combine(Directory, name);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, doc.ToJson());
        File.Move(tmp, path, overwrite: true);
        return path;
    }

    public IReadOnlyList<StoredReport> List()
    {
        if (!System.IO.Directory.Exists(Directory)) return [];
        var list = new List<StoredReport>();
        foreach (var file in System.IO.Directory.EnumerateFiles(Directory, "report-*.json"))
        {
            try
            {
                var d = Load(file);
                list.Add(new StoredReport(file, d.Meta.Started, d.Meta.ComputerName, d.Findings.Count(f => f.IsIssue), d.NotCheckedCount, d.Meta.Summary));
            }
            catch (Exception ex) when (ex is JsonException or IOException or NotSupportedException or UnauthorizedAccessException)
            {
                // Повреждённый или чужой файл не ломает историю — просто не показывается.
            }
        }
        return list.OrderByDescending(r => r.Started).ToList();
    }

    public static ReportDocument Load(string path) => ReportDocument.FromJson(File.ReadAllText(path));
}

/// <summary>Отметки пользователя о статусе устранения находок, переносятся между отчётами по Id проверки.</summary>
public sealed class ResolutionStore(string file)
{
    private Dictionary<string, Resolution>? _cache;

    public static string DefaultFile =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NEXORA", "resolutions.json");

    private Dictionary<string, Resolution> Data
    {
        get
        {
            if (_cache is not null) return _cache;
            try
            {
                _cache = File.Exists(file)
                    ? JsonSerializer.Deserialize<Dictionary<string, Resolution>>(File.ReadAllText(file), ReportDocument.JsonOptions) ?? []
                    : [];
            }
            catch (JsonException) { _cache = []; }
            return _cache;
        }
    }

    public Resolution? Get(string id) => Data.TryGetValue(id, out var r) ? r : null;

    public void Set(string id, ResolutionStatus status, string? note, DateTimeOffset now)
    {
        if (status == ResolutionStatus.None && string.IsNullOrWhiteSpace(note)) Data.Remove(id);
        else Data[id] = new Resolution(status, note, now);
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, JsonSerializer.Serialize(Data, ReportDocument.JsonOptions));
    }
}
