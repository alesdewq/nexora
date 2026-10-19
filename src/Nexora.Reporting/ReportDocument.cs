using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Nexora.Reporting;

/// <summary>Отчёт о проверке. Схема версионируется: при несовместимых изменениях увеличивается <see cref="SchemaVersion"/>.</summary>
public sealed record ReportDocument
{
    public const int CurrentSchema = 1;
    public int SchemaVersion { get; init; } = CurrentSchema;
    public required ReportMeta Meta { get; init; }
    public required IReadOnlyList<ReportedFinding> Findings { get; init; }
    /// <summary>Модули, которые были выполнены.</summary>
    public required IReadOnlyList<string> ExecutedModules { get; init; }
    /// <summary>Модули, которые были пропущены или завершились ошибкой, с причиной.</summary>
    public required IReadOnlyList<SkippedModule> SkippedModules { get; init; }
    /// <summary>Собранные технические данные (снимки модулей) — доказательная база отчёта.</summary>
    public JsonObject? Data { get; init; }
    public bool Masked { get; init; }

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // кириллица без \uXXXX; HTML формируется отдельно с экранированием
        Converters = { new JsonStringEnumConverter(), new MeasuredJsonConverterFactory() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static ReportDocument FromJson(string json)
    {
        var doc = JsonSerializer.Deserialize<ReportDocument>(json, JsonOptions) ?? throw new JsonException("пустой отчёт");
        if (doc.SchemaVersion > CurrentSchema)
            throw new NotSupportedException($"Отчёт создан более новой версией NEXORA (схема {doc.SchemaVersion}).");
        return doc;
    }

    public IReadOnlyDictionary<Severity, int> CountBySeverity() =>
        Findings.Where(f => f.Status == CheckStatus.Finding).GroupBy(f => f.Severity).ToDictionary(g => g.Key, g => g.Count());

    public int NotCheckedCount => Findings.Count(f => f.Status is CheckStatus.Unavailable or CheckStatus.Failed);
}

public sealed record ReportMeta(string Product, string Version, DateTimeOffset Started, TimeSpan Duration, string ComputerName,
    string OsSummary, bool Elevated, string Summary);

public sealed record SkippedModule(string Module, string Reason);

public enum ResolutionStatus { None, InProgress, Resolved, Accepted }

public sealed record Resolution(ResolutionStatus Status, string? Note, DateTimeOffset At);

public sealed record ReportedFinding(
    string Id, string Title, Section Section, CheckStatus Status, Severity Severity, FindingKind Kind, Confidence Confidence,
    string WhatFound, string? WhyItMatters, string? Recommendation, string? Consequences, bool AutomatedActionAvailable,
    IReadOnlyList<Evidence> Evidence, IReadOnlyList<string> Limitations, Resolution? Resolution = null)
{
    public static ReportedFinding From(CheckResult r, Resolution? resolution = null) => new(
        r.Id, r.Title, r.Section, r.Status, r.Severity, r.Kind, r.Confidence, r.WhatFound, r.WhyItMatters, r.Recommendation,
        r.Consequences, r.AutomatedActionAvailable, r.Evidence, r.Limitations, resolution);

    public bool IsIssue => Status == CheckStatus.Finding && Severity != Severity.Info;
}
