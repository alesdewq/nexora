namespace Nexora.Core;

/// <summary>
/// Результат одной проверки. Создаётся только фабриками, которые держат инварианты:
/// недоступная/неудавшаяся проверка всегда имеет <see cref="Severity.NotChecked"/>, у замечания есть объяснение и источник.
/// </summary>
public sealed record CheckResult
{
    private CheckResult(string id, string title, Section section, CheckStatus status, Severity severity,
        FindingKind kind, Confidence confidence, string whatFound)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(whatFound);
        Id = id; Title = title; Section = section; Status = status; Severity = severity;
        Kind = kind; Confidence = confidence; WhatFound = whatFound;
    }

    public string Id { get; }
    public string Title { get; }
    public Section Section { get; }
    public CheckStatus Status { get; }
    public Severity Severity { get; }
    public FindingKind Kind { get; }
    public Confidence Confidence { get; }

    /// <summary>Что обнаружено.</summary>
    public string WhatFound { get; }
    /// <summary>Почему это важно.</summary>
    public string? WhyItMatters { get; init; }
    /// <summary>Что рекомендуется сделать.</summary>
    public string? Recommendation { get; init; }
    /// <summary>Какие последствия возможны (у проблемы или у рекомендуемого действия).</summary>
    public string? Consequences { get; init; }
    /// <summary>Есть ли безопасное автоматизированное действие. В MVP всегда false — система не меняется.</summary>
    public bool AutomatedActionAvailable { get; init; }
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
    public IReadOnlyList<string> Limitations { get; init; } = [];

    public static CheckResult Ok(string id, string title, Section section, string whatFound, Evidence evidence,
        Confidence confidence = Confidence.High) =>
        new(id, title, section, CheckStatus.Ok, Severity.Info, FindingKind.Fact, confidence, whatFound)
        {
            Evidence = [evidence ?? throw new ArgumentNullException(nameof(evidence))],
        };

    public static CheckResult Finding(string id, string title, Section section, Severity severity, FindingKind kind,
        Confidence confidence, string whatFound, string whyItMatters, string recommendation, Evidence evidence)
    {
        if (severity == Severity.NotChecked)
            throw new ArgumentException("Для непроведённой проверки используйте Unavailable/Failed.", nameof(severity));
        ArgumentException.ThrowIfNullOrWhiteSpace(whyItMatters);
        ArgumentException.ThrowIfNullOrWhiteSpace(recommendation);
        // Эвристика по определению не может давать высокую уверенность.
        if (kind == FindingKind.Heuristic && confidence == Confidence.High)
            throw new ArgumentException("Эвристическое подозрение не может иметь высокую уверенность.", nameof(confidence));
        // «Критический» без подтверждённых данных означал бы обвинение (например, в заражении) без оснований.
        if (kind == FindingKind.Heuristic && severity == Severity.Critical)
            throw new ArgumentException("Эвристическое подозрение не может быть критическим.", nameof(severity));
        return new(id, title, section, CheckStatus.Finding, severity, kind, confidence, whatFound)
        {
            WhyItMatters = whyItMatters,
            Recommendation = recommendation,
            Evidence = [evidence ?? throw new ArgumentNullException(nameof(evidence))],
        };
    }

    public static CheckResult Unavailable(string id, string title, Section section, string source, string reason) =>
        new(id, title, section, CheckStatus.Unavailable, Severity.NotChecked, FindingKind.Fact, Confidence.High,
            $"Данные недоступны: {reason}")
        {
            Evidence = [new Evidence(source, reason)],
        };

    public static CheckResult Failed(string id, string title, Section section, string source, string error) =>
        new(id, title, section, CheckStatus.Failed, Severity.NotChecked, FindingKind.Fact, Confidence.High,
            $"Проверку не удалось выполнить: {error}")
        {
            Evidence = [new Evidence(source, error)],
        };
}
