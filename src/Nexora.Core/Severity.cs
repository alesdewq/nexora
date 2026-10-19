namespace Nexora.Core;

/// <summary>Степень риска. <see cref="NotChecked"/> — отдельный статус, а не «самый низкий риск».</summary>
public enum Severity
{
    Info = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
    NotChecked = 100,
}

/// <summary>Природа вывода: что именно утверждается.</summary>
public enum FindingKind
{
    /// <summary>Подтверждённый факт, прочитанный из системы.</summary>
    Fact,
    /// <summary>Настройка или состояние, которое в некоторых условиях повышает риск.</summary>
    PotentialRisk,
    /// <summary>Эвристическое подозрение — не доказательство.</summary>
    Heuristic,
    /// <summary>Совет без утверждения о проблеме.</summary>
    Recommendation,
}

public enum Confidence
{
    Low,
    Medium,
    High,
}

public enum CheckStatus
{
    /// <summary>Проверка выполнена, замечаний нет.</summary>
    Ok,
    /// <summary>Проверка выполнена, есть замечание.</summary>
    Finding,
    /// <summary>Источник данных отсутствует (нет датчика, Defender не активен и т. п.).</summary>
    Unavailable,
    /// <summary>Проверку не удалось выполнить (отказ в доступе, ошибка).</summary>
    Failed,
}

public static class SeverityText
{
    public static string ToDisplay(this Severity s) => s switch
    {
        Severity.Critical => "Критический",
        Severity.High => "Высокий",
        Severity.Medium => "Средний",
        Severity.Info => "Низкий/информационный",
        Severity.NotChecked => "Не удалось проверить",
        _ => throw new ArgumentOutOfRangeException(nameof(s), s, null),
    };

    public static string ToDisplay(this FindingKind k) => k switch
    {
        FindingKind.Fact => "Факт",
        FindingKind.PotentialRisk => "Потенциальный риск",
        FindingKind.Heuristic => "Эвристическое подозрение",
        FindingKind.Recommendation => "Рекомендация",
        _ => throw new ArgumentOutOfRangeException(nameof(k), k, null),
    };

    public static string ToDisplay(this Confidence c) => c switch
    {
        Confidence.High => "высокая",
        Confidence.Medium => "средняя",
        Confidence.Low => "низкая",
        _ => throw new ArgumentOutOfRangeException(nameof(c), c, null),
    };
}
