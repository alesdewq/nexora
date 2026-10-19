using System.Windows.Media;
using Nexora.Core;
using Nexora.Reporting;

namespace Nexora.App.ViewModels;

/// <summary>Одна находка в интерфейсе: что, почему, насколько надёжно, что делать, последствия, источник, ограничения.</summary>
public sealed class FindingViewModel : ObservableObject
{
    private readonly ReportedFinding f;
    private readonly ResolutionStore? store;

    public FindingViewModel(ReportedFinding finding, ResolutionStore? resolutions)
    {
        f = finding;
        store = resolutions;
        _resolution = store?.Get(f.Id)?.Status ?? f.Resolution?.Status ?? ResolutionStatus.None;
    }

    public ReportedFinding Model => f;
    public string Title => f.Title;
    public string WhatFound => f.WhatFound;
    public string? WhyItMatters => f.WhyItMatters;
    public string? Recommendation => f.Recommendation;
    public string? Consequences => f.Consequences;
    public bool IsFinding => f.Status == CheckStatus.Finding;
    public string KindText => IsFinding ? f.Kind.ToDisplay() : f.Status switch
    {
        CheckStatus.Ok => "Проверено, замечаний нет",
        CheckStatus.Unavailable => "Данные недоступны",
        _ => "Проверка не выполнена",
    };
    public string ConfidenceText => $"Надёжность вывода: {f.Confidence.ToDisplay()}";
    public string ActionText => f.AutomatedActionAvailable
        ? "Есть безопасное действие в NEXORA (раздел «Файлы и программы», с подтверждением)."
        : IsFinding ? "Автоматического действия нет — решение и действие за вами." : "";
    public string EvidenceText => string.Join("\n", f.Evidence.Select(e => $"• {e.Source}{(e.Detail.Length > 0 ? " — " + e.Detail : "")}"));
    public string LimitationsText => string.Join("\n", f.Limitations.Select(l => "• " + l));
    public bool HasLimitations => f.Limitations.Count > 0;

    public string BadgeText => f.Status switch
    {
        CheckStatus.Ok => "Норма",
        CheckStatus.Unavailable or CheckStatus.Failed => "Не удалось проверить",
        _ => f.Severity.ToDisplay(),
    };

    /// <summary>Форма значка дублирует цвет, чтобы уровень различался и без цветового восприятия.</summary>
    public string BadgeGlyph => f.Status switch
    {
        CheckStatus.Ok => "✓",
        CheckStatus.Unavailable or CheckStatus.Failed => "?",
        _ => f.Severity switch { Severity.Critical => "⛔", Severity.High => "▲", Severity.Medium => "◆", _ => "ℹ" },
    };

    public Brush AccentBrush => Brushes.Get(f.Status == CheckStatus.Ok ? "ok" : f.Status != CheckStatus.Finding ? "nc" : f.Severity switch
    {
        Severity.Critical => "crit", Severity.High => "high", Severity.Medium => "med", _ => "info",
    });

    public int SortKey => f.Status switch
    {
        CheckStatus.Finding => 10 - (int)f.Severity,
        CheckStatus.Unavailable or CheckStatus.Failed => 20,
        _ => 30,
    };

    public static IReadOnlyList<KeyValuePair<ResolutionStatus, string>> ResolutionOptions { get; } =
        Enum.GetValues<ResolutionStatus>().Select(s => new KeyValuePair<ResolutionStatus, string>(s, s.ToDisplay())).ToList();

    private ResolutionStatus _resolution;

    public ResolutionStatus Resolution
    {
        get => _resolution;
        set
        {
            if (Set(ref _resolution, value)) store?.Set(f.Id, value, null, DateTimeOffset.Now);
        }
    }

    public bool CanMarkResolution => IsFinding && store is not null;

    private static class Brushes
    {
        private static readonly Dictionary<string, Brush> Map = new()
        {
            ["crit"] = Freeze("#B91C1C"), ["high"] = Freeze("#C2410C"), ["med"] = Freeze("#A16207"),
            ["info"] = Freeze("#1D4ED8"), ["ok"] = Freeze("#15803D"), ["nc"] = Freeze("#6B7280"),
        };

        public static Brush Get(string key) => Map[key];

        private static SolidColorBrush Freeze(string hex)
        {
            var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return b;
        }
    }
}
