using Nexora.Core;

namespace Nexora.App.ViewModels;

public sealed class SectionViewModel(Section section, string icon, string purpose, int plannedStage)
{
    public Section Section { get; } = section;
    public string Title { get; } = section.ToDisplay();
    /// <summary>Символ Segoe MDL2 Assets.</summary>
    public string Icon { get; } = icon;
    public string Purpose { get; } = purpose;
    public int PlannedStage { get; } = plannedStage;
    public string StatusText => $"Раздел пока не реализован — появится на этапе {PlannedStage}. Сейчас здесь ничего не проверяется.";
}
