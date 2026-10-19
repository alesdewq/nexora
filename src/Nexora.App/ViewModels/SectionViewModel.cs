using System.Collections.ObjectModel;
using Nexora.Core;

namespace Nexora.App.ViewModels;

public sealed class SectionViewModel(Section section, string icon, string purpose) : ObservableObject
{
    public Section Section { get; } = section;
    public string Title { get; } = section.ToDisplay();
    /// <summary>Символ Segoe MDL2 Assets.</summary>
    public string Icon { get; } = icon;
    public string Purpose { get; } = purpose;
    public ObservableCollection<FindingViewModel> Findings { get; } = [];

    private string _badge = "";
    /// <summary>Число замечаний уровня «средний» и выше — показывается в меню.</summary>
    public string Badge { get => _badge; set => Set(ref _badge, value); }

    public void SetFindings(IEnumerable<FindingViewModel> items)
    {
        Findings.Clear();
        foreach (var f in items.OrderBy(f => f.SortKey).ThenBy(f => f.Title, StringComparer.CurrentCulture)) Findings.Add(f);
        var issues = Findings.Count(f => f.IsFinding && f.Model.Severity >= Severity.Medium);
        Badge = issues > 0 ? issues.ToString(System.Globalization.CultureInfo.InvariantCulture) : "";
    }
}
