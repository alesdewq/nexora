namespace Nexora.Core.Tests;

public class AssessmentTests
{
    private static readonly Evidence Ev = new("test", "value");

    private static CheckResult Ok(string id) => CheckResult.Ok(id, id, Section.Security, "ок", Ev);

    private static CheckResult Finding(string id, Severity s) => CheckResult.Finding(id, id, Section.Security, s,
        FindingKind.PotentialRisk, Confidence.Medium, "w", "why", "rec", Ev);

    [Fact]
    public void Empty_SaysNothingWasChecked()
    {
        var a = Assessment.From([]);
        Assert.Equal(0, a.Total);
        Assert.Null(a.Highest);
        Assert.Equal("Проверки не выполнялись.", a.Summary);
    }

    [Fact]
    public void NoFindings_NeverClaimsSystemIsSafe()
    {
        var a = Assessment.From([Ok("a"), Ok("b")]);
        Assert.Contains("не гарантирует", a.Summary);
        Assert.DoesNotContain("система безопасна.", a.Summary);
    }

    [Fact]
    public void NotChecked_IsCountedSeparately_AndMentioned()
    {
        var a = Assessment.From([
            Ok("a"),
            CheckResult.Unavailable("b", "b", Section.Performance, "src", "нет датчика"),
            CheckResult.Failed("c", "c", Section.Security, "src", "отказано в доступе"),
        ]);

        Assert.Equal(1, a.Ok);
        Assert.Equal(2, a.NotChecked);
        Assert.Null(a.Highest);
        Assert.Contains("1 из 3", a.Summary);
        Assert.Contains("Не удалось проверить: 2", a.Summary);
    }

    [Fact]
    public void Highest_IsMaxFindingSeverity_IgnoringNotChecked()
    {
        var a = Assessment.From([
            Finding("a", Severity.Medium),
            Finding("b", Severity.High),
            Finding("c", Severity.Medium),
            CheckResult.Unavailable("d", "d", Section.Security, "src", "r"),
        ]);

        Assert.Equal(Severity.High, a.Highest);
        Assert.Equal(2, a.FindingsBySeverity[Severity.Medium]);
        Assert.Equal(1, a.FindingsBySeverity[Severity.High]);
        Assert.False(a.FindingsBySeverity.ContainsKey(Severity.NotChecked));
        Assert.Contains("Высокий", a.Summary);
    }

    [Fact]
    public void DuplicateIds_AreRejected()
    {
        Assert.Throws<ArgumentException>(() => Assessment.From([Ok("a"), Ok("a")]));
    }
}
