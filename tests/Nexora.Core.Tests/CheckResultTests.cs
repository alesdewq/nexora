namespace Nexora.Core.Tests;

public class CheckResultTests
{
    private static readonly Evidence Ev = new("test", "value");

    [Fact]
    public void Unavailable_IsNotChecked_NotLowRisk()
    {
        var r = CheckResult.Unavailable("sec.defender", "Defender", Section.Security,
            "WMI ROOT\\Microsoft\\Windows\\Defender", "пространство имён не найдено");

        Assert.Equal(CheckStatus.Unavailable, r.Status);
        Assert.Equal(Severity.NotChecked, r.Severity);
        Assert.Contains("недоступны", r.WhatFound);
        Assert.Single(r.Evidence);
    }

    [Fact]
    public void Failed_IsNotChecked()
    {
        var r = CheckResult.Failed("sec.bitlocker", "BitLocker", Section.Security, "Win32_EncryptableVolume", "отказано в доступе");
        Assert.Equal(Severity.NotChecked, r.Severity);
        Assert.Equal(CheckStatus.Failed, r.Status);
    }

    [Fact]
    public void Finding_CannotBeNotChecked()
    {
        Assert.Throws<ArgumentException>(() => CheckResult.Finding("x", "x", Section.Security, Severity.NotChecked,
            FindingKind.Fact, Confidence.High, "w", "why", "rec", Ev));
    }

    [Fact]
    public void Finding_RequiresExplanationAndRecommendation()
    {
        Assert.ThrowsAny<ArgumentException>(() => CheckResult.Finding("x", "x", Section.Security, Severity.Medium,
            FindingKind.Fact, Confidence.High, "w", "", "rec", Ev));
        Assert.ThrowsAny<ArgumentException>(() => CheckResult.Finding("x", "x", Section.Security, Severity.Medium,
            FindingKind.Fact, Confidence.High, "w", "why", " ", Ev));
        Assert.Throws<ArgumentNullException>(() => CheckResult.Finding("x", "x", Section.Security, Severity.Medium,
            FindingKind.Fact, Confidence.High, "w", "why", "rec", null!));
    }

    [Fact]
    public void Heuristic_CannotClaimHighConfidence()
    {
        Assert.Throws<ArgumentException>(() => CheckResult.Finding("x", "x", Section.Security, Severity.Medium,
            FindingKind.Heuristic, Confidence.High, "w", "why", "rec", Ev));
    }

    [Fact]
    public void Heuristic_CannotBeCritical()
    {
        Assert.Throws<ArgumentException>(() => CheckResult.Finding("x", "x", Section.Security, Severity.Critical,
            FindingKind.Heuristic, Confidence.Medium, "w", "why", "rec", Ev));
    }

    [Fact]
    public void Finding_NoAutomatedActionByDefault()
    {
        var r = CheckResult.Finding("perf.disk", "Свободное место", Section.Performance, Severity.Medium,
            FindingKind.Fact, Confidence.High, "На C: свободно 4 %", "Мало места замедляет систему", "Освободите место", Ev);
        Assert.False(r.AutomatedActionAvailable);
        Assert.Equal("Свободное место", r.Title);
    }

    [Fact]
    public void Evidence_RequiresSource()
    {
        Assert.Throws<ArgumentException>(() => new Evidence(" ", "x"));
    }

    [Fact]
    public void AllEnums_HaveRussianNames()
    {
        foreach (var s in Enum.GetValues<Severity>()) Assert.False(string.IsNullOrWhiteSpace(s.ToDisplay()));
        foreach (var k in Enum.GetValues<FindingKind>()) Assert.False(string.IsNullOrWhiteSpace(k.ToDisplay()));
        foreach (var c in Enum.GetValues<Confidence>()) Assert.False(string.IsNullOrWhiteSpace(c.ToDisplay()));
        foreach (var s in Enum.GetValues<Section>()) Assert.False(string.IsNullOrWhiteSpace(s.ToDisplay()));
        Assert.Equal(8, Enum.GetValues<Section>().Length);
    }
}
