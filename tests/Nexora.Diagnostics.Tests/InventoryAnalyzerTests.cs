using Nexora.Diagnostics.Inventory;
using static Nexora.Diagnostics.Tests.Fakes;

namespace Nexora.Diagnostics.Tests;

public class InventoryAnalyzerTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void FullSnapshot_ProducesUniqueIds()
    {
        var results = InventoryAnalyzer.Analyze(Snapshot(), Now);
        Assert.Equal(results.Count, results.Select(r => r.Id).Distinct().Count());
        _ = Assessment.From(results);
    }

    [Fact]
    public void Win10_22H2_IsHighPotentialRisk_NotFact()
    {
        var r = InventoryAnalyzer.OsSupport(Os(19045), Now);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Equal(FindingKind.PotentialRisk, r.Kind);
        Assert.NotEqual(Confidence.High, r.Confidence);
        Assert.NotEmpty(r.Limitations);
    }

    [Fact]
    public void Win11_25H2_IsOk()
    {
        var r = InventoryAnalyzer.OsSupport(Os(26200, "Professional"), Now);
        Assert.Equal(CheckStatus.Ok, r.Status);
    }

    [Fact]
    public void MissingBuild_IsUnavailable()
    {
        var os = Os() with { Build = Na<int>("WMI недоступен") };
        var r = InventoryAnalyzer.OsSupport(os, Now);
        Assert.Equal(CheckStatus.Unavailable, r.Status);
        Assert.Contains("WMI недоступен", r.WhatFound);
    }

    [Theory]
    [InlineData(500, 200, null)]          // 40 % — норма
    [InlineData(500, 40, Severity.Medium)] // 8 %
    [InlineData(500, 20, Severity.High)]   // 4 %
    [InlineData(100, 12, Severity.Medium)] // 12 %, но меньше 15 ГБ
    [InlineData(100, 4, Severity.High)]    // меньше 5 ГБ
    public void SystemDiskThresholds(long sizeGb, long freeGb, Severity? expected)
    {
        var disks = Of<IReadOnlyList<LogicalDiskInfo>>([new("C:", "NTFS", sizeGb << 30, freeGb << 30, true)]);
        var r = Assert.Single(InventoryAnalyzer.Disks(disks));
        if (expected is null) Assert.Equal(CheckStatus.Ok, r.Status);
        else Assert.Equal(expected, r.Severity);
    }

    [Fact]
    public void NonSystemDisk_NearlyFull_IsOnlyInfo()
    {
        var disks = Of<IReadOnlyList<LogicalDiskInfo>>([new("D:", "NTFS", 1000L << 30, 10L << 30, false)]);
        Assert.Equal(Severity.Info, Assert.Single(InventoryAnalyzer.Disks(disks)).Severity);
    }

    [Fact]
    public void ZeroSizeDisk_Ignored_NoDivideByZero()
    {
        var disks = Of<IReadOnlyList<LogicalDiskInfo>>([new("E:", null, 0, 0, false)]);
        Assert.Empty(InventoryAnalyzer.Disks(disks));
    }

    [Fact]
    public void DisksUnavailable_SingleUnavailableResult()
    {
        var r = Assert.Single(InventoryAnalyzer.Disks(Na<IReadOnlyList<LogicalDiskInfo>>()));
        Assert.Equal(Severity.NotChecked, r.Severity);
    }

    [Fact]
    public void DiskHealth_Unhealthy_IsCritical_Warning_IsHigh()
    {
        var bad = Of<IReadOnlyList<PhysicalDiskInfo>>([new("HDD1", "HDD", "SATA", 1, DiskHealth.Unhealthy, "Error")]);
        Assert.Equal(Severity.Critical, InventoryAnalyzer.DiskHealthCheck(bad).Severity);
        var warn = Of<IReadOnlyList<PhysicalDiskInfo>>([new("HDD1", "HDD", "SATA", 1, DiskHealth.Warning, "Predictive Failure")]);
        Assert.Equal(Severity.High, InventoryAnalyzer.DiskHealthCheck(warn).Severity);
    }

    [Fact]
    public void DiskHealth_AllUnknown_IsUnavailable_NotOk()
    {
        var unk = Of<IReadOnlyList<PhysicalDiskInfo>>([new("X", "не указан", "USB", 1, DiskHealth.Unknown, "")]);
        Assert.Equal(CheckStatus.Unavailable, InventoryAnalyzer.DiskHealthCheck(unk).Status);
        Assert.Equal(CheckStatus.Unavailable, InventoryAnalyzer.DiskHealthCheck(Of<IReadOnlyList<PhysicalDiskInfo>>([])).Status);
    }

    [Fact]
    public void Updates_StaleAfter45Days_MediumConfidenceOnly()
    {
        var old = Of<IReadOnlyList<HotfixInfo>>([new("KB1", null, Now.AddDays(-80)), new("KB2", null, null)]);
        var r = InventoryAnalyzer.Updates(old, Now);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Equal(Confidence.Medium, r.Confidence);
        Assert.Contains("KB1", r.WhatFound);
    }

    [Fact]
    public void Updates_NoDates_IsUnavailable()
    {
        var r = InventoryAnalyzer.Updates(Of<IReadOnlyList<HotfixInfo>>([new("KB2", null, null)]), Now);
        Assert.Equal(CheckStatus.Unavailable, r.Status);
    }

    [Fact]
    public void Devices_DisabledByUserIsNotAnError()
    {
        var onlyDisabled = Of<IReadOnlyList<ProblemDevice>>([new("Bluetooth", 22)]);
        Assert.Equal(CheckStatus.Ok, InventoryAnalyzer.Devices(onlyDisabled).Status);
        var broken = Of<IReadOnlyList<ProblemDevice>>([new("Bluetooth", 22), new("Датчик", 28)]);
        var r = InventoryAnalyzer.Devices(broken);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Contains("Датчик", r.WhatFound);
        Assert.DoesNotContain("Bluetooth (код", r.WhatFound);
    }

    [Fact]
    public void Uptime_LongIsInfoRecommendation()
    {
        var r = InventoryAnalyzer.Uptime(Of(Now.AddDays(-30)), Now);
        Assert.Equal(Severity.Info, r.Severity);
        Assert.Equal(FindingKind.Recommendation, r.Kind);
        Assert.Equal(CheckStatus.Ok, InventoryAnalyzer.Uptime(Of(Now.AddDays(-1)), Now).Status);
    }

    [Fact]
    public void PendingReboot()
    {
        Assert.Equal(Severity.Medium, InventoryAnalyzer.PendingReboot(Of(true)).Severity);
        Assert.Equal(CheckStatus.Ok, InventoryAnalyzer.PendingReboot(Of(false)).Status);
        Assert.Equal(CheckStatus.Unavailable, InventoryAnalyzer.PendingReboot(Na<bool>()).Status);
    }
}
