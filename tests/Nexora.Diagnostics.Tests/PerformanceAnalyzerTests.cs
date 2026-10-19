using Nexora.Diagnostics.Performance;
using static Nexora.Diagnostics.Tests.Fakes;

namespace Nexora.Diagnostics.Tests;

public class PerformanceAnalyzerTests
{
    private static PerformanceSession Session(double[] cpu, double mem = 50, double? disk = 10, double? perf = 100,
        int seconds = 180, Measured<IReadOnlyList<ThermalZoneReading>>? thermal = null, Measured<EventLogSummary>? events = null)
    {
        var step = TimeSpan.FromSeconds(seconds / (double)cpu.Length);
        return new PerformanceSession
        {
            Started = DateTimeOffset.Now, Duration = TimeSpan.FromSeconds(seconds), Interval = step, LogicalProcessors = 8,
            Samples = cpu.Select((c, i) => new PerformanceSample(step * (i + 1), c, mem, disk, perf)).ToList(),
            TopByCpu = [new("chrome", 1, 40, 90, 500L << 20, 400L << 20)],
            TopByMemory = [new("chrome", 1, 40, 90, 500L << 20, 400L << 20)],
            InaccessibleProcesses = 3,
            DiskCounterUnavailable = disk is null ? "счётчик отсутствует в этой системе" : null,
            Thermal = thermal ?? Na<IReadOnlyList<ThermalZoneReading>>("нет термозон"),
            Events = events ?? Of(new EventLogSummary(7, 0, [], false)),
        };
    }

    private static double[] Repeat(double v, int n) => Enumerable.Repeat(v, n).ToArray();

    [Fact]
    public void SustainedCpu_IsFinding_WithTopProcess()
    {
        var r = PerformanceAnalyzer.Cpu(Session(Repeat(95, 60)));
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Equal(Confidence.High, r.Confidence);
        Assert.Contains("chrome", r.WhatFound);
    }

    [Fact]
    public void ShortSpikes_AreNotAProblem()
    {
        var cpu = Repeat(10, 60); cpu[5] = 100; cpu[30] = 99;
        var r = PerformanceAnalyzer.Cpu(Session(cpu));
        Assert.Equal(CheckStatus.Ok, r.Status);
        Assert.Contains("кратковременные пики", r.WhatFound);
    }

    [Fact]
    public void ShortObservation_LowersConfidence_AndSaysSo()
    {
        var r = PerformanceAnalyzer.Cpu(Session(Repeat(95, 20), seconds: 20));
        Assert.Equal(Confidence.Low, r.Confidence);
        Assert.Contains(r.Limitations, l => l.Contains("мало"));
    }

    [Theory]
    [InlineData(50, null)]
    [InlineData(85, Severity.Medium)]
    [InlineData(95, Severity.High)]
    public void MemoryThresholds(double mem, Severity? expected)
    {
        var r = PerformanceAnalyzer.Memory(Session(Repeat(10, 30), mem: mem));
        if (expected is null) Assert.Equal(CheckStatus.Ok, r.Status); else Assert.Equal(expected, r.Severity);
    }

    [Fact]
    public void DiskCounterMissing_IsUnavailable()
    {
        var r = PerformanceAnalyzer.Disk(Session(Repeat(10, 30), disk: null));
        Assert.Equal(CheckStatus.Unavailable, r.Status);
        Assert.Contains("отсутствует", r.WhatFound);
    }

    [Fact]
    public void NoTemperatureSensor_IsUnavailable_NeverInvented()
    {
        var r = PerformanceAnalyzer.Thermal(Session(Repeat(10, 30)));
        Assert.Equal(CheckStatus.Unavailable, r.Status);
        Assert.Equal(Severity.NotChecked, r.Severity);
        Assert.DoesNotContain("°C", r.WhatFound);
    }

    [Fact]
    public void ImplausibleTemperature_IsUnavailable()
    {
        var t = Of<IReadOnlyList<ThermalZoneReading>>([new("TZ0", -273, -273, null)]);
        Assert.Equal(CheckStatus.Unavailable, PerformanceAnalyzer.Thermal(Session(Repeat(10, 30), thermal: t)).Status);
    }

    [Fact]
    public void HotAtLowLoad_IsStrongerThanHotAtFullLoad()
    {
        var t = Of<IReadOnlyList<ThermalZoneReading>>([new("TZ0", 96, 92, null)]);
        var idle = PerformanceAnalyzer.Thermal(Session(Repeat(10, 30), thermal: t));
        var busy = PerformanceAnalyzer.Thermal(Session(Repeat(95, 30), thermal: t));
        Assert.Equal(Severity.High, idle.Severity);
        Assert.Equal(Severity.Medium, busy.Severity);
        Assert.Equal(FindingKind.Heuristic, idle.Kind);
        Assert.True(busy.Confidence < idle.Confidence);
    }

    [Fact]
    public void PassiveLimit_IsThrottlingFact()
    {
        var t = Of<IReadOnlyList<ThermalZoneReading>>([new("TZ0", 80, 70, 60)]);
        var r = PerformanceAnalyzer.Throttling(Session(Repeat(50, 30), thermal: t));
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Equal(FindingKind.Fact, r.Kind);
    }

    [Fact]
    public void LowFrequencyUnderLoad_IsHeuristic()
    {
        var r = PerformanceAnalyzer.Throttling(Session(Repeat(95, 30), perf: 40));
        Assert.Equal(FindingKind.Heuristic, r.Kind);
        Assert.Contains("40 %", r.WhatFound);
    }

    [Fact]
    public void NoLoad_ThrottlingOkButLowConfidence()
    {
        var r = PerformanceAnalyzer.Throttling(Session(Repeat(10, 30), perf: 40));
        Assert.Equal(CheckStatus.Ok, r.Status);
        Assert.Equal(Confidence.Low, r.Confidence);
    }

    [Fact]
    public void Events_DiskAndShutdown()
    {
        var ev = Of(new EventLogSummary(7, 5, [
            new("disk", 7, EventCategory.Disk, 3, 2, DateTimeOffset.Now),
            new("Microsoft-Windows-Kernel-Power", 41, EventCategory.UnexpectedShutdown, 2, 1, DateTimeOffset.Now),
        ], false));
        var results = PerformanceAnalyzer.Events(ev).ToList();
        Assert.Equal(Severity.High, results.Single(r => r.Id == "perf.events.disk").Severity);
        Assert.Equal(Severity.Medium, results.Single(r => r.Id == "perf.events.shutdown").Severity);
        Assert.Equal(CheckStatus.Ok, results.Single(r => r.Id == "perf.events.hardware").Status);
    }

    [Fact]
    public void Events_Unavailable()
    {
        var r = Assert.Single(PerformanceAnalyzer.Events(Na<EventLogSummary>("отказано в доступе")));
        Assert.Equal(CheckStatus.Unavailable, r.Status);
    }

    [Fact]
    public void Analyze_TooFewSamples_IsFailed()
    {
        var r = Assert.Single(PerformanceAnalyzer.Analyze(Session([50])));
        Assert.Equal(CheckStatus.Failed, r.Status);
    }

    [Fact]
    public void Analyze_IdsUnique()
    {
        var results = PerformanceAnalyzer.Analyze(Session(Repeat(10, 30)));
        Assert.Equal(results.Count, results.Select(r => r.Id).Distinct().Count());
    }
}

public class PluralTests
{
    [Theory]
    [InlineData(1, "1 раз")]
    [InlineData(2, "2 раза")]
    [InlineData(5, "5 раз")]
    [InlineData(12, "12 раз")]
    [InlineData(22, "22 раза")]
    public void Times(int n, string expected) => Assert.Equal(expected, PerformanceAnalyzer.Times(n));
}
