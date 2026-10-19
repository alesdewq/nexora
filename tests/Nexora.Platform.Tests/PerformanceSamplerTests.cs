using Nexora.Diagnostics.Performance;

namespace Nexora.Platform.Tests;

public class PerformanceSamplerTests
{
    [Fact]
    public async Task ShortSession_ProducesSamplesAndAnalysis()
    {
        var s = await PerformanceSampler.RunAsync(TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(1), ct: TestContext.Current.CancellationToken);

        Assert.InRange(s.Samples.Count, 3, 5);
        Assert.All(s.Samples, x => Assert.InRange(x.CpuPercent, 0, 100));
        Assert.All(s.Samples, x => Assert.InRange(x.MemoryUsedPercent, 1, 100));
        Assert.NotEmpty(s.TopByMemory);
        // Температура может отсутствовать — тогда обязательно указана причина.
        Assert.True(s.Thermal.IsAvailable || !string.IsNullOrEmpty(s.Thermal.Reason));

        var results = PerformanceAnalyzer.Analyze(s);
        Assert.Contains(results, r => r.Id == "perf.cpu");
        Assert.All(results, r => Assert.Contains(r.Confidence, new[] { Confidence.Low, Confidence.Medium, Confidence.High }));
    }

    [Theory]
    [InlineData("disk", 7, 2, EventCategory.Disk)]
    [InlineData("stornvme", 129, 3, EventCategory.Disk)]
    [InlineData("Ntfs", 98, 4, EventCategory.Other)]
    [InlineData("Microsoft-Windows-WHEA-Logger", 17, 3, EventCategory.Hardware)]
    [InlineData("Microsoft-Windows-Kernel-Power", 41, 1, EventCategory.UnexpectedShutdown)]
    [InlineData("EventLog", 6008, 2, EventCategory.UnexpectedShutdown)]
    [InlineData("Service Control Manager", 7000, 2, EventCategory.Other)]
    public void EventClassification(string provider, int id, int level, EventCategory expected) =>
        Assert.Equal(expected, EventLogScanner.Classify(provider, id, level));

    [Fact]
    public void Summarize_DropsOtherWarnings_KeepsOtherErrors()
    {
        var now = DateTimeOffset.Now;
        var s = EventLogScanner.Summarize([("X", 1, 3, now), ("X", 2, 2, now), ("disk", 7, 3, now)], 7, false);
        Assert.Equal(1, s.TotalCriticalAndErrors);
        Assert.DoesNotContain(s.Groups, g => g.EventId == 1);
        Assert.Contains(s.Groups, g => g.EventId == 2);
        Assert.Contains(s.Groups, g => g.Category == EventCategory.Disk);
    }

    [Fact]
    public void EventLog_ReadableWithoutAdmin()
    {
        var m = EventLogScanner.Scan(1);
        Assert.True(m.IsAvailable, m.Reason);
    }
}
