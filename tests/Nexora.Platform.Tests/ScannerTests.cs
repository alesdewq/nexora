using Nexora.Reporting;

namespace Nexora.Platform.Tests;

public class ScannerTests
{
    [Fact]
    public async Task FullScan_ProducesConsistentReport()
    {
        var r = await Scanner.RunAsync(new ScanOptions(TimeSpan.FromSeconds(3)) { IncludeDrivers = false }, ct: TestContext.Current.CancellationToken);

        Assert.Empty(r.Document.SkippedModules);
        Assert.Equal(5, r.Document.ExecutedModules.Count);
        Assert.Equal(r.Results.Count, r.Results.Select(x => x.Id).Distinct().Count());
        Assert.All(r.Document.Findings, f => Assert.NotEmpty(f.Evidence));

        var json = r.Document.ToJson();
        var back = ReportDocument.FromJson(json);
        Assert.Equal(r.Document.Findings.Count, back.Findings.Count);
        var html = HtmlReport.Render(back);
        Assert.Contains("<html", html);
    }

    [Fact]
    public async Task DisabledModules_AreListedAsSkipped()
    {
        var r = await Scanner.RunAsync(new ScanOptions(TimeSpan.FromSeconds(1)) { Performance = false, Security = false, Network = false, Cleanup = false, IncludeDrivers = false },
            ct: TestContext.Current.CancellationToken);
        Assert.Equal(4, r.Document.SkippedModules.Count);
        Assert.Single(r.Document.ExecutedModules);
    }
}
