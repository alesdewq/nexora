using System.Text.Json;
using Nexora.Diagnostics.Inventory;

namespace Nexora.Platform.Tests;

public class InventoryCollectorTests
{
    [Fact]
    public void Collect_DoesNotThrow_AndReadsBasicFacts()
    {
        var s = InventoryCollector.Collect(includeDrivers: false);

        // На любой поддерживаемой Windows эти поля доступны без прав администратора.
        Assert.True(s.Os.Build.IsAvailable, s.Os.Build.Reason);
        Assert.True(s.Os.Build.Value >= 10240);
        Assert.True(s.Computer.TotalMemoryBytes.IsAvailable, s.Computer.TotalMemoryBytes.Reason);
        Assert.True(s.LogicalDisks.IsAvailable, s.LogicalDisks.Reason);
        Assert.Contains(s.LogicalDisks.Value, d => d.IsSystem);
        Assert.False(s.Drivers.IsAvailable);

        var results = InventoryAnalyzer.Analyze(s, DateTimeOffset.Now);
        Assert.All(results, r => Assert.NotEmpty(r.Evidence));
    }

    [Fact]
    public void Snapshot_RoundTripsThroughJson()
    {
        var s = InventoryCollector.Collect(includeDrivers: false);
        var options = new JsonSerializerOptions { Converters = { new MeasuredJsonConverterFactory() } };
        var json = JsonSerializer.Serialize(s, options);
        var back = JsonSerializer.Deserialize<InventorySnapshot>(json, options)!;
        Assert.Equal(s.Os.Build.Value, back.Os.Build.Value);
        Assert.Equal(s.Drivers.Reason, back.Drivers.Reason);
    }

    [Theory]
    [InlineData("10/8/2026", 2026, 10, 8)]
    [InlineData("20261008", 2026, 10, 8)]
    public void HotfixDateFormats(string raw, int y, int m, int d)
    {
        var date = InventoryCollector.ParseHotfixDate(raw);
        Assert.Equal(new DateTime(y, m, d), date!.Value.Date);
    }

    [Fact]
    public void HotfixDate_Garbage_IsNull() => Assert.Null(InventoryCollector.ParseHotfixDate("not a date"));
}
