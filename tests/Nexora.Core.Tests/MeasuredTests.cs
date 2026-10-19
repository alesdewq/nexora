namespace Nexora.Core.Tests;

public class MeasuredTests
{
    [Fact]
    public void Unavailable_FormatsAsUnavailable_NotAsZero()
    {
        var t = Measured<double>.Unavailable("WMI MSAcpi_ThermalZoneTemperature", "класс отсутствует");

        Assert.False(t.IsAvailable);
        Assert.Equal("данные недоступны", t.Format(v => $"{v:0} °C"));
        Assert.Equal("класс отсутствует", t.Reason);
        Assert.False(t.TryGetValue(out _));
        Assert.Throws<InvalidOperationException>(() => t.Value);
    }

    [Fact]
    public void Available_KeepsValueAndSource()
    {
        var m = Measured<int>.Of(0, "PerformanceCounter Processor(_Total)");

        Assert.True(m.IsAvailable);
        Assert.Equal(0, m.Value);
        Assert.Null(m.Reason);
        Assert.Equal("0", m.Format());
    }

    [Fact]
    public void DefaultStruct_IsUnavailable()
    {
        Measured<int> m = default;
        Assert.False(m.IsAvailable);
        Assert.Equal(Measured<int>.UnavailableText, m.Format());
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void RequiresSourceAndReason(string blank)
    {
        Assert.ThrowsAny<ArgumentException>(() => Measured<int>.Of(1, blank));
        Assert.ThrowsAny<ArgumentException>(() => Measured<int>.Unavailable("src", blank));
        Assert.ThrowsAny<ArgumentException>(() => Measured<int>.Unavailable(blank, "reason"));
    }

    [Fact]
    public void Of_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => Measured<string>.Of(null!, "src"));
    }
}
