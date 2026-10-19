using Nexora.Diagnostics.Inventory;

namespace Nexora.Diagnostics.Tests;

public class LifecycleTests
{
    private static readonly DateOnly Today = new(2026, 10, 19);

    [Fact]
    public void Win10_22H2_Home_EndedButEsuPossible()
    {
        var i = WindowsLifecycle.Evaluate(19045, "Core", Today);
        Assert.Equal(SupportState.EndedEsuPossible, i.State);
        Assert.Equal(new DateOnly(2025, 10, 14), i.EndOfSupport);
        Assert.Contains("ESU", i.Note);
    }

    [Fact]
    public void Win11_25H2_Pro_Supported()
    {
        var i = WindowsLifecycle.Evaluate(26200, "Professional", Today);
        Assert.Equal(SupportState.Supported, i.State);
        Assert.StartsWith("Windows 11", i.Name);
    }

    [Fact]
    public void Win11_24H2_DependsOnEdition()
    {
        Assert.Equal(SupportState.Ended, WindowsLifecycle.Evaluate(26100, "Core", Today).State);
        Assert.Equal(SupportState.Supported, WindowsLifecycle.Evaluate(26100, "Enterprise", Today).State);
        Assert.Equal(SupportState.Supported, WindowsLifecycle.Evaluate(26100, "EnterpriseS", Today).State);
    }

    [Fact]
    public void Win11_23H2_Enterprise_EndingSoon()
    {
        // До 10.11.2026 осталось 22 дня.
        Assert.Equal(SupportState.EndingSoon, WindowsLifecycle.Evaluate(22631, "Enterprise", Today).State);
    }

    [Fact]
    public void Ltsc2021_UsesLtscDate()
    {
        var i = WindowsLifecycle.Evaluate(19044, "EnterpriseS", Today);
        Assert.Equal(new DateOnly(2027, 1, 12), i.EndOfSupport);
        Assert.Contains("LTSC", i.Name);
        Assert.Equal(new DateOnly(2032, 1, 13), WindowsLifecycle.Evaluate(19044, "IoTEnterpriseS", Today).EndOfSupport);
    }

    [Fact]
    public void UnknownNewerBuild_IsUnknown_NotSupported()
    {
        var i = WindowsLifecycle.Evaluate(27000, "Core", Today);
        Assert.Equal(SupportState.Unknown, i.State);
        Assert.Null(i.EndOfSupport);
    }

    [Fact]
    public void NullEdition_TreatedAsConsumer()
    {
        Assert.Equal(new DateOnly(2026, 10, 13), WindowsLifecycle.Evaluate(26100, null, Today).EndOfSupport);
    }

    [Theory]
    [InlineData("Core", true)]
    [InlineData("CoreSingleLanguage", true)]
    [InlineData("Professional", false)]
    [InlineData(null, false)]
    public void HomeEditionDetection(string? edition, bool home) => Assert.Equal(home, WindowsLifecycle.IsHomeEdition(edition));
}
