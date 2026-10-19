namespace Nexora.NetworkAudit.Tests;

public class NetworkTests
{
    private static Measured<T> Of<T>(T v) => Measured<T>.Of(v, "fake");

    private static ListeningSocket Sock(int port, string addr = "0.0.0.0", string? path = @"C:\Windows\System32\svchost.exe", Protocol p = Protocol.Tcp) =>
        new(p, addr, port, 1234, Path.GetFileNameWithoutExtension(path) ?? "?", path, []);

    private static FirewallRule Rule(string ports, FirewallProfiles profiles, string? app = null, bool enabled = true, bool allow = true, int proto = 6) =>
        new("rule " + ports, enabled, true, allow, proto, ports, app, profiles, null);

    private static NetworkSnapshot Snap(IReadOnlyList<ListeningSocket> socks, IReadOnlyList<FirewallRule>? rules) => new()
    {
        Listeners = Of(socks),
        FirewallRules = rules is null ? Measured<IReadOnlyList<FirewallRule>>.Unavailable("fake", "COM недоступен") : Of(rules),
        ActiveProfiles = Of(2),
    };

    [Theory]
    [InlineData("*", 3389, true)]
    [InlineData("", 3389, true)]
    [InlineData("80,443", 443, true)]
    [InlineData("80,443", 8080, false)]
    [InlineData("5000-5010", 5005, true)]
    [InlineData("5000-5010", 5011, false)]
    [InlineData("RPC", 135, false)]
    [InlineData("RPC-EPMap, 3389", 3389, true)]
    public void PortMatching(string ports, int port, bool expected) => Assert.Equal(expected, FirewallMatcher.PortMatches(ports, port));

    [Fact]
    public void ProtocolAndApplicationMatching()
    {
        Assert.True(FirewallMatcher.ProtocolMatches(256, Protocol.Udp));
        Assert.False(FirewallMatcher.ProtocolMatches(6, Protocol.Udp));
        Assert.True(FirewallMatcher.ApplicationMatches(null, @"C:\a.exe"));
        Assert.True(FirewallMatcher.ApplicationMatches(@"C:\A.EXE", @"c:\a.exe"));
        Assert.False(FirewallMatcher.ApplicationMatches(@"C:\b.exe", @"C:\a.exe"));
        Assert.False(FirewallMatcher.ApplicationMatches(@"C:\b.exe", null));
    }

    [Fact]
    public void DisabledAndBlockRules_DoNotAllow()
    {
        var s = Sock(3389);
        Assert.Equal(FirewallProfiles.None, FirewallMatcher.AllowedProfiles(s, [Rule("3389", FirewallProfiles.All, enabled: false), Rule("3389", FirewallProfiles.All, allow: false)], out _));
        Assert.Equal(FirewallProfiles.Private | FirewallProfiles.Domain,
            FirewallMatcher.AllowedProfiles(s, [Rule("3389", FirewallProfiles.Private), Rule("3389", FirewallProfiles.Domain)], out var m));
        Assert.Equal(2, m.Count);
    }

    [Fact]
    public void LoopbackDetection()
    {
        Assert.True(Sock(1, "127.0.0.1").IsLoopbackOnly);
        Assert.True(Sock(1, "::1").IsLoopbackOnly);
        Assert.False(Sock(1, "0.0.0.0").IsLoopbackOnly);
        Assert.True(Sock(1, "::").IsAllInterfaces);
    }

    [Fact]
    public void Rdp_AllowedOnPublic_IsMedium_AndNeverClaimsInternetExposure()
    {
        var r = NetworkAnalyzer.Analyze(Snap([Sock(3389)], [Rule("3389", FirewallProfiles.All)])).Single(x => x.Id == "net.port.tcp.3389");
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Equal(FindingKind.PotentialRisk, r.Kind);
        Assert.Contains(r.Limitations, l => l.Contains("интернет"));
    }

    [Fact]
    public void Telnet_AllowedOnPublic_IsHigh_PrivateOnly_IsMedium()
    {
        Assert.Equal(Severity.High, NetworkAnalyzer.Analyze(Snap([Sock(23)], [Rule("23", FirewallProfiles.Public)])).Single(x => x.Id == "net.port.tcp.23").Severity);
        Assert.Equal(Severity.Medium, NetworkAnalyzer.Analyze(Snap([Sock(23)], [Rule("23", FirewallProfiles.Private)])).Single(x => x.Id == "net.port.tcp.23").Severity);
    }

    [Fact]
    public void LoopbackOnly_IsNotReported()
    {
        var r = NetworkAnalyzer.Analyze(Snap([Sock(6379, "127.0.0.1")], [Rule("*", FirewallProfiles.All)]));
        Assert.DoesNotContain(r, x => x.Id.StartsWith("net.port.", StringComparison.Ordinal));
    }

    [Fact]
    public void RulesUnavailable_StillReportsPortsAsInfo_WithReason()
    {
        var r = NetworkAnalyzer.Analyze(Snap([Sock(445)], null));
        Assert.Equal(Severity.Info, r.Single(x => x.Id == "net.port.tcp.445").Severity);
        Assert.Contains(r.Single(x => x.Id == "net.listeners").Limitations, l => l.Contains("COM недоступен"));
    }

    [Fact]
    public void UnknownProgramFromTemp_AllowedInbound_IsLowConfidenceHeuristic()
    {
        var r = NetworkAnalyzer.Analyze(Snap([Sock(4444, path: @"C:\Users\me\AppData\Local\Temp\x.exe")], [Rule("*", FirewallProfiles.Private, app: @"C:\Users\me\AppData\Local\Temp\x.exe")]))
            .Single(x => x.Id == "net.port.tcp.4444");
        Assert.Equal(FindingKind.Heuristic, r.Kind);
        Assert.Equal(Confidence.Low, r.Confidence);
    }

    [Fact]
    public void ListenersUnavailable()
    {
        var snap = new NetworkSnapshot
        {
            Listeners = Measured<IReadOnlyList<ListeningSocket>>.Unavailable("fake", "отказано"),
            FirewallRules = Of<IReadOnlyList<FirewallRule>>([]), ActiveProfiles = Of(2),
        };
        Assert.Equal(CheckStatus.Unavailable, Assert.Single(NetworkAnalyzer.Analyze(snap)).Status);
    }
}
