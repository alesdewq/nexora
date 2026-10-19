using System.Net;
using System.Net.Sockets;
using Nexora.NetworkAudit;

namespace Nexora.Platform.Tests;

public class NetworkCollectorTests
{
    [Fact]
    public void FindsOwnLoopbackListener_WithProcess()
    {
        // Тест открывает собственный сокет только на 127.0.0.1 — наружу ничего не публикуется.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var sockets = NetworkCollector.Listeners().ToList();
        var mine = Assert.Single(sockets, s => s.Protocol == Protocol.Tcp && s.Port == port);
        Assert.Equal(Environment.ProcessId, mine.Pid);
        Assert.True(mine.IsLoopbackOnly);
        Assert.NotNull(mine.ProcessPath);
    }

    [Fact]
    public void Collect_ReadsFirewallRules()
    {
        var n = NetworkCollector.Collect();
        Assert.True(n.Listeners.IsAvailable, n.Listeners.Reason);
        Assert.True(n.FirewallRules.IsAvailable, n.FirewallRules.Reason);
        Assert.NotEmpty(n.FirewallRules.Value);
        _ = NetworkAnalyzer.Analyze(n);
    }
}
