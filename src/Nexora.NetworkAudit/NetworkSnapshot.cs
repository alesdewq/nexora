using System.Net;

namespace Nexora.NetworkAudit;

public sealed record NetworkSnapshot
{
    public required Measured<IReadOnlyList<ListeningSocket>> Listeners { get; init; }
    public required Measured<IReadOnlyList<FirewallRule>> FirewallRules { get; init; }
    /// <summary>Профили брандмауэра, активные сейчас (битовая маска: 1 — домен, 2 — частная, 4 — общедоступная).</summary>
    public required Measured<int> ActiveProfiles { get; init; }
}

public enum Protocol { Tcp, Udp }

public sealed record ListeningSocket(Protocol Protocol, string LocalAddress, int Port, int Pid, string? ProcessName, string? ProcessPath,
    IReadOnlyList<string> Services)
{
    /// <summary>Сокет принимает подключения только с этого компьютера.</summary>
    public bool IsLoopbackOnly => IPAddress.TryParse(LocalAddress, out var a) && IPAddress.IsLoopback(a);
    /// <summary>Сокет привязан ко всем интерфейсам (0.0.0.0 или ::).</summary>
    public bool IsAllInterfaces => LocalAddress is "0.0.0.0" or "::";
}

[Flags]
public enum FirewallProfiles { None = 0, Domain = 1, Private = 2, Public = 4, All = Domain | Private | Public }

/// <param name="Protocol">IANA: 6 — TCP, 17 — UDP, 256 — любой.</param>
/// <param name="LocalPorts">Как в правиле: «*», «80,443», «5000-5010», или ключевые слова (RPC и т. п.).</param>
public sealed record FirewallRule(string Name, bool Enabled, bool Inbound, bool Allow, int Protocol, string? LocalPorts, string? Application,
    FirewallProfiles Profiles, string? Service);
