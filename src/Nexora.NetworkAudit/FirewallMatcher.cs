namespace Nexora.NetworkAudit;

/// <summary>
/// Упрощённое сопоставление сокета с разрешающими входящими правилами. Учитывает порт, протокол и программу;
/// не учитывает адреса удалённой стороны, приоритет запрещающих правил, правила для служб и IPsec — поэтому вывод «разрешено» приблизителен.
/// </summary>
public static class FirewallMatcher
{
    public static bool PortMatches(string? localPorts, int port)
    {
        if (string.IsNullOrWhiteSpace(localPorts) || localPorts.Trim() == "*") return true;
        foreach (var part in localPorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = part.IndexOf('-');
            if (dash > 0 && int.TryParse(part[..dash], out var lo) && int.TryParse(part[(dash + 1)..], out var hi))
            {
                if (port >= lo && port <= hi) return true;
            }
            else if (int.TryParse(part, out var single) && single == port) return true;
        }
        return false; // ключевые слова RPC, IPHTTPS и т. п. к обычному порту не относятся
    }

    public static bool ProtocolMatches(int ruleProtocol, Protocol p) =>
        ruleProtocol == 256 || (p == Protocol.Tcp && ruleProtocol == 6) || (p == Protocol.Udp && ruleProtocol == 17);

    public static bool ApplicationMatches(string? ruleApp, string? processPath)
    {
        if (string.IsNullOrWhiteSpace(ruleApp) || ruleApp.Trim() == "*") return true;
        if (string.IsNullOrEmpty(processPath)) return false;
        var expanded = Environment.ExpandEnvironmentVariables(ruleApp.Trim());
        try { return string.Equals(Path.GetFullPath(expanded), Path.GetFullPath(processPath), StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    /// <summary>Профили, в которых входящие подключения к сокету разрешены хотя бы одним включённым правилом.</summary>
    public static FirewallProfiles AllowedProfiles(ListeningSocket s, IEnumerable<FirewallRule> rules, out List<FirewallRule> matched)
    {
        matched = rules.Where(r => r.Enabled && r.Inbound && r.Allow && ProtocolMatches(r.Protocol, s.Protocol)
                                   && PortMatches(r.LocalPorts, s.Port) && ApplicationMatches(r.Application, s.ProcessPath)
                                   && ServiceMatches(r.Service, s.Services)
                                   // правило «любой порт, любая программа» без службы — это не разрешение конкретного сокета
                                   && !(IsAny(r.LocalPorts) && IsAny(r.Application) && IsAny(r.Service)))
            .ToList();
        return matched.Aggregate(FirewallProfiles.None, (acc, r) => acc | r.Profiles);
    }

    /// <summary>Правило, привязанное к службе, действует только для этой службы (в одном svchost их бывает несколько).</summary>
    public static bool ServiceMatches(string? ruleService, IReadOnlyList<string> socketServices) =>
        IsAny(ruleService) || socketServices.Contains(ruleService!.Trim(), StringComparer.OrdinalIgnoreCase);

    private static bool IsAny(string? v) => string.IsNullOrWhiteSpace(v) || v.Trim() == "*";
}
