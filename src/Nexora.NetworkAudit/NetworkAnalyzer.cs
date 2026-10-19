using Nexora.SecurityAudit;

namespace Nexora.NetworkAudit;

public static class NetworkAnalyzer
{
    private const string SrcSockets = "Win32 GetExtendedTcpTable/GetExtendedUdpTable (iphlpapi)";
    private const string SrcRules = "COM HNetCfg.FwPolicy2 (правила брандмауэра Windows)";

    public sealed record PortInfo(string Name, string Purpose, bool Dangerous);

    /// <summary>Порты служб, которые стоит знать в лицо. «Dangerous» — протоколы без шифрования или частые цели атак.</summary>
    public static readonly IReadOnlyDictionary<(Protocol, int), PortInfo> Known = new Dictionary<(Protocol, int), PortInfo>
    {
        [(Protocol.Tcp, 21)] = new("FTP", "передача файлов без шифрования", true),
        [(Protocol.Tcp, 22)] = new("SSH", "удалённая командная строка", false),
        [(Protocol.Tcp, 23)] = new("Telnet", "удалённый доступ без шифрования", true),
        [(Protocol.Tcp, 135)] = new("RPC", "служебный порт Windows", false),
        [(Protocol.Tcp, 139)] = new("NetBIOS/SMB", "общий доступ к файлам (устаревший транспорт)", false),
        [(Protocol.Tcp, 445)] = new("SMB", "общий доступ к файлам и принтерам", false),
        [(Protocol.Tcp, 3389)] = new("RDP", "удалённый рабочий стол", false),
        [(Protocol.Tcp, 5985)] = new("WinRM HTTP", "удалённое управление Windows", false),
        [(Protocol.Tcp, 5986)] = new("WinRM HTTPS", "удалённое управление Windows", false),
        [(Protocol.Tcp, 5900)] = new("VNC", "удалённый рабочий стол VNC", true),
        [(Protocol.Tcp, 5901)] = new("VNC", "удалённый рабочий стол VNC", true),
        [(Protocol.Tcp, 1433)] = new("MS SQL Server", "база данных", false),
        [(Protocol.Tcp, 3306)] = new("MySQL/MariaDB", "база данных", false),
        [(Protocol.Tcp, 5432)] = new("PostgreSQL", "база данных", false),
        [(Protocol.Tcp, 27017)] = new("MongoDB", "база данных", true),
        [(Protocol.Tcp, 6379)] = new("Redis", "хранилище данных (часто без пароля)", true),
        [(Protocol.Tcp, 9200)] = new("Elasticsearch", "поисковая база данных", true),
        [(Protocol.Tcp, 11211)] = new("Memcached", "кэш без проверки доступа", true),
        [(Protocol.Udp, 69)] = new("TFTP", "передача файлов без пароля", true),
        [(Protocol.Udp, 161)] = new("SNMP", "мониторинг устройств", true),
    };

    public static IReadOnlyList<CheckResult> Analyze(NetworkSnapshot n)
    {
        if (!n.Listeners.TryGetValue(out var sockets))
            return [CheckResult.Unavailable("net.listeners", "Прослушиваемые порты", Section.Network, n.Listeners.Source, n.Listeners.Reason!)];

        var rules = n.FirewallRules.IsAvailable ? n.FirewallRules.Value : null;
        var exposed = sockets.Where(s => !s.IsLoopbackOnly).ToList();
        var results = new List<CheckResult>
        {
            CheckResult.Ok("net.listeners", "Прослушиваемые порты", Section.Network,
                $"Компьютер ожидает подключений на {sockets.Count(s => s.Protocol == Protocol.Tcp)} TCP-портах и {sockets.Count(s => s.Protocol == Protocol.Udp)} UDP-портах; " +
                $"из них только для самого компьютера (localhost): {sockets.Count(s => s.IsLoopbackOnly)}.",
                new Evidence(SrcSockets, $"{sockets.Count} сокетов; без процесса: {sockets.Count(s => s.ProcessName is null)}"))
                with { Limitations = CommonLimits(rules is null ? n.FirewallRules.Reason : null) },
        };

        foreach (var group in exposed.GroupBy(s => (s.Protocol, s.Port)).OrderBy(g => g.Key.Port))
        {
            var s = group.First();
            var processes = string.Join(", ", group.Select(x => x.ProcessName ?? $"PID {x.Pid}").Distinct());
            var services = group.SelectMany(x => x.Services).Distinct().ToList();
            var who = processes + (services.Count > 0 ? $" (службы: {string.Join(", ", services)})" : "");
            FirewallProfiles allowed = FirewallProfiles.None;
            var matched = new List<FirewallRule>();
            if (rules is not null)
                foreach (var x in group) { allowed |= FirewallMatcher.AllowedProfiles(x, rules, out var m); matched.AddRange(m); }
            var fwText = rules is null ? "правила брандмауэра не прочитаны" : allowed == FirewallProfiles.None
                ? "разрешающих входящих правил не найдено"
                : $"разрешено правилами для профилей: {ProfilesText(allowed)} ({string.Join("; ", matched.Select(r => r.Name).Distinct().Take(3))})";
            var ev = new Evidence($"{SrcSockets}; {SrcRules}", $"{s.Protocol} {string.Join(", ", group.Select(x => x.LocalAddress).Distinct())}:{s.Port} — {who}; {fwText}");
            var id = $"net.port.{s.Protocol.ToString().ToLowerInvariant()}.{s.Port}";

            if (Known.TryGetValue((s.Protocol, s.Port), out var info))
            {
                var title = $"Порт {s.Port} ({info.Name})";
                var publicAllowed = allowed.HasFlag(FirewallProfiles.Public);
                var what = $"{info.Name} — {info.Purpose} — ожидает подключений по сети на порту {s.Port}: {who}. Брандмауэр: {fwText}.";
                Severity sev = rules is null ? Severity.Info
                    : publicAllowed ? (info.Dangerous ? Severity.High : Severity.Medium)
                    : allowed != FirewallProfiles.None ? (info.Dangerous ? Severity.Medium : Severity.Info)
                    : Severity.Info;
                results.Add(CheckResult.Finding(id, title, Section.Network, sev, FindingKind.PotentialRisk, Confidence.Medium, what,
                    publicAllowed
                        ? "Порт разрешён и в общедоступных сетях: в кафе или гостинице к службе смогут подключиться чужие устройства."
                        : "Служба доступна устройствам локальной сети, если это разрешено брандмауэром.",
                    info.Dangerous
                        ? "Если служба не нужна — остановите её или удалите программу; если нужна — ограничьте доступ брандмауэром и не открывайте порт в интернет."
                        : "Если вы не пользуетесь этой функцией, её можно отключить; не открывайте этот порт в интернет на роутере.", ev)
                    with { Limitations = ["Порт виден локально; доступен ли он из интернета, зависит от роутера и провайдера и здесь не проверяется."] });
                continue;
            }

            var unusualPath = group.Select(x => x.ProcessPath).FirstOrDefault(p => CommandLine.IsUserWritableLocation(p, out _));
            if (unusualPath is not null && allowed != FirewallProfiles.None)
                results.Add(CheckResult.Finding(id, $"Порт {s.Port}: программа из пользовательской папки", Section.Network, Severity.Medium,
                    FindingKind.Heuristic, Confidence.Low,
                    $"Программа {processes} из {unusualPath} принимает подключения из сети на порту {s.Port} ({s.Protocol}); {fwText}.",
                    "Так работают некоторые игры, мессенджеры и средства удалённого доступа, но так же — и вредоносные программы с удалённым управлением.",
                    "Убедитесь, что знаете эту программу и что ей нужен входящий доступ.", ev));
        }
        return results;
    }

    private static string[] CommonLimits(string? rulesReason) =>
    [
        "«Порт прослушивается» не означает «доступен из интернета»: это зависит от брандмауэра, роутера и провайдера. Внешняя доступность не проверялась.",
        "Сопоставление с правилами брандмауэра упрощённое: не учитываются запрещающие правила, удалённые адреса и правила IPsec.",
        .. rulesReason is null ? Array.Empty<string>() : [$"Правила брандмауэра не прочитаны: {rulesReason}."],
    ];

    public static string ProfilesText(FirewallProfiles p)
    {
        var parts = new List<string>();
        if (p.HasFlag(FirewallProfiles.Domain)) parts.Add("доменная");
        if (p.HasFlag(FirewallProfiles.Private)) parts.Add("частная");
        if (p.HasFlag(FirewallProfiles.Public)) parts.Add("общедоступная");
        return parts.Count == 0 ? "нет" : string.Join(", ", parts);
    }
}
