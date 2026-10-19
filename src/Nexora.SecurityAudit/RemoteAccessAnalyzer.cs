namespace Nexora.SecurityAudit;

/// <summary>RDP, SMB, WinRM, общие папки. Включённая служба — не уязвимость сама по себе: оценка зависит от контекста.</summary>
public static class RemoteAccessAnalyzer
{
    private const string SrcRdp = @"Реестр HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server (fDenyTSConnections, WinStations\RDP-Tcp)";

    public static IReadOnlyList<CheckResult> Analyze(SecuritySnapshot s) => [Rdp(s), Smb1(s), Shares(s), WinRm(s)];

    public static CheckResult Rdp(SecuritySnapshot s)
    {
        const string id = "sec.rdp", title = "Удалённый рабочий стол (RDP)";
        if (!s.Rdp.TryGetValue(out var r))
            return CheckResult.Unavailable(id, title, Section.Security, s.Rdp.Source, s.Rdp.Reason!);
        var ev = new Evidence(SrcRdp, $"Enabled={r.Enabled}, NLA={r.NetworkLevelAuthentication}, Port={r.Port}");
        var limits = new[] { "NEXORA видит только локальные настройки и не знает, доступен ли порт из интернета (это зависит от роутера и провайдера)." };
        if (!r.Enabled)
            return CheckResult.Ok(id, title, Section.Security, "Входящие подключения к удалённому рабочему столу запрещены.", ev);
        if (r.NetworkLevelAuthentication == false)
            return CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.PotentialRisk, Confidence.High,
                $"Удалённый рабочий стол включён (порт {r.Port}) без проверки подлинности на уровне сети (NLA).",
                "Без NLA экран входа доступен до проверки пароля — это облегчает подбор паролей и атаки на саму службу.",
                "Если RDP не нужен — выключите его в «Параметры → Система → Удалённый рабочий стол»; если нужен — включите NLA.", ev) with { Limitations = limits };
        return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.PotentialRisk, Confidence.High,
            $"Удалённый рабочий стол включён (порт {r.Port}), проверка NLA включена.",
            "RDP — частая цель подбора паролей, если порт доступен из интернета.",
            "Если удалённый доступ не используется — выключите его. Если используется — не открывайте порт в интернет напрямую, используйте VPN и сложные пароли.", ev)
            with { Limitations = limits };
    }

    public static CheckResult Smb1(SecuritySnapshot s)
    {
        const string id = "sec.smb1", title = "Устаревший протокол SMB1";
        if (!s.Smb1Enabled.TryGetValue(out var on))
            return CheckResult.Unavailable(id, title, Section.Security, s.Smb1Enabled.Source, s.Smb1Enabled.Reason!);
        var ev = new Evidence(s.Smb1Enabled.Source, on ? "SMB1 включён" : "SMB1 отключён");
        return on
            ? CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.PotentialRisk, Confidence.High,
                "Компонент SMB1 включён.", "SMB1 устарел и использовался для массового распространения вирусов-шифровальщиков (WannaCry).",
                "Отключите «Поддержка общего доступа к файлам SMB 1.0/CIFS» в компонентах Windows, если у вас нет очень старых устройств, которым он нужен.", ev)
            : CheckResult.Ok(id, title, Section.Security, "SMB1 отключён.", ev);
    }

    public static CheckResult Shares(SecuritySnapshot s)
    {
        const string id = "sec.shares", title = "Общие папки";
        if (!s.Shares.TryGetValue(out var shares))
            return CheckResult.Unavailable(id, title, Section.Network, s.Shares.Source, s.Shares.Reason!);
        var custom = shares.Where(x => !x.IsDefaultAdminShare).ToList();
        var ev = new Evidence(s.Shares.Source, shares.Count == 0 ? "нет" : string.Join("; ", shares.Select(x => $"{x.Name} → {x.Path}")));
        return custom.Count == 0
            ? CheckResult.Ok(id, title, Section.Network, "Пользовательских общих папок нет (стандартные административные ресурсы вида C$ не в счёт).", ev)
            : CheckResult.Finding(id, title, Section.Network, Severity.Info, FindingKind.Fact, Confidence.High,
                $"Открыты общие папки: {string.Join(", ", custom.Select(x => $"{x.Name} ({x.Path})"))}.",
                "Содержимое общих папок доступно по сети тем, у кого есть разрешения.",
                "Проверьте, нужны ли эти папки и кому выданы разрешения на доступ.", ev)
                with { Limitations = ["Разрешения на общие папки NEXORA не анализирует."] };
    }

    public static CheckResult WinRm(SecuritySnapshot s)
    {
        const string id = "sec.winrm", title = "Удалённое управление (WinRM)";
        if (!s.WinRm.TryGetValue(out var w))
            return CheckResult.Unavailable(id, title, Section.Security, s.WinRm.Source, s.WinRm.Reason!);
        var ev = new Evidence(s.WinRm.Source, $"{w.Name}: State={w.State}, StartMode={w.StartMode}");
        return w.State.Equals("Running", StringComparison.OrdinalIgnoreCase)
            ? CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.PotentialRisk, Confidence.Medium,
                "Служба удалённого управления WinRM запущена.",
                "WinRM позволяет администраторам выполнять команды удалённо; на домашнем компьютере обычно не нужна.",
                "Если вы не используете удалённое управление (PowerShell Remoting), служба может быть остановлена — уточните у администратора, если компьютер рабочий.", ev)
                with { Limitations = ["Наличие прослушивателей WinRM без прав администратора не проверяется; см. раздел «Сеть» (порты 5985/5986)."] }
            : CheckResult.Ok(id, title, Section.Security, "Служба WinRM не запущена.", ev);
    }
}
