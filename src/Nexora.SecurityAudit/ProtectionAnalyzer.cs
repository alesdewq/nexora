namespace Nexora.SecurityAudit;

/// <summary>Defender и сторонний антивирус, брандмауэр, UAC, BitLocker, Winlogon.</summary>
public static class ProtectionAnalyzer
{
    public const int SignaturesMediumDays = 3, SignaturesHighDays = 7;
    private const string SrcDefender = @"WMI root\Microsoft\Windows\Defender: MSFT_MpComputerStatus";
    private const string SrcCenter = @"WMI root\SecurityCenter2: AntiVirusProduct";
    private const string SrcFirewall = @"Реестр HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy; HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall";
    private const string SrcUac = @"Реестр HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    public static IReadOnlyList<CheckResult> Analyze(SecuritySnapshot s) =>
        [Antivirus(s), Signatures(s), Tamper(s), Exclusions(s), .. Firewall(s), Uac(s), BitLocker(s), Winlogon(s)];

    private static SecurityProduct? ThirdPartyAv(SecuritySnapshot s) =>
        s.AntivirusProducts.TryGetValue(out var p) ? p.FirstOrDefault(x => x.Enabled && !x.IsMicrosoftDefender) : null;

    public static CheckResult Antivirus(SecuritySnapshot s)
    {
        const string id = "sec.av", title = "Антивирусная защита";
        var other = ThirdPartyAv(s);
        if (other is not null)
            return CheckResult.Ok(id, title, Section.Security, $"Активен сторонний антивирус: {other.Name}. Microsoft Defender в этом случае обычно работает в пассивном режиме.",
                new Evidence(SrcCenter, $"{other.Name}: включён, базы {(other.UpToDate switch { true => "актуальны", false => "устарели", _ => "?" })}"), Confidence.Medium)
                with { Limitations = ["Состояние стороннего антивируса известно только со слов Центра безопасности Windows; его настройки NEXORA не проверяет."] };

        if (!s.Defender.TryGetValue(out var d))
        {
            var anyAv = s.AntivirusProducts.IsAvailable && s.AntivirusProducts.Value.Any(p => p.Enabled);
            return s.AntivirusProducts.IsAvailable && !anyAv
                ? CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.PotentialRisk, Confidence.Medium,
                    "Центр безопасности Windows не сообщает ни об одном включённом антивирусе, а данные Defender недоступны.",
                    "Без антивируса известные вредоносные программы не блокируются.",
                    "Откройте «Безопасность Windows» и проверьте раздел «Защита от вирусов и угроз».",
                    new Evidence(SrcDefender, s.Defender.Reason ?? "недоступно"))
                : CheckResult.Unavailable(id, title, Section.Security, s.Defender.Source, s.Defender.Reason!);
        }

        var ev = new Evidence(SrcDefender, $"AMServiceEnabled={d.ServiceEnabled}, AntivirusEnabled={d.AntivirusEnabled}, RealTimeProtectionEnabled={d.RealTimeProtectionEnabled}, AMRunningMode={d.RunningMode}");
        if (!d.AntivirusEnabled || !d.ServiceEnabled)
            return CheckResult.Finding(id, title, Section.Security, Severity.Critical, FindingKind.Fact, Confidence.High,
                "Microsoft Defender выключен, и другой активный антивирус не обнаружен.",
                "Компьютер не защищён от известных вредоносных программ.",
                "Включите защиту в «Безопасность Windows → Защита от вирусов и угроз» или установите другой антивирус.", ev);
        if (!d.RealTimeProtectionEnabled)
            return CheckResult.Finding(id, title, Section.Security, Severity.Critical, FindingKind.Fact, Confidence.High,
                "Защита Microsoft Defender в реальном времени выключена.",
                "Без защиты в реальном времени вредоносные файлы не блокируются при запуске и скачивании.",
                "Включите «Защиту в режиме реального времени» в «Безопасность Windows». NEXORA не меняет эту настройку сама.", ev);
        return CheckResult.Ok(id, title, Section.Security, "Microsoft Defender включён, защита в реальном времени работает.", ev);
    }

    public static CheckResult Signatures(SecuritySnapshot s)
    {
        const string id = "sec.av.signatures", title = "Актуальность антивирусных баз";
        if (ThirdPartyAv(s) is { } other)
            return other.UpToDate == false
                ? CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.Fact, Confidence.Medium,
                    $"Центр безопасности сообщает, что базы антивируса {other.Name} устарели.",
                    "Устаревшие базы не распознают новые угрозы.", "Обновите базы в интерфейсе антивируса.", new Evidence(SrcCenter, $"{other.Name}: UpToDate=false"))
                : CheckResult.Ok(id, title, Section.Security, $"Центр безопасности не сообщает об устаревших базах {other.Name}.",
                    new Evidence(SrcCenter, $"{other.Name}: UpToDate={other.UpToDate}"), Confidence.Medium);
        if (!s.Defender.TryGetValue(out var d) || d.SignatureAgeDays is null)
            return CheckResult.Unavailable(id, title, Section.Security, SrcDefender, s.Defender.Reason ?? "возраст баз не указан");
        var age = d.SignatureAgeDays.Value;
        var ev = new Evidence(SrcDefender, $"AntivirusSignatureAge={age}, AntivirusSignatureLastUpdated={d.SignatureLastUpdated:yyyy-MM-dd HH:mm}");
        var what = $"Базы Microsoft Defender обновлены {age} дн. назад.";
        if (age > SignaturesHighDays || age > SignaturesMediumDays)
            return CheckResult.Finding(id, title, Section.Security, age > SignaturesHighDays ? Severity.High : Severity.Medium, FindingKind.Fact, Confidence.High, what,
                "Defender получает новые базы несколько раз в день; устаревшие базы не распознают свежие угрозы.",
                "Откройте «Безопасность Windows → Обновления защиты» и нажмите «Проверить наличие обновлений»; проверьте подключение к интернету.", ev);
        return CheckResult.Ok(id, title, Section.Security, what, ev);
    }

    public static CheckResult Tamper(SecuritySnapshot s)
    {
        const string id = "sec.av.tamper", title = "Защита от подделки (Tamper Protection)";
        if (ThirdPartyAv(s) is not null || !s.Defender.TryGetValue(out var d) || d.TamperProtected is null)
            return CheckResult.Unavailable(id, title, Section.Security, SrcDefender,
                ThirdPartyAv(s) is not null ? "не применяется: основной антивирус — сторонний" : s.Defender.Reason ?? "значение не получено");
        var ev = new Evidence(SrcDefender, $"IsTamperProtected={d.TamperProtected}");
        return d.TamperProtected.Value
            ? CheckResult.Ok(id, title, Section.Security, "Защита от подделки включена: вредоносные программы не могут отключить Defender без вашего участия.", ev)
            : CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.PotentialRisk, Confidence.High,
                "Защита от подделки выключена.", "Вредоносная программа с правами администратора сможет незаметно отключить Defender.",
                "Включите «Защиту от подделки» в параметрах защиты от вирусов (если компьютером не управляет организация).", ev);
    }

    public static CheckResult Exclusions(SecuritySnapshot s)
    {
        const string id = "sec.av.exclusions", title = "Исключения Microsoft Defender";
        if (!s.Exclusions.TryGetValue(out var ex))
            return CheckResult.Unavailable(id, title, Section.Security, s.Exclusions.Source, s.Exclusions.Reason!);
        var ev = new Evidence(@"WMI root\Microsoft\Windows\Defender: MSFT_MpPreference",
            $"пути: {ex.Paths.Count}, расширения: {ex.Extensions.Count}, процессы: {ex.Processes.Count}");
        if (ex.IsEmpty) return CheckResult.Ok(id, title, Section.Security, "Исключений из проверки нет.", ev);

        var broad = ex.Paths.Where(IsBroadExclusion).ToList();
        var riskyExt = ex.Extensions.Where(e => e.TrimStart('.', '*').ToLowerInvariant() is "exe" or "dll" or "ps1" or "bat" or "cmd" or "js" or "vbs" or "scr").ToList();
        var all = ex.Paths.Concat(ex.Extensions.Select(e => $"*{e}")).Concat(ex.Processes.Select(p => $"процесс {p}")).ToList();
        var high = broad.Count > 0 || riskyExt.Count > 0;
        return CheckResult.Finding(id, title, Section.Security, high ? Severity.High : Severity.Medium, FindingKind.PotentialRisk,
            Confidence.Medium, $"Из проверки Defender исключено: {string.Join("; ", all.Take(10))}{(all.Count > 10 ? "…" : "")}.",
            high
                ? "Исключены целые диски, пользовательские/временные папки или исполняемые типы файлов — вредоносная программа там не будет обнаружена. Вредоносное ПО иногда само добавляет такие исключения."
                : "Файлы в исключённых местах Defender не проверяет.",
            "Проверьте, знаете ли вы, кто и зачем добавил каждое исключение; удалите ненужные в параметрах Defender.", ev);
    }

    public static bool IsBroadExclusion(string path)
    {
        var p = path.Trim().TrimEnd('\\').Replace('/', '\\');
        if (p.Length <= 2 && p.EndsWith(':')) return true; // целый диск
        var lower = p.ToLowerInvariant();
        return lower.EndsWith(@"\users", StringComparison.Ordinal) || lower.Contains(@"\appdata", StringComparison.Ordinal) || lower.Contains(@"\temp", StringComparison.Ordinal)
            || lower.Contains(@"\downloads", StringComparison.Ordinal) || lower.Contains("%temp%", StringComparison.Ordinal) || lower.Contains("%appdata%", StringComparison.Ordinal)
            || lower.Contains(@"\users\public", StringComparison.Ordinal) || lower is @"c:\windows" or @"c:\programdata" or @"c:\program files";
    }

    public static IEnumerable<CheckResult> Firewall(SecuritySnapshot s)
    {
        if (!s.Firewall.TryGetValue(out var profiles))
        {
            yield return CheckResult.Unavailable("sec.firewall", "Брандмауэр Windows", Section.Security, s.Firewall.Source, s.Firewall.Reason!);
            yield break;
        }
        var other = s.FirewallProducts.IsAvailable ? s.FirewallProducts.Value.FirstOrDefault(p => p.Enabled && !p.IsMicrosoftDefender) : null;
        foreach (var p in profiles)
        {
            var (name, id) = p.Profile switch
            {
                FirewallProfile.Domain => ("доменной сети", "sec.firewall.domain"),
                FirewallProfile.Private => ("частной сети", "sec.firewall.private"),
                _ => ("общедоступной сети", "sec.firewall.public"),
            };
            var title = $"Брандмауэр: профиль {name}";
            var ev = new Evidence(SrcFirewall, $"{p.Profile}: EnableFirewall={(p.Enabled ? 1 : 0)}{(p.SetByPolicy ? " (групповая политика)" : "")}");
            if (p.Enabled) { yield return CheckResult.Ok(id, title, Section.Security, $"Брандмауэр Windows для {name} включён.", ev); continue; }
            if (other is not null)
            {
                yield return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.Fact, Confidence.Medium,
                    $"Брандмауэр Windows для {name} выключен; Центр безопасности сообщает об активном стороннем брандмауэре «{other.Name}».",
                    "Защиту сети в этом случае обеспечивает сторонний продукт.", "Убедитесь, что сторонний брандмауэр действительно настроен и работает.", ev);
                continue;
            }
            var sev = p.Profile switch
            {
                FirewallProfile.Public => Severity.High,
                FirewallProfile.Private => Severity.Medium,
                _ => s.PartOfDomain == true ? Severity.Medium : Severity.Info,
            };
            yield return CheckResult.Finding(id, title, Section.Security, sev, FindingKind.Fact, Confidence.High,
                $"Брандмауэр Windows для {name} выключен{(p.SetByPolicy ? " групповой политикой" : "")}.",
                p.Profile == FirewallProfile.Public
                    ? "В общественных сетях (кафе, гостиницы) службы компьютера становятся доступны чужим устройствам."
                    : "Службы компьютера (общие папки, удалённый доступ) доступны всем устройствам этой сети.",
                p.SetByPolicy
                    ? "Настройка задана политикой — обратитесь к администратору организации."
                    : "Включите брандмауэр в «Безопасность Windows → Брандмауэр и защита сети». NEXORA не меняет эту настройку сама.", ev);
        }
    }

    public static CheckResult Uac(SecuritySnapshot s)
    {
        const string id = "sec.uac", title = "Контроль учётных записей (UAC)";
        if (!s.Uac.TryGetValue(out var u))
            return CheckResult.Unavailable(id, title, Section.Security, s.Uac.Source, s.Uac.Reason!);
        var ev = new Evidence(SrcUac, $"EnableLUA={(u.EnableLua ? 1 : 0)}, ConsentPromptBehaviorAdmin={u.ConsentPromptBehaviorAdmin}, PromptOnSecureDesktop={u.PromptOnSecureDesktop}");
        if (!u.EnableLua)
            return CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.Fact, Confidence.High, "UAC полностью отключён.",
                "Любая программа администратора сразу получает полные права без запроса, а современные приложения Windows работают некорректно.",
                "Включите UAC (требуется перезагрузка). NEXORA не меняет эту настройку сама.", ev);
        if (u.ConsentPromptBehaviorAdmin == 0)
            return CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.PotentialRisk, Confidence.High,
                "UAC включён, но администраторы получают повышенные права без запроса.",
                "Программа, запущенная администратором, может незаметно получить полный контроль над системой.",
                "Верните уровень UAC «Уведомлять только при попытках приложений внести изменения» (по умолчанию).", ev);
        if (u.PromptOnSecureDesktop == false)
            return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.PotentialRisk, Confidence.Medium,
                "Запрос UAC показывается без затемнения рабочего стола (без защищённого рабочего стола).",
                "Без защищённого рабочего стола другие программы теоретически могут взаимодействовать с окном запроса.",
                "Верните уровень UAC по умолчанию.", ev);
        return CheckResult.Ok(id, title, Section.Security, "UAC включён с запросом подтверждения.", ev);
    }

    public static CheckResult BitLocker(SecuritySnapshot s)
    {
        const string id = "sec.bitlocker", title = "Шифрование системного диска";
        var home = s.EditionId?.StartsWith("Core", StringComparison.OrdinalIgnoreCase) == true;
        if (!s.BitLocker.TryGetValue(out var vols) || vols.FirstOrDefault(v => v.IsSystem) is not { } sys || sys.State == ProtectionState.Unknown)
            return CheckResult.Unavailable(id, title, Section.Security, s.BitLocker.Source, s.BitLocker.Reason ?? "состояние системного диска не определено");

        var ev = new Evidence(s.BitLocker.Source, string.Join("; ", vols.Select(v => $"{v.Drive} {v.State}")));
        var limits = new[] { "Шифрование защищает данные при краже или потере выключенного устройства; от вирусов оно не защищает." };
        switch (sys.State)
        {
            case ProtectionState.On:
                return CheckResult.Ok(id, title, Section.Security, $"Системный диск {sys.Drive} зашифрован, защита включена.", ev) with { Limitations = limits };
            case ProtectionState.Encrypting or ProtectionState.Decrypting:
                return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.Fact, Confidence.High,
                    $"Системный диск {sys.Drive}: идёт {(sys.State == ProtectionState.Encrypting ? "шифрование" : "расшифровка")}.",
                    "До завершения процесса защита неполная.", "Дождитесь окончания процесса, не выключая питание надолго.", ev) with { Limitations = limits };
            case ProtectionState.Suspended:
                return CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.Fact, Confidence.High,
                    $"Шифрование диска {sys.Drive} приостановлено — ключ хранится открыто.",
                    "Пока защита приостановлена, данные на диске доступны при краже устройства. Windows приостанавливает защиту при обновлении BIOS и сама её возобновляет.",
                    "Если приостановка не связана с обновлением, возобновите защиту в «Управление BitLocker».", ev) with { Limitations = limits };
        }
        if (home)
            return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.Recommendation, Confidence.Medium,
                $"Системный диск {sys.Drive} не зашифрован. В редакции Home BitLocker недоступен.",
                "При краже или потере устройства данные на диске можно прочитать, подключив его к другому компьютеру.",
                "Проверьте «Параметры → Конфиденциальность и защита → Шифрование устройства» — эта функция есть на части устройств с Home.", ev) with { Limitations = limits };
        return CheckResult.Finding(id, title, Section.Security, s.IsPortable == true ? Severity.Medium : Severity.Info,
            s.IsPortable == true ? FindingKind.PotentialRisk : FindingKind.Recommendation, Confidence.Medium,
            $"Системный диск {sys.Drive} не зашифрован.",
            s.IsPortable == true
                ? "Ноутбук легко потерять или украсть; без шифрования данные на диске доступны любому."
                : "Для стационарного компьютера риск ниже, но данные доступны при краже диска.",
            "Включите BitLocker и сохраните ключ восстановления в надёжном месте. Это решение пользователя: NEXORA не включает шифрование сама.", ev) with { Limitations = limits };
    }

    public static CheckResult Winlogon(SecuritySnapshot s)
    {
        const string id = "sec.winlogon", title = "Параметры входа Winlogon";
        if (!s.Winlogon.TryGetValue(out var w))
            return CheckResult.Unavailable(id, title, Section.Security, s.Winlogon.Source, s.Winlogon.Reason!);
        var ev = new Evidence(@"Реестр HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", $"Shell={w.Shell}; Userinit={w.Userinit}");
        var shellOk = w.Shell is null || w.Shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
        // Стандарт: ровно один элемент «<папка Windows>\system32\userinit.exe» (диск Windows может быть любым).
        var userinitParts = w.Userinit?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];
        var userinitOk = w.Userinit is null || (userinitParts.Length == 1
            && userinitParts[0].EndsWith(@"\system32\userinit.exe", StringComparison.OrdinalIgnoreCase));
        if (shellOk && userinitOk)
            return CheckResult.Ok(id, title, Section.Security, "Оболочка и программа входа стандартные.", ev);
        return CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.Heuristic, Confidence.Medium,
            "Изменены параметры Winlogon: " + (shellOk ? "" : $"оболочка «{w.Shell}» ") + (userinitOk ? "" : $"Userinit «{w.Userinit}»"),
            "Вредоносные программы иногда прописывают себя сюда, чтобы запускаться при каждом входе. Изменение бывает и легитимным (киоски, корпоративные оболочки).",
            "Если вы не настраивали особую оболочку, проверьте компьютер антивирусом и обратитесь к специалисту. Не меняйте эти значения вручную без резервной копии.", ev);
    }
}
