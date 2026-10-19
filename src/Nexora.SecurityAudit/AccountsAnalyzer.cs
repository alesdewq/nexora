namespace Nexora.SecurityAudit;

public static class AccountsAnalyzer
{
    public const int MaxExpectedAdmins = 2;
    public const int StaleAccountDays = 180;
    private const string SrcAccounts = @"WMI root\cimv2: Win32_UserAccount (LocalAccount=TRUE)";
    private const string SrcGroups = "Win32 NetLocalGroupGetMembers (группы по SID, не по локализованному имени)";

    public static IReadOnlyList<CheckResult> Analyze(SecuritySnapshot s, DateTimeOffset now)
    {
        var r = new List<CheckResult>();
        if (!s.Accounts.TryGetValue(out var accounts))
        {
            r.Add(CheckResult.Unavailable("users.accounts", "Локальные учётные записи", Section.Users, s.Accounts.Source, s.Accounts.Reason!));
        }
        else
        {
            r.Add(Summary(accounts));
            r.Add(Guest(accounts));
            r.Add(BuiltInAdmin(accounts));
            r.Add(Passwordless(accounts));
            r.Add(Stale(accounts, now));
        }
        r.AddRange(Admins(s));
        return r;
    }

    private static CheckResult Summary(IReadOnlyList<LocalAccount> accounts)
    {
        var people = accounts.Where(a => !a.IsSystemManaged).ToList();
        var enabled = people.Count(a => a.Enabled);
        return CheckResult.Ok("users.accounts", "Локальные учётные записи", Section.Users,
            $"Локальных учётных записей: {accounts.Count} (включено {enabled}, отключено {people.Count - enabled}, служебных Windows: {accounts.Count - people.Count}). " +
            "Число учётных записей не равно числу людей: один человек может иметь несколько записей, часть записей создаётся программами.",
            new Evidence(SrcAccounts, string.Join(", ", accounts.Select(a => $"{a.Name} ({(a.Enabled ? "вкл" : "откл")})"))));
    }

    private static CheckResult Guest(IReadOnlyList<LocalAccount> accounts)
    {
        const string id = "users.guest", title = "Учётная запись «Гость»";
        var guest = accounts.FirstOrDefault(a => a.IsGuest);
        var ev = new Evidence(SrcAccounts, guest is null ? "RID 501 не найден" : $"{guest.Name}: Enabled={guest.Enabled}");
        return guest is { Enabled: true }
            ? CheckResult.Finding(id, title, Section.Users, Severity.High, FindingKind.PotentialRisk, Confidence.High,
                $"Встроенная учётная запись «{guest.Name}» включена.",
                "Гостевой вход позволяет пользоваться компьютером и общими папками без пароля.",
                "Отключите учётную запись «Гость», если она не нужна намеренно.", ev)
            : CheckResult.Ok(id, title, Section.Users, "Учётная запись «Гость» отключена.", ev);
    }

    private static CheckResult BuiltInAdmin(IReadOnlyList<LocalAccount> accounts)
    {
        const string id = "users.builtin-admin", title = "Встроенная учётная запись администратора";
        var admin = accounts.FirstOrDefault(a => a.IsBuiltInAdministrator);
        var ev = new Evidence(SrcAccounts, admin is null ? "RID 500 не найден" : $"{admin.Name}: Enabled={admin.Enabled}");
        return admin is { Enabled: true }
            ? CheckResult.Finding(id, title, Section.Users, Severity.Medium, FindingKind.PotentialRisk, Confidence.High,
                $"Встроенная учётная запись «{admin.Name}» включена.",
                "Её имя известно заранее, и для неё по умолчанию не действует запрос UAC — это частая цель подбора пароля.",
                "Если она не используется для обслуживания, отключите её; для администрирования используйте именную учётную запись.", ev)
            : CheckResult.Ok(id, title, Section.Users, "Встроенная учётная запись администратора отключена (так и должно быть по умолчанию).", ev);
    }

    private static CheckResult Passwordless(IReadOnlyList<LocalAccount> accounts)
    {
        const string id = "users.no-password-required", title = "Учётные записи без обязательного пароля";
        var list = accounts.Where(a => a.Enabled && !a.PasswordRequired && !a.IsSystemManaged).ToList();
        var ev = new Evidence(SrcAccounts, list.Count == 0 ? "нет" : string.Join(", ", list.Select(a => a.Name)));
        return list.Count == 0
            ? CheckResult.Ok(id, title, Section.Users, "У всех включённых учётных записей пароль обязателен.", ev, Confidence.Medium)
            : CheckResult.Finding(id, title, Section.Users, Severity.Medium, FindingKind.PotentialRisk, Confidence.Low,
                $"Для учётных записей не требуется пароль: {string.Join(", ", list.Select(a => a.Name))}.",
                "Учётная запись без пароля позволяет войти любому, кто имеет физический доступ к компьютеру.",
                "Проверьте, установлен ли у этих записей пароль, и при необходимости задайте его.", ev)
                with { Limitations = ["Флаг PasswordRequired показывает политику, а не факт наличия пароля; у учётных записей Microsoft он может быть неточен."] };
    }

    private static CheckResult Stale(IReadOnlyList<LocalAccount> accounts, DateTimeOffset now)
    {
        const string id = "users.stale", title = "Давно не используемые учётные записи";
        var known = accounts.Where(a => a.Enabled && !a.IsSystemManaged && a.LastLogon is not null).ToList();
        var stale = known.Where(a => (now - a.LastLogon!.Value).TotalDays > StaleAccountDays).ToList();
        var ev = new Evidence("WMI Win32_NetworkLoginProfile.LastLogon", string.Join(", ", known.Select(a => $"{a.Name}: {a.LastLogon:dd.MM.yyyy}")));
        var limits = new[] { "Время последнего входа известно не для всех учётных записей (например, для никогда не входивших)." };
        if (known.Count == 0)
            return CheckResult.Unavailable(id, title, Section.Users, ev.Source, "время последнего входа не получено") with { Limitations = limits };
        return stale.Count == 0
            ? CheckResult.Ok(id, title, Section.Users, "Все включённые учётные записи с известным временем входа использовались в последние полгода.", ev, Confidence.Medium) with { Limitations = limits }
            : CheckResult.Finding(id, title, Section.Users, Severity.Info, FindingKind.Recommendation, Confidence.Medium,
                $"Включённые учётные записи без входа более {StaleAccountDays} дней: {string.Join(", ", stale.Select(a => a.Name))}.",
                "Неиспользуемые учётные записи с паролями — лишняя точка входа.",
                "Отключите учётные записи, которые больше не нужны (удалять не обязательно).", ev) with { Limitations = limits };
    }

    private static IEnumerable<CheckResult> Admins(SecuritySnapshot s)
    {
        const string id = "users.admins", title = "Состав группы «Администраторы»";
        if (!s.Groups.TryGetValue(out var groups))
        {
            yield return CheckResult.Unavailable(id, title, Section.Users, s.Groups.Source, s.Groups.Reason!);
            yield break;
        }
        var admins = groups.FirstOrDefault(g => g.Sid == GroupInfo.AdministratorsSid);
        if (admins is null)
        {
            yield return CheckResult.Unavailable(id, title, Section.Users, SrcGroups, "группа S-1-5-32-544 не найдена");
            yield break;
        }

        var accounts = s.Accounts.IsAvailable ? s.Accounts.Value : [];
        bool EnabledLocal(GroupMember m) => accounts.FirstOrDefault(a => a.Sid == m.Sid) is not { Enabled: false };
        var activeUsers = admins.Members.Where(m => m.Kind == MemberKind.User && EnabledLocal(m)).ToList();
        var ev = new Evidence(SrcGroups, string.Join(", ", admins.Members.Select(m => $"{m.Name} [{m.Kind}]")));
        var what = $"В группе «{admins.Name}»: {admins.Members.Count} членов, из них активных пользователей: {activeUsers.Count} ({string.Join(", ", activeUsers.Select(m => m.Name))}).";

        yield return activeUsers.Count > MaxExpectedAdmins
            ? CheckResult.Finding(id, title, Section.Users, Severity.Medium, FindingKind.Heuristic, Confidence.Medium, what,
                "Каждая административная учётная запись может изменить систему и отключить защиту; чем их больше, тем выше риск.",
                "Проверьте, всем ли этим людям/программам действительно нужны права администратора.", ev)
            : CheckResult.Ok(id, title, Section.Users, what, ev);

        if (admins.Members.Any(m => m.Kind == MemberKind.Deleted))
            yield return CheckResult.Finding("users.admins.orphaned", "Удалённые учётные записи в «Администраторах»", Section.Users, Severity.Info,
                FindingKind.Fact, Confidence.High, "В группе администраторов остались записи удалённых учётных записей (неразрешимые SID).",
                "Это не опасно само по себе, но мешает понять, кто имеет права.", "Удалите неразрешимые SID из группы через «Управление компьютером».", ev);

        if (s.CurrentUserSid.TryGetValue(out var me))
        {
            var isAdmin = admins.Members.Any(m => m.Sid == me);
            yield return isAdmin
                ? CheckResult.Finding("users.current-admin", "Повседневная работа с правами администратора", Section.Users, Severity.Info,
                    FindingKind.Recommendation, Confidence.High, "Текущий пользователь входит в группу администраторов.",
                    "Вредоносная программа, запущенная от такого пользователя, после подтверждения UAC получает полный контроль над системой.",
                    "Для повседневной работы удобнее и безопаснее обычная учётная запись, а администраторская — только для установки и настройки.",
                    new Evidence("WindowsIdentity.User", "SID текущего пользователя найден в S-1-5-32-544"))
                : CheckResult.Ok("users.current-admin", "Повседневная работа с правами администратора", Section.Users,
                    "Текущий пользователь работает без прав администратора.", new Evidence("WindowsIdentity.User", "SID не входит в S-1-5-32-544"));
        }

        var rdu = groups.FirstOrDefault(g => g.Sid == GroupInfo.RemoteDesktopUsersSid);
        if (rdu is { Members.Count: > 0 })
            yield return CheckResult.Finding("users.rdp-group", "Пользователи удалённого рабочего стола", Section.Users, Severity.Info, FindingKind.Fact, Confidence.High,
                $"В группе «{rdu.Name}»: {string.Join(", ", rdu.Members.Select(m => m.Name))}.",
                "Эти учётные записи могут входить по RDP, если удалённый рабочий стол включён.",
                "Оставьте в группе только тех, кому нужен удалённый доступ.", new Evidence(SrcGroups, string.Join(", ", rdu.Members.Select(m => m.Sid))));
    }
}
