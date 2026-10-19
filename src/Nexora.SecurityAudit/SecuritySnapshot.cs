namespace Nexora.SecurityAudit;

public sealed record SecuritySnapshot
{
    public required Measured<IReadOnlyList<LocalAccount>> Accounts { get; init; }
    public required Measured<IReadOnlyList<GroupInfo>> Groups { get; init; }
    public required Measured<string> CurrentUserSid { get; init; }
    public required Measured<DefenderStatus> Defender { get; init; }
    public required Measured<IReadOnlyList<SecurityProduct>> AntivirusProducts { get; init; }
    public required Measured<IReadOnlyList<SecurityProduct>> FirewallProducts { get; init; }
    public required Measured<IReadOnlyList<ThreatDetection>> Threats { get; init; }
    public required Measured<DefenderExclusions> Exclusions { get; init; }
    public required Measured<IReadOnlyList<FirewallProfileState>> Firewall { get; init; }
    public required Measured<UacSettings> Uac { get; init; }
    public required Measured<IReadOnlyList<VolumeProtection>> BitLocker { get; init; }
    public required Measured<RdpSettings> Rdp { get; init; }
    public required Measured<bool> Smb1Enabled { get; init; }
    public required Measured<IReadOnlyList<ShareInfo>> Shares { get; init; }
    public required Measured<ServiceState> WinRm { get; init; }
    public required Measured<IReadOnlyList<AutorunEntry>> Autoruns { get; init; }
    public required Measured<WinlogonSettings> Winlogon { get; init; }
    /// <summary>Контекст для трактовки: редакция Windows, ноутбук или нет, входит ли в домен.</summary>
    public string? EditionId { get; init; }
    public bool? IsPortable { get; init; }
    public bool? PartOfDomain { get; init; }
}

public sealed record LocalAccount(string Name, string Sid, bool Enabled, bool PasswordRequired, DateTimeOffset? LastLogon)
{
    public int Rid => int.TryParse(Sid[(Sid.LastIndexOf('-') + 1)..], out var r) ? r : -1;
    public bool IsBuiltInAdministrator => Rid == 500;
    public bool IsGuest => Rid == 501;
    /// <summary>Служебные учётные записи Windows (DefaultAccount, WDAGUtilityAccount) — не люди.</summary>
    public bool IsSystemManaged => Rid is 503 or 504;
}

public enum MemberKind { User, Group, WellKnown, Deleted, Unknown }

public sealed record GroupMember(string Name, string Sid, MemberKind Kind);

public sealed record GroupInfo(string Name, string Sid, IReadOnlyList<GroupMember> Members)
{
    public const string AdministratorsSid = "S-1-5-32-544";
    public const string RemoteDesktopUsersSid = "S-1-5-32-555";
    public const string RemoteManagementUsersSid = "S-1-5-32-580";
}

public sealed record DefenderStatus(bool ServiceEnabled, bool AntivirusEnabled, bool RealTimeProtectionEnabled, int? SignatureAgeDays,
    DateTimeOffset? SignatureLastUpdated, bool? TamperProtected, string? RunningMode, int? QuickScanAgeDays, string? ProductVersion);

public sealed record SecurityProduct(string Name, bool Enabled, bool? UpToDate)
{
    public bool IsMicrosoftDefender => Name.Contains("Defender", StringComparison.OrdinalIgnoreCase) || Name.Contains("Windows Firewall", StringComparison.OrdinalIgnoreCase)
        || Name.Contains("Брандмауэр Windows", StringComparison.OrdinalIgnoreCase);
}

public enum ThreatState { Active, Resolved, Allowed, Unknown }

public sealed record ThreatDetection(string Name, int? SeverityId, IReadOnlyList<string> Resources, DateTimeOffset? Detected,
    DateTimeOffset? StatusChanged, string StatusText, ThreatState State);

public sealed record DefenderExclusions(IReadOnlyList<string> Paths, IReadOnlyList<string> Extensions, IReadOnlyList<string> Processes)
{
    public bool IsEmpty => Paths.Count + Extensions.Count + Processes.Count == 0;
}

public enum FirewallProfile { Domain, Private, Public }

public sealed record FirewallProfileState(FirewallProfile Profile, bool Enabled, bool SetByPolicy);

/// <param name="EnableLua">UAC включён.</param>
/// <param name="ConsentPromptBehaviorAdmin">0 — повышать без запроса, 5 — по умолчанию (запрос для не-Windows программ).</param>
public sealed record UacSettings(bool EnableLua, int? ConsentPromptBehaviorAdmin, bool? PromptOnSecureDesktop);

public enum ProtectionState { On, Off, Encrypting, Decrypting, Suspended, Unknown }

public sealed record VolumeProtection(string Drive, ProtectionState State, bool IsSystem);

public sealed record RdpSettings(bool Enabled, bool? NetworkLevelAuthentication, int? Port);

public sealed record ShareInfo(string Name, string Path, bool IsDefaultAdminShare);

public sealed record ServiceState(string Name, string State, string StartMode);

public sealed record WinlogonSettings(string? Shell, string? Userinit);

public enum AutorunLocation { RunKey, RunOnceKey, StartupFolder, ScheduledTask, Service }

public enum SignatureState { Valid, NotSigned, Invalid, NotChecked }

/// <param name="Command">Команда запуска как она записана в системе (после подстановки переменных окружения).</param>
/// <param name="ImagePath">Исполняемый файл, извлечённый из команды (если удалось).</param>
public sealed record AutorunEntry(AutorunLocation Location, string Where, string Name, string Command, string? ImagePath,
    bool? FileExists, SignatureState Signature, string? Publisher, bool Enabled, bool MachineWide);
