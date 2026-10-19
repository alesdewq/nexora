namespace Nexora.SecurityAudit.Tests;

internal static class Fakes
{
    public static Measured<T> Of<T>(T v) => Measured<T>.Of(v, "fake");
    public static Measured<T> Na<T>(string reason = "нет источника") => Measured<T>.Unavailable("fake", reason);

    public const string Me = "S-1-5-21-1-2-3-1001";

    public static SecuritySnapshot Snapshot() => new()
    {
        Accounts = Of<IReadOnlyList<LocalAccount>>([
            new("Администратор", "S-1-5-21-1-2-3-500", false, true, null),
            new("Гость", "S-1-5-21-1-2-3-501", false, false, null),
            new("DefaultAccount", "S-1-5-21-1-2-3-503", false, false, null),
            new("user", Me, true, true, DateTimeOffset.Now),
        ]),
        Groups = Of<IReadOnlyList<GroupInfo>>([
            new("Администраторы", GroupInfo.AdministratorsSid, [new("PC\\Администратор", "S-1-5-21-1-2-3-500", MemberKind.User), new("PC\\user", Me, MemberKind.User)]),
        ]),
        CurrentUserSid = Of(Me),
        Defender = Of(new DefenderStatus(true, true, true, 0, DateTimeOffset.Now, true, "Normal", 1, "4.18")),
        AntivirusProducts = Of<IReadOnlyList<SecurityProduct>>([new("Windows Defender", true, true)]),
        FirewallProducts = Of<IReadOnlyList<SecurityProduct>>([]),
        Threats = Of<IReadOnlyList<ThreatDetection>>([]),
        Exclusions = Na<DefenderExclusions>("отказано в доступе — возможно, нужны права администратора"),
        Firewall = Of<IReadOnlyList<FirewallProfileState>>([new(FirewallProfile.Domain, true, false), new(FirewallProfile.Private, true, false), new(FirewallProfile.Public, true, false)]),
        Uac = Of(new UacSettings(true, 5, true)),
        BitLocker = Of<IReadOnlyList<VolumeProtection>>([new("C:", ProtectionState.Off, true)]),
        Rdp = Of(new RdpSettings(false, true, 3389)),
        Smb1Enabled = Of(false),
        Shares = Of<IReadOnlyList<ShareInfo>>([new("C$", "C:\\", true), new("ADMIN$", "C:\\Windows", true)]),
        WinRm = Of(new ServiceState("WinRM", "Stopped", "Manual")),
        Autoruns = Of<IReadOnlyList<AutorunEntry>>([]),
        Winlogon = Of(new WinlogonSettings("explorer.exe", @"C:\Windows\system32\userinit.exe,")),
        EditionId = "Core",
        IsPortable = true,
        PartOfDomain = false,
    };

    public static AutorunEntry Autorun(string command, SignatureState sig = SignatureState.NotSigned, bool? exists = true,
        AutorunLocation loc = AutorunLocation.RunKey) =>
        new(loc, @"HKCU\Run", "test", command, CommandLine.ImagePath(command), exists, sig, sig == SignatureState.Valid ? "Acme" : null, true, false);
}
