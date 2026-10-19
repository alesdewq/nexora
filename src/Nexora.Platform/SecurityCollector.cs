using System.Security.Principal;
using Microsoft.Win32;
using Nexora.SecurityAudit;
using Nexora.SecurityAudit.Malware;

namespace Nexora.Platform;

/// <summary>Сбор данных для аудита безопасности. Только чтение: никакие настройки не меняются, методы WMI не вызываются.</summary>
public static class SecurityCollector
{
    public static SecuritySnapshot Collect(string? editionId, bool? isPortable, bool? partOfDomain) => new()
    {
        Accounts = Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_UserAccount"), Accounts),
        Groups = Probe.List("Win32 NetLocalGroupGetMembers", () => new[] { GroupInfo.AdministratorsSid, GroupInfo.RemoteDesktopUsersSid, GroupInfo.RemoteManagementUsersSid }
            .Select(sid => { try { return NetApi.Group(sid); } catch (IdentityNotMappedException) { return null; } })
            .OfType<GroupInfo>()),
        CurrentUserSid = Probe.Try("WindowsIdentity.GetCurrent()", () => { using var id = WindowsIdentity.GetCurrent(); return id.User?.Value; }),
        Defender = Probe.Try(Wmi.Source(Wmi.Defender, "MSFT_MpComputerStatus"), Defender),
        AntivirusProducts = Probe.List(Wmi.Source(Wmi.SecurityCenter2, "AntiVirusProduct"), () => Products("AntiVirusProduct")),
        FirewallProducts = Probe.List(Wmi.Source(Wmi.SecurityCenter2, "FirewallProduct"), () => Products("FirewallProduct")),
        Threats = Probe.List(Wmi.Source(Wmi.Defender, "MSFT_MpThreatDetection"), Threats),
        Exclusions = Probe.Try(Wmi.Source(Wmi.Defender, "MSFT_MpPreference"), Exclusions),
        Firewall = Probe.List(@"Реестр FirewallPolicy (+ политики WindowsFirewall)", Firewall),
        Uac = Probe.Try(Reg.Source(RegistryHive.LocalMachine, PoliciesSystem), Uac),
        BitLocker = BitLocker(),
        Rdp = Probe.Try(Reg.Source(RegistryHive.LocalMachine, TerminalServer), Rdp),
        Smb1Enabled = Smb1(),
        Shares = Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_Share"), Shares),
        WinRm = Probe.Try(Wmi.Source(Wmi.Cimv2, "Win32_Service (WinRM)"), () =>
            Wmi.First(Wmi.Cimv2, "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'WinRM'") is { } o
                ? new ServiceState("WinRM", o.Str("State") ?? "?", o.Str("StartMode") ?? "?") : null, "служба WinRM не установлена"),
        Autoruns = Probe.List("Ключи Run/RunOnce, папки «Автозагрузка», планировщик заданий, службы", AutorunCollector.Collect),
        Winlogon = Probe.Try(Reg.Source(RegistryHive.LocalMachine, WinlogonKey), () => new WinlogonSettings(
            Reg.Str(RegistryHive.LocalMachine, WinlogonKey, "Shell"), Reg.Str(RegistryHive.LocalMachine, WinlogonKey, "Userinit"))),
        EditionId = editionId,
        IsPortable = isPortable,
        PartOfDomain = partOfDomain,
    };

    private const string PoliciesSystem = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string TerminalServer = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static IEnumerable<LocalAccount> Accounts()
    {
        var lastLogon = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var p in Wmi.Query(Wmi.Cimv2, "SELECT Name, LastLogon FROM Win32_NetworkLoginProfile"))
                if (p.Str("Name") is { } n && p.Date("LastLogon") is { } d) lastLogon[n[(n.LastIndexOf('\\') + 1)..]] = d;
        }
        catch (Exception ex) when (ex is System.Management.ManagementException or UnauthorizedAccessException) { /* время входа — необязательное поле */ }

        return Wmi.Query(Wmi.Cimv2, "SELECT Name, SID, Disabled, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount = TRUE")
            .Select(a => new LocalAccount(a.Str("Name") ?? "?", a.Str("SID") ?? "", !(a.Get<bool?>("Disabled") ?? false), a.Get<bool?>("PasswordRequired") ?? true,
                lastLogon.TryGetValue(a.Str("Name") ?? "", out var d) ? d : null));
    }

    private static DefenderStatus? Defender()
    {
        var o = Wmi.First(Wmi.Defender, "SELECT * FROM MSFT_MpComputerStatus");
        if (o is null) return null;
        var age = o.Get<uint?>("AntivirusSignatureAge");
        return new DefenderStatus(o.Get<bool?>("AMServiceEnabled") ?? false, o.Get<bool?>("AntivirusEnabled") ?? false,
            o.Get<bool?>("RealTimeProtectionEnabled") ?? false,
            age is null or 65535 ? null : (int)age.Value, o.Date("AntivirusSignatureLastUpdated"), o.Get<bool?>("IsTamperProtected"),
            o.Str("AMRunningMode"), o.Get<uint?>("QuickScanAge") is { } q and < 65535 ? (int)q : null, o.Str("AMProductVersion"));
    }

    private static IEnumerable<SecurityProduct> Products(string cls) =>
        Wmi.Query(Wmi.SecurityCenter2, $"SELECT displayName, productState FROM {cls}")
            .Select(p =>
            {
                var state = p.Get<uint?>("productState") ?? 0;
                // productState: байт 2 — состояние (0x10/0x11 — включён), байт 1 — базы (0x00 — актуальны, 0x10 — устарели).
                var enabled = ((state >> 8) & 0xF0) == 0x10;
                bool? upToDate = cls == "AntiVirusProduct" ? (state & 0xF0) == 0 : null;
                return new SecurityProduct(p.Str("displayName") ?? "?", enabled, upToDate);
            });

    private static IEnumerable<ThreatDetection> Threats()
    {
        var names = new Dictionary<long, (string Name, int? Severity)>();
        foreach (var t in Wmi.Query(Wmi.Defender, "SELECT ThreatID, ThreatName, SeverityID FROM MSFT_MpThreat"))
            names[t.Get<long?>("ThreatID") ?? -1] = (t.Str("ThreatName") ?? "?", t.Get<int?>("SeverityID"));
        foreach (var d in Wmi.Query(Wmi.Defender, "SELECT ThreatID, Resources, InitialDetectionTime, LastThreatStatusChangeTime, ThreatStatusID FROM MSFT_MpThreatDetection"))
        {
            var id = d.Get<long?>("ThreatID") ?? -1;
            var (state, text) = MalwareAssessment.Status(d.Get<int?>("ThreatStatusID"));
            var (name, sev) = names.TryGetValue(id, out var n) ? n : ($"угроза {id}", null);
            yield return new ThreatDetection(name, sev, d["Resources"] as string[] ?? [], d.Date("InitialDetectionTime"), d.Date("LastThreatStatusChangeTime"), text, state);
        }
    }

    private static DefenderExclusions? Exclusions()
    {
        var o = Wmi.First(Wmi.Defender, "SELECT ExclusionPath, ExclusionExtension, ExclusionProcess FROM MSFT_MpPreference");
        if (o is null) return null;
        string[] Arr(string p) => o[p] as string[] ?? [];
        var all = Arr("ExclusionPath").Concat(Arr("ExclusionExtension")).Concat(Arr("ExclusionProcess"));
        // Без прав администратора Defender вместо списка возвращает «N/A: Must be an administrator to view exclusions».
        if (all.Any(x => x.StartsWith("N/A", StringComparison.OrdinalIgnoreCase))) throw new UnauthorizedAccessException();
        return new DefenderExclusions(Arr("ExclusionPath"), Arr("ExclusionExtension"), Arr("ExclusionProcess"));
    }

    private static IEnumerable<FirewallProfileState> Firewall()
    {
        const string local = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        const string policy = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        foreach (var (profile, localKey, policyKey) in new[]
                 {
                     (FirewallProfile.Domain, "DomainProfile", "DomainProfile"),
                     (FirewallProfile.Private, "StandardProfile", "PrivateProfile"),
                     (FirewallProfile.Public, "PublicProfile", "PublicProfile"),
                 })
        {
            var byPolicy = Reg.Dword(RegistryHive.LocalMachine, $@"{policy}\{policyKey}", "EnableFirewall");
            var value = byPolicy ?? Reg.Dword(RegistryHive.LocalMachine, $@"{local}\{localKey}", "EnableFirewall")
                ?? throw new InvalidOperationException($"нет значения EnableFirewall для {localKey}");
            yield return new FirewallProfileState(profile, value != 0, byPolicy is not null);
        }
    }

    private static UacSettings Uac() => new(
        (Reg.Dword(RegistryHive.LocalMachine, PoliciesSystem, "EnableLUA") ?? 1) != 0,
        Reg.Dword(RegistryHive.LocalMachine, PoliciesSystem, "ConsentPromptBehaviorAdmin"),
        Reg.Dword(RegistryHive.LocalMachine, PoliciesSystem, "PromptOnSecureDesktop") is { } p ? p != 0 : null);

    private static RdpSettings Rdp()
    {
        var deny = Reg.Dword(RegistryHive.LocalMachine, TerminalServer, "fDenyTSConnections") ?? 1;
        var policyDeny = Reg.Dword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections");
        var nla = Reg.Dword(RegistryHive.LocalMachine, $@"{TerminalServer}\WinStations\RDP-Tcp", "UserAuthentication");
        var port = Reg.Dword(RegistryHive.LocalMachine, $@"{TerminalServer}\WinStations\RDP-Tcp", "PortNumber");
        return new RdpSettings((policyDeny ?? deny) == 0, nla is null ? null : nla != 0, port);
    }

    private static Measured<bool> Smb1()
    {
        var feature = Probe.TryValue(Wmi.Source(Wmi.Cimv2, "Win32_OptionalFeature (SMB1Protocol)"), () =>
            Wmi.First(Wmi.Cimv2, "SELECT InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol'") is { } o
                ? o.Get<uint?>("InstallState") == 1 : (bool?)null, "компонент SMB1Protocol отсутствует");
        if (feature.IsAvailable) return feature;
        // Запасной источник: драйвер клиента SMB1 (Start=4 — отключён).
        return Probe.TryValue<bool>(Reg.Source(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"), () =>
            Reg.Dword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") is { } start ? start != 4 : false);
    }

    private static IEnumerable<ShareInfo> Shares() =>
        Wmi.Query(Wmi.Cimv2, "SELECT Name, Path, Type FROM Win32_Share")
            .Select(s => new ShareInfo(s.Str("Name") ?? "?", s.Str("Path") ?? "",
                ((s.Get<uint?>("Type") ?? 0) & 0x80000000) != 0 || (s.Str("Name") ?? "").EndsWith('$')));

    private static Measured<IReadOnlyList<VolumeProtection>> BitLocker()
    {
        var sys = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');
        var wmi = Probe.List(Wmi.Source(Wmi.BitLocker, "Win32_EncryptableVolume"), () =>
            Wmi.Query(Wmi.BitLocker, "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume")
                .Where(v => v.Str("DriveLetter") is not null)
                .Select(v => new VolumeProtection(v.Str("DriveLetter")!, v.Get<uint?>("ProtectionStatus") switch
                {
                    1 => ProtectionState.On, 0 => ProtectionState.Off, _ => ProtectionState.Unknown,
                }, string.Equals(v.Str("DriveLetter"), sys, StringComparison.OrdinalIgnoreCase))));
        if (wmi.IsAvailable) return wmi;

        // Без прав администратора: свойство оболочки System.Volume.BitLockerProtection (то же, что показывает Проводник).
        return Probe.List("Оболочка Windows: свойство System.Volume.BitLockerProtection", () => Sta.Run(() =>
        {
            var list = new List<VolumeProtection>();
            var shellType = Type.GetTypeFromProgID("Shell.Application") ?? throw new InvalidOperationException("Shell.Application недоступен");
            dynamic shell = Activator.CreateInstance(shellType)!;
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
            {
                var letter = drive.Name.TrimEnd('\\');
                object? value = shell.NameSpace(17).ParseName(drive.Name).ExtendedProperty("System.Volume.BitLockerProtection");
                var state = value switch
                {
                    1 or 6 or 7 => ProtectionState.On,
                    2 or 0 => ProtectionState.Off,
                    3 => ProtectionState.Encrypting,
                    4 => ProtectionState.Decrypting,
                    5 => ProtectionState.Suspended,
                    _ => ProtectionState.Unknown,
                };
                list.Add(new VolumeProtection(letter, state, string.Equals(letter, sys, StringComparison.OrdinalIgnoreCase)));
            }
            return list;
        }));
    }
}
