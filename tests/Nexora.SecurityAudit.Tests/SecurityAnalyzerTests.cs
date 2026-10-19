using Nexora.SecurityAudit.Malware;
using static Nexora.SecurityAudit.Tests.Fakes;

namespace Nexora.SecurityAudit.Tests;

public class SecurityAnalyzerTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Now;

    private static IReadOnlyList<CheckResult> All(SecuritySnapshot s) =>
        [.. AccountsAnalyzer.Analyze(s, Now), .. ProtectionAnalyzer.Analyze(s), .. RemoteAccessAnalyzer.Analyze(s),
         .. AutorunAnalyzer.Analyze(s), .. MalwareAssessment.Analyze(s, Now)];

    [Fact]
    public void HealthySnapshot_UniqueIds_NoHighFindings()
    {
        var results = All(Snapshot());
        Assert.Equal(results.Count, results.Select(r => r.Id).Distinct().Count());
        Assert.DoesNotContain(results, r => r.Status == CheckStatus.Finding && r.Severity >= Severity.High);
        // Исключения без администратора — «не удалось проверить», а не «нет исключений».
        Assert.Equal(CheckStatus.Unavailable, results.Single(r => r.Id == "sec.av.exclusions").Status);
    }

    [Fact]
    public void GuestEnabled_IsHigh()
    {
        var s = Snapshot() with { Accounts = Of<IReadOnlyList<LocalAccount>>([new("Guest", "S-1-5-21-9-501", true, false, null)]) };
        Assert.Equal(Severity.High, AccountsAnalyzer.Analyze(s, Now).Single(r => r.Id == "users.guest").Severity);
    }

    [Fact]
    public void AdminsCountedBySid_DisabledBuiltinNotCounted()
    {
        var r = AccountsAnalyzer.Analyze(Snapshot(), Now).Single(r => r.Id == "users.admins");
        Assert.Equal(CheckStatus.Ok, r.Status);
        Assert.Contains("включённых локальных пользователей: 1", r.WhatFound);
    }

    [Fact]
    public void ManyAdmins_IsHeuristicNotFact()
    {
        var members = Enumerable.Range(1, 4).Select(i => new GroupMember($"u{i}", $"S-1-5-21-1-2-3-{1000 + i}", MemberKind.User)).ToList();
        var s = Snapshot() with
        {
            Groups = Of<IReadOnlyList<GroupInfo>>([new("Administrators", GroupInfo.AdministratorsSid, members)]),
            Accounts = Of<IReadOnlyList<LocalAccount>>(members.Select(m => new LocalAccount(m.Name, m.Sid, true, true, null)).ToList()),
        };
        var r = AccountsAnalyzer.Analyze(s, Now).Single(r => r.Id == "users.admins");
        Assert.Equal(FindingKind.Heuristic, r.Kind);
        Assert.Equal(Severity.Medium, r.Severity);
    }

    [Fact]
    public void AccountSummary_SaysAccountsAreNotPeople()
    {
        var r = AccountsAnalyzer.Analyze(Snapshot(), Now).Single(r => r.Id == "users.accounts");
        Assert.Contains("не равно числу людей", r.WhatFound);
    }

    [Fact]
    public void RealtimeOff_IsCritical_UnlessThirdPartyAv()
    {
        var off = Snapshot() with { Defender = Of(new DefenderStatus(true, true, false, 0, null, true, "Normal", null, null)) };
        Assert.Equal(Severity.Critical, ProtectionAnalyzer.Antivirus(off).Severity);

        var other = off with { AntivirusProducts = Of<IReadOnlyList<SecurityProduct>>([new("Kaspersky", true, true), new("Windows Defender", false, true)]) };
        Assert.Equal(CheckStatus.Ok, ProtectionAnalyzer.Antivirus(other).Status);
        Assert.Equal(CheckStatus.Unavailable, ProtectionAnalyzer.Tamper(other).Status);
    }

    [Fact]
    public void DefenderUnavailable_NoAvAtAll_IsHighPotentialRisk()
    {
        var s = Snapshot() with { Defender = Na<DefenderStatus>(), AntivirusProducts = Of<IReadOnlyList<SecurityProduct>>([]) };
        var r = ProtectionAnalyzer.Antivirus(s);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Equal(FindingKind.PotentialRisk, r.Kind);
    }

    [Fact]
    public void DefenderAndCenterUnavailable_IsNotChecked()
    {
        var s = Snapshot() with { Defender = Na<DefenderStatus>(), AntivirusProducts = Na<IReadOnlyList<SecurityProduct>>() };
        Assert.Equal(Severity.NotChecked, ProtectionAnalyzer.Antivirus(s).Severity);
    }

    [Theory]
    [InlineData(1, null)]
    [InlineData(5, Severity.Medium)]
    [InlineData(10, Severity.High)]
    public void SignatureAge(int days, Severity? expected)
    {
        var s = Snapshot() with { Defender = Of(new DefenderStatus(true, true, true, days, null, true, "Normal", null, null)) };
        var r = ProtectionAnalyzer.Signatures(s);
        if (expected is null) Assert.Equal(CheckStatus.Ok, r.Status); else Assert.Equal(expected, r.Severity);
    }

    [Theory]
    [InlineData(@"C:\", true)]
    [InlineData("C:", true)]
    [InlineData(@"C:\Users\me\AppData\Local\Temp", true)]
    [InlineData(@"C:\Users\me\Downloads", true)]
    [InlineData(@"D:\Projects\build", false)]
    public void BroadExclusions(string path, bool broad) => Assert.Equal(broad, ProtectionAnalyzer.IsBroadExclusion(path));

    [Fact]
    public void Exclusions_DriveIsHigh_ProjectFolderIsMedium()
    {
        var drive = Snapshot() with { Exclusions = Of(new DefenderExclusions([@"C:\"], [], [])) };
        Assert.Equal(Severity.High, ProtectionAnalyzer.Exclusions(drive).Severity);
        var proj = Snapshot() with { Exclusions = Of(new DefenderExclusions([@"D:\src"], [], [])) };
        Assert.Equal(Severity.Medium, ProtectionAnalyzer.Exclusions(proj).Severity);
        var none = Snapshot() with { Exclusions = Of(new DefenderExclusions([], [], [])) };
        Assert.Equal(CheckStatus.Ok, ProtectionAnalyzer.Exclusions(none).Status);
    }

    [Fact]
    public void FirewallPublicOff_IsHigh_DomainOffOnHomePc_IsInfo()
    {
        var s = Snapshot() with { Firewall = Of<IReadOnlyList<FirewallProfileState>>([new(FirewallProfile.Domain, false, false), new(FirewallProfile.Public, false, false)]) };
        var r = ProtectionAnalyzer.Firewall(s).ToList();
        Assert.Equal(Severity.Info, r.Single(x => x.Id == "sec.firewall.domain").Severity);
        Assert.Equal(Severity.High, r.Single(x => x.Id == "sec.firewall.public").Severity);
    }

    [Fact]
    public void FirewallOff_WithThirdPartyFirewall_IsInfo()
    {
        var s = Snapshot() with
        {
            Firewall = Of<IReadOnlyList<FirewallProfileState>>([new(FirewallProfile.Public, false, false)]),
            FirewallProducts = Of<IReadOnlyList<SecurityProduct>>([new("ESET Firewall", true, null)]),
        };
        Assert.Equal(Severity.Info, ProtectionAnalyzer.Firewall(s).Single().Severity);
    }

    [Fact]
    public void Uac()
    {
        Assert.Equal(Severity.High, ProtectionAnalyzer.Uac(Snapshot() with { Uac = Of(new UacSettings(false, 5, true)) }).Severity);
        Assert.Equal(Severity.Medium, ProtectionAnalyzer.Uac(Snapshot() with { Uac = Of(new UacSettings(true, 0, true)) }).Severity);
        Assert.Equal(CheckStatus.Ok, ProtectionAnalyzer.Uac(Snapshot()).Status);
    }

    [Fact]
    public void BitLockerOff_DependsOnEditionAndChassis()
    {
        var home = ProtectionAnalyzer.BitLocker(Snapshot());
        Assert.Equal(Severity.Info, home.Severity);
        Assert.Contains("Home", home.WhatFound);

        var proLaptop = ProtectionAnalyzer.BitLocker(Snapshot() with { EditionId = "Professional" });
        Assert.Equal(Severity.Medium, proLaptop.Severity);
        var proDesktop = ProtectionAnalyzer.BitLocker(Snapshot() with { EditionId = "Professional", IsPortable = false });
        Assert.Equal(Severity.Info, proDesktop.Severity);
        Assert.Equal(CheckStatus.Unavailable, ProtectionAnalyzer.BitLocker(Snapshot() with { BitLocker = Na<IReadOnlyList<VolumeProtection>>() }).Status);
    }

    [Theory]
    [InlineData("explorer.exe", @"C:\Windows\system32\userinit.exe,", true)]
    [InlineData("explorer.exe", @"D:\WINDOWS\System32\userinit.exe", true)]
    [InlineData("explorer.exe, evil.exe", @"C:\Windows\system32\userinit.exe,", false)]
    [InlineData("explorer.exe", @"C:\Windows\system32\userinit.exe,C:\Users\Public\x.exe", false)]
    public void Winlogon(string shell, string userinit, bool ok)
    {
        var r = ProtectionAnalyzer.Winlogon(Snapshot() with { Winlogon = Of(new WinlogonSettings(shell, userinit)) });
        Assert.Equal(ok ? CheckStatus.Ok : CheckStatus.Finding, r.Status);
        if (!ok) Assert.Equal(FindingKind.Heuristic, r.Kind);
    }

    [Fact]
    public void Rdp_EnabledIsNotAutomaticallyVulnerability()
    {
        var nla = RemoteAccessAnalyzer.Rdp(Snapshot() with { Rdp = Of(new RdpSettings(true, true, 3389)) });
        Assert.Equal(Severity.Info, nla.Severity);
        Assert.Contains(nla.Limitations, l => l.Contains("интернета"));
        var noNla = RemoteAccessAnalyzer.Rdp(Snapshot() with { Rdp = Of(new RdpSettings(true, false, 3389)) });
        Assert.Equal(Severity.High, noNla.Severity);
    }

    [Fact]
    public void Smb1AndShares()
    {
        Assert.Equal(Severity.High, RemoteAccessAnalyzer.Smb1(Snapshot() with { Smb1Enabled = Of(true) }).Severity);
        Assert.Equal(CheckStatus.Ok, RemoteAccessAnalyzer.Shares(Snapshot()).Status);
        var custom = Snapshot() with { Shares = Of<IReadOnlyList<ShareInfo>>([new("Music", @"D:\Music", false)]) };
        Assert.Equal(Severity.Info, RemoteAccessAnalyzer.Shares(custom).Severity);
    }

    [Fact]
    public void ActiveThreat_IsCriticalFact_ResolvedIsInfo()
    {
        var s = Snapshot() with { Threats = Of<IReadOnlyList<ThreatDetection>>([
            new("Trojan:Win32/Test", 5, [@"file:_C:\Users\me\Downloads\x.exe"], Now.AddDays(-1), Now, "обнаружена", ThreatState.Active),
            new("PUA:Win32/Old", 1, [], Now.AddDays(-3), Now, "в карантине", ThreatState.Resolved),
        ]) };
        var r = MalwareAssessment.Analyze(s, Now);
        var active = r.Single(x => x.Id.StartsWith("mal.active.", StringComparison.Ordinal));
        Assert.Equal(Severity.Critical, active.Severity);
        Assert.Equal(FindingKind.Fact, active.Kind);
        Assert.Contains(@"C:\Users\me\Downloads\x.exe", active.WhatFound);
        Assert.Equal(Severity.Info, r.Single(x => x.Id == "mal.recent").Severity);
    }

    [Fact]
    public void NoThreats_DoesNotClaimClean()
    {
        var r = Assert.Single(MalwareAssessment.Analyze(Snapshot(), Now));
        Assert.Equal(CheckStatus.Ok, r.Status);
        Assert.Contains(r.Limitations, l => l.Contains("не доказывает"));
    }

    [Theory]
    [InlineData(1, ThreatState.Active)]
    [InlineData(3, ThreatState.Resolved)]
    [InlineData(5, ThreatState.Allowed)]
    [InlineData(103, ThreatState.Active)]
    [InlineData(null, ThreatState.Unknown)]
    public void ThreatStatusMapping(int? id, ThreatState state) => Assert.Equal(state, MalwareAssessment.Status(id).State);
}

public class AdminsWithoutAccountListTests
{
    [Fact]
    public void AccountsUnavailable_DoesNotInventEnabledAdmins()
    {
        var members = Enumerable.Range(1, 4).Select(i => new GroupMember($"u{i}", $"S-1-5-21-1-2-3-{1000 + i}", MemberKind.User)).ToList();
        var s = Fakes.Snapshot() with
        {
            Accounts = Fakes.Na<IReadOnlyList<LocalAccount>>("отказано в доступе"),
            Groups = Fakes.Of<IReadOnlyList<GroupInfo>>([new("Administrators", GroupInfo.AdministratorsSid, members)]),
        };
        var r = AccountsAnalyzer.Analyze(s, DateTimeOffset.Now).Single(x => x.Id == "users.admins");
        Assert.Equal(CheckStatus.Ok, r.Status);
        Assert.Equal(Confidence.Low, r.Confidence);
        Assert.Contains("неизвестным состоянием: 4", r.WhatFound);
        Assert.NotEmpty(r.Limitations);
    }
}
