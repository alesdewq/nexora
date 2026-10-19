using Nexora.SecurityAudit;
using Nexora.SecurityAudit.Malware;

namespace Nexora.Platform.Tests;

public class SecurityCollectorTests
{
    [Fact]
    public void Collect_DoesNotThrow_AndReadsBasics()
    {
        var s = SecurityCollector.Collect("Core", true, false);

        Assert.True(s.Accounts.IsAvailable, s.Accounts.Reason);
        Assert.True(s.Groups.IsAvailable, s.Groups.Reason);
        Assert.Contains(s.Groups.Value, g => g.Sid == GroupInfo.AdministratorsSid);
        Assert.True(s.Firewall.IsAvailable, s.Firewall.Reason);
        Assert.Equal(3, s.Firewall.Value.Count);
        Assert.True(s.Uac.IsAvailable, s.Uac.Reason);
        Assert.True(s.Autoruns.IsAvailable, s.Autoruns.Reason);

        var now = DateTimeOffset.Now;
        IReadOnlyList<CheckResult> results = [.. AccountsAnalyzer.Analyze(s, now), .. ProtectionAnalyzer.Analyze(s), .. RemoteAccessAnalyzer.Analyze(s),
            .. AutorunAnalyzer.Analyze(s), .. MalwareAssessment.Analyze(s, now)];
        Assert.Equal(results.Count, results.Select(r => r.Id).Distinct().Count());
    }

    [Fact]
    public void Authenticode_SignedSystemBinary_And_UnsignedFile()
    {
        // notepad.exe в Windows 10/11 подписан встроенной подписью или каталогом — допускаем оба исхода, но не ошибку.
        var (state, _) = Authenticode.Check(Path.Combine(Environment.SystemDirectory, "notepad.exe"));
        Assert.NotEqual(SignatureState.NotChecked, state);

        var tmp = Path.Combine(Path.GetTempPath(), $"nexora-unsigned-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(tmp, [0x4D, 0x5A, 0, 0]);
        try { Assert.NotEqual(SignatureState.Valid, Authenticode.Check(tmp).State); }
        finally { File.Delete(tmp); }
    }

    [Fact]
    public void Authenticode_MissingFile_NotChecked() =>
        Assert.Equal(SignatureState.NotChecked, Authenticode.Check(@"C:\definitely\missing\file.exe").State);
}
