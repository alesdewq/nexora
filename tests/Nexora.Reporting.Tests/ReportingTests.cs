using System.Text.Json.Nodes;

namespace Nexora.Reporting.Tests;

public class ReportingTests
{
    private static readonly Evidence Ev = new("WMI test", "PC-ANNA user anna 192.168.1.20 fe80::1c2d:3e4f:5a6b:7c8d%12 00-1A-2B-3C-4D-5E C:\\Users\\anna\\Desktop");

    private static ReportDocument Doc(params CheckResult[] results) => new()
    {
        Meta = new ReportMeta("NEXORA", "0.9.0", new DateTimeOffset(2026, 10, 19, 12, 0, 0, TimeSpan.Zero), TimeSpan.FromSeconds(95),
            "PC-ANNA", "Windows 10 22H2", false, Assessment.From(results).Summary),
        Findings = results.Select(r => ReportedFinding.From(r)).ToList(),
        ExecutedModules = ["Инвентаризация"],
        SkippedModules = [],
        Data = new JsonObject { ["computer"] = new JsonObject { ["name"] = "PC-ANNA", ["ip"] = "10.0.0.5", ["loop"] = "127.0.0.1" } },
    };

    private static CheckResult F(string id, Severity s) =>
        CheckResult.Finding(id, "Проверка " + id, Section.Security, s, FindingKind.Fact, Confidence.High, "найдено <b>теги</b>", "важно", "сделать", Ev);

    [Fact]
    public void Json_RoundTrip_PreservesFindings()
    {
        var d = Doc(F("a", Severity.High), CheckResult.Unavailable("b", "B", Section.Performance, "src", "нет датчика"));
        var back = ReportDocument.FromJson(d.ToJson());
        Assert.Equal(2, back.Findings.Count);
        Assert.Equal(Severity.High, back.Findings[0].Severity);
        Assert.Equal(CheckStatus.Unavailable, back.Findings[1].Status);
        Assert.Equal("WMI test", back.Findings[0].Evidence[0].Source);
        Assert.Contains("\"High\"", d.ToJson()); // перечисления — строками, читаемо человеком
        Assert.Equal(TimeSpan.FromSeconds(95), back.Meta.Duration);
    }

    [Fact]
    public void Json_NewerSchema_Rejected()
    {
        var json = Doc().ToJson().Replace("\"SchemaVersion\": 1", "\"SchemaVersion\": 99");
        Assert.Throws<NotSupportedException>(() => ReportDocument.FromJson(json));
    }

    [Fact]
    public void Html_EscapesContent_HasNoScripts_AndLabelsSeverityWithText()
    {
        var html = HtmlReport.Render(Doc(F("a", Severity.Critical)));
        Assert.DoesNotContain("<b>теги</b>", html);
        Assert.Contains("&lt;b&gt;теги&lt;/b&gt;", html);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Критический", html);
        Assert.Contains("может содержать имена учётных записей", html);
        Assert.Contains("не означает, что компьютер безопасен", html);
    }

    [Fact]
    public void Html_ShowsUnavailableMeasuredValues()
    {
        var d = Doc() with { Data = new JsonObject { ["temp"] = new JsonObject { ["unavailable"] = "нет датчика", ["source"] = "PDH" } } };
        Assert.Contains("данные недоступны: нет датчика", HtmlReport.Render(d));
    }

    [Fact]
    public void Masking_RemovesIdentifiers_KeepsHarmlessAddresses()
    {
        var o = new MaskOptions("PC-ANNA", ["anna"], @"C:\Users\anna");
        var m = ReportMasker.Mask(Doc(F("a", Severity.Medium)), o);
        var json = m.ToJson();
        Assert.True(m.Masked);
        Assert.DoesNotContain("PC-ANNA", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("anna", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.168.1.20", json);
        Assert.DoesNotContain("10.0.0.5", json);
        Assert.DoesNotContain("fe80::1c2d", json);
        Assert.DoesNotContain("00-1A-2B-3C-4D-5E", json);
        Assert.Contains("127.0.0.1", json);
        Assert.Contains(@"C:\\Users\\<пользователь>\\Desktop", json);
        Assert.Contains("Замаскирован", HtmlReport.Render(m).Replace("замаскирован", "Замаскирован"));
    }

    [Theory]
    [InlineData("время 12:30:45", "время 12:30:45")]
    [InlineData("версия 10.0.19045.6456", "версия 10.0.19045.6456")]
    [InlineData("адрес 8.8.8.8", "адрес <IP>")]
    [InlineData("0.0.0.0:445", "0.0.0.0:445")]
    public void Masking_DoesNotBreakTimesAndVersions(string input, string expected) =>
        Assert.Equal(expected, ReportMasker.MaskText(input, new MaskOptions(null, [], null)));

    [Fact]
    public void Masking_ShortUserNameNotReplacedInsideWords()
    {
        var s = ReportMasker.MaskText("user32.dll запущен пользователем user", new MaskOptions(null, ["user"], null));
        Assert.Equal("user32.dll запущен пользователем <пользователь>", s);
    }

    [Fact]
    public void Compare_NewResolvedChangedAndNotChecked()
    {
        var older = Doc(F("gone", Severity.High), F("same", Severity.Medium), F("worse", Severity.Medium), F("unk", Severity.High));
        var newer = Doc(F("same", Severity.Medium), F("worse", Severity.High), F("new", Severity.Critical),
            CheckResult.Ok("gone", "gone", Section.Security, "ok", Ev),
            CheckResult.Unavailable("unk", "unk", Section.Security, "src", "нет доступа"));
        var c = ReportComparer.Compare(older, newer);
        Assert.Equal("new", Assert.Single(c.New).Id);
        Assert.Equal("gone", Assert.Single(c.Resolved).Id);
        Assert.Equal("worse", Assert.Single(c.Changed).After.Id);
        Assert.Equal("same", Assert.Single(c.Persisting).Id);
        // Проверка, которая не выполнилась, не считается устранённой.
        Assert.Equal("unk", Assert.Single(c.NoLongerChecked).Id);
    }

    [Fact]
    public void Store_SaveListLoad_IgnoresCorruptFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nexora-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new ReportStore(dir);
            var path = store.Save(Doc(F("a", Severity.High)));
            File.WriteAllText(Path.Combine(dir, "report-broken.json"), "{ not json");
            var list = store.List();
            Assert.Single(list);
            Assert.Equal(1, list[0].Issues);
            Assert.Equal("a", ReportStore.Load(path).Findings[0].Id);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Resolutions_PersistAndClear()
    {
        var file = Path.Combine(Path.GetTempPath(), "nexora-res-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            new ResolutionStore(file).Set("sec.smb1", ResolutionStatus.Resolved, "отключил", DateTimeOffset.Now);
            var again = new ResolutionStore(file);
            Assert.Equal(ResolutionStatus.Resolved, again.Get("sec.smb1")!.Status);
            again.Set("sec.smb1", ResolutionStatus.None, null, DateTimeOffset.Now);
            Assert.Null(new ResolutionStore(file).Get("sec.smb1"));
        }
        finally { File.Delete(file); }
    }
}
