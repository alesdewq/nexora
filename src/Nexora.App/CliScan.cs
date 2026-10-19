using System.IO;
using Nexora.Platform;
using Nexora.Reporting;

namespace Nexora.App;

/// <summary>
/// Неинтерактивная проверка: <c>Nexora.exe --scan &lt;папка&gt; [--duration секунды] [--no-drivers] [--mask]</c>.
/// Пишет report.json, report.html и scan.log в указанную папку. Только чтение системы.
/// </summary>
internal static class CliScan
{
    public static async Task<int> RunAsync(string[] args)
    {
        var i = Array.IndexOf(args, "--scan");
        var outDir = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[i + 1] : "nexora-scan";
        var d = Array.IndexOf(args, "--duration");
        var seconds = d >= 0 && d + 1 < args.Length && int.TryParse(args[d + 1], out var s) ? Math.Clamp(s, 3, 600) : 30;
        var log = new List<string>();
        try
        {
            Directory.CreateDirectory(outDir);
            var progress = new Progress<ScanProgress>(p => log.Add($"{DateTime.Now:HH:mm:ss} {p.Fraction:P0} {p.Stage}"));
            var result = await Scanner.RunAsync(new ScanOptions(TimeSpan.FromSeconds(seconds)) { IncludeDrivers = !args.Contains("--no-drivers") }, progress);
            var doc = args.Contains("--mask") ? Masking.For(result).Apply(result.Document) : result.Document;
            await File.WriteAllTextAsync(Path.Combine(outDir, "report.json"), doc.ToJson());
            await File.WriteAllTextAsync(Path.Combine(outDir, "report.html"), HtmlReport.Render(doc));
            log.Add($"OK: {doc.Findings.Count} проверок; {doc.Meta.Summary}");
            return 0;
        }
        catch (Exception ex)
        {
            log.Add($"FAIL: {ex}");
            return 1;
        }
        finally
        {
            await File.WriteAllLinesAsync(Path.Combine(outDir, "scan.log"), log);
        }
    }
}
