using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nexora.Cleanup;
using Nexora.Diagnostics.Inventory;
using Nexora.Diagnostics.Performance;
using Nexora.NetworkAudit;
using Nexora.Reporting;
using Nexora.SecurityAudit;
using Nexora.SecurityAudit.Malware;

namespace Nexora.Platform;

public sealed record ScanOptions(TimeSpan PerformanceDuration)
{
    public bool Inventory { get; init; } = true;
    public bool IncludeDrivers { get; init; } = true;
    public bool Performance { get; init; } = true;
    public bool Security { get; init; } = true;
    public bool Network { get; init; } = true;
    public bool Cleanup { get; init; } = true;
}

public sealed record ScanProgress(string Stage, double Fraction);

public sealed class ScanResult
{
    public InventorySnapshot? Inventory { get; init; }
    public PerformanceSession? Performance { get; init; }
    public SecuritySnapshot? Security { get; init; }
    public NetworkSnapshot? Network { get; init; }
    public CleanupPreview? Cleanup { get; init; }
    public required IReadOnlyList<CheckResult> Results { get; init; }
    public required ReportDocument Document { get; init; }
}

/// <summary>Полная проверка: сбор (только чтение) → анализ → отчёт. Модули изолированы: ошибка одного не останавливает остальные.</summary>
public static class Scanner
{
    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static async Task<ScanResult> RunAsync(ScanOptions o, IProgress<ScanProgress>? progress = null, ResolutionStore? resolutions = null,
        CancellationToken ct = default)
    {
        var started = DateTimeOffset.Now;
        var results = new List<CheckResult>();
        var executed = new List<string>();
        var skipped = new List<SkippedModule>();
        var data = new JsonObject();
        InventorySnapshot? inv = null; PerformanceSession? perf = null; SecuritySnapshot? sec = null; NetworkSnapshot? net = null; CleanupPreview? clean = null;

        void Report(string stage, double f) => progress?.Report(new ScanProgress(stage, f));
        void Fail(string module, Exception ex)
        {
            skipped.Add(new SkippedModule(module, Probe.Describe(ex)));
            results.Add(CheckResult.Failed($"module.{module.ToLowerInvariant()}", $"Модуль «{module}»", Section.Overview, "NEXORA", Probe.Describe(ex)));
        }

        // Производительность измеряется первой, пока остальные модули не создают собственную нагрузку.
        if (o.Performance)
        {
            try
            {
                var p = new Progress<double>(f => Report($"Наблюдение за нагрузкой ({(int)o.PerformanceDuration.TotalSeconds} с)", 0.05 + f * 0.5));
                perf = await PerformanceSampler.RunAsync(o.PerformanceDuration, TimeSpan.FromSeconds(1), p, ct).ConfigureAwait(false);
                results.AddRange(PerformanceAnalyzer.Analyze(perf));
                data["performance"] = Node(perf with { Samples = perf.Samples });
                executed.Add($"Производительность ({(int)perf.Duration.TotalSeconds} с)");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Fail("Производительность", ex); }
        }
        else skipped.Add(new SkippedModule("Производительность", "отключено пользователем"));

        await Task.Run(() =>
        {
            if (o.Inventory)
            {
                Report("Сведения о системе", 0.6);
                try
                {
                    inv = InventoryCollector.Collect(o.IncludeDrivers);
                    results.AddRange(InventoryAnalyzer.Analyze(inv, DateTimeOffset.Now));
                    data["inventory"] = Node(inv);
                    executed.Add("Инвентаризация");
                }
                catch (Exception ex) { Fail("Инвентаризация", ex); }
            }
            else skipped.Add(new SkippedModule("Инвентаризация", "отключено пользователем"));
            ct.ThrowIfCancellationRequested();

            if (o.Security)
            {
                Report("Пользователи и безопасность", 0.7);
                try
                {
                    sec = SecurityCollector.Collect(inv?.Os.EditionId.IsAvailable == true ? inv.Os.EditionId.Value : null,
                        inv?.Computer.IsPortable.IsAvailable == true ? inv.Computer.IsPortable.Value : null,
                        inv?.Computer.PartOfDomain.IsAvailable == true ? inv.Computer.PartOfDomain.Value : null);
                    var now = DateTimeOffset.Now;
                    results.AddRange(AccountsAnalyzer.Analyze(sec, now));
                    results.AddRange(ProtectionAnalyzer.Analyze(sec));
                    results.AddRange(RemoteAccessAnalyzer.Analyze(sec));
                    results.AddRange(AutorunAnalyzer.Analyze(sec));
                    results.AddRange(MalwareAssessment.Analyze(sec, now));
                    data["security"] = Node(sec);
                    executed.Add("Безопасность и пользователи");
                }
                catch (Exception ex) { Fail("Безопасность", ex); }
            }
            else skipped.Add(new SkippedModule("Безопасность", "отключено пользователем"));
            ct.ThrowIfCancellationRequested();

            if (o.Network)
            {
                Report("Локальная сеть", 0.82);
                try
                {
                    net = NetworkCollector.Collect();
                    results.AddRange(NetworkAnalyzer.Analyze(net));
                    // Полный список правил брандмауэра (сотни записей) в отчёт не попадает — только сокеты и активные профили.
                    data["network"] = new JsonObject { ["listeners"] = Node(net.Listeners), ["activeProfiles"] = Node(net.ActiveProfiles) };
                    executed.Add("Сеть");
                }
                catch (Exception ex) { Fail("Сеть", ex); }
            }
            else skipped.Add(new SkippedModule("Сеть", "отключено пользователем"));
            ct.ThrowIfCancellationRequested();

            if (o.Cleanup)
            {
                Report("Файлы (только просмотр)", 0.9);
                try
                {
                    clean = CleanupCollector.Collect(ct);
                    results.AddRange(CleanupAnalyzer.Analyze(clean));
                    data["files"] = Node(clean.Categories.Select(c => new
                    {
                        c.Category, c.Title, c.Root, c.FileCount, c.TotalBytes, c.Unavailable, c.SkippedInaccessible,
                        Largest = c.Items.OrderByDescending(i => i.SizeBytes).Take(30),
                    }));
                    executed.Add("Файлы (просмотр)");
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { Fail("Файлы", ex); }
            }
            else skipped.Add(new SkippedModule("Файлы", "отключено пользователем"));
        }, ct).ConfigureAwait(false);

        Report("Формирование отчёта", 0.98);
        var os = inv?.Os;
        var osSummary = os is null ? "Windows" :
            $"{os.ProductName.Format()} {os.DisplayVersion.Format()} (сборка {os.Build.Format()}{(os.Ubr.IsAvailable ? "." + os.Ubr.Value : "")})";
        var doc = new ReportDocument
        {
            Meta = new ReportMeta(Product.Name, Product.Version, started, DateTimeOffset.Now - started, Environment.MachineName, osSummary,
                IsElevated(), Assessment.From(results).Summary),
            Findings = results.Select(r => ReportedFinding.From(r, resolutions?.Get(r.Id))).ToList(),
            ExecutedModules = executed,
            SkippedModules = skipped,
            Data = data,
        };
        Report("Готово", 1);
        return new ScanResult { Inventory = inv, Performance = perf, Security = sec, Network = net, Cleanup = clean, Results = results, Document = doc };
    }

    private static JsonNode? Node<T>(T value) => JsonSerializer.SerializeToNode(value, ReportDocument.JsonOptions);
}
