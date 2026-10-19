using System.Diagnostics;
using Nexora.Diagnostics.Performance;
using static Nexora.Platform.Native;

namespace Nexora.Platform;

/// <summary>Наблюдение за нагрузкой. Только чтение: процессы не завершаются и не меняют приоритет.</summary>
public static class PerformanceSampler
{
    private const string DiskIdle = @"\PhysicalDisk(_Total)\% Idle Time";
    private const string CpuPerf = @"\Processor Information(_Total)\% Processor Performance";
    private const string ThermalTemp = @"\Thermal Zone Information(*)\Temperature";
    private const string ThermalPassive = @"\Thermal Zone Information(*)\% Passive Limit";

    private sealed class ProcStat
    {
        public required string Name;
        public TimeSpan LastCpu;
        public double SumPercent, MaxPercent;
        public int Count;
        public long WorkingSet, Private;
    }

    public static async Task<PerformanceSession> RunAsync(TimeSpan duration, TimeSpan interval, IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        var started = DateTimeOffset.Now;
        var logical = Environment.ProcessorCount;
        using var pdh = new Pdh();
        var disk = pdh.Add(DiskIdle, out var diskError);
        var perf = pdh.Add(CpuPerf, out var perfError);
        var temp = pdh.Add(ThermalTemp, out var tempError);
        var passive = pdh.Add(ThermalPassive, out _);

        var samples = new List<PerformanceSample>();
        var procs = new Dictionary<int, ProcStat>();
        var inaccessible = new HashSet<int>();
        var thermal = new Dictionary<string, (double Max, double Sum, int N, double? MinPassive)>();

        pdh.Collect();
        var (prevIdle, prevTotal) = SystemTimes();
        ReadProcesses(procs, inaccessible, null);
        var sw = Stopwatch.StartNew();
        var last = sw.Elapsed;

        while (sw.Elapsed < duration)
        {
            await Task.Delay(interval, ct).ConfigureAwait(false);
            var now = sw.Elapsed;
            var dt = now - last;
            last = now;

            pdh.Collect();
            var (idle, total) = SystemTimes();
            var cpu = total > prevTotal ? 100.0 * (1 - (double)(idle - prevIdle) / (total - prevTotal)) : 0;
            (prevIdle, prevTotal) = (idle, total);

            var mem = new MEMORYSTATUSEX { Length = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORYSTATUSEX>() };
            GlobalMemoryStatusEx(ref mem);
            var memUsed = mem.TotalPhys == 0 ? 0 : 100.0 * (mem.TotalPhys - mem.AvailPhys) / mem.TotalPhys;

            double? diskBusy = disk is { } d && Pdh.Value(d) is { } di ? Math.Clamp(100 - di, 0, 100) : null;
            double? cpuPerf = perf is { } p ? Pdh.Value(p) : null;
            if (temp is { } t)
            {
                var passiveValues = passive is { } pv ? Pdh.Values(pv) : [];
                foreach (var (zone, kelvin) in Pdh.Values(t))
                {
                    var c = kelvin - 273.15;
                    thermal.TryGetValue(zone, out var z);
                    double? lim = passiveValues.TryGetValue(zone, out var l) ? Math.Min(l, z.MinPassive ?? 100) : z.MinPassive;
                    thermal[zone] = (z.N == 0 ? c : Math.Max(z.Max, c), z.Sum + c, z.N + 1, lim);
                }
            }

            ReadProcesses(procs, inaccessible, dt.TotalMilliseconds * logical);
            samples.Add(new PerformanceSample(now, Math.Clamp(cpu, 0, 100), memUsed, diskBusy, cpuPerf));
            progress?.Report(Math.Min(1, now / duration));
        }

        var usage = procs.Where(kv => kv.Value.Count > 0)
            .Select(kv => new ProcessUsage(kv.Value.Name, kv.Key, kv.Value.SumPercent / kv.Value.Count, kv.Value.MaxPercent, kv.Value.WorkingSet, kv.Value.Private))
            .ToList();

        return new PerformanceSession
        {
            Started = started,
            Duration = sw.Elapsed,
            Interval = interval,
            LogicalProcessors = logical,
            Samples = samples,
            TopByCpu = usage.OrderByDescending(u => u.AvgCpuPercent).Take(10).ToList(),
            TopByMemory = usage.OrderByDescending(u => u.WorkingSetBytes).Take(10).ToList(),
            InaccessibleProcesses = inaccessible.Count,
            DiskCounterUnavailable = disk is null ? diskError : null,
            CpuPerformanceUnavailable = perf is null ? perfError : null,
            Thermal = temp is null
                ? Measured<IReadOnlyList<ThermalZoneReading>>.Unavailable(@"PDH \Thermal Zone Information", tempError ?? "нет счётчика")
                : thermal.Count == 0
                    ? Measured<IReadOnlyList<ThermalZoneReading>>.Unavailable(@"PDH \Thermal Zone Information", "в системе нет термозон ACPI с данными")
                    : Measured<IReadOnlyList<ThermalZoneReading>>.Of(thermal.Select(kv =>
                        new ThermalZoneReading(ShortZone(kv.Key), kv.Value.Max, kv.Value.Sum / kv.Value.N, kv.Value.MinPassive)).ToList(),
                        @"PDH \Thermal Zone Information(*)"),
            Events = EventLogScanner.Scan(7),
        };
    }

    private static string ShortZone(string instance) => instance.Replace(@"\_TZ.", "", StringComparison.Ordinal).Trim('\\');

    private static (ulong Idle, ulong Total) SystemTimes()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user)) return (0, 0);
        return (idle.Value, kernel.Value + user.Value); // kernel включает idle
    }

    private static void ReadProcesses(Dictionary<int, ProcStat> stats, HashSet<int> inaccessible, double? budgetMs)
    {
        var seen = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id == 0) continue; // System Idle Process
                seen.Add(p.Id);
                try
                {
                    var cpu = p.TotalProcessorTime;
                    if (!stats.TryGetValue(p.Id, out var s))
                    {
                        stats[p.Id] = s = new ProcStat { Name = p.ProcessName, LastCpu = cpu };
                    }
                    else if (budgetMs is > 0)
                    {
                        var pct = Math.Clamp((cpu - s.LastCpu).TotalMilliseconds / budgetMs.Value * 100, 0, 100);
                        s.SumPercent += pct; s.Count++; s.MaxPercent = Math.Max(s.MaxPercent, pct);
                        s.LastCpu = cpu;
                    }
                    s.WorkingSet = p.WorkingSet64;
                    s.Private = p.PrivateMemorySize64;
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or UnauthorizedAccessException)
                {
                    inaccessible.Add(p.Id);
                }
            }
        }
        foreach (var gone in stats.Keys.Where(k => !seen.Contains(k) && stats[k].Count == 0).ToList()) stats.Remove(gone);
    }
}
