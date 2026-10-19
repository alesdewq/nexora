using System.Globalization;

namespace Nexora.Diagnostics.Performance;

public static class PerformanceAnalyzer
{
    public const double HighCpuPercent = 85;
    public const double SustainedShare = 0.7;
    public static readonly TimeSpan MinReliableDuration = TimeSpan.FromSeconds(60);
    public const double MemoryHigh = 90, MemoryMedium = 80;
    public const double DiskBusyPercent = 80;
    public const double HotCelsius = 90, WarmCelsius = 80;
    public const double ThrottledPerformancePercent = 60;

    private const string SrcCpu = "Win32 GetSystemTimes; Process.TotalProcessorTime";
    private const string SrcMem = "Win32 GlobalMemoryStatusEx; Process.WorkingSet64";
    private const string SrcDisk = @"PDH \PhysicalDisk(_Total)\% Idle Time";
    private const string SrcThermal = @"PDH \Thermal Zone Information(*)\Temperature, % Passive Limit";
    private const string SrcPerf = @"PDH \Processor Information(_Total)\% Processor Performance";
    private const string SrcEvents = "Журнал событий «Система» (уровни: критический, ошибка, предупреждение)";

    public static IReadOnlyList<CheckResult> Analyze(PerformanceSession s)
    {
        if (s.Samples.Count < 2)
            return [CheckResult.Failed("perf.sampling", "Наблюдение за нагрузкой", Section.Performance, SrcCpu, "собрано меньше двух замеров")];
        return [Cpu(s), Memory(s), Disk(s), Thermal(s), Throttling(s), .. Events(s.Events)];
    }

    private static Confidence DurationConfidence(PerformanceSession s, Confidence best = Confidence.High) =>
        s.Duration >= MinReliableDuration * 2 ? best : s.Duration >= MinReliableDuration ? Confidence.Medium : Confidence.Low;

    private static string[] DurationLimits(PerformanceSession s) =>
        s.Duration < MinReliableDuration
            ? [$"Наблюдение длилось {Secs(s.Duration)} — этого мало, чтобы отличить кратковременную нагрузку от устойчивой. Повторите проверку на 2–5 минут."]
            : [$"Наблюдение длилось {Secs(s.Duration)}; нагрузка вне этого интервала не учтена."];

    public static CheckResult Cpu(PerformanceSession s)
    {
        const string id = "perf.cpu", title = "Загрузка процессора";
        var avg = s.Samples.Average(x => x.CpuPercent);
        var max = s.Samples.Max(x => x.CpuPercent);
        var share = s.Samples.Count(x => x.CpuPercent >= HighCpuPercent) / (double)s.Samples.Count;
        var top = TopText(s.TopByCpu.Where(p => p.AvgCpuPercent >= 1), p => $"{p.Name} — {p.AvgCpuPercent:0.#} %");
        var ev = new Evidence(SrcCpu, $"среднее {avg:0.#} %, максимум {max:0.#} %, ≥{HighCpuPercent:0} % в {share:P0} замеров; {s.Samples.Count} замеров за {Secs(s.Duration)}" +
                                      (s.InaccessibleProcesses > 0 ? $"; без доступа к {s.InaccessibleProcesses} процессам" : ""));
        var limits = DurationLimits(s).Append("Нагрузка процессов, к которым нет доступа без прав администратора, видна только в общей загрузке.").ToArray();
        var what = $"Средняя загрузка {avg:0} %, максимум {max:0} %." + (top.Length > 0 ? $" Больше всего нагружают: {top}." : "");

        if (share >= SustainedShare)
            return CheckResult.Finding(id, title, Section.Performance, Severity.Medium, FindingKind.Fact, DurationConfidence(s), what,
                "Процессор почти всё время занят — это прямая причина тормозов, а при недостаточном охлаждении и нагрева.",
                "Проверьте процессы из списка: закройте ненужные программы; если нагружает незнакомый процесс — проверьте его происхождение (раздел «Безопасность»).", ev)
                with { Limitations = limits };

        var note = max >= 95 && share < 0.3 ? " Были кратковременные пики — это нормально для открытия программ и обновлений." : "";
        return CheckResult.Ok(id, title, Section.Performance, what + note, ev, DurationConfidence(s)) with { Limitations = limits };
    }

    public static CheckResult Memory(PerformanceSession s)
    {
        const string id = "perf.memory", title = "Использование оперативной памяти";
        var avg = s.Samples.Average(x => x.MemoryUsedPercent);
        var top = TopText(s.TopByMemory, p => $"{p.Name} — {Mb(p.WorkingSetBytes)}");
        var ev = new Evidence(SrcMem, $"занято в среднем {avg:0.#} %, максимум {s.Samples.Max(x => x.MemoryUsedPercent):0.#} %");
        var what = $"Память занята в среднем на {avg:0} %." + (top.Length > 0 ? $" Больше всего используют: {top}." : "");
        var sev = avg >= MemoryHigh ? Severity.High : avg >= MemoryMedium ? Severity.Medium : (Severity?)null;
        return sev is null
            ? CheckResult.Ok(id, title, Section.Performance, what, ev, DurationConfidence(s)) with { Limitations = DurationLimits(s) }
            : CheckResult.Finding(id, title, Section.Performance, sev.Value, FindingKind.Fact, DurationConfidence(s), what,
                "Когда памяти не хватает, Windows использует файл подкачки на диске — всё начинает работать заметно медленнее.",
                "Закройте лишние вкладки и программы; если память занята постоянно при обычной работе — подумайте об увеличении объёма RAM.", ev)
                with { Limitations = DurationLimits(s) };
    }

    public static CheckResult Disk(PerformanceSession s)
    {
        const string id = "perf.disk", title = "Активность диска";
        var values = s.Samples.Where(x => x.DiskBusyPercent is not null).Select(x => x.DiskBusyPercent!.Value).ToList();
        if (s.DiskCounterUnavailable is not null || values.Count == 0)
            return CheckResult.Unavailable(id, title, Section.Performance, SrcDisk, s.DiskCounterUnavailable ?? "счётчик не вернул значений");
        var avg = values.Average();
        var share = values.Count(v => v >= DiskBusyPercent) / (double)values.Count;
        var ev = new Evidence(SrcDisk, $"занят в среднем {avg:0.#} %, ≥{DiskBusyPercent:0} % в {share:P0} замеров");
        var what = $"Диск занят в среднем на {avg:0} % времени.";
        return share >= 0.6
            ? CheckResult.Finding(id, title, Section.Performance, Severity.Medium, FindingKind.Fact, DurationConfidence(s), what,
                "Постоянно занятый диск — частая причина «подвисаний», особенно на механических дисках (HDD).",
                "Проверьте, не идёт ли обновление, индексация или антивирусная проверка; при постоянной нагрузке на HDD заметно поможет замена на SSD.", ev)
                with { Limitations = DurationLimits(s) }
            : CheckResult.Ok(id, title, Section.Performance, what, ev, DurationConfidence(s)) with { Limitations = DurationLimits(s) };
    }

    public static CheckResult Thermal(PerformanceSession s)
    {
        const string id = "perf.thermal", title = "Температура";
        if (!s.Thermal.TryGetValue(out var zones) || zones.Count == 0)
            return CheckResult.Unavailable(id, title, Section.Performance, s.Thermal.Source,
                s.Thermal.Reason ?? "компьютер не предоставляет датчики температуры через штатные интерфейсы Windows");

        var plausible = zones.Where(z => z.MaxCelsius is > 10 and < 125).ToList();
        if (plausible.Count == 0)
            return CheckResult.Unavailable(id, title, Section.Performance, SrcThermal,
                "датчик возвращает недостоверные значения: " + string.Join(", ", zones.Select(z => $"{z.Zone} {z.MaxCelsius:0} °C")));

        var hottest = plausible.MaxBy(z => z.MaxCelsius)!;
        var avgLoad = s.Samples.Average(x => x.CpuPercent);
        var ev = new Evidence(SrcThermal, string.Join("; ", plausible.Select(z => $"{z.Zone}: макс {z.MaxCelsius:0} °C, ср. {z.AvgCelsius:0} °C")));
        var limits = new[]
        {
            "Это температура термозоны ACPI, а не обязательно ядер процессора; на многих компьютерах она обновляется редко и неточна.",
            "Допустимая температура зависит от модели процессора; NEXORA не знает предел для вашей модели.",
        };
        var what = $"Максимальная температура термозоны {hottest.Zone}: {hottest.MaxCelsius:0} °C при средней загрузке CPU {avgLoad:0} %.";

        if (hottest.MaxCelsius >= HotCelsius)
        {
            // Высокая температура при низкой нагрузке говорит о проблеме охлаждения сильнее, чем при полной.
            var lowLoad = avgLoad < 50;
            return CheckResult.Finding(id, title, Section.Performance, lowLoad ? Severity.High : Severity.Medium, FindingKind.Heuristic,
                lowLoad ? Confidence.Medium : Confidence.Low, what,
                lowLoad
                    ? "Высокая температура без большой нагрузки — частый признак забитой пылью системы охлаждения или высохшей термопасты."
                    : "Под полной нагрузкой высокая температура может быть нормой для ноутбука, но вместе со снижением частоты она объясняет тормоза.",
                "Почистите вентиляционные отверстия, не ставьте ноутбук на мягкие поверхности; если температура высокая и без нагрузки — обратитесь в сервис.", ev)
                with { Limitations = limits };
        }
        if (hottest.MaxCelsius >= WarmCelsius)
            return CheckResult.Finding(id, title, Section.Performance, Severity.Info, FindingKind.Heuristic, Confidence.Low, what,
                "Температура повышена, но сама по себе не означает перегрев.", "Сравните со значением без нагрузки и с результатами проверки снижения частоты.", ev)
                with { Limitations = limits };
        return CheckResult.Ok(id, title, Section.Performance, what, ev, Confidence.Medium) with { Limitations = limits };
    }

    public static CheckResult Throttling(PerformanceSession s)
    {
        const string id = "perf.throttling", title = "Снижение частоты процессора";
        var passive = s.Thermal.TryGetValue(out var zones)
            ? zones.Where(z => z.MinPassiveLimitPercent is < 100).ToList()
            : [];
        var loaded = s.Samples.Where(x => x.CpuPercent >= HighCpuPercent && x.CpuPerformancePercent is not null).ToList();
        double? loadedPerf = loaded.Count >= 3 ? loaded.Average(x => x.CpuPerformancePercent!.Value) : null;

        if (passive.Count == 0 && loadedPerf is null && s.CpuPerformanceUnavailable is not null && !s.Thermal.IsAvailable)
            return CheckResult.Unavailable(id, title, Section.Performance, SrcPerf, s.CpuPerformanceUnavailable);

        var details = new List<string>();
        if (passive.Count > 0) details.Add("термозона ограничивала частоту для охлаждения: " + string.Join(", ", passive.Select(z => $"{z.Zone} до {z.MinPassiveLimitPercent:0} %")));
        if (loadedPerf is not null) details.Add($"под нагрузкой процессор работал на {loadedPerf:0} % номинальной частоты");
        var ev = new Evidence($"{SrcPerf}; {SrcThermal}", details.Count > 0 ? string.Join("; ", details) : "признаков не обнаружено");
        var limits = new List<string> { "Частота также снижается в режиме энергосбережения и при работе от батареи — это не всегда перегрев." };
        if (loadedPerf is null) limits.Add("Высокой нагрузки во время наблюдения не было (или счётчик частоты недоступен), поэтому снижение частоты под нагрузкой не оценено.");

        if (passive.Count > 0)
            return CheckResult.Finding(id, title, Section.Performance, Severity.Medium, FindingKind.Fact, Confidence.Medium,
                "Windows снижала частоту процессора для охлаждения (пассивное охлаждение).",
                "Снижение частоты из-за температуры напрямую замедляет работу и говорит о недостаточном охлаждении.",
                "Проверьте и почистите систему охлаждения; используйте подставку для ноутбука.", ev) with { Limitations = limits };
        if (loadedPerf is < ThrottledPerformancePercent)
            return CheckResult.Finding(id, title, Section.Performance, Severity.Medium, FindingKind.Heuristic, Confidence.Medium,
                $"Под высокой нагрузкой процессор работал всего на {loadedPerf:0} % номинальной частоты.",
                "Это может быть перегрев, ограничение питания или режим энергосбережения — всё это замедляет работу.",
                "Подключите зарядное устройство, выберите режим питания «Сбалансированный» или «Максимальная производительность» и повторите проверку; если не помогло — проверьте охлаждение.", ev)
                with { Limitations = limits };
        return CheckResult.Ok(id, title, Section.Performance, "Признаков снижения частоты не обнаружено.", ev,
            loadedPerf is null ? Confidence.Low : Confidence.Medium) with { Limitations = limits };
    }

    public static IEnumerable<CheckResult> Events(Measured<EventLogSummary> events)
    {
        if (!events.TryGetValue(out var e))
        {
            yield return CheckResult.Unavailable("perf.events", "Системные ошибки в журнале", Section.Performance, events.Source, events.Reason!);
            yield break;
        }
        var limits = e.Truncated ? new[] { "Событий слишком много — проанализирована только часть журнала (самые новые)." } : [];
        string List(IEnumerable<EventGroup> g) => string.Join("; ", g.Select(x => $"{x.Provider} #{x.EventId}: {x.Count} раз, последнее {x.Last.ToLocalTime():dd.MM HH:mm}"));

        var disk = e.Groups.Where(g => g.Category == EventCategory.Disk).ToList();
        yield return disk.Count == 0
            ? CheckResult.Ok("perf.events.disk", "Ошибки дисков в журнале", Section.Performance,
                $"За {e.Days} дн. ошибок дисков и файловой системы в журнале нет.", new Evidence(SrcEvents, "нет событий")) with { Limitations = limits }
            : CheckResult.Finding("perf.events.disk", "Ошибки дисков в журнале", Section.Performance, Severity.High, FindingKind.Fact, Confidence.Medium,
                $"За {e.Days} дн. в журнале {disk.Sum(g => g.Count)} событий об ошибках диска или файловой системы.",
                "Ошибки чтения, сбросы контроллера и повреждения файловой системы вызывают зависания и могут предшествовать отказу диска.",
                "Сделайте резервную копию важных данных; проверьте состояние диска утилитой производителя.", new Evidence(SrcEvents, List(disk)))
                with { Limitations = [.. limits, "Отдельные события (например, после внезапного отключения USB-диска) не обязательно означают неисправность."] };

        var hw = e.Groups.Where(g => g.Category == EventCategory.Hardware).ToList();
        if (hw.Count > 0)
            yield return CheckResult.Finding("perf.events.hardware", "Аппаратные ошибки (WHEA)", Section.Performance,
                hw.Any(g => g.WorstLevel <= 2) ? Severity.High : Severity.Medium, FindingKind.Fact, Confidence.Medium,
                $"За {e.Days} дн. Windows зарегистрировала {hw.Sum(g => g.Count)} аппаратных ошибок (WHEA).",
                "Аппаратные ошибки процессора, памяти или шины PCIe могут вызывать сбои и зависания; часть из них исправляется автоматически.",
                "Обновите BIOS/UEFI и драйверы с сайта производителя; если ошибки повторяются — проверьте память и охлаждение в сервисе.",
                new Evidence(SrcEvents, List(hw))) with { Limitations = limits };
        else
            yield return CheckResult.Ok("perf.events.hardware", "Аппаратные ошибки (WHEA)", Section.Performance,
                $"За {e.Days} дн. аппаратных ошибок WHEA в журнале нет.", new Evidence(SrcEvents, "нет событий")) with { Limitations = limits };

        var shut = e.Groups.Where(g => g.Category == EventCategory.UnexpectedShutdown).ToList();
        if (shut.Count > 0)
            yield return CheckResult.Finding("perf.events.shutdown", "Неожиданные выключения", Section.Performance, Severity.Medium, FindingKind.Fact, Confidence.High,
                $"За {e.Days} дн. компьютер {shut.Sum(g => g.Count)} раз выключался или перезагружался некорректно.",
                "Причинами бывают перегрев, проблемы питания или батареи, зависания и принудительное выключение кнопкой.",
                "Вспомните, не выключали ли вы компьютер кнопкой; если нет — сопоставьте время событий с нагрузкой и температурой.",
                new Evidence(SrcEvents, List(shut))) with { Limitations = limits };
        else
            yield return CheckResult.Ok("perf.events.shutdown", "Неожиданные выключения", Section.Performance,
                $"За {e.Days} дн. неожиданных выключений не зарегистрировано.", new Evidence(SrcEvents, "нет событий")) with { Limitations = limits };
    }

    private static string TopText(IEnumerable<ProcessUsage> list, Func<ProcessUsage, string> f) => string.Join(", ", list.Take(3).Select(f));
    private static string Secs(TimeSpan t) => t.TotalSeconds < 120 ? $"{t.TotalSeconds:0} с" : $"{t.TotalMinutes:0.#} мин";
    public static string Mb(long bytes) => (bytes / 1048576.0).ToString("0", CultureInfo.InvariantCulture) + " МБ";
}
