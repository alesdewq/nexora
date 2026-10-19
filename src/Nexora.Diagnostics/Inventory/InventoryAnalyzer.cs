using System.Globalization;

namespace Nexora.Diagnostics.Inventory;

/// <summary>Правила оценки снимка инвентаризации. Пороговые значения — константы, чтобы их было видно и можно было тестировать.</summary>
public static class InventoryAnalyzer
{
    public const double SystemDiskMediumFreePercent = 10, SystemDiskHighFreePercent = 5;
    public const long SystemDiskMediumFreeBytes = 15L << 30, SystemDiskHighFreeBytes = 5L << 30;
    public const int HotfixStaleDays = 45;
    public const int LongUptimeDays = 14;

    private const string SrcOs = "Реестр HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion; WMI Win32_OperatingSystem";

    public static IReadOnlyList<CheckResult> Analyze(InventorySnapshot s, DateTimeOffset now)
    {
        var r = new List<CheckResult>();
        r.Add(OsSupport(s.Os, now));
        r.AddRange(Disks(s.LogicalDisks));
        r.Add(DiskHealthCheck(s.PhysicalDisks));
        r.Add(Updates(s.Hotfixes, now));
        r.Add(PendingReboot(s.RebootPending));
        r.Add(Devices(s.ProblemDevices));
        r.Add(Uptime(s.Os.LastBoot, now));
        r.Add(Memory(s.Computer.TotalMemoryBytes));
        return r;
    }

    public static CheckResult OsSupport(OsInfo os, DateTimeOffset now)
    {
        const string id = "inv.os.support", title = "Поддержка версии Windows";
        if (!os.Build.TryGetValue(out var build))
            return CheckResult.Unavailable(id, title, Section.Security, os.Build.Source, os.Build.Reason ?? "номер сборки не получен");

        var edition = os.EditionId.IsAvailable ? os.EditionId.Value : null;
        var info = WindowsLifecycle.Evaluate(build, edition, DateOnly.FromDateTime(now.Date));
        var ubr = os.Ubr.IsAvailable ? $".{os.Ubr.Value}" : "";
        var ev = new Evidence(SrcOs, $"Сборка {build}{ubr}, редакция {WindowsLifecycle.EditionDisplay(edition)}, " +
                                     $"срок поддержки: {info.EndOfSupport?.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture) ?? "неизвестен"}");
        var limits = new[] { $"Сроки поддержки взяты из встроенной таблицы по состоянию на {WindowsLifecycle.DataAsOf}; Microsoft может их изменить." };
        var what = $"{info.Name}, {WindowsLifecycle.EditionDisplay(edition)}. {info.Note}";
        var upgrade = WindowsLifecycle.IsWindows11(build)
            ? "Установите актуальную версию Windows 11 через «Параметры → Центр обновления Windows» (обновление бесплатное)."
            : "Перейдите на Windows 11, если компьютер соответствует требованиям, или подключите ESU; иначе компьютер перестанет получать исправления безопасности.";

        return info.State switch
        {
            SupportState.Supported => CheckResult.Ok(id, title, Section.Security, what, ev) with { Limitations = limits },
            SupportState.EndingSoon => CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.Recommendation,
                Confidence.High, what, "После окончания поддержки Microsoft перестаёт выпускать исправления уязвимостей для этой версии.", upgrade, ev) with { Limitations = limits },
            SupportState.EndedEsuPossible => CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.PotentialRisk,
                Confidence.Medium, what, "Без ESU новые уязвимости в этой версии Windows не исправляются.", upgrade, ev) with { Limitations = limits },
            SupportState.Ended => CheckResult.Finding(id, title, Section.Security, Severity.High, FindingKind.Fact,
                Confidence.High, what, "Новые уязвимости в этой версии Windows не исправляются.", upgrade, ev) with { Limitations = limits },
            _ => CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.Recommendation, Confidence.Low,
                what, "Без срока поддержки нельзя оценить, получает ли система исправления.",
                "Проверьте срок поддержки на сайте Microsoft Lifecycle.", ev) with { Limitations = limits },
        };
    }

    public static IEnumerable<CheckResult> Disks(Measured<IReadOnlyList<LogicalDiskInfo>> disks)
    {
        const string src = "WMI Win32_LogicalDisk (DriveType=3)";
        if (!disks.TryGetValue(out var list))
        {
            yield return CheckResult.Unavailable("inv.disk.free", "Свободное место на дисках", Section.Performance, disks.Source, disks.Reason!);
            yield break;
        }
        foreach (var d in list.Where(d => d.SizeBytes > 0))
        {
            var id = $"inv.disk.free.{d.Name.TrimEnd(':', '\\').ToUpperInvariant()}";
            var title = $"Свободное место на диске {d.Name}";
            var what = $"Свободно {Gb(d.FreeBytes)} из {Gb(d.SizeBytes)} ({d.FreePercent:0.#} %).";
            var ev = new Evidence(src, $"{d.Name} {d.FileSystem}: FreeSpace={d.FreeBytes}, Size={d.SizeBytes}");

            Severity? sev = null;
            if (d.IsSystem)
            {
                if (d.FreePercent < SystemDiskHighFreePercent || d.FreeBytes < SystemDiskHighFreeBytes) sev = Severity.High;
                else if (d.FreePercent < SystemDiskMediumFreePercent || d.FreeBytes < SystemDiskMediumFreeBytes) sev = Severity.Medium;
            }
            else if (d.FreePercent < SystemDiskHighFreePercent)
            {
                sev = Severity.Info;
            }

            yield return sev is null
                ? CheckResult.Ok(id, title, Section.Performance, what, ev)
                : CheckResult.Finding(id, title, Section.Performance, sev.Value, FindingKind.Fact, Confidence.High, what,
                    d.IsSystem
                        ? "Когда на системном диске мало места, Windows не может установить обновления, а файл подкачки и временные файлы замедляют работу."
                        : "Диск почти заполнен — новые данные могут не поместиться.",
                    "Посмотрите крупные файлы и временные файлы в разделе «Файлы и программы»; удаляйте только то, назначение чего понятно.", ev);
        }
    }

    public static CheckResult DiskHealthCheck(Measured<IReadOnlyList<PhysicalDiskInfo>> disks)
    {
        const string id = "inv.disk.health", title = "Состояние физических дисков";
        if (!disks.TryGetValue(out var list))
            return CheckResult.Unavailable(id, title, Section.Performance, disks.Source, disks.Reason!);
        if (list.Count == 0)
            return CheckResult.Unavailable(id, title, Section.Performance, disks.Source, "диски не перечислены источником");

        var ev = new Evidence(disks.Source, string.Join("; ", list.Select(d => $"{d.Name} ({d.MediaType}, {d.BusType}): {d.Health}, {d.OperationalStatus}")));
        var limits = new[] { "Используется оценка Windows (Storage Management). Подробные SMART-счётчики требуют прав администратора и здесь не читаются." };
        var bad = list.Where(d => d.Health is DiskHealth.Warning or DiskHealth.Unhealthy).ToList();
        if (bad.Count > 0)
        {
            var sev = bad.Any(d => d.Health == DiskHealth.Unhealthy) ? Severity.Critical : Severity.High;
            return CheckResult.Finding(id, title, Section.Performance, sev, FindingKind.Fact, Confidence.High,
                "Windows сообщает о проблемах с диском: " + string.Join(", ", bad.Select(d => $"{d.Name} — {HealthText(d.Health)}")) + ".",
                "Неисправный диск вызывает зависания и может привести к потере данных.",
                "Срочно сделайте резервную копию важных данных и проверьте диск у специалиста или утилитой производителя.", ev) with { Limitations = limits };
        }
        if (list.All(d => d.Health == DiskHealth.Unknown))
            return CheckResult.Unavailable(id, title, Section.Performance, disks.Source, "Windows не сообщает состояние дисков") with { Limitations = limits };

        var hdd = list.FirstOrDefault(d => d.MediaType == "HDD");
        var result = CheckResult.Ok(id, title, Section.Performance,
            "Windows не сообщает о проблемах с физическими дисками." + (hdd is not null ? $" Диск {hdd.Name} — механический (HDD)." : ""), ev);
        return result with { Limitations = limits };
    }

    public static CheckResult Updates(Measured<IReadOnlyList<HotfixInfo>> hotfixes, DateTimeOffset now)
    {
        const string id = "inv.updates.recent", title = "Последние установленные обновления";
        if (!hotfixes.TryGetValue(out var list))
            return CheckResult.Unavailable(id, title, Section.Security, hotfixes.Source, hotfixes.Reason!);
        var limits = new[] { "Win32_QuickFixEngineering показывает не все обновления (например, не показывает обновления Microsoft Store и драйверов)." };
        var latest = list.Where(h => h.InstalledOn is not null).OrderByDescending(h => h.InstalledOn).FirstOrDefault();
        if (latest is null)
            return CheckResult.Unavailable(id, title, Section.Security, hotfixes.Source, "даты установки обновлений не указаны") with { Limitations = limits };

        var days = (int)(now - latest.InstalledOn!.Value).TotalDays;
        var what = $"Последнее обновление в списке: {latest.Id} от {latest.InstalledOn:dd.MM.yyyy} ({days} дн. назад). Всего записей: {list.Count}.";
        var ev = new Evidence(hotfixes.Source, $"{latest.Id} {latest.Description} InstalledOn={latest.InstalledOn:yyyy-MM-dd}");
        return days <= HotfixStaleDays
            ? CheckResult.Ok(id, title, Section.Security, what, ev, Confidence.Medium) with { Limitations = limits }
            : CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.PotentialRisk, Confidence.Medium, what,
                "Microsoft выпускает исправления безопасности ежемесячно; долгий перерыв может означать, что обновления не устанавливаются.",
                "Откройте «Центр обновления Windows» и проверьте наличие обновлений и ошибок установки.", ev) with { Limitations = limits };
    }

    public static CheckResult PendingReboot(Measured<bool> pending)
    {
        const string id = "inv.updates.reboot", title = "Ожидание перезагрузки";
        if (!pending.TryGetValue(out var p))
            return CheckResult.Unavailable(id, title, Section.Security, pending.Source, pending.Reason!);
        var ev = new Evidence(pending.Source, p ? "найден признак ожидающей перезагрузки" : "признаков нет");
        return p
            ? CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.Fact, Confidence.High,
                "Windows ожидает перезагрузку для завершения установки обновлений или компонентов.",
                "Пока компьютер не перезагружен, часть исправлений не действует.", "Сохраните работу и перезагрузите компьютер.", ev)
            : CheckResult.Ok(id, title, Section.Security, "Перезагрузка для установки обновлений не требуется.", ev);
    }

    public static CheckResult Devices(Measured<IReadOnlyList<ProblemDevice>> devices)
    {
        const string id = "inv.devices", title = "Устройства с ошибками";
        if (!devices.TryGetValue(out var list))
            return CheckResult.Unavailable(id, title, Section.Performance, devices.Source, devices.Reason!);
        // Код 22 — устройство отключено пользователем: это не ошибка.
        var errors = list.Where(d => d.ErrorCode != 22).ToList();
        var ev = new Evidence(devices.Source, list.Count == 0 ? "нет устройств с ненулевым кодом" : string.Join("; ", list.Select(d => $"{d.Name}: код {d.ErrorCode}")));
        if (errors.Count == 0)
            return CheckResult.Ok(id, title, Section.Performance,
                list.Count == 0 ? "Диспетчер устройств не сообщает об ошибках." : $"Ошибок нет; отключено вручную устройств: {list.Count}.", ev);
        return CheckResult.Finding(id, title, Section.Performance, Severity.Medium, FindingKind.Fact, Confidence.High,
            $"Устройств с ошибками: {errors.Count} — " + string.Join(", ", errors.Take(5).Select(d => $"{d.Name} (код {d.ErrorCode})")) + ".",
            "Неработающий драйвер может вызывать сбои, лишнюю нагрузку или отсутствие функций (например, датчиков или управления питанием).",
            "Откройте «Диспетчер устройств», посмотрите описание ошибки и установите драйвер с сайта производителя компьютера.", ev);
    }

    public static CheckResult Uptime(Measured<DateTimeOffset> lastBoot, DateTimeOffset now)
    {
        const string id = "inv.uptime", title = "Время работы без перезагрузки";
        if (!lastBoot.TryGetValue(out var boot))
            return CheckResult.Unavailable(id, title, Section.Performance, lastBoot.Source, lastBoot.Reason!);
        var up = now - boot;
        var what = $"Компьютер работает без перезагрузки {(int)up.TotalDays} дн. {up.Hours} ч (с {boot.ToLocalTime():dd.MM.yyyy HH:mm}).";
        var ev = new Evidence(lastBoot.Source, $"LastBootUpTime={boot:O}");
        var limits = new[] { "При включённом «быстром запуске» завершение работы не всегда сбрасывает этот счётчик — точнее всего считается перезагрузка." };
        return up.TotalDays <= LongUptimeDays
            ? CheckResult.Ok(id, title, Section.Performance, what, ev) with { Limitations = limits }
            : CheckResult.Finding(id, title, Section.Performance, Severity.Info, FindingKind.Recommendation, Confidence.High, what,
                "Долгая работа без перезагрузки откладывает установку обновлений; утечки памяти в программах накапливаются.",
                "Перезагрузите компьютер (именно «Перезагрузка», а не «Завершение работы»).", ev) with { Limitations = limits };
    }

    public static CheckResult Memory(Measured<long> total)
    {
        const string id = "inv.memory.size", title = "Объём оперативной памяти";
        if (!total.TryGetValue(out var bytes))
            return CheckResult.Unavailable(id, title, Section.Performance, total.Source, total.Reason!);
        var ev = new Evidence(total.Source, $"TotalPhysicalMemory={bytes}");
        var what = $"Установлено {Gb(bytes)} оперативной памяти.";
        return bytes >= 7L << 30
            ? CheckResult.Ok(id, title, Section.Performance, what, ev)
            : CheckResult.Finding(id, title, Section.Performance, Severity.Info, FindingKind.Recommendation, Confidence.Medium, what,
                "Современным браузерам и Windows 10/11 при обычной работе часто не хватает менее 8 ГБ памяти.",
                "Сравните с результатами раздела «Производительность»: если память постоянно занята, добавление памяти может помочь.", ev);
    }

    private static string HealthText(DiskHealth h) => h switch
    {
        DiskHealth.Warning => "предупреждение",
        DiskHealth.Unhealthy => "неисправен",
        DiskHealth.Healthy => "исправен",
        _ => "неизвестно",
    };

    public static string Gb(long bytes) => (bytes / (double)(1L << 30)).ToString("0.#", CultureInfo.GetCultureInfo("ru-RU")) + " ГБ";
}
