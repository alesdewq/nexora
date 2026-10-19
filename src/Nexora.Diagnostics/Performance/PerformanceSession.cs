namespace Nexora.Diagnostics.Performance;

/// <summary>Результат наблюдения за производительностью в течение <see cref="Duration"/>.</summary>
public sealed record PerformanceSession
{
    public required DateTimeOffset Started { get; init; }
    public required TimeSpan Duration { get; init; }
    public required TimeSpan Interval { get; init; }
    public required int LogicalProcessors { get; init; }
    public required IReadOnlyList<PerformanceSample> Samples { get; init; }
    public required IReadOnlyList<ProcessUsage> TopByCpu { get; init; }
    public required IReadOnlyList<ProcessUsage> TopByMemory { get; init; }
    /// <summary>Процессы, чьё потребление CPU нельзя прочитать без прав администратора (системные службы и т. п.).</summary>
    public required int InaccessibleProcesses { get; init; }
    /// <summary>Причина, если счётчик активности диска недоступен.</summary>
    public string? DiskCounterUnavailable { get; init; }
    /// <summary>Причина, если счётчик «% Processor Performance» (фактическая частота относительно номинальной) недоступен.</summary>
    public string? CpuPerformanceUnavailable { get; init; }
    public required Measured<IReadOnlyList<ThermalZoneReading>> Thermal { get; init; }
    public required Measured<EventLogSummary> Events { get; init; }
}

/// <param name="CpuPerformancePercent">Фактическая производительность CPU относительно номинальной частоты (&gt;100 — турбо, сильно &lt;100 под нагрузкой — снижение частоты).</param>
public sealed record PerformanceSample(TimeSpan Offset, double CpuPercent, double MemoryUsedPercent, double? DiskBusyPercent, double? CpuPerformancePercent);

/// <param name="AvgCpuPercent">Средняя доля от всей вычислительной мощности (все логические процессоры = 100 %).</param>
public sealed record ProcessUsage(string Name, int Pid, double AvgCpuPercent, double MaxCpuPercent, long WorkingSetBytes, long PrivateBytes);

/// <param name="MinPassiveLimitPercent">Минимальное значение «% Passive Limit»: меньше 100 — система снижала частоту для охлаждения.</param>
public sealed record ThermalZoneReading(string Zone, double MaxCelsius, double AvgCelsius, double? MinPassiveLimitPercent);

public enum EventCategory { Disk, Hardware, UnexpectedShutdown, Other }

public sealed record EventGroup(string Provider, int EventId, EventCategory Category, int Count, int WorstLevel, DateTimeOffset Last);

public sealed record EventLogSummary(int Days, int TotalCriticalAndErrors, IReadOnlyList<EventGroup> Groups, bool Truncated);
