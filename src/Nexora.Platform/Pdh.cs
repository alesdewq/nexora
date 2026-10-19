using System.Runtime.InteropServices;
using static Nexora.Platform.Native;

namespace Nexora.Platform;

/// <summary>
/// Счётчики производительности через PDH с английскими именами (PdhAddEnglishCounter) — работают на локализованной Windows,
/// где PerformanceCounter требует русских названий категорий.
/// </summary>
public sealed class Pdh : IDisposable
{
    private readonly IntPtr _query;

    public Pdh()
    {
        var status = PdhOpenQuery(null, IntPtr.Zero, out _query);
        if (status != 0) throw new InvalidOperationException($"PdhOpenQuery: 0x{status:X8}");
    }

    /// <summary>Добавить счётчик; при ошибке возвращает null и причину (счётчика нет в системе, нет доступа…).</summary>
    public IntPtr? Add(string englishPath, out string? error)
    {
        var status = PdhAddEnglishCounter(_query, englishPath, IntPtr.Zero, out var counter);
        error = status == 0 ? null : status switch
        {
            0xC0000BB8 or 0xC0000BB9 or 0xC0000BBA => "счётчик отсутствует в этой системе",
            0xC0000BDB => "служба счётчиков производительности недоступна",
            _ => $"ошибка PDH 0x{status:X8}",
        };
        return status == 0 ? counter : null;
    }

    /// <summary>Снять замер; false — замер не удался (значения счётчиков в этом шаге будут недоступны).</summary>
    public bool Collect() => PdhCollectQueryData(_query) == 0;

    public static double? Value(IntPtr counter)
    {
        var status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, out _, out var v);
        return status == 0 && v.CStatus is PDH_CSTATUS_VALID_DATA or PDH_CSTATUS_NEW_DATA ? v.DoubleValue : null;
    }

    /// <summary>Значения счётчика с подстановкой «(*)» по экземплярам.</summary>
    public static Dictionary<string, double> Values(IntPtr counter)
    {
        var result = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        uint size = 0;
        var status = PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, ref size, out _, IntPtr.Zero);
        if (status != PDH_MORE_DATA || size == 0) return result;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            status = PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, ref size, out var count, buffer);
            if (status != 0) return result;
            var itemSize = Marshal.SizeOf<PDH_FMT_COUNTERVALUE_ITEM>();
            for (var i = 0; i < count; i++)
            {
                var item = Marshal.PtrToStructure<PDH_FMT_COUNTERVALUE_ITEM>(buffer + i * itemSize);
                if (item.Value.CStatus is PDH_CSTATUS_VALID_DATA or PDH_CSTATUS_NEW_DATA)
                    result[Marshal.PtrToStringUni(item.Name) ?? $"#{i}"] = item.Value.DoubleValue;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return result;
    }

    public void Dispose() => _ = PdhCloseQuery(_query);
}
