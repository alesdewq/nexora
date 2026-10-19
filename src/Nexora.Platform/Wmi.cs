using System.Management;

namespace Nexora.Platform;

/// <summary>Чтение WMI/CIM. Только запросы SELECT; методы классов не вызываются.</summary>
public static class Wmi
{
    public const string Cimv2 = @"root\cimv2";
    public const string Storage = @"root\Microsoft\Windows\Storage";
    public const string Defender = @"root\Microsoft\Windows\Defender";
    public const string SecurityCenter2 = @"root\SecurityCenter2";
    public const string StandardCimv2 = @"root\StandardCimv2";
    public const string BitLocker = @"root\CIMV2\Security\MicrosoftVolumeEncryption";

    public static string Source(string ns, string cls) => $"WMI {ns}: {cls}";

    /// <summary>
    /// Пространства имён, в которых уже получен отказ в доступе. При ограниченном токене каждый отказ WMI может занимать
    /// секунды; повторять их нет смысла — следующие запросы сразу получают ту же причину.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> Denied = new(StringComparer.OrdinalIgnoreCase);

    public static List<ManagementBaseObject> Query(string ns, string wql, TimeSpan? timeout = null)
    {
        if (Denied.ContainsKey(ns)) throw new UnauthorizedAccessException($"WMI {ns}: доступ запрещён");
        try { return QueryCore(ns, wql, timeout); }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            Denied[ns] = true;
            throw;
        }
    }

    private static bool IsAccessDenied(Exception ex) => ex is UnauthorizedAccessException
        || ex is ManagementException { ErrorCode: ManagementStatus.AccessDenied }
        || ex is System.Runtime.InteropServices.COMException { HResult: unchecked((int)0x80070005) };

    private static List<ManagementBaseObject> QueryCore(string ns, string wql, TimeSpan? timeout)
    {
        var scope = new ManagementScope(ns);
        var options = new System.Management.EnumerationOptions { Timeout = timeout ?? TimeSpan.FromSeconds(60), ReturnImmediately = true, Rewindable = false };
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql), options);
        var list = new List<ManagementBaseObject>();
        foreach (var o in searcher.Get()) list.Add(o);
        return list;
    }

    public static ManagementBaseObject? First(string ns, string wql) => Query(ns, wql).FirstOrDefault();

    public static T? Get<T>(this ManagementBaseObject o, string prop)
    {
        var v = o[prop];
        if (v is null) return default;
        var target = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        return target.IsInstanceOfType(v) ? (T)v : (T)Convert.ChangeType(v, target, System.Globalization.CultureInfo.InvariantCulture);
    }

    public static string? Str(this ManagementBaseObject o, string prop) => o[prop]?.ToString()?.Trim() is { Length: > 0 } s ? s : null;

    public static DateTimeOffset? Date(this ManagementBaseObject o, string prop)
    {
        var s = o[prop] as string;
        if (string.IsNullOrWhiteSpace(s)) return null;
        try { return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(s)); }
        catch (ArgumentOutOfRangeException) { return null; }
    }
}
