using System.ComponentModel;
using System.Management;
using System.Runtime.InteropServices;

namespace Nexora.Platform;

/// <summary>Обёртка «получить значение или честно сказать, почему не получилось».</summary>
public static class Probe
{
    public static Measured<T> Try<T>(string source, Func<T?> read, string missingReason = "значение не задано в источнике") where T : class
    {
        try
        {
            var v = read();
            return v is null || (v is string s && string.IsNullOrWhiteSpace(s))
                ? Measured<T>.Unavailable(source, missingReason)
                : Measured<T>.Of(v, source);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Measured<T>.Unavailable(source, Describe(ex));
        }
    }

    public static Measured<T> TryValue<T>(string source, Func<T?> read, string missingReason = "значение не задано в источнике") where T : struct
    {
        try
        {
            var v = read();
            return v is null ? Measured<T>.Unavailable(source, missingReason) : Measured<T>.Of(v.Value, source);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Measured<T>.Unavailable(source, Describe(ex));
        }
    }

    public static Measured<IReadOnlyList<T>> List<T>(string source, Func<IEnumerable<T>> read)
    {
        try { return Measured<IReadOnlyList<T>>.Of(read().ToList(), source); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return Measured<IReadOnlyList<T>>.Unavailable(source, Describe(ex)); }
    }

    public const string AccessDenied = "отказано в доступе — возможно, нужны права администратора";
    public const string SourceMissing = "источник данных отсутствует в этой системе";

    public static string Describe(Exception ex) => ex switch
    {
        ManagementException { ErrorCode: ManagementStatus.AccessDenied } => AccessDenied,
        ManagementException { ErrorCode: ManagementStatus.InvalidNamespace or ManagementStatus.InvalidClass or ManagementStatus.NotFound or ManagementStatus.NotSupported } => SourceMissing,
        ManagementException me => $"ошибка WMI: {me.ErrorCode}",
        UnauthorizedAccessException or System.Security.SecurityException => AccessDenied,
        COMException { HResult: unchecked((int)0x80070005) } => AccessDenied,
        COMException { HResult: unchecked((int)0x8004100E) or unchecked((int)0x80041010) } => SourceMissing,
        Win32Exception { NativeErrorCode: 5 } => AccessDenied,
        TimeoutException => "превышено время ожидания ответа источника",
        _ => $"{ex.GetType().Name}: {ex.Message}",
    };
}
