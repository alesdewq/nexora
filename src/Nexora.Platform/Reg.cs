using Microsoft.Win32;

namespace Nexora.Platform;

/// <summary>Чтение реестра (только чтение: ключи открываются без права записи).</summary>
public static class Reg
{
    public static object? Value(RegistryHive hive, string path, string name, RegistryView view = RegistryView.Registry64)
    {
        using var root = RegistryKey.OpenBaseKey(hive, view);
        using var key = root.OpenSubKey(path, writable: false);
        return key?.GetValue(name);
    }

    public static int? Dword(RegistryHive hive, string path, string name, RegistryView view = RegistryView.Registry64) =>
        Value(hive, path, name, view) switch { int i => i, long l => (int)l, string s when int.TryParse(s, out var p) => p, _ => null };

    public static string? Str(RegistryHive hive, string path, string name, RegistryView view = RegistryView.Registry64) =>
        Value(hive, path, name, view)?.ToString();

    public static bool KeyExists(RegistryHive hive, string path, RegistryView view = RegistryView.Registry64)
    {
        using var root = RegistryKey.OpenBaseKey(hive, view);
        using var key = root.OpenSubKey(path, writable: false);
        return key is not null;
    }

    public static string Source(RegistryHive hive, string path, string? name = null) =>
        $"Реестр {(hive == RegistryHive.LocalMachine ? "HKLM" : hive == RegistryHive.CurrentUser ? "HKCU" : hive.ToString())}\\{path}{(name is null ? "" : $" → {name}")}";
}
