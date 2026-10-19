using Microsoft.Win32;
using Nexora.Diagnostics.Inventory;

namespace Nexora.Platform;

public static class InstalledPrograms
{
    private const string Uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    /// <summary>Установленные программы с их штатными деинсталляторами (UninstallString). Системные компоненты и обновления пропускаются.</summary>
    public static IEnumerable<InstalledProgram> Read() => ReadEntries().Select(e => e.Program)
        .GroupBy(p => (p.Name, p.Version)).Select(g => g.First()).OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase);

    public sealed record Entry(InstalledProgram Program, string? UninstallString, string? QuietUninstallString, string KeyPath);

    public static List<Entry> ReadEntries()
    {
        var list = new List<Entry>();
        Read(list, RegistryHive.LocalMachine, RegistryView.Registry64, "компьютер (64-бит)");
        Read(list, RegistryHive.LocalMachine, RegistryView.Registry32, "компьютер (32-бит)");
        Read(list, RegistryHive.CurrentUser, RegistryView.Default, "текущий пользователь");
        return list;
    }

    private static void Read(List<Entry> list, RegistryHive hive, RegistryView view, string scope)
    {
        using var root = RegistryKey.OpenBaseKey(hive, view);
        using var key = root.OpenSubKey(Uninstall, writable: false);
        if (key is null) return;
        foreach (var name in key.GetSubKeyNames())
        {
            using var sub = key.OpenSubKey(name, writable: false);
            if (sub?.GetValue("DisplayName") is not string display || string.IsNullOrWhiteSpace(display)) continue;
            if (sub.GetValue("SystemComponent") is int sc && sc == 1) continue;
            if (sub.GetValue("ParentKeyName") is not null || sub.GetValue("ReleaseType") is "Update" or "Hotfix" or "Security Update") continue;
            var uninstall = sub.GetValue("UninstallString") as string;
            var program = new InstalledProgram(display.Trim(), sub.GetValue("DisplayVersion") as string, sub.GetValue("Publisher") as string,
                sub.GetValue("InstallDate") as string, scope, !string.IsNullOrWhiteSpace(uninstall));
            list.Add(new Entry(program, uninstall, sub.GetValue("QuietUninstallString") as string,
                $"{(hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU")}\\{Uninstall}\\{name} ({view})"));
        }
    }
}
