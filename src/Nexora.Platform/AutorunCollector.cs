using Microsoft.Win32;
using Nexora.SecurityAudit;

namespace Nexora.Platform;

/// <summary>Перечисление записей автозапуска. Только чтение (ярлыки читаются через WScript.Shell без сохранения).</summary>
public static class AutorunCollector
{
    private const string RunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOncePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string ApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ApprovedRun32 = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
    private const string ApprovedFolder = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    public static string WindowsDir => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public static IEnumerable<AutorunEntry> Collect()
    {
        var list = new List<AutorunEntry>();
        RunKeys(list);
        StartupFolders(list);
        TryAdd(list, ScheduledTasks);
        TryAdd(list, Services);
        return list;
    }

    private static void TryAdd(List<AutorunEntry> list, Func<IEnumerable<AutorunEntry>> source)
    {
        try { list.AddRange(source()); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Runtime.InteropServices.COMException or System.Management.ManagementException) { }
    }

    public static AutorunEntry Make(AutorunLocation location, string where, string name, string command, bool enabled, bool machine)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command);
        var image = CommandLine.ImagePath(expanded, WindowsDir);
        if (image is not null && !Path.IsPathRooted(image))
            image = ResolveOnPath(image) ?? image;
        bool? exists = image is null || !Path.IsPathRooted(image) ? null : File.Exists(image);
        var (sig, publisher) = image is null || exists != true ? (SignatureState.NotChecked, (string?)null)
            : image.StartsWith(WindowsDir + "\\", StringComparison.OrdinalIgnoreCase) ? (SignatureState.NotChecked, null) // каталожные подписи не проверяем
            : Authenticode.Check(image);
        return new AutorunEntry(location, where, name, expanded, image, exists, sig, publisher, enabled, machine);
    }

    private static string? ResolveOnPath(string file)
    {
        var candidates = Path.HasExtension(file) ? [file] : new[] { file + ".exe" };
        foreach (var dir in new[] { Path.Combine(WindowsDir, "System32"), WindowsDir })
            foreach (var c in candidates)
                if (File.Exists(Path.Combine(dir, c))) return Path.Combine(dir, c);
        return null;
    }

    private static void RunKeys(List<AutorunEntry> list)
    {
        foreach (var (hive, view, label) in new[]
                 {
                     (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM"),
                     (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM (32-бит)"),
                     (RegistryHive.CurrentUser, RegistryView.Default, "HKCU"),
                 })
        {
            foreach (var (path, loc) in new[] { (RunPath, AutorunLocation.RunKey), (RunOncePath, AutorunLocation.RunOnceKey) })
            {
                try
                {
                    using var root = RegistryKey.OpenBaseKey(hive, view);
                    using var key = root.OpenSubKey(path, writable: false);
                    if (key is null) continue;
                    foreach (var name in key.GetValueNames())
                    {
                        if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string cmd || cmd.Length == 0) continue;
                        var enabled = loc == AutorunLocation.RunOnceKey || IsApproved(hive, view == RegistryView.Registry32 ? ApprovedRun32 : ApprovedRun, name);
                        list.Add(Make(loc, $@"{label}\{path}", name.Length == 0 ? "(по умолчанию)" : name, cmd, enabled, hive == RegistryHive.LocalMachine));
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    /// <summary>StartupApproved: первый байт 0x02/0x06 — включено, 0x03/0x07 — отключено пользователем в Диспетчере задач.</summary>
    public static bool IsApproved(RegistryHive hive, string approvedPath, string name)
    {
        foreach (var h in new[] { hive, RegistryHive.CurrentUser }.Distinct())
        {
            using var root = RegistryKey.OpenBaseKey(h, RegistryView.Default);
            using var key = root.OpenSubKey(approvedPath, writable: false);
            if (key?.GetValue(name) is byte[] { Length: > 0 } b) return (b[0] & 1) == 0;
        }
        return true;
    }

    private static void StartupFolders(List<AutorunEntry> list)
    {
        var folders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), false, RegistryHive.CurrentUser),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), true, RegistryHive.LocalMachine),
        };
        var entries = Sta.Run(() =>
        {
            var result = new List<AutorunEntry>();
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            dynamic? shell = shellType is null ? null : Activator.CreateInstance(shellType);
            foreach (var (folder, machine, hive) in folders)
            {
                if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
                foreach (var file in Directory.EnumerateFiles(folder))
                {
                    var name = Path.GetFileName(file);
                    if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    var command = $"\"{file}\"";
                    if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && shell is not null)
                    {
                        try
                        {
                            dynamic link = shell.CreateShortcut(file); // только чтение: Save() не вызывается
                            string target = link.TargetPath;
                            string args = link.Arguments;
                            if (!string.IsNullOrWhiteSpace(target)) command = $"\"{target}\" {args}".Trim();
                        }
                        catch (System.Runtime.InteropServices.COMException) { }
                    }
                    result.Add(Make(AutorunLocation.StartupFolder, folder, name, command, IsApproved(hive, ApprovedFolder, name), machine));
                }
            }
            return result;
        });
        list.AddRange(entries);
    }

    private static IEnumerable<AutorunEntry> ScheduledTasks() => Sta.Run(() =>
    {
        var result = new List<AutorunEntry>();
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("Schedule.Service недоступен");
        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        void Walk(dynamic folder)
        {
            string path = folder.Path;
            var microsoft = path.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase);
            try
            {
                foreach (dynamic task in folder.GetTasks(1)) // 1 = TASK_ENUM_HIDDEN: скрытые задания тоже
                {
                    try
                    {
                        bool enabled = task.Enabled;
                        foreach (dynamic action in task.Definition.Actions)
                        {
                            if ((int)action.Type != 0) continue; // только «запуск программы»
                            string exe = action.Path ?? "";
                            string args = action.Arguments ?? "";
                            var entry = Make(AutorunLocation.ScheduledTask, $"Планировщик {path}", (string)task.Name, $"\"{exe}\" {args}".Trim(), enabled, true);
                            // Стандартные задания Microsoft показываем, только если они запускают что-то из пользовательских папок.
                            if (microsoft && !CommandLine.IsUserWritableLocation(entry.ImagePath, out _) && CommandLine.SuspiciousPattern(entry.Command) is null) continue;
                            result.Add(entry);
                        }
                    }
                    catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException) { }
                }
                foreach (dynamic sub in folder.GetFolders(0)) Walk(sub);
            }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException) { }
        }
        Walk(service.GetFolder(@"\"));
        return result;
    });

    private static IEnumerable<AutorunEntry> Services() =>
        Wmi.Query(Wmi.Cimv2, "SELECT Name, DisplayName, PathName, StartMode FROM Win32_Service WHERE StartMode = 'Auto'")
            .Where(s => s.Str("PathName") is { } p && !Environment.ExpandEnvironmentVariables(p).TrimStart('"')
                .StartsWith(WindowsDir + "\\", StringComparison.OrdinalIgnoreCase))
            .Select(s => Make(AutorunLocation.Service, $"Служба {s.Str("Name")}", s.Str("DisplayName") ?? s.Str("Name") ?? "?", s.Str("PathName")!, true, true));
}
