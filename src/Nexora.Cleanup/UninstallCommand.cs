using System.Text.RegularExpressions;

namespace Nexora.Cleanup;

/// <summary>
/// Разбор UninstallString из реестра в «программа + аргументы» без участия командной оболочки.
/// Запускается только штатный деинсталлятор программы; файлы приложения вручную не удаляются.
/// </summary>
public static partial class UninstallCommand
{
    [GeneratedRegex(@"^msiexec(\.exe)?$", RegexOptions.IgnoreCase)]
    private static partial Regex MsiExec();

    [GeneratedRegex(@"/I\s*(\{[0-9A-Fa-f\-]{36}\})", RegexOptions.IgnoreCase)]
    private static partial Regex MsiInstall();

    public sealed record Parsed(string FileName, string Arguments, bool IsMsi);

    public static Parsed? Parse(string? uninstallString, string system32)
    {
        if (string.IsNullOrWhiteSpace(uninstallString)) return null;
        var s = uninstallString.Trim();
        string exe, args;
        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            if (end < 0) return null;
            exe = s[1..end];
            args = s[(end + 1)..].Trim();
        }
        else
        {
            var idx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;
            exe = s[..(idx + 4)];
            args = s[(idx + 4)..].Trim();
        }

        var isMsi = MsiExec().IsMatch(Path.GetFileName(exe));
        if (isMsi)
        {
            exe = Path.Combine(system32, "msiexec.exe");
            // «MsiExec.exe /I{GUID}» открывает режим изменения; для удаления нужен /X{GUID}.
            args = MsiInstall().Replace(args, "/X$1");
        }
        if (!Path.IsPathRooted(exe) || !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        if (exe.Contains("..", StringComparison.Ordinal)) return null;
        // Команды-обёртки не допускаются: деинсталлятор должен быть исполняемым файлом программы.
        var name = Path.GetFileName(exe).ToLowerInvariant();
        if (name is "cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "rundll32.exe") return null;
        return new Parsed(exe, args, isMsi);
    }
}
