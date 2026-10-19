using System.Text.RegularExpressions;

namespace Nexora.SecurityAudit;

/// <summary>Разбор командных строк автозапуска. Только анализ текста — ничего не выполняется.</summary>
public static partial class CommandLine
{
    [GeneratedRegex(@"^(?<p>.+?\.(exe|com|bat|cmd|scr|dll|cpl|ps1|vbs|vbe|js|jse|wsf|hta|jar|msc|lnk))(?=\s|,|$)", RegexOptions.IgnoreCase)]
    private static partial Regex Unquoted();

    /// <summary>Извлечь путь к запускаемому файлу. Возвращает null, если путь не распознан.</summary>
    public static string? ImagePath(string? command, string windowsDir = @"C:\Windows")
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var c = command.Trim();
        string? path;
        if (c.StartsWith('"'))
        {
            var end = c.IndexOf('"', 1);
            path = end > 1 ? c[1..end] : c.Trim('"');
        }
        else
        {
            var m = Unquoted().Match(c);
            path = m.Success ? m.Groups["p"].Value : c.Split(' ', 2)[0];
        }
        path = path.Trim();
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = windowsDir + path[11..];
        else if (path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(windowsDir, path);
        return path.Length == 0 ? null : path;
    }

    /// <summary>Путь службы без кавычек, содержащий пробел до имени файла, — классическая слабость «unquoted service path».</summary>
    public static bool IsUnquotedPathWithSpaces(string? command)
    {
        if (string.IsNullOrWhiteSpace(command) || command.TrimStart().StartsWith('"')) return false;
        var m = Unquoted().Match(command.Trim());
        return m.Success && m.Groups["p"].Value.Contains(' ');
    }

    private static readonly string[] UserWritableMarkers =
    [
        @"\appdata\local\temp\", @"\windows\temp\", @"\users\public\", @"\downloads\", @"\$recycle.bin\", @"\appdata\roaming\", @"\appdata\local\",
    ];

    /// <summary>Расположение, куда может писать обычный пользователь (и куда часто кладут вредоносные файлы).</summary>
    public static bool IsUserWritableLocation(string? path, out bool veryUnusual)
    {
        veryUnusual = false;
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('/', '\\').ToLowerInvariant();
        if (p.Contains(@"\temp\", StringComparison.Ordinal) || p.Contains(@"\users\public\", StringComparison.Ordinal)
            || p.Contains(@"\downloads\", StringComparison.Ordinal) || p.Contains(@"\$recycle.bin\", StringComparison.Ordinal))
        {
            veryUnusual = true;
            return true;
        }
        // Исполняемый файл прямо в корне ProgramData — нетипично для нормальных установщиков.
        var pd = p.IndexOf(@"\programdata\", StringComparison.Ordinal);
        if (pd >= 0 && p.IndexOf('\\', pd + 13) < 0) { veryUnusual = true; return true; }
        return UserWritableMarkers.Any(m => p.Contains(m, StringComparison.Ordinal));
    }

    [GeneratedRegex(@"(-|/)(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|iex\s*\(|invoke-expression|downloadstring|downloadfile|frombase64string|invoke-webrequest|\biwr\b|start-bitstransfer", RegexOptions.IgnoreCase)]
    private static partial Regex SuspiciousPowerShell();

    [GeneratedRegex(@"-w(indowstyle)?\s+h(idden)?\b", RegexOptions.IgnoreCase)]
    private static partial Regex HiddenWindow();

    [GeneratedRegex(@"\b(mshta|rundll32|regsvr32)(\.exe)?\b.*\b(https?:|javascript:|vbscript:|/i:http|scrobj\.dll)", RegexOptions.IgnoreCase)]
    private static partial Regex SuspiciousLolbin();

    [GeneratedRegex(@"\b(wscript|cscript)(\.exe)?\b.*\.(js|jse|vbs|vbe|wsf)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptHost();

    /// <summary>Признаки скрытого запуска сценариев через системные программы. Возвращает описание или null.</summary>
    public static string? SuspiciousPattern(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        if (command.Contains("powershell", StringComparison.OrdinalIgnoreCase) || command.Contains("pwsh", StringComparison.OrdinalIgnoreCase))
        {
            if (SuspiciousPowerShell().IsMatch(command)) return "PowerShell запускается с закодированной командой, выполнением строки или загрузкой из сети";
            // Скрытое окно само по себе нормально (так работают и задания Windows) — подозрительно только вместе со скриптом из пользовательской папки.
            if (HiddenWindow().IsMatch(command) && IsUserWritableLocation(command, out _)) return "PowerShell скрыто запускает скрипт из пользовательской папки";
        }
        if (SuspiciousLolbin().IsMatch(command)) return "системная программа (mshta/rundll32/regsvr32) запускает сценарий или адрес из сети";
        if (ScriptHost().IsMatch(command) && IsUserWritableLocation(command, out _)) return "сценарий Windows Script Host запускается из пользовательской папки";
        return null;
    }
}
