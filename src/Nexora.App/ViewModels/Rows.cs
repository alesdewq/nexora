using System.Globalization;
using Nexora.Cleanup;
using Nexora.Diagnostics.Performance;
using Nexora.NetworkAudit;
using Nexora.Platform;
using Nexora.Reporting;
using Nexora.SecurityAudit;

namespace Nexora.App.ViewModels;

public sealed record DurationOption(string Title, TimeSpan Duration)
{
    public override string ToString() => Title;
}

public sealed record ProcessRow(string Name, int Pid, string AvgCpu, string MaxCpu, string Memory)
{
    public static ProcessRow From(ProcessUsage p) => new(p.Name, p.Pid, $"{p.AvgCpuPercent:0.0} %", $"{p.MaxCpuPercent:0} %", PerformanceAnalyzer.Mb(p.WorkingSetBytes));
}

public sealed record AccountRow(string Name, string State, string Kind, string LastLogon, string Admin);

public sealed record ListenerRow(string Protocol, string Address, int Port, string Process, string Services, string Scope, string? Path)
{
    public static ListenerRow From(ListeningSocket s) => new(s.Protocol.ToString().ToUpperInvariant(), s.LocalAddress, s.Port,
        s.ProcessName ?? $"PID {s.Pid}", string.Join(", ", s.Services),
        s.IsLoopbackOnly ? "только этот компьютер" : s.IsAllInterfaces ? "все сетевые интерфейсы" : "один интерфейс", s.ProcessPath);
}

public sealed record CategoryRow(CategoryPreview Preview)
{
    public string Title => Preview.Title;
    public string Size => Preview.Unavailable is null ? $"{CleanupAnalyzer.Size(Preview.TotalBytes)} · {Preview.FileCount} файлов" : "данные недоступны";
    public string Details => Preview.Unavailable ?? (Preview.Explanation + (Preview.SkippedInaccessible > 0 ? $" Недоступных файлов пропущено: {Preview.SkippedInaccessible}." : ""));
    public string Consequences => Preview.Consequences;
    public bool CanCleanFiles => Preview.CanClean && Preview.Unavailable is null && Preview.FileCount > 0;
    public bool CanEmptyRecycleBin => Preview.Category == CleanupCategory.RecycleBin && Preview.Unavailable is null && Preview.FileCount > 0;
    public string LargestText => Preview.Category == CleanupCategory.LargeFiles && Preview.Items.Count > 0
        ? string.Join("\n", Preview.Items.Take(15).Select(i => $"{CleanupAnalyzer.Size(i.SizeBytes),10}  {i.LastWriteUtc.ToLocalTime():dd.MM.yyyy}  {i.Path}"))
        : "";
}

public sealed record ProgramRow(InstalledPrograms.Entry Entry, bool CanUninstall)
{
    public string Name => Entry.Program.Name;
    public string Version => Entry.Program.Version ?? "";
    public string Publisher => Entry.Program.Publisher ?? "";
    public string Scope => Entry.Program.Scope;
    public string Installed => FormatDate(Entry.Program.InstallDate);

    private static string FormatDate(string? yyyymmdd) =>
        DateTime.TryParseExact(yyyymmdd, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture) : "";
}

public sealed record AutorunRow(AutorunEntry Entry)
{
    public string Name => Entry.Name;
    public string Where => AutorunAnalyzer.LocationText(Entry.Location);
    public string Command => Entry.Command;
    public string State => Entry.Enabled ? "включено" : "отключено";
    public string Signature => AutorunAnalyzer.SignatureText(Entry.Signature) + (Entry.Publisher is null ? "" : $" ({Entry.Publisher})");
    public bool CanToggle => Platform.Actions.StartupActions.CanToggle(Entry);
    public string ToggleText => Entry.Enabled ? "Отключить…" : "Включить";
}

public sealed record HistoryRow(StoredReport Report)
{
    public string Date => Report.Started.ToLocalTime().ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture);
    public string Summary => Report.Summary;
    public string Issues => $"замечаний: {Report.Issues}, не проверено: {Report.NotChecked}";
    public override string ToString() => $"{Date} — {Issues}";
}
