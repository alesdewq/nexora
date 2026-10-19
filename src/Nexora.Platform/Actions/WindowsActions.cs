using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Nexora.Cleanup;
using Nexora.SecurityAudit;

namespace Nexora.Platform.Actions;

/// <summary>
/// Этап 8: действия, МЕНЯЮЩИЕ систему. Вызываются только из интерфейса после явного подтверждения пользователя;
/// каждое действие записывается в журнал. Ни одно действие не требует и не запрашивает прав администратора само по себе.
/// </summary>
public sealed class WindowsFileRemover : IFileRemover
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd; public uint wFunc; public string pFrom; public string? pTo; public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted; public IntPtr hNameMappings; public string? lpszProgressTitle;
    }

#pragma warning disable SYSLIB1054 // структура со строками — классический P/Invoke проще и надёжнее генератора
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT op);
#pragma warning restore SYSLIB1054

    private const uint FO_DELETE = 3;
    private const ushort FOF_SILENT = 0x4, FOF_NOCONFIRMATION = 0x10, FOF_ALLOWUNDO = 0x40, FOF_NOERRORUI = 0x400;

    public void Remove(string path, bool toRecycleBin)
    {
        if (!toRecycleBin) { File.Delete(path); return; }
        var op = new SHFILEOPSTRUCT
        {
            wFunc = FO_DELETE, pFrom = path + "\0\0",
            fFlags = (ushort)(FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI),
        };
        var rc = SHFileOperation(ref op);
        if (rc != 0 || op.fAnyOperationsAborted) throw new IOException($"не удалось переместить в корзину (код {rc})");
    }
}

public static partial class RecycleBinActions
{
    [LibraryImport("shell32.dll", EntryPoint = "SHEmptyRecycleBinW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SHEmptyRecycleBin(IntPtr hwnd, string? root, uint flags);

    /// <summary>Очистить корзину текущего пользователя (необратимо). Подтверждение — до вызова, в интерфейсе.</summary>
    public static void Empty(ActionJournal journal, long sizeBefore, int countBefore)
    {
        var hr = SHEmptyRecycleBin(IntPtr.Zero, null, 0x1 | 0x2 | 0x4); // без собственных диалогов Windows: подтверждение уже получено
        // S_OK или «корзина уже пуста» (0x8000FFFF на некоторых системах) — не ошибка.
        var ok = hr == 0 || hr == unchecked((int)0x8000FFFF);
        journal.Write(new JournalEntry(DateTimeOffset.Now, "recyclebin.empty", "Корзина", ok ? "ok" : "error",
            $"до очистки: {countBefore} объектов, {sizeBefore} байт; HRESULT 0x{hr:X8}"));
        if (!ok) throw new IOException($"Windows не очистила корзину (0x{hr:X8})");
    }
}

/// <summary>
/// Отключение и включение автозагрузки тем же механизмом, что и в Диспетчере задач (StartupApproved в HKCU):
/// исходная запись Run / ярлык не удаляются, поэтому действие полностью обратимо. Только записи текущего пользователя.
/// </summary>
public static class StartupActions
{
    private const string ApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ApprovedFolder = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    public static bool CanToggle(AutorunEntry e) =>
        !e.MachineWide && e.Location is AutorunLocation.RunKey or AutorunLocation.StartupFolder;

    public static void SetEnabled(AutorunEntry e, bool enabled, ActionJournal journal)
    {
        if (!CanToggle(e)) throw new InvalidOperationException("Эту запись автозагрузки NEXORA не изменяет (общая для компьютера или другого типа).");
        var keyPath = e.Location == AutorunLocation.StartupFolder ? ApprovedFolder : ApprovedRun;
        using var key = Registry.CurrentUser.CreateSubKey(keyPath, writable: true);
        var previous = key.GetValue(e.Name) as byte[];
        var value = new byte[12];
        value[0] = enabled ? (byte)0x02 : (byte)0x03;
        if (!enabled) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(value, 4);
        key.SetValue(e.Name, value, RegistryValueKind.Binary);
        journal.Write(new JournalEntry(DateTimeOffset.Now, enabled ? "startup.enable" : "startup.disable", $@"HKCU\{keyPath}\{e.Name}", "ok",
            $"команда: {e.Command}; прежнее значение: {(previous is null ? "нет" : Convert.ToHexString(previous))}"));
    }
}

/// <summary>Запуск штатного деинсталлятора программы. NEXORA не удаляет файлы приложений сама.</summary>
public static class UninstallActions
{
    public static UninstallCommand.Parsed? Prepare(InstalledPrograms.Entry entry) =>
        UninstallCommand.Parse(entry.UninstallString, Environment.SystemDirectory) is { } p && File.Exists(p.FileName) ? p : null;

    public static void Launch(InstalledPrograms.Entry entry, ActionJournal journal)
    {
        var p = Prepare(entry) ?? throw new InvalidOperationException("Деинсталлятор не найден или команда удаления не распознана.");
        // UseShellExecute: деинсталлятору может понадобиться запрос UAC. Командная оболочка не используется.
        using var process = Process.Start(new ProcessStartInfo(p.FileName, p.Arguments) { UseShellExecute = true });
        journal.Write(new JournalEntry(DateTimeOffset.Now, "program.uninstall.launch", entry.Program.Name, "launched",
            $"{p.FileName} {p.Arguments} (раздел {entry.KeyPath})"));
    }
}
