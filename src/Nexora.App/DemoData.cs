using Nexora.Cleanup;
using Nexora.Core;
using Nexora.Diagnostics.Inventory;
using Nexora.Diagnostics.Performance;
using Nexora.NetworkAudit;
using Nexora.Platform;
using Nexora.Reporting;
using Nexora.SecurityAudit;
using Nexora.SecurityAudit.Malware;

namespace Nexora.App;

/// <summary>
/// Вымышленный компьютер для скриншотов и демонстрации (smoke-тест с --demo). Реальные анализаторы применяются к
/// синтетическим снимкам — ни одно значение не берётся с настоящей системы.
/// </summary>
internal static class DemoData
{
    private static Measured<T> Of<T>(T v) => Measured<T>.Of(v, "демонстрационные данные");
    private static Measured<T> Na<T>(string why) => Measured<T>.Unavailable("демонстрационные данные", why);

    public static ScanResult Build()
    {
        var now = DateTimeOffset.Now;
        var inv = new InventorySnapshot
        {
            Os = new OsInfo
            {
                ProductName = Of("Windows 11 Pro"), EditionId = Of("Professional"), DisplayVersion = Of("25H2"), Build = Of(26200), Ubr = Of(6899),
                Architecture = Of("64-разрядная"), LastBoot = Of(now.AddDays(-21)), InstallDate = Of(now.AddYears(-1)),
            },
            Computer = new ComputerInfo
            {
                ComputerName = Of("DEMO-PC"), Manufacturer = Of("Contoso"), Model = Of("Laptop 15"), IsPortable = Of(true), PartOfDomain = Of(false),
                CpuName = Of("Демо CPU 8 ядер"), CpuCores = Of(8), CpuLogicalProcessors = Of(16), TotalMemoryBytes = Of(8L << 30),
            },
            LogicalDisks = Of<IReadOnlyList<LogicalDiskInfo>>([new("C:", "NTFS", 237L << 30, 17L << 30, true)]),
            PhysicalDisks = Of<IReadOnlyList<PhysicalDiskInfo>>([new("NVMe SSD 256GB", "SSD", "NVMe", 256L << 30, DiskHealth.Healthy, "OK")]),
            NetworkAdapters = Of<IReadOnlyList<NetworkAdapterInfo>>([new("Wi-Fi", ["192.0.2.10"], "00-00-5E-00-53-01", true)]),
            Programs = Of<IReadOnlyList<InstalledProgram>>([]),
            Hotfixes = Of<IReadOnlyList<HotfixInfo>>([new("KB0000001", "Security Update", now.AddDays(-9))]),
            Drivers = Na<IReadOnlyList<DriverInfo>>("сбор драйверов отключён"),
            ProblemDevices = Of<IReadOnlyList<ProblemDevice>>([]),
            RebootPending = Of(false),
        };
        var cpu = Enumerable.Range(0, 120).Select(i => 70 + (i % 7) * 4.0).ToList();
        var perf = new PerformanceSession
        {
            Started = now.AddMinutes(-2), Duration = TimeSpan.FromMinutes(2), Interval = TimeSpan.FromSeconds(1), LogicalProcessors = 16,
            Samples = cpu.Select((c, i) => new PerformanceSample(TimeSpan.FromSeconds(i + 1), c, 88, 12, 52)).ToList(),
            TopByCpu = [new("browser", 4120, 38.5, 71, 1900L << 20, 1700L << 20), new("updater", 5012, 21.2, 40, 210L << 20, 180L << 20), new("explorer", 6120, 1.1, 6, 190L << 20, 120L << 20)],
            TopByMemory = [new("browser", 4120, 38.5, 71, 1900L << 20, 1700L << 20), new("chat", 7344, 0.6, 3, 640L << 20, 600L << 20), new("updater", 5012, 21.2, 40, 210L << 20, 180L << 20)],
            InaccessibleProcesses = 12,
            Thermal = Of<IReadOnlyList<ThermalZoneReading>>([new("TZ00", 94, 90, 72)]),
            Events = Of(new EventLogSummary(7, 3, [new("Microsoft-Windows-Kernel-Power", 41, EventCategory.UnexpectedShutdown, 2, 1, now.AddDays(-2))], false)),
        };
        var sec = new SecuritySnapshot
        {
            Accounts = Of<IReadOnlyList<LocalAccount>>([
                new("Администратор", "S-1-5-21-0-0-0-500", false, true, null), new("Гость", "S-1-5-21-0-0-0-501", false, false, null),
                new("DefaultAccount", "S-1-5-21-0-0-0-503", false, false, null), new("demo", "S-1-5-21-0-0-0-1001", true, true, now),
            ]),
            Groups = Of<IReadOnlyList<GroupInfo>>([new("Администраторы", GroupInfo.AdministratorsSid, [new("DEMO-PC\\demo", "S-1-5-21-0-0-0-1001", MemberKind.User)])]),
            CurrentUserSid = Of("S-1-5-21-0-0-0-1001"),
            Defender = Of(new DefenderStatus(true, true, true, 0, now, true, "Normal", 1, "4.18")),
            AntivirusProducts = Of<IReadOnlyList<SecurityProduct>>([new("Windows Defender", true, true)]),
            FirewallProducts = Of<IReadOnlyList<SecurityProduct>>([]),
            Threats = Of<IReadOnlyList<ThreatDetection>>([new("PUA:Win32/Demo", 1, [@"file:_C:\Users\demo\Downloads\setup.exe"], now.AddDays(-4), now.AddDays(-4), "в карантине", ThreatState.Resolved)]),
            Exclusions = Na<DefenderExclusions>(Probe.AccessDenied),
            Firewall = Of<IReadOnlyList<FirewallProfileState>>([new(FirewallProfile.Domain, true, false), new(FirewallProfile.Private, true, false), new(FirewallProfile.Public, false, false)]),
            Uac = Of(new UacSettings(true, 5, true)),
            BitLocker = Of<IReadOnlyList<VolumeProtection>>([new("C:", ProtectionState.Off, true)]),
            Rdp = Of(new RdpSettings(false, true, 3389)),
            Smb1Enabled = Of(false),
            Shares = Of<IReadOnlyList<ShareInfo>>([]),
            WinRm = Of(new ServiceState("WinRM", "Stopped", "Manual")),
            Autoruns = Of<IReadOnlyList<AutorunEntry>>([
                new(AutorunLocation.RunKey, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Chat", @"""C:\Users\demo\AppData\Local\Chat\chat.exe"" --tray",
                    @"C:\Users\demo\AppData\Local\Chat\chat.exe", true, SignatureState.Valid, "Contoso Ltd", true, false),
                new(AutorunLocation.RunKey, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", @"C:\Users\demo\AppData\Local\Temp\upd\updater.exe /silent",
                    @"C:\Users\demo\AppData\Local\Temp\upd\updater.exe", true, SignatureState.NotSigned, null, true, false),
            ]),
            Winlogon = Of(new WinlogonSettings("explorer.exe", @"C:\Windows\system32\userinit.exe,")),
            EditionId = "Professional", IsPortable = true, PartOfDomain = false,
        };
        var net = new NetworkSnapshot
        {
            Listeners = Of<IReadOnlyList<ListeningSocket>>([
                new(Protocol.Tcp, "0.0.0.0", 3389, 1100, "svchost", @"C:\Windows\System32\svchost.exe", ["TermService"]),
                new(Protocol.Tcp, "127.0.0.1", 5939, 2200, "helper", @"C:\Program Files\Helper\helper.exe", []),
            ]),
            FirewallRules = Of<IReadOnlyList<FirewallRule>>([new("Удалённый рабочий стол (TCP-In)", true, true, true, 6, "3389", null, FirewallProfiles.All, null)]),
            ActiveProfiles = Of(4),
        };
        var clean = new CleanupPreview(now,
        [
            new(CleanupCategory.UserTemp, "Временные файлы пользователя", "Программы складывают сюда промежуточные файлы и часто не удаляют их за собой.",
                @"C:\Users\demo\AppData\Local\Temp", 4210, 3_400_000_000, [], true, "Удаляются только файлы старше 24 часов. Файлы, занятые запущенными программами, будут пропущены."),
            new(CleanupCategory.RecycleBin, "Корзина", "Файлы, которые вы удалили, но ещё можете восстановить.", null, 37, 1_200_000_000, [], false,
                "Очистка корзины необратима: удалённые файлы нельзя будет восстановить средствами Windows."),
            new(CleanupCategory.LargeFiles, "Крупные файлы", "Файлы от 500 МБ в папке пользователя — для информации.", @"C:\Users\demo", 2, 9_800_000_000,
                [new(@"C:\Users\demo\Videos\vacation.mp4", 6_100_000_000, now.AddMonths(-8)), new(@"C:\Users\demo\Downloads\distr.iso", 3_700_000_000, now.AddMonths(-3))], false,
                "NEXORA не предлагает удалять эти файлы: размер и возраст не говорят о том, что файл не нужен."),
        ]);

        var results = new List<CheckResult>();
        results.AddRange(PerformanceAnalyzer.Analyze(perf));
        results.AddRange(InventoryAnalyzer.Analyze(inv, now));
        results.AddRange(AccountsAnalyzer.Analyze(sec, now));
        results.AddRange(ProtectionAnalyzer.Analyze(sec));
        results.AddRange(RemoteAccessAnalyzer.Analyze(sec));
        results.AddRange(AutorunAnalyzer.Analyze(sec));
        results.AddRange(MalwareAssessment.Analyze(sec, now));
        results.AddRange(NetworkAnalyzer.Analyze(net));
        results.AddRange(CleanupAnalyzer.Analyze(clean));
        var doc = new ReportDocument
        {
            Meta = new ReportMeta(Product.Name, Product.Version, now.AddMinutes(-2), TimeSpan.FromSeconds(131), "DEMO-PC",
                "Windows 11 Pro 25H2 (демонстрационные данные)", false, Assessment.From(results).Summary),
            Findings = results.Select(r => ReportedFinding.From(r)).ToList(),
            ExecutedModules = ["Производительность (120 с)", "Инвентаризация", "Безопасность и пользователи", "Сеть", "Файлы (просмотр)"],
            SkippedModules = [],
        };
        return new ScanResult { Inventory = inv, Performance = perf, Security = sec, Network = net, Cleanup = clean, Results = results, Document = doc };
    }
}
