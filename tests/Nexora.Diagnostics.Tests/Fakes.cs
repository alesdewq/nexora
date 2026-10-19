using Nexora.Diagnostics.Inventory;

namespace Nexora.Diagnostics.Tests;

internal static class Fakes
{
    public static Measured<T> Of<T>(T v) => Measured<T>.Of(v, "fake");
    public static Measured<T> Na<T>(string reason = "нет источника") => Measured<T>.Unavailable("fake", reason);

    public static OsInfo Os(int build = 19045, string edition = "Core", DateTimeOffset? boot = null) => new()
    {
        ProductName = Of("Windows 10 Home"), EditionId = Of(edition), DisplayVersion = Of("22H2"),
        Build = Of(build), Ubr = Of(6456), Architecture = Of("64-bit"),
        LastBoot = Of(boot ?? new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero)), InstallDate = Na<DateTimeOffset>(),
    };

    public static InventorySnapshot Snapshot(OsInfo? os = null) => new()
    {
        Os = os ?? Os(),
        Computer = new ComputerInfo
        {
            ComputerName = Of("PC"), Manufacturer = Of("Acme"), Model = Of("X"), IsPortable = Of(true), PartOfDomain = Of(false),
            CpuName = Of("Intel"), CpuCores = Of(8), CpuLogicalProcessors = Of(12), TotalMemoryBytes = Of(16L << 30),
        },
        LogicalDisks = Of<IReadOnlyList<LogicalDiskInfo>>([new("C:", "NTFS", 500L << 30, 200L << 30, true)]),
        PhysicalDisks = Of<IReadOnlyList<PhysicalDiskInfo>>([new("NVMe", "SSD", "NVMe", 512L << 30, DiskHealth.Healthy, "OK")]),
        NetworkAdapters = Of<IReadOnlyList<NetworkAdapterInfo>>([]),
        Programs = Of<IReadOnlyList<InstalledProgram>>([]),
        Hotfixes = Of<IReadOnlyList<HotfixInfo>>([new("KB1", "Security Update", new DateTimeOffset(2026, 10, 15, 0, 0, 0, TimeSpan.Zero))]),
        Drivers = Na<IReadOnlyList<DriverInfo>>(),
        ProblemDevices = Of<IReadOnlyList<ProblemDevice>>([]),
        RebootPending = Of(false),
    };
}
