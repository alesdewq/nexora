namespace Nexora.Diagnostics.Inventory;

/// <summary>Снимок сведений о системе. Каждое поле — значение с источником или «недоступно» с причиной.</summary>
public sealed record InventorySnapshot
{
    public required OsInfo Os { get; init; }
    public required ComputerInfo Computer { get; init; }
    public required Measured<IReadOnlyList<LogicalDiskInfo>> LogicalDisks { get; init; }
    public required Measured<IReadOnlyList<PhysicalDiskInfo>> PhysicalDisks { get; init; }
    public required Measured<IReadOnlyList<NetworkAdapterInfo>> NetworkAdapters { get; init; }
    public required Measured<IReadOnlyList<InstalledProgram>> Programs { get; init; }
    public required Measured<IReadOnlyList<HotfixInfo>> Hotfixes { get; init; }
    public required Measured<IReadOnlyList<DriverInfo>> Drivers { get; init; }
    public required Measured<IReadOnlyList<ProblemDevice>> ProblemDevices { get; init; }
    public required Measured<bool> RebootPending { get; init; }
}

public sealed record OsInfo
{
    public required Measured<string> ProductName { get; init; }
    /// <summary>EditionID из реестра: Core, Professional, Enterprise, EnterpriseS, Education, IoTEnterprise…</summary>
    public required Measured<string> EditionId { get; init; }
    public required Measured<string> DisplayVersion { get; init; }
    public required Measured<int> Build { get; init; }
    public required Measured<int> Ubr { get; init; }
    public required Measured<string> Architecture { get; init; }
    public required Measured<DateTimeOffset> LastBoot { get; init; }
    public required Measured<DateTimeOffset> InstallDate { get; init; }
}

public sealed record ComputerInfo
{
    public required Measured<string> ComputerName { get; init; }
    public required Measured<string> Manufacturer { get; init; }
    public required Measured<string> Model { get; init; }
    /// <summary>Тип корпуса по SMBIOS (ноутбук/настольный) — нужен для контекста BitLocker и перегрева.</summary>
    public required Measured<bool> IsPortable { get; init; }
    public required Measured<bool> PartOfDomain { get; init; }
    public required Measured<string> CpuName { get; init; }
    public required Measured<int> CpuCores { get; init; }
    public required Measured<int> CpuLogicalProcessors { get; init; }
    public required Measured<long> TotalMemoryBytes { get; init; }
}

public sealed record LogicalDiskInfo(string Name, string? FileSystem, long SizeBytes, long FreeBytes, bool IsSystem)
{
    public double FreePercent => SizeBytes <= 0 ? 0 : FreeBytes * 100.0 / SizeBytes;
}

public enum DiskHealth { Healthy, Warning, Unhealthy, Unknown }

public sealed record PhysicalDiskInfo(string Name, string MediaType, string BusType, long SizeBytes, DiskHealth Health, string OperationalStatus);

public sealed record NetworkAdapterInfo(string Description, IReadOnlyList<string> Addresses, string? MacAddress, bool DhcpEnabled);

public sealed record InstalledProgram(string Name, string? Version, string? Publisher, string? InstallDate, string Scope, bool HasUninstaller);

public sealed record HotfixInfo(string Id, string? Description, DateTimeOffset? InstalledOn);

public sealed record DriverInfo(string DeviceName, string? Version, DateTimeOffset? Date, string? Provider, bool? IsSigned);

/// <summary>Устройство с ненулевым кодом ошибки диспетчера устройств (ConfigManagerErrorCode).</summary>
public sealed record ProblemDevice(string Name, int ErrorCode);
