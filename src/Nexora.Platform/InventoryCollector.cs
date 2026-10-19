using Microsoft.Win32;
using Nexora.Diagnostics.Inventory;

namespace Nexora.Platform;

/// <summary>Сбор сведений о системе. Только чтение.</summary>
public static class InventoryCollector
{
    private const string CurrentVersion = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    public static InventorySnapshot Collect(bool includeDrivers = true)
    {
        var os = Wmi.Source(Wmi.Cimv2, "Win32_OperatingSystem");
        var cs = Wmi.Source(Wmi.Cimv2, "Win32_ComputerSystem");
        var cpu = Wmi.Source(Wmi.Cimv2, "Win32_Processor");
        var osObj = new Lazy<System.Management.ManagementBaseObject?>(() => Wmi.First(Wmi.Cimv2,
            "SELECT Caption, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate FROM Win32_OperatingSystem"));
        var csObj = new Lazy<System.Management.ManagementBaseObject?>(() => Wmi.First(Wmi.Cimv2,
            "SELECT Name, Manufacturer, Model, PartOfDomain, TotalPhysicalMemory FROM Win32_ComputerSystem"));
        var cpus = new Lazy<List<System.Management.ManagementBaseObject>>(() => Wmi.Query(Wmi.Cimv2,
            "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"));

        return new InventorySnapshot
        {
            Os = new OsInfo
            {
                ProductName = Probe.Try(os, () => ProductName()),
                EditionId = Probe.Try(Reg.Source(RegistryHive.LocalMachine, CurrentVersion, "EditionID"),
                    () => Reg.Str(RegistryHive.LocalMachine, CurrentVersion, "EditionID")),
                DisplayVersion = Probe.Try(Reg.Source(RegistryHive.LocalMachine, CurrentVersion, "DisplayVersion"),
                    () => Reg.Str(RegistryHive.LocalMachine, CurrentVersion, "DisplayVersion")),
                Build = Probe.TryValue(os, () => int.TryParse(osObj.Value?.Str("BuildNumber"), out var b) ? b : (int?)null),
                Ubr = Probe.TryValue(Reg.Source(RegistryHive.LocalMachine, CurrentVersion, "UBR"),
                    () => Reg.Dword(RegistryHive.LocalMachine, CurrentVersion, "UBR")),
                Architecture = Probe.Try(os, () => osObj.Value?.Str("OSArchitecture")),
                LastBoot = Probe.TryValue(os, () => osObj.Value?.Date("LastBootUpTime")),
                InstallDate = Probe.TryValue(os, () => osObj.Value?.Date("InstallDate")),
            },
            Computer = new ComputerInfo
            {
                ComputerName = Probe.Try("Environment.MachineName", () => Environment.MachineName),
                Manufacturer = Probe.Try(cs, () => csObj.Value?.Str("Manufacturer")),
                Model = Probe.Try(cs, () => csObj.Value?.Str("Model")),
                IsPortable = Probe.TryValue(Wmi.Source(Wmi.Cimv2, "Win32_SystemEnclosure.ChassisTypes"), IsPortable, "тип корпуса не указан"),
                PartOfDomain = Probe.TryValue(cs, () => csObj.Value?.Get<bool?>("PartOfDomain")),
                CpuName = Probe.Try(cpu, () => cpus.Value.FirstOrDefault()?.Str("Name")),
                CpuCores = Probe.TryValue(cpu, () => cpus.Value.Count == 0 ? (int?)null : cpus.Value.Sum(c => c.Get<int>("NumberOfCores"))),
                CpuLogicalProcessors = Probe.TryValue("Environment.ProcessorCount", () => (int?)Environment.ProcessorCount),
                TotalMemoryBytes = Probe.TryValue(cs, () => csObj.Value?.Get<long?>("TotalPhysicalMemory")),
            },
            LogicalDisks = Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_LogicalDisk"), LogicalDisks),
            PhysicalDisks = Probe.List(Wmi.Source(Wmi.Storage, "MSFT_PhysicalDisk"), PhysicalDisks),
            NetworkAdapters = Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_NetworkAdapterConfiguration"), Adapters),
            Programs = Probe.List(@"Реестр ...\CurrentVersion\Uninstall (HKLM 64/32, HKCU)", InstalledPrograms.Read),
            Hotfixes = Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_QuickFixEngineering"), Hotfixes),
            Drivers = includeDrivers
                ? Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_PnPSignedDriver"), Drivers)
                : Measured<IReadOnlyList<DriverInfo>>.Unavailable(Wmi.Source(Wmi.Cimv2, "Win32_PnPSignedDriver"), "сбор драйверов отключён"),
            ProblemDevices = Probe.List(Wmi.Source(Wmi.Cimv2, "Win32_PnPEntity"), ProblemDevices),
            RebootPending = Probe.TryValue("Реестр: Component Based Servicing\\RebootPending, WindowsUpdate\\Auto Update\\RebootRequired", () => (bool?)RebootPending()),
        };
    }

    private static string? ProductName()
    {
        // ProductName в реестре у Windows 11 по-прежнему «Windows 10 …» — название строится по номеру сборки.
        var caption = Wmi.First(Wmi.Cimv2, "SELECT Caption FROM Win32_OperatingSystem")?.Str("Caption");
        return caption?.Replace("Майкрософт ", "").Replace("Microsoft ", "");
    }

    private static readonly HashSet<ushort> PortableChassis = [8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32];

    private static bool? IsPortable()
    {
        foreach (var e in Wmi.Query(Wmi.Cimv2, "SELECT ChassisTypes FROM Win32_SystemEnclosure"))
            if (e["ChassisTypes"] is ushort[] types && types.Length > 0)
                return types.Any(PortableChassis.Contains);
        return null;
    }

    private static IEnumerable<LogicalDiskInfo> LogicalDisks()
    {
        var sys = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');
        return Wmi.Query(Wmi.Cimv2, "SELECT DeviceID, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3")
            .Select(d => new LogicalDiskInfo(d.Str("DeviceID") ?? "?", d.Str("FileSystem"),
                (long)(d.Get<ulong?>("Size") ?? 0), (long)(d.Get<ulong?>("FreeSpace") ?? 0),
                string.Equals(d.Str("DeviceID"), sys, StringComparison.OrdinalIgnoreCase)));
    }

    private static IEnumerable<PhysicalDiskInfo> PhysicalDisks() =>
        Wmi.Query(Wmi.Storage, "SELECT FriendlyName, MediaType, BusType, Size, HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk")
            .Select(d => new PhysicalDiskInfo(
                d.Str("FriendlyName") ?? "диск",
                d.Get<ushort?>("MediaType") switch { 3 => "HDD", 4 => "SSD", 5 => "SCM", _ => "не указан" },
                d.Get<ushort?>("BusType") switch { 7 => "USB", 8 => "RAID", 10 => "SAS", 11 => "SATA", 12 => "SD", 17 => "NVMe", 15 => "File-backed", var b => $"код {b}" },
                (long)(d.Get<ulong?>("Size") ?? 0),
                d.Get<ushort?>("HealthStatus") switch { 0 => DiskHealth.Healthy, 1 => DiskHealth.Warning, 2 => DiskHealth.Unhealthy, _ => DiskHealth.Unknown },
                d["OperationalStatus"] is ushort[] st ? string.Join(",", st.Select(OperationalText)) : "не указан"));

    private static string OperationalText(ushort s) => s switch
    {
        2 => "OK", 3 => "Degraded", 5 => "Predictive Failure", 6 => "Error", 10 => "Stopped", 11 => "In Service",
        13 => "Lost Communication", 0xD00A => "Not Usable", 0xD00B => "Transient Error", _ => $"код {s}",
    };

    private static IEnumerable<NetworkAdapterInfo> Adapters() =>
        Wmi.Query(Wmi.Cimv2, "SELECT Description, IPAddress, MACAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")
            .Select(a => new NetworkAdapterInfo(a.Str("Description") ?? "адаптер",
                a["IPAddress"] as string[] ?? [], a.Str("MACAddress"), a.Get<bool?>("DHCPEnabled") ?? false));

    private static IEnumerable<HotfixInfo> Hotfixes() =>
        Wmi.Query(Wmi.Cimv2, "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering")
            .Select(h => new HotfixInfo(h.Str("HotFixID") ?? "?", h.Str("Description"), ParseHotfixDate(h.Str("InstalledOn"))));

    /// <summary>InstalledOn бывает «M/d/yyyy», «yyyyMMdd» или шестнадцатеричным FILETIME.</summary>
    public static DateTimeOffset? ParseHotfixDate(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        if (DateTime.TryParseExact(s, ["M/d/yyyy", "MM/dd/yyyy", "yyyyMMdd"], inv, System.Globalization.DateTimeStyles.AssumeLocal, out var d))
            return new DateTimeOffset(d);
        if (long.TryParse(s, System.Globalization.NumberStyles.HexNumber, inv, out var ft) && ft > 0)
            try { return DateTimeOffset.FromFileTime(ft); } catch (ArgumentOutOfRangeException) { }
        return null;
    }

    private static IEnumerable<DriverInfo> Drivers() =>
        Wmi.Query(Wmi.Cimv2, "SELECT DeviceName, DriverVersion, DriverDate, DriverProviderName, IsSigned FROM Win32_PnPSignedDriver", TimeSpan.FromSeconds(90))
            .Where(d => d.Str("DeviceName") is not null)
            .Select(d => new DriverInfo(d.Str("DeviceName")!, d.Str("DriverVersion"), d.Date("DriverDate"), d.Str("DriverProviderName"), d.Get<bool?>("IsSigned")));

    private static IEnumerable<ProblemDevice> ProblemDevices() =>
        Wmi.Query(Wmi.Cimv2, "SELECT Name, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0")
            .Select(d => new ProblemDevice(d.Str("Name") ?? "устройство без имени", (int)(d.Get<uint?>("ConfigManagerErrorCode") ?? 0)));

    private static bool RebootPending() =>
        Reg.KeyExists(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
        || Reg.KeyExists(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
}
