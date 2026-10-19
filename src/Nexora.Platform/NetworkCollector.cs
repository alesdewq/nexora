using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using Nexora.NetworkAudit;

namespace Nexora.Platform;

/// <summary>Локальные сокеты и правила брандмауэра. Только чтение; сетевые подключения не создаются, другие хосты не сканируются.</summary>
public static partial class NetworkCollector
{
    public static NetworkSnapshot Collect()
    {
        var firewall = Probe.Try("COM HNetCfg.FwPolicy2", () => Sta.Run(ReadFirewall));
        return new NetworkSnapshot
        {
            Listeners = Probe.List("Win32 GetExtendedTcpTable/GetExtendedUdpTable", Listeners),
            FirewallRules = firewall.IsAvailable
                ? Measured<IReadOnlyList<FirewallRule>>.Of(firewall.Value.Rules, firewall.Source)
                : Measured<IReadOnlyList<FirewallRule>>.Unavailable(firewall.Source, firewall.Reason!),
            ActiveProfiles = firewall.IsAvailable
                ? Measured<int>.Of(firewall.Value.ActiveProfiles, firewall.Source)
                : Measured<int>.Unavailable(firewall.Source, firewall.Reason!),
        };
    }

    private const int AF_INET = 2, AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_LISTENER = 3, UDP_TABLE_OWNER_PID = 1;

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(IntPtr process, uint flags, char* buffer, ref int size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    private delegate uint TableFn(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);

    private static byte[] Table(TableFn fn, int af, int cls)
    {
        var size = 0;
        _ = fn(IntPtr.Zero, ref size, false, af, cls, 0);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                var rc = fn(buf, ref size, false, af, cls, 0);
                if (rc == 0) { var bytes = new byte[size]; Marshal.Copy(buf, bytes, 0, size); return bytes; }
                if (rc != 122) throw new InvalidOperationException($"iphlpapi: {rc}"); // 122 — буфер мал, таблица выросла
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        throw new InvalidOperationException("таблица сокетов меняется слишком быстро");
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    public static IEnumerable<ListeningSocket> Listeners()
    {
        var raw = new List<(Protocol P, string Addr, int Port, int Pid)>();
        var t4 = Table(GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_LISTENER);
        for (int i = 0, n = BinaryPrimitives.ReadInt32LittleEndian(t4); i < n; i++)
        {
            var row = t4.AsSpan(4 + i * 24, 24);
            raw.Add((Protocol.Tcp, new IPAddress(row.Slice(4, 4)).ToString(), Port(BinaryPrimitives.ReadUInt32LittleEndian(row[8..])), BinaryPrimitives.ReadInt32LittleEndian(row[20..])));
        }
        var t6 = Table(GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER);
        for (int i = 0, n = BinaryPrimitives.ReadInt32LittleEndian(t6); i < n; i++)
        {
            var row = t6.AsSpan(4 + i * 56, 56);
            raw.Add((Protocol.Tcp, new IPAddress(row[..16]).ToString(), Port(BinaryPrimitives.ReadUInt32LittleEndian(row[20..])), BinaryPrimitives.ReadInt32LittleEndian(row[52..])));
        }
        var u4 = Table(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID);
        for (int i = 0, n = BinaryPrimitives.ReadInt32LittleEndian(u4); i < n; i++)
        {
            var row = u4.AsSpan(4 + i * 12, 12);
            raw.Add((Protocol.Udp, new IPAddress(row[..4]).ToString(), Port(BinaryPrimitives.ReadUInt32LittleEndian(row[4..])), BinaryPrimitives.ReadInt32LittleEndian(row[8..])));
        }
        var u6 = Table(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID);
        for (int i = 0, n = BinaryPrimitives.ReadInt32LittleEndian(u6); i < n; i++)
        {
            var row = u6.AsSpan(4 + i * 28, 28);
            raw.Add((Protocol.Udp, new IPAddress(row[..16]).ToString(), Port(BinaryPrimitives.ReadUInt32LittleEndian(row[20..])), BinaryPrimitives.ReadInt32LittleEndian(row[24..])));
        }

        var services = new Dictionary<int, List<string>>();
        try
        {
            foreach (var s in Wmi.Query(Wmi.Cimv2, "SELECT Name, ProcessId FROM Win32_Service WHERE ProcessId <> 0"))
            {
                var pid = (int)(s.Get<uint?>("ProcessId") ?? 0);
                if (!services.TryGetValue(pid, out var l)) services[pid] = l = [];
                l.Add(s.Str("Name") ?? "?");
            }
        }
        catch (System.Management.ManagementException) { /* привязка к службам необязательна */ }

        var names = new Dictionary<int, (string?, string?)>();
        foreach (var r in raw.Distinct())
        {
            if (!names.TryGetValue(r.Pid, out var proc)) names[r.Pid] = proc = ProcessInfo(r.Pid);
            yield return new ListeningSocket(r.P, r.Addr, r.Port, r.Pid, proc.Item1, proc.Item2,
                services.TryGetValue(r.Pid, out var svc) ? svc : []);
        }
    }

    private static unsafe (string? Name, string? Path) ProcessInfo(int pid)
    {
        if (pid == 0) return ("System Idle", null);
        if (pid == 4) return ("System", null);
        string? name = null;
        try { using var p = System.Diagnostics.Process.GetProcessById(pid); name = p.ProcessName; }
        catch (ArgumentException) { }
        catch (InvalidOperationException) { }
        var h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (h == IntPtr.Zero) return (name, null);
        try
        {
            var buffer = stackalloc char[1024];
            var size = 1024;
            return QueryFullProcessImageName(h, 0, buffer, ref size) ? (name, new string(buffer, 0, size)) : (name, null);
        }
        finally { _ = CloseHandle(h); }
    }

    private sealed record FirewallData(IReadOnlyList<FirewallRule> Rules, int ActiveProfiles);

    private static FirewallData ReadFirewall()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new InvalidOperationException("HNetCfg.FwPolicy2 недоступен");
        dynamic policy = Activator.CreateInstance(type)!;
        var rules = new List<FirewallRule>();
        foreach (dynamic r in policy.Rules)
        {
            int profiles = r.Profiles;
            rules.Add(new FirewallRule((string)r.Name, (bool)r.Enabled, (int)r.Direction == 1, (int)r.Action == 1, (int)r.Protocol,
                (string?)r.LocalPorts, (string?)r.ApplicationName,
                profiles == 0x7FFFFFFF ? FirewallProfiles.All : (FirewallProfiles)(profiles & 7), (string?)r.serviceName));
        }
        return new FirewallData(rules, (int)policy.CurrentProfileTypes);
    }
}
