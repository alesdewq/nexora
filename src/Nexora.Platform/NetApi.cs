using System.Runtime.InteropServices;
using System.Security.Principal;
using Nexora.SecurityAudit;

namespace Nexora.Platform;

/// <summary>Состав локальных групп через NetLocalGroupGetMembers; группы ищутся по SID (имена локализованы).</summary>
public static partial class NetApi
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_2 { public IntPtr Sid; public int SidUsage; public IntPtr DomainAndName; }

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetLocalGroupGetMembers(string? server, string group, int level, out IntPtr buffer, int prefMax,
        out int read, out int total, IntPtr resume);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    public static string NameOfSid(string sid)
    {
        var name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        var slash = name.IndexOf('\\');
        return slash >= 0 ? name[(slash + 1)..] : name;
    }

    public static GroupInfo Group(string sid)
    {
        var name = NameOfSid(sid);
        var status = NetLocalGroupGetMembers(null, name, 2, out var buffer, -1, out var read, out _, IntPtr.Zero);
        if (status == 5) throw new UnauthorizedAccessException();
        if (status != 0) throw new InvalidOperationException($"NetLocalGroupGetMembers({name}): {status}");
        try
        {
            var members = new List<GroupMember>();
            var size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
            for (var i = 0; i < read; i++)
            {
                var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buffer + i * size);
                var memberSid = new SecurityIdentifier(m.Sid).Value;
                // SID_NAME_USE: 1 пользователь, 2 группа домена, 4 локальная группа, 5 встроенная группа, 6/7/8 — удалённая или неразрешимая запись.
                var kind = m.SidUsage switch { 1 => MemberKind.User, 2 or 4 => MemberKind.Group, 5 => MemberKind.WellKnown, 6 or 7 or 8 => MemberKind.Deleted, _ => MemberKind.Unknown };
                members.Add(new GroupMember(Marshal.PtrToStringUni(m.DomainAndName) ?? memberSid, memberSid, kind));
            }
            return new GroupInfo(name, sid, members);
        }
        finally { _ = NetApiBufferFree(buffer); }
    }
}
