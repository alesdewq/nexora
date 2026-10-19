using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Nexora.SecurityAudit;

namespace Nexora.Platform;

/// <summary>
/// Проверка встроенной цифровой подписи (WinVerifyTrust) БЕЗ обращения к сети: отзыв сертификатов не проверяется,
/// цепочка строится только из локального кэша. Каталожные подписи (большинство системных файлов Windows) не проверяются.
/// </summary>
public static partial class Authenticode
{
    private static readonly ConcurrentDictionary<string, (SignatureState, string?)> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static Guid _genericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO { public uint cbStruct; public IntPtr pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public uint dwUIChoice; public uint fdwRevocationChecks;
        public uint dwUnionChoice; public IntPtr pFile; public uint dwStateAction; public IntPtr hWVTStateData; public IntPtr pwszURLReference;
        public uint dwProvFlags; public uint dwUIContext; public IntPtr pSignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    public static (SignatureState State, string? Publisher) Check(string path) => Cache.GetOrAdd(path, CheckCore);

    private static (SignatureState, string?) CheckCore(string path)
    {
        if (!File.Exists(path)) return (SignatureState.NotChecked, null);
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pathPtr };
        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = WTD_UI_NONE, fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE, pFile = filePtr, dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            var hr = (uint)WinVerifyTrust(IntPtr.Zero, ref _genericVerifyV2, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            _ = WinVerifyTrust(IntPtr.Zero, ref _genericVerifyV2, ref data);
            var state = hr switch
            {
                0 => SignatureState.Valid,
                0x800B0100 or 0x800B0003 or 0x800B0001 => SignatureState.NotSigned,
                _ => SignatureState.Invalid,
            };
            return (state, state == SignatureState.Valid ? Publisher(path) : null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (SignatureState.NotChecked, null);
        }
        finally
        {
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    private static string? Publisher(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // нужен сертификат из подписи PE-файла; X509CertificateLoader такого не умеет
            using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            using var c2 = new X509Certificate2(cert);
            return c2.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (System.Security.Cryptography.CryptographicException) { return null; }
    }
}
