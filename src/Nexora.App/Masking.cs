using Nexora.Platform;
using Nexora.Reporting;

namespace Nexora.App;

/// <summary>Параметры маскирования для конкретной проверки: имя компьютера, локальные учётные записи, профиль.</summary>
internal sealed record Masking(MaskOptions Options)
{
    public static Masking For(ScanResult? scan)
    {
        var users = new List<string> { Environment.UserName };
        if (scan?.Security?.Accounts is { IsAvailable: true } accounts) users.AddRange(accounts.Value.Select(a => a.Name));
        return new Masking(new MaskOptions(Environment.MachineName, users, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)));
    }

    public ReportDocument Apply(ReportDocument doc) => ReportMasker.Mask(doc, Options);
}
