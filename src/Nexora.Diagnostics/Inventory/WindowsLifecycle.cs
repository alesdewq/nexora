namespace Nexora.Diagnostics.Inventory;

public enum SupportState
{
    Supported,
    EndingSoon,
    /// <summary>Основная поддержка завершена, но может действовать платная/корпоративная ESU — проверить нельзя.</summary>
    EndedEsuPossible,
    Ended,
    Unknown,
}

public sealed record LifecycleInfo(string Name, DateOnly? EndOfSupport, SupportState State, string Note);

/// <summary>
/// Сроки поддержки Windows 10/11 по данным Microsoft Lifecycle на дату сборки (октябрь 2026).
/// Таблица статична: для сборок новее известных возвращается <see cref="SupportState.Unknown"/>.
/// </summary>
public static class WindowsLifecycle
{
    public const string DataAsOf = "2026-10-19";
    public const int EndingSoonDays = 90;

    private enum Channel { Consumer, Enterprise, Ltsc, IotLtsc }

    // build → (название, Home/Pro, Enterprise/Education, LTSC, IoT LTSC)
    private static readonly Dictionary<int, (string Name, DateOnly? Consumer, DateOnly? Enterprise, DateOnly? Ltsc, DateOnly? IotLtsc)> Table = new()
    {
        [14393] = ("Windows 10 1607", new(2018, 4, 10), new(2019, 4, 9), new(2026, 10, 13), new(2026, 10, 13)),
        [17763] = ("Windows 10 1809", new(2020, 11, 10), new(2021, 5, 11), new(2029, 1, 9), new(2029, 1, 9)),
        [19041] = ("Windows 10 2004", new(2021, 12, 14), new(2021, 12, 14), null, null),
        [19042] = ("Windows 10 20H2", new(2022, 5, 10), new(2023, 5, 9), null, null),
        [19043] = ("Windows 10 21H1", new(2022, 12, 13), new(2022, 12, 13), null, null),
        [19044] = ("Windows 10 21H2", new(2023, 6, 13), new(2024, 6, 11), new(2027, 1, 12), new(2032, 1, 13)),
        [19045] = ("Windows 10 22H2", new(2025, 10, 14), new(2025, 10, 14), null, null),
        [22000] = ("Windows 11 21H2", new(2023, 10, 10), new(2024, 10, 8), null, null),
        [22621] = ("Windows 11 22H2", new(2024, 10, 8), new(2025, 10, 14), null, null),
        [22631] = ("Windows 11 23H2", new(2025, 11, 11), new(2026, 11, 10), null, null),
        [26100] = ("Windows 11 24H2", new(2026, 10, 13), new(2027, 10, 12), new(2029, 10, 9), new(2034, 10, 10)),
        [26200] = ("Windows 11 25H2", new(2027, 10, 12), new(2028, 10, 10), null, null),
    };

    public static bool IsWindows11(int build) => build >= 22000;

    public static LifecycleInfo Evaluate(int build, string? editionId, DateOnly today)
    {
        var channel = ChannelOf(editionId);
        if (!Table.TryGetValue(build, out var row))
        {
            var newer = build > Table.Keys.Max();
            return new(IsWindows11(build) ? $"Windows 11 (сборка {build})" : $"Windows (сборка {build})", null, SupportState.Unknown,
                newer ? "Сборка новее известных NEXORA — срок поддержки не определён." : "Сборка отсутствует в таблице сроков поддержки.");
        }

        DateOnly? end = channel switch
        {
            Channel.IotLtsc => row.IotLtsc ?? row.Enterprise,
            Channel.Ltsc => row.Ltsc ?? row.Enterprise,
            Channel.Enterprise => row.Enterprise,
            _ => row.Consumer,
        };
        var name = channel is Channel.Ltsc or Channel.IotLtsc && row.Ltsc is not null ? $"{row.Name} LTSC" : row.Name;
        if (end is null) return new(name, null, SupportState.Unknown, "Срок поддержки для этой редакции неизвестен.");

        if (today > end.Value)
        {
            // Для Windows 10 22H2 действует программа Extended Security Updates; её наличие локально проверить нельзя.
            if (build == 19045)
                return new(name, end, SupportState.EndedEsuPossible,
                    "Основная поддержка завершена. Обновления безопасности продолжают получать только устройства с ESU " +
                    "(потребительская ESU — до 13.10.2026, корпоративная — дольше); NEXORA не может проверить подписку ESU.");
            return new(name, end, SupportState.Ended, "Поддержка завершена: обновления безопасности больше не выпускаются.");
        }

        return end.Value.DayNumber - today.DayNumber <= EndingSoonDays
            ? new(name, end, SupportState.EndingSoon, "Поддержка скоро закончится.")
            : new(name, end, SupportState.Supported, "Версия поддерживается.");
    }

    private static Channel ChannelOf(string? editionId) => editionId switch
    {
        null => Channel.Consumer,
        _ when editionId.StartsWith("IoTEnterpriseS", StringComparison.OrdinalIgnoreCase) => Channel.IotLtsc,
        _ when editionId.StartsWith("EnterpriseS", StringComparison.OrdinalIgnoreCase) => Channel.Ltsc,
        _ when editionId.StartsWith("Enterprise", StringComparison.OrdinalIgnoreCase)
            || editionId.StartsWith("Education", StringComparison.OrdinalIgnoreCase)
            || editionId.StartsWith("IoTEnterprise", StringComparison.OrdinalIgnoreCase) => Channel.Enterprise,
        _ => Channel.Consumer,
    };

    public static string EditionDisplay(string? editionId) => editionId switch
    {
        "Core" or "CoreSingleLanguage" or "CoreCountrySpecific" => "Домашняя (Home)",
        "Professional" => "Pro",
        "ProfessionalWorkstation" => "Pro для рабочих станций",
        "Education" => "Education",
        "Enterprise" => "Enterprise",
        "EnterpriseS" => "Enterprise LTSC",
        "IoTEnterprise" => "IoT Enterprise",
        "IoTEnterpriseS" => "IoT Enterprise LTSC",
        null => "неизвестно",
        _ => editionId,
    };

    /// <summary>В Home-редакциях нет BitLocker, групповых политик и сервера RDP — это влияет на трактовку проверок.</summary>
    public static bool IsHomeEdition(string? editionId) =>
        editionId is not null && editionId.StartsWith("Core", StringComparison.OrdinalIgnoreCase);
}
