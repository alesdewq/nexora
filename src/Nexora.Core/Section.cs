namespace Nexora.Core;

public enum Section
{
    Overview,
    Performance,
    Security,
    Users,
    Network,
    FilesAndPrograms,
    Reports,
    History,
}

public static class SectionText
{
    public static string ToDisplay(this Section s) => s switch
    {
        Section.Overview => "Обзор",
        Section.Performance => "Производительность",
        Section.Security => "Безопасность",
        Section.Users => "Пользователи",
        Section.Network => "Сеть",
        Section.FilesAndPrograms => "Файлы и программы",
        Section.Reports => "Отчёты",
        Section.History => "История",
        _ => throw new ArgumentOutOfRangeException(nameof(s), s, null),
    };
}
