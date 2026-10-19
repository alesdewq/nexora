namespace Nexora.SecurityAudit;

/// <summary>
/// Эвристики по записям автозапуска. Ни одна эвристика не является доказательством заражения:
/// максимум — «средний» уровень и «средняя» уверенность, формулировки «стоит проверить».
/// </summary>
public static class AutorunAnalyzer
{
    public static IReadOnlyList<CheckResult> Analyze(SecuritySnapshot s)
    {
        if (!s.Autoruns.TryGetValue(out var entries))
            return [CheckResult.Unavailable("sec.autoruns", "Автозагрузка", Section.Security, s.Autoruns.Source, s.Autoruns.Reason!)];

        var results = new List<CheckResult>();
        foreach (var e in entries)
            if (Assess(e) is { } r) results.Add(r);

        var flagged = results.Count(r => r.Status == CheckStatus.Finding && r.Severity >= Severity.Medium);
        var byKind = entries.GroupBy(e => e.Location).Select(g => $"{LocationText(g.Key)}: {g.Count()}");
        results.Insert(0, CheckResult.Ok("sec.autoruns", "Автозагрузка", Section.Security,
            $"Проверено записей автозапуска: {entries.Count} ({string.Join(", ", byKind)}). Требуют внимания: {flagged}.",
            new Evidence(s.Autoruns.Source, $"{entries.Count} записей"), Confidence.Medium)
            with { Limitations = [
                "Проверяются ключи Run/RunOnce, папки «Автозагрузка», задания планировщика (кроме стандартных Microsoft) и службы сторонних производителей. Драйверы, расширения браузеров, WMI-подписки и другие способы автозапуска не проверяются.",
                "Подписи системных файлов Windows (подписанных через каталог) не проверяются.",
            ] });
        return results;
    }

    public static CheckResult? Assess(AutorunEntry e)
    {
        var id = $"sec.autorun.{StableId(e)}";
        var title = $"Автозапуск: {e.Name}";
        var ev = new Evidence(e.Where, $"{e.Command} | файл: {(e.FileExists switch { true => "существует", false => "не найден", _ => "?" })}, подпись: {SignatureText(e.Signature)}{(e.Publisher is null ? "" : $" ({e.Publisher})")}");
        var pattern = CommandLine.SuspiciousPattern(e.Command);
        var writable = CommandLine.IsUserWritableLocation(e.ImagePath, out var veryUnusual);

        if (pattern is not null)
            return CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.Heuristic, Confidence.Medium,
                $"{LocationText(e.Location)} «{e.Name}»: {pattern}.",
                "Так часто запускаются вредоносные программы, но так же делают и некоторые легитимные скрипты администраторов.",
                "Если вы не знаете, что это за запись, проверьте компьютер антивирусом и покажите запись специалисту. Отключить запись можно в разделе «Файлы и программы».", ev)
                with { Limitations = ["Эвристика по тексту команды; содержимое скрипта не анализируется."] };

        if (writable && e.Signature != SignatureState.Valid && e.FileExists == true)
            return CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.Heuristic, veryUnusual ? Confidence.Medium : Confidence.Low,
                $"{LocationText(e.Location)} «{e.Name}» запускает {(e.Signature == SignatureState.Invalid ? "файл с недействительной подписью" : "неподписанный файл")} из папки, доступной для записи обычному пользователю: {e.ImagePath}.",
                veryUnusual
                    ? "Временные, общие папки и «Загрузки» — нетипичное место для программ автозагрузки; так часто закрепляются вредоносные программы."
                    : "Многие нормальные программы (мессенджеры, обновляльщики) устанавливаются в профиль пользователя, но так же поступают и вредоносные.",
                "Проверьте, знаете ли вы эту программу. При сомнениях проверьте файл антивирусом; не удаляйте файлы вручную.", ev)
                with { Limitations = ["Отсутствие цифровой подписи не означает, что файл вредоносный."] };

        if (e.Location == AutorunLocation.Service && CommandLine.IsUnquotedPathWithSpaces(e.Command) && writable)
            return CheckResult.Finding(id, title, Section.Security, Severity.Medium, FindingKind.PotentialRisk, Confidence.Low,
                $"Путь службы «{e.Name}» содержит пробелы и не заключён в кавычки: {e.Command}.",
                "Если в одну из папок на этом пути может писать обычный пользователь, это позволяет подменить запускаемую программу.",
                "Сообщите производителю программы; исправление пути службы требует прав администратора.", ev);

        if (e.FileExists == false && e.Enabled)
            return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.Fact, Confidence.High,
                $"{LocationText(e.Location)} «{e.Name}» ссылается на отсутствующий файл {e.ImagePath}.",
                "Обычно это остаток удалённой программы; запись бесполезна, но не опасна.",
                "Запись можно отключить в разделе «Файлы и программы».", ev);

        if (writable && e.Signature == SignatureState.Valid && veryUnusual)
            return CheckResult.Finding(id, title, Section.Security, Severity.Info, FindingKind.Heuristic, Confidence.Low,
                $"{LocationText(e.Location)} «{e.Name}» запускает подписанный файл ({e.Publisher}) из нетипичной папки: {e.ImagePath}.",
                "Подписанные программы редко запускаются из временных папок, но подпись говорит в пользу легитимности.",
                "Убедитесь, что знаете эту программу.", ev);
        return null;
    }

    public static string LocationText(AutorunLocation l) => l switch
    {
        AutorunLocation.RunKey => "Запись реестра Run",
        AutorunLocation.RunOnceKey => "Запись реестра RunOnce",
        AutorunLocation.StartupFolder => "Ярлык в папке «Автозагрузка»",
        AutorunLocation.ScheduledTask => "Задание планировщика",
        AutorunLocation.Service => "Служба",
        _ => l.ToString(),
    };

    public static string SignatureText(SignatureState s) => s switch
    {
        SignatureState.Valid => "действительна",
        SignatureState.NotSigned => "нет",
        SignatureState.Invalid => "недействительна",
        _ => "не проверялась",
    };

    /// <summary>Детерминированный идентификатор записи (FNV-1a), чтобы находки совпадали между отчётами.</summary>
    public static string StableId(AutorunEntry e)
    {
        var key = $"{e.Location}|{e.Where}|{e.Name}".ToLowerInvariant();
        uint h = 2166136261;
        foreach (var ch in key) { h ^= ch; h *= 16777619; }
        return h.ToString("x8", System.Globalization.CultureInfo.InvariantCulture);
    }
}
