using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using Nexora.Cleanup;
using Nexora.Core;
using Nexora.Platform;
using Nexora.Platform.Actions;
using Nexora.Reporting;
using Nexora.SecurityAudit;

namespace Nexora.App.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly IDialogs _dialogs;
    private readonly ReportStore _store;
    private readonly ResolutionStore _resolutions;
    private readonly ActionJournal _journal;
    private CancellationTokenSource? _cts;
    private SectionViewModel _selected;
    private ScanResult? _scan;
    private ReportDocument? _report;

    public MainViewModel(IDialogs dialogs, ReportStore? store = null, ResolutionStore? resolutions = null, ActionJournal? journal = null)
    {
        _dialogs = dialogs;
        _store = store ?? new ReportStore(ReportStore.DefaultDirectory);
        _resolutions = resolutions ?? new ResolutionStore(ResolutionStore.DefaultFile);
        _journal = journal ?? new ActionJournal(ActionJournal.DefaultFile);

        Sections =
        [
            new(Section.Overview, "", "Сводка последней проверки: главное, что найдено, и что не удалось проверить."),
            new(Section.Performance, "", "Нагрузка процессора, памяти и диска, температура и системные ошибки. Отличаем короткие пики от устойчивой проблемы."),
            new(Section.Security, "", "Defender, брандмауэр, UAC, шифрование, удалённый доступ и автозагрузка — с учётом контекста."),
            new(Section.Users, "", "Локальные учётные записи и состав группы «Администраторы»."),
            new(Section.Network, "", "Какие порты этого компьютера ждут подключений и что о них говорит брандмауэр. Другие устройства не сканируются."),
            new(Section.FilesAndPrograms, "", "Временные файлы, корзина, крупные файлы, программы и автозагрузка. Любое изменение — только после вашего подтверждения."),
            new(Section.Reports, "", "Сохранение отчёта в HTML и JSON."),
            new(Section.History, "", "Сохранённые проверки и сравнение результатов во времени."),
        ];
        _selected = Sections[0];
        Durations = [new("30 секунд", TimeSpan.FromSeconds(30)), new("2 минуты", TimeSpan.FromMinutes(2)), new("5 минут", TimeSpan.FromMinutes(5))];
        _duration = Durations[0];

        ScanCommand = new AsyncCommand(_ => ScanAsync(), _ => !IsScanning);
        CancelCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsScanning);
        ExportHtmlCommand = new RelayCommand(_ => Export(html: true), _ => _report is not null);
        ExportJsonCommand = new RelayCommand(_ => Export(html: false), _ => _report is not null);
        OpenReportsFolderCommand = new RelayCommand(_ => OpenFolder(_store.Directory));
        OpenJournalCommand = new RelayCommand(_ => OpenFolder(Path.GetDirectoryName(_journal.File)!));
        CleanCommand = new AsyncCommand(p => CleanAsync((CategoryRow)p!), p => p is CategoryRow { CanCleanFiles: true } && !IsBusy);
        EmptyRecycleBinCommand = new AsyncCommand(p => EmptyRecycleBinAsync((CategoryRow)p!), p => p is CategoryRow { CanEmptyRecycleBin: true } && !IsBusy);
        UninstallCommand = new RelayCommand(p => Uninstall((ProgramRow)p!), p => p is ProgramRow { CanUninstall: true });
        ToggleAutorunCommand = new RelayCommand(p => ToggleAutorun((AutorunRow)p!), p => p is AutorunRow { CanToggle: true });
        RefreshHistoryCommand = new RelayCommand(_ => RefreshHistory());
        OpenHistoryCommand = new RelayCommand(p => OpenHistory((HistoryRow)p!), p => p is HistoryRow);
        CompareCommand = new RelayCommand(_ => Compare(), _ => CompareOlder is not null && CompareNewer is not null && CompareOlder != CompareNewer);

        RefreshHistory();
    }

    // ── Разделы ───────────────────────────────────────────────────────────────
    public IReadOnlyList<SectionViewModel> Sections { get; }
    public SectionViewModel Selected { get => _selected; set => Set(ref _selected, value); }
    public string VersionText { get; } = $"{Product.Name} {Product.Version} · без сети";

    // ── Проверка ──────────────────────────────────────────────────────────────
    public IReadOnlyList<DurationOption> Durations { get; }
    private DurationOption _duration;
    public DurationOption SelectedDuration { get => _duration; set => Set(ref _duration, value); }

    private bool _isScanning;
    public bool IsScanning { get => _isScanning; private set { if (Set(ref _isScanning, value)) OnChanged(nameof(IsBusy)); } }
    private bool _isActing;
    public bool IsBusy => _isScanning || _isActing;
    private string _progressText = "Проверка ещё не запускалась.";
    public string ProgressText { get => _progressText; private set => Set(ref _progressText, value); }
    private double _progress;
    public double ProgressValue { get => _progress; private set => Set(ref _progress, value); }

    public AsyncCommand ScanCommand { get; }
    public RelayCommand CancelCommand { get; }

    public bool IsElevated { get; } = Scanner.IsElevated();
    public string RightsText => IsElevated
        ? "NEXORA запущена с правами администратора. Для обычного просмотра они не нужны."
        : "NEXORA запущена без прав администратора. Некоторые проверки (например, исключения Defender, BitLocker) могут быть недоступны — они будут отмечены как «Не удалось проверить».";

    public async Task ScanAsync(ScanOptions? options = null)
    {
        IsScanning = true;
        _cts = new CancellationTokenSource();
        var progress = new Progress<ScanProgress>(p => { ProgressText = p.Stage; ProgressValue = p.Fraction * 100; });
        try
        {
            var result = await Scanner.RunAsync(options ?? new ScanOptions(SelectedDuration.Duration), progress, _resolutions, _cts.Token);
            _scan = result;
            try { _store.Save(result.Document); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { ProgressText = $"Отчёт не сохранён в историю: {ex.Message}"; }
            ShowReport(result.Document, live: true);
            ProgressText = $"Проверка завершена {result.Document.Meta.Started.ToLocalTime():dd.MM.yyyy HH:mm} за {result.Document.Meta.Duration.TotalSeconds:0} с.";
            RefreshHistory();
        }
        catch (OperationCanceledException)
        {
            ProgressText = "Проверка отменена. Система не изменялась.";
        }
        finally
        {
            IsScanning = false;
            _cts.Dispose();
            _cts = null;
        }
    }

    // ── Отображение отчёта ────────────────────────────────────────────────────
    private string _summary = "Нажмите «Начать проверку». NEXORA только читает сведения о системе и ничего не меняет.";
    public string Summary { get => _summary; private set => Set(ref _summary, value); }
    private string _reportInfo = "";
    public string ReportInfo { get => _reportInfo; private set => Set(ref _reportInfo, value); }
    private string _counts = "";
    public string Counts { get => _counts; private set => Set(ref _counts, value); }
    public bool HasReport => _report is not null;
    private bool _isLive;
    public bool IsLive { get => _isLive; private set => Set(ref _isLive, value); }

    public ObservableCollection<ProcessRow> TopCpu { get; } = [];
    public ObservableCollection<ProcessRow> TopMemory { get; } = [];
    public ObservableCollection<AccountRow> Accounts { get; } = [];
    public ObservableCollection<ListenerRow> Listeners { get; } = [];
    public ObservableCollection<CategoryRow> Categories { get; } = [];
    public ObservableCollection<ProgramRow> Programs { get; } = [];
    public ObservableCollection<AutorunRow> Autoruns { get; } = [];

    private void ShowReport(ReportDocument doc, bool live)
    {
        _report = doc;
        IsLive = live;
        OnChanged(nameof(HasReport));
        var vms = doc.Findings.Select(f => new FindingViewModel(f, _resolutions)).ToList();
        foreach (var s in Sections)
        {
            s.SetFindings(s.Section switch
            {
                Section.Overview => vms.Where(f => f.Model.Section == Section.Overview || (f.IsFinding && f.Model.Severity >= Severity.Medium)),
                Section.Reports or Section.History => [],
                _ => vms.Where(f => f.Model.Section == s.Section),
            });
        }
        var c = doc.CountBySeverity();
        Summary = doc.Meta.Summary;
        Counts = $"⛔ Критический: {c.GetValueOrDefault(Severity.Critical)}   ▲ Высокий: {c.GetValueOrDefault(Severity.High)}   ◆ Средний: {c.GetValueOrDefault(Severity.Medium)}   " +
                 $"ℹ Информация: {c.GetValueOrDefault(Severity.Info)}   ? Не удалось проверить: {doc.NotCheckedCount}";
        ReportInfo = $"{(live ? "Текущая проверка" : "Отчёт из истории")}: {doc.Meta.Started.ToLocalTime():dd.MM.yyyy HH:mm}, {doc.Meta.OsSummary}. " +
                     $"Выполнено: {string.Join(", ", doc.ExecutedModules)}." +
                     (doc.SkippedModules.Count > 0 ? $" Пропущено: {string.Join("; ", doc.SkippedModules.Select(s => $"{s.Module} ({s.Reason})"))}." : "") +
                     (live ? "" : " Таблицы процессов, портов и файлов доступны только для текущей проверки.");
        FillTables(live ? _scan : null);
    }

    private void FillTables(ScanResult? scan)
    {
        TopCpu.Clear(); TopMemory.Clear(); Accounts.Clear(); Listeners.Clear(); Categories.Clear(); Programs.Clear(); Autoruns.Clear();
        if (scan is null) return;
        foreach (var p in scan.Performance?.TopByCpu ?? []) TopCpu.Add(ProcessRow.From(p));
        foreach (var p in scan.Performance?.TopByMemory ?? []) TopMemory.Add(ProcessRow.From(p));
        if (scan.Security is { } sec && sec.Accounts.TryGetValue(out var accounts))
        {
            var admins = sec.Groups.IsAvailable ? sec.Groups.Value.FirstOrDefault(g => g.Sid == GroupInfo.AdministratorsSid) : null;
            foreach (var a in accounts)
                Accounts.Add(new AccountRow(a.Name, a.Enabled ? "включена" : "отключена",
                    a.IsSystemManaged ? "служебная Windows" : a.IsBuiltInAdministrator ? "встроенный администратор" : a.IsGuest ? "гость" : "пользователь",
                    a.LastLogon?.ToLocalTime().ToString("dd.MM.yyyy HH:mm", System.Globalization.CultureInfo.InvariantCulture) ?? "нет данных",
                    admins is null ? "нет данных" : admins.Members.Any(m => m.Sid == a.Sid) ? "да" : "нет"));
        }
        if (scan.Network is { } net && net.Listeners.TryGetValue(out var socks))
            foreach (var l in socks.OrderBy(x => x.IsLoopbackOnly).ThenBy(x => x.Protocol).ThenBy(x => x.Port)) Listeners.Add(ListenerRow.From(l));
        foreach (var c in scan.Cleanup?.Categories ?? []) Categories.Add(new CategoryRow(c));
        try
        {
            foreach (var e in InstalledPrograms.ReadEntries().GroupBy(e => (e.Program.Name, e.Program.Version)).Select(g => g.First())
                         .OrderBy(e => e.Program.Name, StringComparer.CurrentCultureIgnoreCase))
                Programs.Add(new ProgramRow(e, UninstallActions.Prepare(e) is not null));
        }
        catch (UnauthorizedAccessException) { }
        if (scan.Security is { } s2 && s2.Autoruns.TryGetValue(out var autoruns))
            foreach (var a in autoruns.OrderBy(a => a.Location).ThenBy(a => a.Name, StringComparer.CurrentCulture)) Autoruns.Add(new AutorunRow(a));
    }

    // ── Отчёты ────────────────────────────────────────────────────────────────
    private bool _mask = true;
    public bool MaskOnExport { get => _mask; set => Set(ref _mask, value); }
    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ExportJsonCommand { get; }
    public RelayCommand OpenReportsFolderCommand { get; }
    public RelayCommand OpenJournalCommand { get; }
    public string ReportsFolder => _store.Directory;

    private void Export(bool html)
    {
        if (_report is null) return;
        if (!_dialogs.Confirm("Экспорт отчёта",
                "Отчёт может содержать имена учётных записей, имя компьютера, локальные IP-адреса и пути к файлам.\n\n" +
                (MaskOnExport ? "Включено маскирование: эти сведения будут заменены метками. " : "Маскирование ВЫКЛЮЧЕНО: сведения попадут в файл как есть. ") +
                "Передавайте отчёт только тем, кому доверяете. Продолжить?")) return;
        var stamp = _report.Meta.Started.ToLocalTime().ToString("yyyyMMdd-HHmm", System.Globalization.CultureInfo.InvariantCulture);
        var path = _dialogs.SaveFile($"nexora-{stamp}.{(html ? "html" : "json")}", html ? "HTML-отчёт|*.html" : "JSON|*.json");
        if (path is null) return;
        var doc = MaskOnExport ? Masking.For(IsLive ? _scan : null).Apply(_report) : _report;
        File.WriteAllText(path, html ? HtmlReport.Render(doc) : doc.ToJson(), new UTF8Encoding(false));
        _dialogs.Info("Отчёт сохранён", path);
    }

    private static void OpenFolder(string dir)
    {
        Directory.CreateDirectory(dir);
        using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = false });
    }

    // ── История ───────────────────────────────────────────────────────────────
    public ObservableCollection<HistoryRow> History { get; } = [];
    public RelayCommand RefreshHistoryCommand { get; }
    public RelayCommand OpenHistoryCommand { get; }
    public RelayCommand CompareCommand { get; }
    private HistoryRow? _older, _newer;
    public HistoryRow? CompareOlder { get => _older; set => Set(ref _older, value); }
    public HistoryRow? CompareNewer { get => _newer; set => Set(ref _newer, value); }
    private string _comparison = "Выберите два отчёта и нажмите «Сравнить».";
    public string ComparisonText { get => _comparison; private set => Set(ref _comparison, value); }

    private void RefreshHistory()
    {
        History.Clear();
        foreach (var r in _store.List()) History.Add(new HistoryRow(r));
        CompareNewer = History.ElementAtOrDefault(0);
        CompareOlder = History.ElementAtOrDefault(1);
    }

    private void OpenHistory(HistoryRow row)
    {
        try { ShowReport(ReportStore.Load(row.Report.Path), live: false); Selected = Sections[0]; }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or NotSupportedException) { _dialogs.Info("Не удалось открыть отчёт", ex.Message); }
    }

    private void Compare()
    {
        if (CompareOlder is null || CompareNewer is null) return;
        var (a, b) = CompareOlder.Report.Started <= CompareNewer.Report.Started ? (CompareOlder, CompareNewer) : (CompareNewer, CompareOlder);
        var c = ReportComparer.Compare(ReportStore.Load(a.Report.Path), ReportStore.Load(b.Report.Path));
        var sb = new StringBuilder($"Сравнение {a.Date} → {b.Date}\n\n");
        void Block(string title, IEnumerable<string> lines)
        {
            var list = lines.ToList();
            sb.Append(title).Append(": ").Append(list.Count).Append('\n');
            foreach (var l in list) sb.Append("   • ").Append(l).Append('\n');
            sb.Append('\n');
        }
        Block("Новые замечания", c.New.Select(f => $"{f.Title} — {f.Severity.ToDisplay()}"));
        Block("Устранены", c.Resolved.Select(f => f.Title));
        Block("Изменился уровень", c.Changed.Select(x => $"{x.After.Title}: {x.Before.Severity.ToDisplay()} → {x.After.Severity.ToDisplay()}"));
        Block("Остались", c.Persisting.Select(f => $"{f.Title} — {f.Severity.ToDisplay()}"));
        Block("Не удалось проверить повторно (не считается устранённым)", c.NoLongerChecked.Select(f => f.Title));
        ComparisonText = sb.ToString();
    }

    // ── Действия этапа 8 (только с подтверждением) ────────────────────────────
    public AsyncCommand CleanCommand { get; }
    public AsyncCommand EmptyRecycleBinCommand { get; }
    public RelayCommand UninstallCommand { get; }
    public RelayCommand ToggleAutorunCommand { get; }
    private string _actionStatus = "";
    public string ActionStatus { get => _actionStatus; private set => Set(ref _actionStatus, value); }
    private bool _toRecycleBin = true;
    public bool CleanToRecycleBin { get => _toRecycleBin; set => Set(ref _toRecycleBin, value); }

    private async Task CleanAsync(CategoryRow row)
    {
        var p = row.Preview;
        var message = $"Будет удалено файлов: {p.FileCount} ({CleanupAnalyzer.Size(p.TotalBytes)}) из папки:\n{p.Root}\n\n" +
                      $"{p.Consequences}\n\n" +
                      (CleanToRecycleBin ? "Файлы будут перемещены в корзину — их можно восстановить." : "Файлы будут удалены ОКОНЧАТЕЛЬНО, без корзины.") +
                      "\n\nПеред удалением каждого файла NEXORA ещё раз проверит путь и то, что файл не изменился. Все действия записываются в журнал.\n\nУдалить?";
        if (!_dialogs.Confirm("Очистка временных файлов", message)) return;
        if (!CleanToRecycleBin && !_dialogs.Confirm("Окончательное удаление", "Файлы нельзя будет восстановить. Точно продолжить?")) return;

        _isActing = true; OnChanged(nameof(IsBusy));
        try
        {
            var plan = CleanupPlan.Confirm(p, p.Items, CleanToRecycleBin, DateTimeOffset.Now);
            ActionStatus = "Очистка…";
            var report = await Task.Run(() => SafeCleaner.Execute(plan, new WindowsFileRemover(), _journal, () => DateTimeOffset.Now));
            ActionStatus = $"Очистка завершена: удалено {report.Removed} файлов ({CleanupAnalyzer.Size(report.FreedBytes)}), пропущено {report.Skipped} (заняты, изменились или нет доступа). Подробности — в журнале.";
            await RefreshFilesAsync();
        }
        finally { _isActing = false; OnChanged(nameof(IsBusy)); }
    }

    private async Task EmptyRecycleBinAsync(CategoryRow row)
    {
        if (!_dialogs.Confirm("Очистка корзины",
                $"В корзине {row.Preview.FileCount} объектов ({CleanupAnalyzer.Size(row.Preview.TotalBytes)}).\n\n{row.Preview.Consequences}\n\nОчистить корзину?")) return;
        _isActing = true; OnChanged(nameof(IsBusy));
        try
        {
            await Task.Run(() => RecycleBinActions.Empty(_journal, row.Preview.TotalBytes, row.Preview.FileCount));
            ActionStatus = "Корзина очищена.";
            await RefreshFilesAsync();
        }
        catch (IOException ex) { ActionStatus = ex.Message; }
        finally { _isActing = false; OnChanged(nameof(IsBusy)); }
    }

    private async Task RefreshFilesAsync()
    {
        var preview = await Task.Run(() => CleanupCollector.Collect());
        Categories.Clear();
        foreach (var c in preview.Categories) Categories.Add(new CategoryRow(c));
    }

    private void Uninstall(ProgramRow row)
    {
        var p = UninstallActions.Prepare(row.Entry);
        if (p is null) return;
        if (!_dialogs.Confirm("Удаление программы",
                $"Будет запущен штатный деинсталлятор программы «{row.Name}»:\n{p.FileName} {p.Arguments}\n\n" +
                "Дальше действуйте в окне деинсталлятора. NEXORA не удаляет файлы программ сама. Запустить?")) return;
        try
        {
            UninstallActions.Launch(row.Entry, _journal);
            ActionStatus = $"Запущен деинсталлятор «{row.Name}». После его завершения повторите проверку, чтобы обновить список.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            ActionStatus = $"Не удалось запустить деинсталлятор: {ex.Message}";
        }
    }

    private void ToggleAutorun(AutorunRow row)
    {
        var enable = !row.Entry.Enabled;
        if (!enable && !_dialogs.Confirm("Отключение автозагрузки",
                $"«{row.Name}» перестанет запускаться при входе в Windows.\n{row.Command}\n\n" +
                "Запись не удаляется — её можно снова включить здесь или в Диспетчере задач. Отключить?")) return;
        StartupActions.SetEnabled(row.Entry, enable, _journal);
        var i = Autoruns.IndexOf(row);
        if (i >= 0) Autoruns[i] = new AutorunRow(row.Entry with { Enabled = enable });
        ActionStatus = $"«{row.Name}»: автозагрузка {(enable ? "включена" : "отключена")}. Изменение записано в журнал.";
    }

    public void Dispose() => _cts?.Dispose();
}
