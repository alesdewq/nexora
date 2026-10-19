using Nexora.Core;

namespace Nexora.App.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private SectionViewModel _selected;

    public MainViewModel()
    {
        Sections =
        [
            new(Section.Overview, "", "Сводка по последней проверке: что найдено, что не удалось проверить и с какой уверенностью.", 6),
            new(Section.Performance, "", "Нагрузка CPU, памяти и дисков по процессам; признаки перегрева — только по реальным датчикам.", 3),
            new(Section.Security, "", "Defender, брандмауэр, UAC, BitLocker, RDP/SMB/WinRM, автозагрузка — с учётом контекста.", 4),
            new(Section.Users, "", "Локальные учётные записи и группы, состав «Администраторов».", 4),
            new(Section.Network, "", "Прослушиваемые порты этого компьютера, процессы и правила брандмауэра. Другие устройства не сканируются.", 5),
            new(Section.FilesAndPrograms, "", "Предпросмотр временных и крупных файлов, установленные программы. Без удаления.", 7),
            new(Section.Reports, "", "Отчёт HTML и JSON с источниками данных и ограничениями.", 6),
            new(Section.History, "", "Сравнение отчётов во времени.", 6),
        ];
        _selected = Sections[0];
        Summary = Assessment.From([]).Summary;
    }

    public IReadOnlyList<SectionViewModel> Sections { get; }

    public SectionViewModel Selected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }

    public string Summary { get; }
    public string VersionText { get; } = $"{Product.Name} {Product.Version} · только чтение · без сети";
}
