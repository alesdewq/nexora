# NEXORA

> **EN:** Read-only Windows 10/11 diagnostics and basic security audit (C# / .NET 10, WPF): performance, inventory,
> Defender/firewall/UAC/BitLocker/RDP checks, listening ports → process → firewall rule, HTML/JSON reports. 220 unit tests.

Настольное приложение для Windows 10/11 x64: почему компьютер тормозит и греется, что в нём установлено и насколько
базово защищена система — с честным отчётом, где факт отделён от подозрения.

**Версия 0.9.0 (MVP).** Этапы 0–9 из [ROADMAP](docs/ROADMAP.md) выполнены; ограничения и непроверенное — в
[LIMITATIONS](docs/LIMITATIONS.md) и [TEST_PLAN](docs/TEST_PLAN.md).

## Что умеет
| Раздел | Что проверяется (только чтение) |
|---|---|
| Производительность | CPU/RAM/диск за 30 с – 5 мин, процессы, температура термозон ACPI, снижение частоты, ошибки дисков/WHEA/неожиданные выключения в журнале |
| Сведения о системе | Windows (редакция, сборка, срок поддержки), CPU, RAM, диски и их состояние, сеть, программы, обновления, драйверы, устройства с ошибками |
| Безопасность | Defender и сторонний антивирус, базы, защита от подделки, исключения, брандмауэр по профилям, UAC, BitLocker, RDP/NLA, SMB1, WinRM, общие папки, Winlogon, автозагрузка (Run, «Автозагрузка», планировщик, службы) с эвристиками, обнаружения Defender |
| Пользователи | Локальные учётные записи, состав «Администраторов» (по SID), гость, встроенный администратор |
| Сеть | Прослушиваемые TCP/UDP-порты → процесс → служба → правила брандмауэра; только этот компьютер |
| Файлы и программы | Предпросмотр временных файлов, корзины, крупных файлов; программы и автозагрузка |
| Отчёты, история | HTML и JSON, маскирование, локальная история, сравнение, отметки «устранено» |

Изменения системы — только по кнопке и после подтверждения, с журналом: очистка временных файлов (по умолчанию в корзину),
очистка корзины, отключение/включение автозагрузки (как в Диспетчере задач), запуск штатного деинсталлятора.

## Сборка и тесты (Windows 10/11 x64, .NET SDK 10.0.402+)
```powershell
powershell -ExecutionPolicy Bypass -File build\ci.ps1          # сборка с -warnaserror + все тесты
powershell -ExecutionPolicy Bypass -File build\publish.ps1     # выпуск: тесты, single-file exe, smoke опубликованного exe, ZIP + SHA256
src\Nexora.App\bin\Debug\net10.0-windows\win-x64\Nexora.exe --smoke-test artifacts\smoke --with-scan
src\Nexora.App\bin\Debug\net10.0-windows\win-x64\Nexora.exe --scan artifacts\scan --duration 30
powershell -ExecutionPolicy Bypass -File build\run-limited.ps1 -Arguments "--scan C:\out" -WaitFor C:\out\scan.log   # без прав администратора
```
С VPS: `build/sync-and-run.sh '<команда>'` синхронизирует исходники на ноутбук и выполняет команду там.

## Как разработан

NEXORA сделана **с помощью ИИ-ассистента**. Мои задачи — идея и требования (ТЗ), принципы безопасности
(только чтение, изменения только по подтверждению, никаких данных в сеть), поэтапный план, проверка на реальном ноутбуке
и решения по ходу разработки. Код, тесты и большую часть документации писал ИИ-агент по этим требованиям.
Ход работы по этапам — в [logs/development/](logs/development/) и [tasks/](tasks/).

## Структура
`src/` — Core (модели, оценка), Diagnostics, SecurityAudit (+Malware), NetworkAudit, Cleanup, Reporting (без обращений к системе,
тестируются на синтетических данных), Platform (сбор с Windows и действия этапа 8), App (WPF). `tests/` — 8 тестовых проектов.
Подробно — [ARCHITECTURE](docs/ARCHITECTURE.md), [SECURITY](docs/SECURITY.md), [USER_GUIDE](docs/USER_GUIDE.md).

Исходный код открыт в этом репозитории. Лицензия пока не выбрана — все права защищены.
