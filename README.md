# NEXORA

Настольное приложение для Windows 10/11 x64: диагностика тормозов и перегрева, инвентаризация системы,
базовый локальный аудит безопасности, предварительный просмотр кандидатов на очистку и понятный отчёт (HTML/JSON).

**Статус: Этап 1 готов (v0.1.0) — каркас приложения, модели ядра, тесты. Реальных проверок системы пока нет:
все разделы честно показывают «не реализован».**

## Сборка и тесты (Windows 10/11 x64, .NET SDK 10.0.402+)
```powershell
dotnet build Nexora.slnx -c Debug
dotnet test --solution Nexora.slnx
src\Nexora.App\bin\Debug\net10.0-windows\win-x64\Nexora.exe --smoke-test artifacts\smoke
powershell -ExecutionPolicy Bypass -File build\smoke-limited.ps1   # то же без прав администратора
```
С VPS: `build/sync-and-run.sh '<команда>'` синхронизирует исходники на ноутбук и выполняет команду там.

Принципы:
- сначала только чтение; любые изменения системы — отдельно, с явным подтверждением и журналом;
- недоступные данные показываются как «данные недоступны», а не выдумываются;
- факт ≠ потенциальный риск ≠ эвристическое подозрение ≠ «не удалось проверить»;
- без телеметрии, облака и скрытых сетевых соединений.

Документы: [ROADMAP](docs/ROADMAP.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) · [SECURITY](docs/SECURITY.md) ·
[LIMITATIONS](docs/LIMITATIONS.md) · [CHANGELOG](CHANGELOG.md)

Среда разработки: исходники на VPS (`/root/nexora`, git локально, без публикации на GitHub),
сборка и тесты — на Windows-ноутбуке через SSH (.NET 10 SDK), по образцу проекта RedactX.
