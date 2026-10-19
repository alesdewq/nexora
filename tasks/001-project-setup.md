# 001 — Подготовка проекта (Этап 0 → Этап 1)

**Цель:** репозиторий, план и документация; затем каркас WPF-решения со сборкой и тестами.

## Этап 0 — сделано 2026-10-19
- Осмотр среды: VPS (Linux, git 2.43, .NET SDK нет — собирать WPF на Linux нельзя); ноутбук
  (Windows 10 Home 22H2, .NET SDK 10.0.402 по проекту RedactX) — **офлайн в Tailscale**, SSH timeout.
- Созданы: README, CHANGELOG, .gitignore, docs/ROADMAP, ARCHITECTURE, SECURITY, LIMITATIONS, журнал.
- Страница проекта: http://170.168.118.49/nexora/

## Этап 1 — план
1. `Nexora.slnx`, проекты App/Core/Diagnostics/Reporting + Core.Tests (остальные — по мере этапов).
2. Модели Core (CheckResult, Severity, Confidence, Evidence) + тесты.
3. Окно WPF с 8 разделами, без прав администратора (`asInvoker` в манифесте).
4. Скрипт sync-and-build (VPS → ноутбук), `dotnet build`, `dotnet test`.

**Критерии приёмки:** сборка без ошибок/предупреждений-ошибок; тесты зелёные (с фактическим выводом); приложение
открывается от обычного пользователя; smoke-скриншот.

## Этап 1 — результат (2026-10-19)
Среда: ноутбук, Windows 10 22H2 (10.0.19045), .NET SDK 10.0.402, Git 2.56.

| Проверка | Команда | Результат |
|---|---|---|
| Сборка | `dotnet build Nexora.slnx -c Debug -warnaserror` | 0 ошибок, 0 предупреждений |
| Модульные тесты | `dotnet test --solution Nexora.slnx` | 20 из 20 пройдено |
| Smoke (SSH, токен администратора) | `Nexora.exe --smoke-test artifacts\smoke` | SMOKE PASS, 8 PNG |
| Smoke без администратора | `powershell -ExecutionPolicy Bypass -File build\smoke-limited.ps1` | `elevated=False`, SMOKE PASS |

Не проверено: ручной запуск с рабочего стола (за консолью ноутбука был другой пользователь), Windows 11, высокий DPI.
Проблемы по ходу: политика выполнения PS запрещает .ps1 → запуск через `-ExecutionPolicy Bypass` (только для процесса);
задача планировщика с RunLevel Limited не подошла (в интерактивном сеансе другой пользователь) → `runas /trustlevel:0x20000`.
