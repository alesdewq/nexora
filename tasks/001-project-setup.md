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

**Тесты:** не запускались — Этап 1 не начат (ноутбук недоступен).
