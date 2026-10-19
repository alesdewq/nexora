# 006 — Отчёты и интерфейс (этап 6)

**Статус:** готово 2026-10-19 (пользователь разрешил выполнить все этапы без отдельных согласований).

**Реализовано:** ReportDocument, HtmlReport, ReportMasker, ReportComparer, ReportStore, ResolutionStore; Scanner; WPF-интерфейс; CLI --scan.

**Критерии приёмки:** сборка с -warnaserror без предупреждений; тесты зелёные; недоступные данные — «не удалось проверить» с причиной;
во время проверки система не меняется. Подробности решений — docs/ARCHITECTURE.md, ограничения — docs/LIMITATIONS.md.

**Тесты:** Reporting.Tests, Platform.Tests (Scanner), smoke --with-scan. Результаты всех прогонов — docs/TEST_PLAN.md и logs/development/2026-10-19.md.
