# 003 — Производительность и перегрев (этап 3)

**Статус:** готово 2026-10-19 (пользователь разрешил выполнить все этапы без отдельных согласований).

**Реализовано:** PerformanceSampler (GetSystemTimes, PDH English counters, термозоны, % Passive Limit), EventLogScanner, PerformanceAnalyzer.

**Критерии приёмки:** сборка с -warnaserror без предупреждений; тесты зелёные; недоступные данные — «не удалось проверить» с причиной;
во время проверки система не меняется. Подробности решений — docs/ARCHITECTURE.md, ограничения — docs/LIMITATIONS.md.

**Тесты:** Diagnostics.Tests (PerformanceAnalyzer), Platform.Tests (сэмплер, журнал). Результаты всех прогонов — docs/TEST_PLAN.md и logs/development/2026-10-19.md.
