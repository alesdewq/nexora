# 005 — Локальный сетевой аудит (этап 5)

**Статус:** готово 2026-10-19 (пользователь разрешил выполнить все этапы без отдельных согласований).

**Реализовано:** NetworkCollector (iphlpapi, PID→процесс/служба, HNetCfg.FwPolicy2), FirewallMatcher, NetworkAnalyzer.

**Критерии приёмки:** сборка с -warnaserror без предупреждений; тесты зелёные; недоступные данные — «не удалось проверить» с причиной;
во время проверки система не меняется. Подробности решений — docs/ARCHITECTURE.md, ограничения — docs/LIMITATIONS.md.

**Тесты:** NetworkAudit.Tests, Platform.Tests (собственный loopback-сокет). Результаты всех прогонов — docs/TEST_PLAN.md и logs/development/2026-10-19.md.
