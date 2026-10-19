# ARCHITECTURE

## Платформа (проверено на 2026-10-19)
- **.NET 10 (LTS, поддержка до ноября 2028)**, C#, WPF, `net10.0-windows`, x64. .NET 8 LTS заканчивается в ноябре 2026 — не берём.
- **Целевые ОС (решение пользователя 2026-10-19): Windows 10 22H2 и Windows 11 (24H2/25H2), x64 — обе полноценно.**
  Сборка и тесты идут на Windows 10 22H2 (19045); машины с Windows 11 для проверки пока нет — это записано в LIMITATIONS.
  У Windows 10 основная поддержка завершена 14.10.2025, потребительский ESU — до 13.10.2026; приложение сообщает об этом
  в отчёте как о факте («ОС вне основной поддержки»), а не как об уязвимости.

## Модули

```
Nexora.App            WPF, MVVM; только отображение и команды. Не вызывает WMI/реестр напрямую.
  └─ Nexora.Core      Модели: Finding, Severity, Confidence, Evidence, CheckResult, Unavailable<T>;
                      интерфейсы ICheck/ICollector; правила оценки риска (чистая логика — главный объект тестов).
Nexora.Diagnostics    Инвентаризация + производительность (CIM/WMI, PerformanceCounter, PDH, Win32 API).
Nexora.SecurityAudit  Учётки/группы, Defender (ROOT\Microsoft\Windows\Defender: MSFT_MpComputerStatus,
                      MSFT_MpThreatDetection), Firewall (ROOT\StandardCimv2), UAC/RDP/SMB/WinRM (реестр, read-only),
                      BitLocker (Win32_EncryptableVolume — требует администратора → иначе «не удалось проверить»).
Nexora.NetworkAudit   GetExtendedTcpTable/GetExtendedUdpTable (iphlpapi) → PID → процесс/служба; правила брандмауэра.
Nexora.MalwareAssessment  Только интерпретация данных Defender и признаков автозапуска. Своего антивируса нет.
Nexora.Cleanup        Этап 7 — только предпросмотр. Этап 8 (удаление) — отдельная сборка/слой, после согласования.
Nexora.Reporting      JSON (System.Text.Json) + HTML (свой шаблон, без внешних зависимостей), сравнение отчётов.
tests/*               xUnit; коллекторы тестируются через фиктивные источники (IWmiSource, IRegistrySource ...).
```

## Ключевые решения
1. **Каждый результат — `CheckResult`** со статусом `Ok | Finding | Unavailable | Failed`, источником данных,
   ограничениями и уровнем уверенности. Нет «молчаливых» нулей вместо отсутствующих данных.
2. **Severity**: Критический / Высокий / Средний / Низкий-информационный / Не удалось проверить.
   **Kind**: Факт / Потенциальный риск / Эвристика / Рекомендация. Цвет никогда не единственный признак.
3. **Источники данных абстрагированы** (интерфейсы над WMI/реестром/API) → логика тестируется на Linux-CI/ноутбуке без
   реальной системы, а для тестов «Defender недоступен», «нет датчика», «отказ в доступе» хватает заглушек.
4. **Права**: UI работает без администратора. Проверки, которым нужен администратор (BitLocker, часть журналов),
   либо помечаются «не удалось проверить: нужны права администратора», либо (позже) выполняются отдельным
   helper-процессом с UAC по явному нажатию пользователя.
5. **Температура**: только `MSAcpi_ThermalZoneTemperature` (часто отсутствует/неточна) и счётчики «Thermal Zone
   Information». Сторонние драйверы датчиков (LibreHardwareMonitor и т. п. — ставят ядерный драйвер) **не подключаем**
   без отдельного решения. Нет данных → «данные недоступны».
6. **Зависимости**: по умолчанию ноль внешних в рантайме. Кандидаты только для тестов (xUnit, MIT/Apache-2.0).
   CommunityToolkit.Mvvm (MIT) — по необходимости, с записью в этот файл.

## Этап 1 — что реально создано
- `Nexora.Core` (net10.0, без Windows-API): `Severity`/`FindingKind`/`Confidence`/`CheckStatus`, `Section`, `Evidence`,
  `Measured<T>` (значение или «данные недоступны» с причиной), `CheckResult` (фабрики с инвариантами), `Assessment` (итог).
- `Nexora.App` (WPF, net10.0-windows, сборка `Nexora.exe`): окно с 8 разделами, MVVM без внешних библиотек,
  манифест `asInvoker` + supportedOS Windows 10/11, режим `--smoke-test <папка>` (PNG каждого раздела + smoke.log).
- Остальные проекты (Diagnostics, SecurityAudit, NetworkAudit, MalwareAssessment, Cleanup, Reporting) появятся на своих этапах.

## Структура репозитория
Как в ТЗ. Проекты в `src/` и `tests/` создаются на Этапе 1 и наполняются постепенно; пустые проекты «для количества» не создаются.
