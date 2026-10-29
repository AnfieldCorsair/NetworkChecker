# Архитектура

## Слои

```text
┌─────────────────────────────────────────────────────────────┐
│ RKNHardering.App (Avalonia, net10.0-windows)                │
│   Views / ViewModels (MVVM, CommunityToolkit)                │
│   Startup/AppServices — Host + DI + Serilog                  │
└───────────────▲──────────────────────────────┬──────────────┘
                │ CheckRunResult / Network*    │ ICheck, IPlatformProbe
┌───────────────┴──────────────────────────────▼──────────────┐
│ RKNHardering.Core (net10.0)                                  │
│   Checks/ (10 модулей)  Verdict/  NetInfo/  Net/             │
│   Plain/ (человеческий язык)                                 │
│   Abstractions/ (ICheck, IPlatformProbe, IHttpProbe)         │
└───────────────▲──────────────────────────────┬──────────────┘
                │                               │
┌───────────────┴───────────────┐  ┌────────────▼────────────┐
│ RKNHardering.Platform.Windows │  │ RKNHardering.Data       │
│  реестр, PowerShell, сеть     │  │ EF Core + SQLite        │
└───────────────────────────────┘  └─────────────────────────┘
        ▲
┌───────┴─────────────────────────────────────────────────────┐
│ RKNHardering.Export                                          │
│  ReportExporter → PDF / DOCX / XLSX / CSV / Markdown / JSON   │
│  (QuestPDF, OpenXml, ClosedXML; шрифт DejaVu внутри сборки)   │
└──────────────────────────────────────────────────────────────┘
```

Core не знает про Avalonia и про реестр: всё платформенное спрятано за `IPlatformProbe`. Поэтому Core тестируется на Linux, а весь Windows-специфичный код собран в одном проекте.

## Прогон проверки

1. `DashboardViewModel.RunCommand` создаёт `CancellationTokenSource` и вызывает `CheckRunner.RunAsync(options, privacyMode, ct)` в фоне (`Task.Run`).
2. `CheckRunner` запускает все `ICheck` параллельно через `SemaphoreSlim(MaxParallelChecks)`. Каждый модуль получает общий `CheckContext`: настройки, колбэк прогресса и сборщик IP-наблюдений.
3. Модуль возвращает `CheckResult`: статус (`Clean/NeedsReview/Detected/Skipped/Failed`), находки (`Finding` с уровнем серьёзности и evidence), метрики для плиток, длительность.
4. `IpConsensusBuilder` группирует наблюдения IP по всем модулям: консенсус, голоса «российский/иностранный», признак расщепления.
5. `VerdictEngine.Build` считает взвешенный балл, применяет жёсткие правила и собирает причины.
6. `HistoryRepository.SaveAsync` пишет прогон в SQLite (если включено). UI обновляется через события `Progress`/`StatusText`.

Ошибка одного модуля не рушит прогон: исключение превращается в `CheckResult.Failed`, вердикт помечается как неполный.

## Ключевые абстракции

| Тип | Назначение |
|---|---|
| `ICheck` | модуль проверки: `Category`, `Title`, `Weight`, `RunAsync` |
| `CheckContext` | настройки + прогресс + `CollectIp(...)` |
| `IPlatformProbe` | всё, что зависит от ОС: адаптеры, маршруты, DNS, прокси, приложения, процессы, службы, VPN-профили, hosts, файрвол |
| `IHttpProbe` | HTTP с опцией «игнорировать системный прокси» и честным таймаутом |
| `PingTools` / `RawIcmp` / `TraceTool` | ICMP-эхо, MTU-проба, трассировка (raw + fallback) |
| `DnsClientLite` / `DnsWire` | запросы к конкретному резолверу, парсер DNS-сообщений, DoH |
| `AsnLookup` | ASN/оператор по IP через DNS Team Cymru |
| `HttpProbe`, `GeoIpParser`, `Masking` | сеть, нормализация GeoIP-ответов, приватный режим |

## Потоки вкладки «Сеть»

`NetworkInfoService` — единственная точка входа для UI:

- `GetOverviewAsync` — адаптеры, маршруты, DNS, прокси (+ внешний IP и STUN, если не офлайн).
- `RunDiagnosticsAsync` — параллельные группы задач: задержки, MTU, DNS-резолверы + DoH, TLS.
- `TraceAsync` — трассировка с построчным `IProgress<TraceHop>` (хопы появляются по мере прохода) и обогащением ASN.

## Хранение

EF Core 10, SQLite, `IDbContextFactory` (короткие контексты на операцию). `DateTimeOffset` хранится как `UtcTicks` — иначе SQLite не умеет сортировать такие значения в SQL. Таблицы: `runs` (плоские поля для списка + JSON-снимок чеков/наблюдений/окружения), `logs`.

## UI

Пять экранов, навигация — коллекция `NavItem` в `MainWindowViewModel`, контент — `ContentControl` с `ViewLocator`. Все цвета — в `ThemeDictionaries` (`App.axaml`), есть тёмная и светлая темы. Стили-классы: `card`, `chip`, `inset`, `h1..h3`, `muted`, `mono`, `overline`, кнопки `primary/ghost/danger/nav`.

Раскладка адаптивная: карточки модулей в `WrapPanel` (2 колонки на 1440 px, 1 колонка на узком окне), таблицы сети — `Grid` с пропорциональными колонками, минимальный размер окна 1080×720.

## Два режима интерфейса

Один и тот же прогон показывается двумя способами; данные не дублируются, меняется только подача.

- `UiModeService` (`IsSimple` / `IsPro`) — единственный источник правды о режиме, сохраняет выбор в `UiOptions.ProModeByDefault`. ViewModel'и сети/настроек/дашборда подписаны на его `PropertyChanged` и пересчитывают свои `Show*`-флаги.
- `PlainLanguage` (`Core/Plain`) превращает `CheckResult` и вердикт в человеческий текст: статус словами, «что это значит», «что делать».
- `PlainFacts` собирает шесть фактов верхнего уровня (интернет-адрес, VPN/туннель, прокси, программы обхода, отклик сети) с тоном `good/warn/bad` и общим выводом о конфигурации.

## Тестирование

`tests/RKNHardering.TestKit` — общие двойники (`FakePlatformProbe`, `FakeHttpProbe`, `FakeCheck`, эталонные прогоны `Sample.CleanRun()/RichRun()`), чтобы тесты не ходили в сеть и не читали реальную ОС.

| Проект | Что проверяет |
|---|---|
| `Core.Tests` (120) | чекеры (включая детект SOCKS5/HTTP-прокси и API Xray/Clash на реальном loopback-листенере), раннер, вердикт, консенсус IP, парсеры, plain-язык, маскирование, настройки |
| `Export.Tests` (20) | все шесть форматов: содержимое, кириллица, валидность ZIP/Office-контейнеров |
| `App.Tests` (23) | ViewModel'и, переключение режимов, навигация, экспорт через фейковый диалог, рендер всех пяти экранов в headless-Avalonia |
| `Data.Tests` (11) | история прогонов (EF Core/SQLite), `settings.json`, повреждённый файл настроек |

Особенность: `Masking.Enabled` — процессный переключатель, поэтому `CheckRunner` восстанавливает его после прогона, а тесты внутри сборки идут последовательно.
