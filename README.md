# NetworkChecker

**Windows network diagnostics · Диагностика сети для Windows**  
**v1.6.5** · .NET 10 · AGPL-3.0-only

A Windows desktop app for exploring network configuration, connectivity and possible VPN/proxy indicators. The 0–100 score is a heuristic, **not a probability**.  
Приложение для диагностики сети, соединения и возможных признаков VPN/прокси в Windows. Индекс 0–100 — **условная оценка, не вероятность**.

**[English documentation →](README.en.md)**　|　**[Документация на русском →](README.ru.md)**

| Simple / Просто | Detailed / Подробно |
|:--:|:--:|
| ![Simple dashboard / простой режим](screenshots/02-dashboard-simple-result.png) | ![Detailed dashboard / подробный режим](screenshots/03-dashboard-pro-result.png) |

| Network / Сеть | Website perspective / Глазами сайта |
|:--:|:--:|
| ![Network overview / обзор сети](screenshots/05-network-overview.png) | ![Website perspective / глазами сайта](screenshots/10-site-view.png) |

Screenshots show an earlier 1.6 interface; current layout and text may differ.  
Скриншоты показывают предыдущий вариант интерфейса 1.6; актуальная компоновка и тексты могут отличаться.

[Source code](https://github.com/AnfieldCorsair/NetworkChecker) · [Licence / Лицензия](LICENSE) · [Changelog / История изменений](CHANGELOG.md) · [HTML presentation / Презентация](presentation.html)

### Detection-methodology research / Исследование методов обнаружения

[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) compares the tool with published RKN/TSPU, app-level and site-level VPN-detection methods: three observation layers, a covered / partial / missing matrix, sources and false-positive caveats. New in this branch: methodology ports and TCP LISTEN probes, whoami-DNS vs egress and DNS-vs-DoH checks, a weight-0 `Transport observations (β)` module (UDP/443 and SNI), an extended client catalog, and a decision matrix in the Markdown/JSON report. The score and `Detected` rules are unchanged; these are observations, not a verdict about browser routing.

[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) сверяет инструмент с опубликованными методами РКН/ТСПУ, приложений и сайтов: три слоя наблюдения, матрица «есть / частично / нет», источники и оговорки о ложных срабатываниях. Добавлены порты и TCP LISTEN, whoami-DNS и DNS vs DoH, модуль «Транспорт и DPI (β)» с весом 0 (UDP/443 и SNI), расширенный каталог клиентов и матрица решений в Markdown/JSON. Индекс и правила `Detected` не изменились.
