using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Platform;

namespace NetworkChecker.TestKit;

/// <summary>Готовые объекты для тестов: одинаковые данные во всех тестовых проектах.</summary>
public static class Sample
{
    public static CheckResult Check(
        CheckCategory category = CheckCategory.DirectSigns,
        string title = "Прямые признаки",
        CheckStatus status = CheckStatus.Detected,
        int weight = 30,
        double seconds = 1.5,
        IReadOnlyList<Finding>? findings = null,
        IReadOnlyList<Metric>? metrics = null,
        string? error = null)
    {
        return new CheckResult
        {
            Category = category,
            Title = title,
            Subtitle = "Подзаголовок модуля",
            Status = status,
            Weight = weight,
            Duration = TimeSpan.FromSeconds(seconds),
            Findings = findings ?? [],
            Metrics = metrics ?? [],
            Error = error,
        };
    }

    /// <summary>Полный набор: смесь статусов, находок и метрик — как в реальном прогоне.</summary>
    public static CheckRunResult RichRun()
    {
        var checks = new List<CheckResult>
        {
            Check(CheckCategory.DirectSigns, "Прямые признаки", CheckStatus.Detected, 30, 2.4,
                [
                    Finding.Critical("Системный прокси включён", "В системе задан прокси-сервер.",
                        "http://127.0.0.1:8080"),
                    Finding.Critical("Активен туннельный интерфейс «wg0»",
                        "MTU 1420, адрес 10.8.0.2. Туннель перехватывает трафик системы.", "WireGuard Tunnel"),
                    Finding.Warning("Установлены клиенты обхода (2)", "Факт установки не доказывает обход.",
                        "Amnezia VPN 4.8; Xray 25.1"),
                    Finding.Info("Системный прокси не настроен"),
                ],
                [
                    new Metric("Системный прокси", "http://127.0.0.1:8080", "WinINET"),
                    new Metric("Активных туннелей", "1", "wg0"),
                ]),
            Check(CheckCategory.GeoIp, "GeoIP и репутация IP", CheckStatus.Detected, 20, 1.9,
                [
                    Finding.Warning("IP принадлежит хостингу/дата-центру", "Для домашнего подключения нетипично.", "1 из 1 источников: hosting=true"),
                    Finding.Notice("Внешний IP не российский", "Страна выхода: Нидерланды."),
                ],
                [
                    new Metric("Внешний IP", "203.0.113.42", "как видят внешние сервисы"),
                    new Metric("Страна", "Нидерланды (NL)", "api.ipapi.is"),
                    new Metric("Hosting", "1/1 голосов"),
                ]),
            Check(CheckCategory.IndirectSigns, "Косвенные признаки", CheckStatus.NeedsReview, 20, 1.1,
                [
                    Finding.Notice("Нетипичный MTU туннеля: 1420", "Значение выдаёт клиента.", "wg0"),
                ],
                [new Metric("Активных интерфейсов", "3", "eth0, wg0, lo")]),
            Check(CheckCategory.Bypass, "Локальный обход", CheckStatus.Detected, 30, 3.2,
                [
                    Finding.Critical("Локальный прокси на 127.0.0.1:1080", "SOCKS5 отвечает."),
                ],
                [
                    new Metric("Портов проверено", "21"),
                    new Metric("Открыто на loopback", "1", "1080"),
                ]),
            Check(CheckCategory.CallTransport, "UDP / STUN-транспорт", CheckStatus.Clean, 10, 0.8,
                [Finding.Info("UDP-транспорт работает", "Ответили 2 STUN-сервера.")],
                [new Metric("STUN-серверов ответило", "2 из 3")]),
            Check(CheckCategory.IpComparison, "Сравнение IP-источников", CheckStatus.Clean, 0, 0.6,
                [Finding.Info("Все источники видят один адрес", "203.0.113.42")],
                [new Metric("Источников", "4"), new Metric("Разных адресов", "1")]),
            Check(CheckCategory.CdnPulling, "CDN и redirector", CheckStatus.NeedsReview, 5, 0.5,
                [Finding.Notice("Edge-CDN определяет страну как NL", "Запрос пришёл не из России.")]),
            Check(CheckCategory.DomainReachability, "Доступность доменов", CheckStatus.Clean, 10, 4.1,
                [Finding.Info("Все проверенные домены доступны")],
                [new Metric("Доступно", "6/6")]),
            Check(CheckCategory.RttTriangulation, "RTT-триангуляция (β)", CheckStatus.Detected, 15, 6.3,
                [Finding.Warning("RU-хосты отвечают медленнее иностранных", "Разница 82 мс.", "RU 118 мс против 36 мс")],
                [
                    new Metric("RU медиана", "118 мс"),
                    new Metric("Иностранные медиана", "36 мс"),
                    new Metric("Метод измерения", "ICMP"),
                ]),
            Check(CheckCategory.IcmpSpoofing, "ICMP-спуфинг (β)", CheckStatus.Failed, 10, 0.2, [], [], "таймаут"),
        };

        return new CheckRunResult
        {
            StartedAt = new DateTimeOffset(2026, 10, 29, 9, 15, 0, TimeSpan.FromHours(3)),
            FinishedAt = new DateTimeOffset(2026, 10, 29, 9, 15, 12, TimeSpan.FromHours(3)),
            Checks = checks,
            Verdict = new VerdictResult
            {
                Level = RiskLevel.Detected,
                Score = 84,
                Headline = "Обнаружены признаки возможного обхода",
                Summary = "Обнаружены несколько сигналов, совместимых с туннелем или прокси; они не доказывают активный обход.",
                Reasons =
                [
                    "Прямые признаки: Системный прокси включён",
                    "Локальный обход: Локальный прокси на 127.0.0.1:1080",
                    "GeoIP и репутация IP: IP принадлежит хостингу/дата-центру",
                ],
                TriggeredCategories = [CheckCategory.DirectSigns, CheckCategory.Bypass, CheckCategory.GeoIp],
            },
            IpConsensus = new IpConsensus
            {
                ConsensusIp = "203.0.113.42",
                RussianVotes = 0,
                ForeignVotes = 3,
                IsSplit = false,
                Observations =
                [
                    new IpObservation("GeoIP · api.ipapi.is", "203.0.113.42", false, "Нидерланды"),
                    new IpObservation("IP comparison · ipify", "203.0.113.42", null),
                    new IpObservation("STUN · stun.l.google.com", "198.51.100.7", null, "UDP-выход"),
                ],
            },
            Environment = new EnvironmentSnapshot
            {
                OsDescription = "Windows 11 (build 26100)",
                MachineName = "DESKTOP-TEST",
                UserName = "user",
                AppVersion = "1.0.0.0",
                PrivacyMode = false,
                Adapters =
                [
                    new AdapterInfo
                    {
                        Id = "{1}", Name = "eth0", Description = "Intel Ethernet", Kind = AdapterKind.Ethernet,
                        IsUp = true, Mtu = 1500, MacAddress = "AA:BB:CC:DD:EE:FF",
                        IPv4 = ["192.168.1.20"], Gateways = ["192.168.1.1"], DnsServers = ["192.168.1.1"],
                    },
                    new AdapterInfo
                    {
                        Id = "{2}", Name = "wg0", Description = "WireGuard Tunnel", Kind = AdapterKind.Tunnel,
                        IsUp = true, Mtu = 1420, IPv4 = ["10.8.0.2"], DnsServers = ["10.8.0.1"],
                    },
                ],
                Proxy = new ProxySettings
                {
                    Enabled = true,
                    HttpProxy = "http://127.0.0.1:8080",
                    Source = "WinINET (реестр пользователя)",
                },
            },
        };
    }

    /// <summary>«Чистый» прогон: все проверки без находок.</summary>
    public static CheckRunResult CleanRun()
    {
        var checks = new List<CheckResult>
        {
            Check(CheckCategory.DirectSigns, "Прямые признаки", CheckStatus.Clean, 30, 1.0,
                [Finding.Info("Системный прокси не настроен")], [new Metric("Активных туннелей", "0")]),
            Check(CheckCategory.GeoIp, "GeoIP и репутация IP", CheckStatus.Clean, 20, 1.2,
                [Finding.Info("Признаков не найдено", "Российский адрес.")],
                [new Metric("Внешний IP", "198.51.100.10"), new Metric("Страна", "Россия (RU)")]),
            Check(CheckCategory.Bypass, "Локальный обход", CheckStatus.Clean, 30, 2.0,
                [Finding.Info("Локальные прокси не обнаружены")]),
        };

        return new CheckRunResult
        {
            StartedAt = new DateTimeOffset(2026, 10, 29, 10, 0, 0, TimeSpan.FromHours(3)),
            FinishedAt = new DateTimeOffset(2026, 10, 29, 10, 0, 5, TimeSpan.FromHours(3)),
            Checks = checks,
            Verdict = new VerdictResult
            {
                Level = RiskLevel.Clean,
                Score = 0,
                Headline = "Признаков обхода не обнаружено",
                Summary = "Ни прямые, ни косвенные проверки не нашли следов туннеля, прокси или подмены.",
            },
            IpConsensus = new IpConsensus { ConsensusIp = "198.51.100.10", RussianVotes = 2 },
            Environment = new EnvironmentSnapshot
            {
                OsDescription = "Windows 10 (build 19045)",
                MachineName = "DESKTOP-CLEAN",
                UserName = "user",
            },
        };
    }

    public static RknOptions Options() => new()
    {
        RequestTimeoutSeconds = 3,
        MaxParallelChecks = 4,
        OfflineMode = true,
        MaxTraceHops = 8,
    };

    /// <summary>Контекст проверки для юнит-тестов (без сетевых вызовов).</summary>
    public static NetworkChecker.Core.Abstractions.CheckContext Context(RknOptions? options = null, List<string>? progress = null) => new()
    {
        Options = options ?? Options(),
        Report = message => progress?.Add(message),
    };
}
