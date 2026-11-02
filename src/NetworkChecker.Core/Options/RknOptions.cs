namespace NetworkChecker.Core.Options;

/// <summary>Настройки прогона и списки целей. Сохраняются в settings.json.</summary>
public sealed class RknOptions
{
    /// <summary>Таймаут одного сетевого запроса, секунды.</summary>
    public int RequestTimeoutSeconds { get; set; } = 8;

    /// <summary>Сколько модулей проверки запускать одновременно.</summary>
    public int MaxParallelChecks { get; set; } = 6;

    /// <summary>Маскировать IP/MAC в UI, логах и экспорте.</summary>
    public bool PrivacyMode { get; set; }

    /// <summary>Не выполнять запросы к внешним сервисам (только локальные данные).</summary>
    public bool OfflineMode { get; set; }

    /// <summary>Сохранять историю прогонов в SQLite.</summary>
    public bool SaveHistory { get; set; } = true;

    // ---- Цели сетевых проверок -------------------------------------------------

    public List<string> GeoIpProviders { get; set; } =
    [
        "https://api.ipapi.is/",
        "https://www.iplocate.io/api/lookup",
        "https://ipinfo.io/json",
        "https://api.myip.com",
    ];

    /// <summary>Домены, доступность которых проверяет DomainReachabilityChecker (DNS → TCP → TLS).</summary>
    public List<string> ReachabilityTargets { get; set; } =
    [
        "example.com",
        "ya.ru",
        "discord.com",
        "rutracker.org",
        "linkedin.com",
        "instagram.com",
    ];

    /// <summary>CDN/redirector-эндпоинты для CdnPullingChecker.</summary>
    public List<string> CdnProbeUrls { get; set; } =
    [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://cloudflare.com/cdn-cgi/trace",
        "https://api.ipify.org?format=json",
    ];

    /// <summary>STUN-серверы для CallTransportChecker (host:port).</summary>
    public List<string> StunServers { get; set; } =
    [
        "stun.l.google.com:19302",
        "stun.cloudflare.com:3478",
        "stun.sipnet.ru:3478",
    ];

    /// <summary>Российские узлы для RTT-триангуляции.</summary>
    public List<string> RttRussianHosts { get; set; } =
    [
        "ya.ru",
        "mail.ru",
        "vk.com",
        "gosuslugi.ru",
    ];

    /// <summary>Иностранные узлы для RTT-триангуляции.</summary>
    public List<string> RttForeignHosts { get; set; } =
    [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
        "cloudflare.com",
    ];

    /// <summary>Хосты для проверки ICMP-спуфинга оператора.</summary>
    public List<string> IcmpSpoofTargets { get; set; } =
    [
        "8.8.8.8",
        "1.1.1.1",
    ];

    /// <summary>Порты локальных прокси, которые сканирует BypassChecker.</summary>
    public List<int> LocalProxyPorts { get; set; } =
    [
        1080, 1081, 1087, 1088, 2080, 3128, 7890, 7891, 7897, 8080, 8081,
        8888, 9050, 9051, 9090, 9091, 10808, 10809, 20170, 20171,
    ];

    /// <summary>Домены для DNS-проверки утечек.</summary>
    public List<string> DnsLeakTestDomains { get; set; } =
    [
        "whoami.akamai.net",
        "o-o.myaddr.l.google.com",
    ];

    /// <summary>Узлы для трассировки по умолчанию.</summary>
    public string DefaultTraceTarget { get; set; } = "1.1.1.1";

    /// <summary>Максимум хопов в трассировке.</summary>
    public int MaxTraceHops { get; set; } = 20;

    // ---- Репутация IP и метка региона Google ----------------------------------

    /// <summary>
    /// Разрешить внешние проверки репутации. Это отправляет внешний IP сторонним
    /// сервисам и DNSBL-зонам; в офлайн-режиме проверка всё равно не выполняется.
    /// </summary>
    public bool ReputationEnabled { get; set; } = true;

    /// <summary>Проверять метку GL (YouTube) и доступность Google AI Studio.</summary>
    public bool GoogleRegionEnabled { get; set; } = true;

    /// <summary>DNSBL-зоны для проверки адреса в спам-базах.</summary>
    public List<string> DnsblZones { get; set; } =
    [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "dnsbl-1.uceprotect.net",
        "psbl.surriel.com",
        "dnsbl.dronebl.org",
    ];

    /// <summary>Максимум DNSBL-зон за один прогон.</summary>
    public int DnsblMaxZones { get; set; } = 12;

    /// <summary>Одновременных DNSBL-запросов.</summary>
    public int DnsblParallelism { get; set; } = 6;

    /// <summary>Бесплатный ключ Spamhaus DQS: заменяет публичное зеркало на *.dq.spamhaus.net.</summary>
    public string? SpamhausDqsKey { get; set; }

    /// <summary>Ключ AbuseIPDB (заголовок Key).</summary>
    public string? AbuseIpDbKey { get; set; }

    /// <summary>Ключ IPQualityScore (в пути URL).</summary>
    public string? IpQualityScoreKey { get; set; }

    /// <summary>Ключ proxycheck.io; без ключа доступно 100 проверок в день.</summary>
    public string? ProxyCheckKey { get; set; }

    /// <summary>Ключ ipapi.is: без него сервис не отдаёт флаги is_abuser / is_vpn / is_tor.</summary>
    public string? IpApiIsKey { get; set; }

    /// <summary>Логин и ключ Scamalytics v3.</summary>
    public string? ScamalyticsUser { get; set; }
    public string? ScamalyticsKey { get; set; }

    /// <summary>Сервис, у которого спрашивают внешний IP и страну.</summary>
    public string EgressIpProvider { get; set; } = "https://api.ipapi.is/";

    /// <summary>Запасной сервис внешнего адреса.</summary>
    public string EgressIpFallback { get; set; } = "https://api.ipify.org?format=json";

    /// <summary>Мобильная главная YouTube: из ytcfg читается поле GL.</summary>
    public string GoogleRegionUrl { get; set; } = "https://m.youtube.com/";

    /// <summary>Страница, переход на которую означает «регион не поддерживается».</summary>
    public string GoogleAiStudioUrl { get; set; } = "https://aistudio.google.com/";

    /// <summary>Код региона, который особенно проверяем (метка RU).</summary>
    public string GoogleRegionWatchCode { get; set; } = "RU";

    public RknOptions Clone()
    {
        var copy = (RknOptions)MemberwiseClone();
        copy.GeoIpProviders = [.. GeoIpProviders];
        copy.ReachabilityTargets = [.. ReachabilityTargets];
        copy.CdnProbeUrls = [.. CdnProbeUrls];
        copy.StunServers = [.. StunServers];
        copy.RttRussianHosts = [.. RttRussianHosts];
        copy.RttForeignHosts = [.. RttForeignHosts];
        copy.IcmpSpoofTargets = [.. IcmpSpoofTargets];
        copy.LocalProxyPorts = [.. LocalProxyPorts];
        copy.DnsLeakTestDomains = [.. DnsLeakTestDomains];
        copy.DnsblZones = [.. DnsblZones];
        return copy;
    }
}

/// <summary>Настройки интерфейса.</summary>
public sealed class UiOptions
{
    public string Theme { get; set; } = "Dark";
    /// <summary>Открывать приложение в подробном режиме (по умолчанию — простой).</summary>
    public bool ProModeByDefault { get; set; }
    public bool CompactNavigation { get; set; }
    public string Culture { get; set; } = "ru-RU";
}
