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
