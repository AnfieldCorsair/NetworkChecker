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

    /// <summary>
    /// Порты локальных прокси, которые сканирует BypassCheck. Включены типовые значения
    /// из опубликованной методики: SOCKS 1080/9000/5555, HTTP 3128/8080/8888, Tor 9050/9051/9150.
    /// </summary>
    public List<int> LocalProxyPorts { get; set; } =
    [
        1080, 1081, 1087, 1088, 2080, 3128, 5555, 7890, 7891, 7897, 8080, 8081,
        8888, 9000, 9050, 9051, 9090, 9091, 9150, 10808, 10809, 20170, 20171,
    ];

    /// <summary>
    /// Диапазоны портов из методики (SOCKS 16000–16100 и др.). Записи вида «16000-16100»
    /// или одиночный порт; некорректные значения игнорируются при разборе.
    /// </summary>
    public List<string> LocalProxyPortRanges { get; set; } = ["16000-16100"];

    /// <summary>Добавлять к списку порты, которые ОС сообщает как TCP LISTEN на этой машине.</summary>
    public bool ScanListeningSockets { get; set; } = true;

    /// <summary>Ограничение на общее число проверяемых локальных портов за прогон.</summary>
    public int MaxLocalProxyPorts { get; set; } = 200;

    /// <summary>Домены для DNS-проверки утечек (whoami-имена возвращают адрес резолвера).</summary>
    public List<string> DnsLeakTestDomains { get; set; } =
    [
        "whoami.akamai.net",
        "o-o.myaddr.l.google.com",
    ];

    /// <summary>Имена для сравнения ответов системного DNS и публичного DoH.</summary>
    public List<string> DnsCompareDomains { get; set; } = ["example.com", "ya.ru"];

    /// <summary>Узлы для наблюдательной UDP/443-пробы (QUIC-подобный датаграмм).</summary>
    public List<string> QuicProbeTargets { get; set; } = ["cloudflare.com"];

    /// <summary>Узел, к которому отправляются TLS-зонды с разным SNI.</summary>
    public string SniControlHost { get; set; } = "cloudflare.com";

    /// <summary>«Триггерные» SNI для сравнения с контрольным именем.</summary>
    public List<string> SniProbeNames { get; set; } = ["rutracker.org", "instagram.com"];

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
        copy.LocalProxyPortRanges = [.. LocalProxyPortRanges];
        copy.DnsLeakTestDomains = [.. DnsLeakTestDomains];
        copy.DnsCompareDomains = [.. DnsCompareDomains];
        copy.QuicProbeTargets = [.. QuicProbeTargets];
        copy.SniProbeNames = [.. SniProbeNames];
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
