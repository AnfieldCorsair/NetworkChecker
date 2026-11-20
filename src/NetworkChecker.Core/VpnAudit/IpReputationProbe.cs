using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace NetworkChecker.Core.VpnAudit;

public enum IpReputationRoutingMode
{
    DirectOrActiveTun,
    AutoLocalVpnProxy,
    ManualTargetIp,
}

public sealed record GeoProviderSample(
    string ProviderName,
    bool Ok,
    string? Ip,
    string? CountryCode,
    string? CountryName,
    string? City,
    string? Asn,
    string? Isp,
    bool? IsHosting,
    bool? IsProxyOrVpn,
    long ElapsedMs,
    string? Error = null);

public sealed record GoogleGeoVerdict(
    bool ProbeExecuted,
    bool ProbeSucceeded,
    string? DetectedGlCode,
    string? PhysicalCountryCode,
    bool IsRuGeoPoisoned,
    bool HasGoogleCaptchaBlock,
    string? YouTubeCountryCode,
    string? GoogleSearchRegion,
    string RoutingChannelUsed,
    string VerdictTitle,
    string VerdictSummary,
    string TechnicalEvidence);

public sealed record IpReputationConsensusReport(
    DateTimeOffset CheckedAt,
    string? TargetQuery,
    string? ConsensusIp,
    string? ConsensusCountryCode,
    string? ConsensusCountryName,
    string? ConsensusAsn,
    string? ConsensusIsp,
    bool MajorityHosting,
    int HostingPositiveCount,
    int HostingKnownCount,
    bool AnyProxyOrVpn,
    int ProxyPositiveCount,
    int ProxyKnownCount,
    bool IpConsistencyOk,
    string? CloudflareEdgeLoc,
    GoogleGeoVerdict GoogleVerdict,
    IReadOnlyList<GeoProviderSample> Providers);

public sealed record ExtractedSubscriptionEndpoint(
    int Index,
    string NodeName,
    string ProtocolLabel,
    string RawHost,
    int Port);

public sealed record SubscriptionIpReputationRow(
    int Index,
    string NodeName,
    string ProtocolLabel,
    string RawHost,
    int Port,
    string? ResolvedIp,
    string? CountryCode,
    string? CountryName,
    string? Asn,
    string? Isp,
    bool IsHosting,
    bool IsProxyOrVpn,
    bool HighRuGoogleBleedRisk,
    bool High16KbRisk,
    string CleanlinessVerdict,
    string TechnicalNotes);

/// <summary>
/// Мульти-провайдерный анализатор репутации IP (4 независимых источника с Majority Vote по Hosting и Any Vote по Proxy/VPN),
/// живой детектор «прокажённой метки RU» и капчи /sorry/ у Google и YouTube (напрямую или через локальный прокси-порт ВПН-клиента),
/// а также пакетный сканер всех IP-адресов серверов из конфигов и подписок.
/// </summary>
public static partial class IpReputationProbe
{
    private static readonly Uri IpWhoIsSelfUri = new("https://ipwho.is/");
    private static readonly Uri IpApiSelfUri = new("http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query");
    private static readonly Uri IpInfoSelfUri = new("https://ipinfo.io/json");
    private static readonly Uri CloudflareTraceUri = new("https://1.1.1.1/cdn-cgi/trace");
    private static readonly Uri YouTubeSwDataUri = new("https://www.youtube.com/sw.js_data");
    private static readonly Uri YouTubeHomeUri = new("https://www.youtube.com/?hl=en");
    private static readonly Uri GooglePrefsUri = new("https://www.google.com/preferences?hl=en");
    private static readonly Uri IpApiBatchUri = new("http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org,as,proxy,hosting,query");

    private static readonly string[] NonProxyOutboundTypes = ["freedom", "direct", "blackhole", "block", "dns"];

    // Хостинги и ASN, где чаще всего встречается «прокажённая метка RU» у Google из-за массового трафика смартфонов из РФ
    private static readonly string[] HighRuGeoBleedKeywords =
    [
        "210644", "aeza",
        "44477", "pq hosting", "pq.hosting", "stark industries",
        "9123", "timeweb",
        "49505", "selectel",
        "197695", "reg.ru",
        "57043", "hostkey",
        "200019", "alexhost",
        "48666", "firstvds",
        "51004", "beget",
        "212238", "datacheap",
        "60781", "leaseweb",
    ];

    // Крупные облачные ASN, где на ТСПУ чаще всего применяется отсечка 16 КБ для незамаскированных протоколов
    private static readonly string[] High16KbCloudKeywords =
    [
        "24940", "hetzner",
        "16276", "ovh",
        "13335", "cloudflare",
        "14061", "digitalocean",
        "51167", "contabo",
        "20473", "vultr", "choopa",
        "63949", "linode", "akamai",
    ];

    private static readonly JsonDocumentOptions TolerantJsonOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    [GeneratedRegex("""(?:"INNERTUBE_CONTEXT_GL"|"countryCode"|"gl")\s*:\s*"(?<code>[A-Za-z]{2})" """, RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace)]
    private static partial Regex YouTubeGlRegex();

    [GeneratedRegex("""(?:["']gl["']\s*:\s*["']|[?&]gl=)(?<code>[A-Za-z]{2})\b""", RegexOptions.IgnoreCase)]
    private static partial Regex GoogleGlRegex();

    /// <summary>
    /// Извлекает все серверы (IP и домены) из подписки или одиночного конфига, включая мульти-outbound балансировщики в JSON Happ/Xray.
    /// </summary>
    public static IReadOnlyList<ExtractedSubscriptionEndpoint> ExtractAllEndpointsFromConfig(string rawConfig)
    {
        if (string.IsNullOrWhiteSpace(rawConfig))
        {
            return [];
        }

        var results = new List<ExtractedSubscriptionEndpoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var working = rawConfig.Trim();
        if (!working.StartsWith('{') && !working.StartsWith('[') && !working.Contains("://", StringComparison.Ordinal))
        {
            var lines = VpnConfigParser.ExtractSubscriptionLines(working);
            if (lines.Count > 0)
            {
                working = string.Join('\n', lines);
            }
        }

        // 1. Если это JSON-объект или JSON-массив подписки Happ/Xray — достаём также все прокси-outbounds внутри каждого профиля
        if (working.StartsWith('{') || working.StartsWith('['))
        {
            try
            {
                var node = JsonNode.Parse(working, nodeOptions: null, TolerantJsonOptions);
                if (node is JsonArray arr)
                {
                    var profileIdx = 0;
                    foreach (var item in arr)
                    {
                        profileIdx++;
                        if (item is JsonObject obj)
                        {
                            ExtractEndpointsFromJsonObject(obj, profileIdx, results, seen);
                        }
                    }
                }
                else if (node is JsonObject singleObj)
                {
                    ExtractEndpointsFromJsonObject(singleObj, 1, results, seen);
                }
            }
            catch (JsonException)
            {
                // Переходим к стандартному парсеру ниже
            }
        }

        // 2. Дополняем через универсальный парсер подписок (vless://, hy2://, trojan://, vmess://, ss://, AmneziaWG)
        var profiles = VpnConfigParser.ParseSubscription(rawConfig);
        foreach (var p in profiles)
        {
            if (string.IsNullOrWhiteSpace(p.ServerHost))
            {
                continue;
            }

            var host = p.ServerHost.Trim();
            var port = p.ServerPort ?? 443;
            if (seen.Add(host))
            {
                results.Add(new ExtractedSubscriptionEndpoint(
                    results.Count + 1,
                    p.Name,
                    p.ProtocolLabel,
                    host,
                    port));
            }
        }

        return results;
    }

    private static void ExtractEndpointsFromJsonObject(
        JsonObject obj,
        int profileIndex,
        List<ExtractedSubscriptionEndpoint> results,
        HashSet<string> seenHosts)
    {
        var baseName = obj["remarks"]?.GetValue<string>()
                       ?? obj["ps"]?.GetValue<string>()
                       ?? string.Create(CultureInfo.InvariantCulture, $"Профиль #{profileIndex}");

        if (obj["outbounds"] is not JsonArray outbounds)
        {
            return;
        }

        var proxyOrdinal = 0;
        foreach (var item in outbounds)
        {
            if (item is not JsonObject ob) continue;

            var proto = (ob["protocol"]?.GetValue<string>() ?? ob["type"]?.GetValue<string>() ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(proto) || NonProxyOutboundTypes.Contains(proto, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            string? host = null;
            var port = 443;

            // Sing-box outbound: server / server_port
            if (ob["server"] is JsonValue sbServer && sbServer.TryGetValue<string>(out var sbHost))
            {
                host = sbHost;
                if (ob["server_port"] is JsonValue sbPort && sbPort.TryGetValue<int>(out var p1))
                {
                    port = p1;
                }
            }

            // Xray settings.vnext[0] или settings.servers[0] или settings.address
            if (string.IsNullOrWhiteSpace(host) && ob["settings"] is JsonObject settings)
            {
                if (settings["vnext"] is JsonArray vnext && vnext.Count > 0 && vnext[0] is JsonObject vn)
                {
                    host = vn["address"]?.GetValue<string>();
                    if (vn["port"] is JsonValue vp && vp.TryGetValue<int>(out var p2)) port = p2;
                }
                else if (settings["servers"] is JsonArray servers && servers.Count > 0 && servers[0] is JsonObject sv)
                {
                    host = sv["address"]?.GetValue<string>();
                    if (sv["port"] is JsonValue sp && sp.TryGetValue<int>(out var p3)) port = p3;
                }
                else if (settings["address"] is JsonValue addrVal && addrVal.TryGetValue<string>(out var directAddr))
                {
                    host = directAddr;
                    if (settings["port"] is JsonValue dp && dp.TryGetValue<int>(out var p4)) port = p4;
                }
            }

            if (string.IsNullOrWhiteSpace(host))
            {
                continue;
            }

            var cleanHost = host.Trim();
            proxyOrdinal++;
            if (!seenHosts.Add(cleanHost))
            {
                continue;
            }

            var tag = ob["tag"]?.GetValue<string>();
            var displayName = proxyOrdinal > 1 && !string.IsNullOrWhiteSpace(tag)
                ? $"{baseName} ({tag})"
                : baseName;

            results.Add(new ExtractedSubscriptionEndpoint(
                results.Count + 1,
                displayName,
                proto.ToUpperInvariant(),
                cleanHost,
                port));
        }
    }

    public static string? ParseYouTubeGlCode(string? rawPayload)
    {
        if (string.IsNullOrWhiteSpace(rawPayload))
        {
            return null;
        }

        // В начале sw.js_data часто идёт префикс )]}' и массив с кодом страны вида ["RU",...]
        var match = YouTubeGlRegex().Match(rawPayload);
        if (match.Success)
        {
            return match.Groups["code"].Value.ToUpperInvariant();
        }

        return null;
    }

    public static (string? RegionCode, bool HasCaptcha) ParseGoogleSearchRegionAndCaptcha(
        string? finalUri,
        int statusCode,
        string? htmlBody)
    {
        var hasCaptcha = statusCode == 429 ||
                         (!string.IsNullOrWhiteSpace(finalUri) && finalUri.Contains("/sorry/", StringComparison.OrdinalIgnoreCase)) ||
                         (!string.IsNullOrWhiteSpace(htmlBody) &&
                          (htmlBody.Contains("/sorry/index", StringComparison.OrdinalIgnoreCase) ||
                           htmlBody.Contains("g-recaptcha", StringComparison.OrdinalIgnoreCase)));

        string? region = null;
        if (!string.IsNullOrWhiteSpace(htmlBody))
        {
            var m = GoogleGlRegex().Match(htmlBody);
            if (m.Success)
            {
                region = m.Groups["code"].Value.ToUpperInvariant();
            }
        }

        return (region, hasCaptcha);
    }

    public static GoogleGeoVerdict EvaluateGoogleGeoVerdict(
        string? physicalCountryCode,
        string? youtubeGl,
        string? googleRegion,
        bool hasCaptcha,
        string routingChannelUsed,
        bool probeExecuted)
    {
        var normPhysical = string.IsNullOrWhiteSpace(physicalCountryCode) ? null : physicalCountryCode.Trim().ToUpperInvariant();
        var normYt = string.IsNullOrWhiteSpace(youtubeGl) ? null : youtubeGl.Trim().ToUpperInvariant();
        var normGoogle = string.IsNullOrWhiteSpace(googleRegion) ? null : googleRegion.Trim().ToUpperInvariant();
        var detectedGl = normYt ?? normGoogle;

        if (!probeExecuted)
        {
            return new GoogleGeoVerdict(
                ProbeExecuted: false,
                ProbeSucceeded: false,
                DetectedGlCode: null,
                PhysicalCountryCode: normPhysical,
                IsRuGeoPoisoned: false,
                HasGoogleCaptchaBlock: false,
                YouTubeCountryCode: null,
                GoogleSearchRegion: null,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: "Проверка стороннего IP (живой ответ Google GL доступен для активного туннеля)",
                VerdictSummary: "Google определяет гео-метку GL только по IP, с которого физически пришёл HTTP-запрос. Для точной проверки метки Google RU подключитесь к этому серверу и выберите режим «Активный интернет» или «Авто-прокси клиента ВПН».",
                TechnicalEvidence: $"Режим: {routingChannelUsed} · Страна по базам GeoIP: {normPhysical ?? "—"}");
        }

        var probeSucceeded = detectedGl is not null || hasCaptcha;
        var isRuPoisoned = !string.IsNullOrWhiteSpace(normPhysical) &&
                           !string.Equals(normPhysical, "RU", StringComparison.OrdinalIgnoreCase) &&
                           (string.Equals(normYt, "RU", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(normGoogle, "RU", StringComparison.OrdinalIgnoreCase));

        var evidence = $"Канал: {routingChannelUsed} · GeoIP страна: {normPhysical ?? "—"} · YouTube GL: {normYt ?? "—"} · Google Search GL: {normGoogle ?? "—"} · Капча /sorry/: {(hasCaptcha ? "ДА (429/sorry)" : "нет")}";

        if (isRuPoisoned)
        {
            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: true,
                DetectedGlCode: "RU",
                PhysicalCountryCode: normPhysical,
                IsRuGeoPoisoned: true,
                HasGoogleCaptchaBlock: hasCaptcha,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: $"КРИТИЧНО: Обнаружена «прокажённая метка RU» у Google (сервер в {normPhysical}, но Google видит RU)",
                VerdictSummary: "Сервер физически находится за рубежом, но база геолокации Google пометила эту подсеть как Россию (RU) из-за утечек GPS/Wi-Fi со смартфонов пользователей. Из-за этого в YouTube остаётся регион РФ, не открывается Gemini / Google AI и возможна капча. Решение: смените локацию/подсеть или пустите geosite:google через другой чистый узел.",
                TechnicalEvidence: evidence);
        }

        if (hasCaptcha)
        {
            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: true,
                DetectedGlCode: detectedGl,
                PhysicalCountryCode: normPhysical,
                IsRuGeoPoisoned: false,
                HasGoogleCaptchaBlock: true,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: "ВНИМАНИЕ: Google выдаёт капчу (/sorry/ · HTTP 429) на этот IP",
                VerdictSummary: "Метки RU нет, но сам IP-адрес перегружен запросами соседей по ВПН-серверу или числится в спам-листах дата-центра. При поиске в Google будет периодически появляться reCAPTCHA.",
                TechnicalEvidence: evidence);
        }

        if (string.Equals(detectedGl, "RU", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(normPhysical, "RU", StringComparison.OrdinalIgnoreCase))
        {
            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: true,
                DetectedGlCode: "RU",
                PhysicalCountryCode: "RU",
                IsRuGeoPoisoned: false,
                HasGoogleCaptchaBlock: false,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: "Google видит российский IP (RU) — запрос ушёл напрямую без зарубежного ВПН",
                VerdictSummary: "И базы GeoIP, и сам Google определяют ваш текущий выходной IP как российский (RU). Если ВПН включён, значит трафик Google идёт мимо туннеля или ваш ВПН работает только в режиме системного прокси (выберите режим «Авто-прокси клиента ВПН»).",
                TechnicalEvidence: evidence);
        }

        if (!string.IsNullOrWhiteSpace(detectedGl))
        {
            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: true,
                DetectedGlCode: detectedGl,
                PhysicalCountryCode: normPhysical,
                IsRuGeoPoisoned: false,
                HasGoogleCaptchaBlock: false,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: $"ОТЛИЧНО: Чистый зарубежный IP для Google (регион {detectedGl}, метки RU и капчи нет)",
                VerdictSummary: $"Google и YouTube корректно определяют страну вашего ВПН-сервера как {detectedGl} (совпадает с зарубежной геолокацией {normPhysical ?? detectedGl}). YouTube Premium, Gemini и поиск работают без региональных ограничений РФ.",
                TechnicalEvidence: evidence);
        }

        return new GoogleGeoVerdict(
            ProbeExecuted: true,
            ProbeSucceeded: false,
            DetectedGlCode: null,
            PhysicalCountryCode: normPhysical,
            IsRuGeoPoisoned: false,
            HasGoogleCaptchaBlock: false,
            YouTubeCountryCode: null,
            GoogleSearchRegion: null,
            RoutingChannelUsed: routingChannelUsed,
            VerdictTitle: "Не удалось прочитать код региона GL из ответа Google/YouTube",
            VerdictSummary: "Запрос к Google выполнен, капчи /sorry/ не обнаружено, но сервер не вернул явный маркер INNERTUBE_CONTEXT_GL. Проверьте консенсус 4 баз репутации ниже.",
            TechnicalEvidence: evidence);
    }

    public static IpReputationConsensusReport BuildConsensus(
        string? targetQuery,
        IReadOnlyList<GeoProviderSample> providers,
        GoogleGeoVerdict googleVerdict,
        string? cloudflareEdgeLoc = null)
    {
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(googleVerdict);

        var okSamples = providers.Where(p => p.Ok).ToList();

        var distinctIps = okSamples
            .Select(p => p.Ip?.Trim())
            .Where(ip => !string.IsNullOrWhiteSpace(ip))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var consensusIp = distinctIps.FirstOrDefault();
        var ipConsistencyOk = distinctIps.Count <= 1;

        var consensusCountryCode = okSamples
            .Select(p => p.CountryCode?.Trim().ToUpperInvariant())
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .GroupBy(c => c, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault();

        var consensusCountryName = okSamples
            .Select(p => p.CountryName?.Trim())
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .FirstOrDefault() ?? consensusCountryCode;

        var consensusAsn = okSamples
            .Select(p => p.Asn?.Trim())
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .FirstOrDefault();

        var consensusIsp = okSamples
            .Select(p => p.Isp?.Trim())
            .Where(i => !string.IsNullOrWhiteSpace(i))
            .FirstOrDefault();

        var hostingKnown = okSamples.Where(p => p.IsHosting.HasValue).ToList();
        var hostingPos = hostingKnown.Count(p => p.IsHosting == true);
        // Majority vote (>= 50% источников, вернувших флаг hosting)
        var majorityHosting = hostingKnown.Count > 0 && (hostingPos * 2 >= hostingKnown.Count);

        var proxyKnown = okSamples.Where(p => p.IsProxyOrVpn.HasValue).ToList();
        var proxyPos = proxyKnown.Count(p => p.IsProxyOrVpn == true);
        // Правило «Хотя бы один источник» для Proxy / VPN / Tor
        var anyProxy = proxyPos > 0;

        return new IpReputationConsensusReport(
            CheckedAt: DateTimeOffset.UtcNow,
            TargetQuery: targetQuery,
            ConsensusIp: consensusIp,
            ConsensusCountryCode: consensusCountryCode,
            ConsensusCountryName: consensusCountryName,
            ConsensusAsn: consensusAsn,
            ConsensusIsp: consensusIsp,
            MajorityHosting: majorityHosting,
            HostingPositiveCount: hostingPos,
            HostingKnownCount: hostingKnown.Count,
            AnyProxyOrVpn: anyProxy,
            ProxyPositiveCount: proxyPos,
            ProxyKnownCount: proxyKnown.Count,
            IpConsistencyOk: ipConsistencyOk,
            CloudflareEdgeLoc: cloudflareEdgeLoc,
            GoogleVerdict: googleVerdict,
            Providers: providers);
    }

    public static (bool HighRuGoogleBleedRisk, bool High16KbRisk, string CleanlinessVerdict, string TechnicalNotes) ClassifySubnetRisks(
        string? countryCode,
        string? asn,
        string? isp,
        bool isHosting,
        bool isProxyOrVpn)
    {
        var combined = $"{asn} {isp}".ToLowerInvariant();
        var isRuCountry = string.Equals(countryCode, "RU", StringComparison.OrdinalIgnoreCase);

        var highRuBleed = !isRuCountry && HighRuGeoBleedKeywords.Any(k => combined.Contains(k, StringComparison.Ordinal));
        var high16Kb = High16KbCloudKeywords.Any(k => combined.Contains(k, StringComparison.Ordinal));

        string verdict;
        if (isRuCountry)
        {
            verdict = "Локация РФ (Google = RU)";
        }
        else if (highRuBleed)
        {
            verdict = "Высокий риск метки Google RU";
        }
        else if (!isHosting && !isProxyOrVpn)
        {
            verdict = "Отличная репутация (чистый ISP)";
        }
        else if (isProxyOrVpn)
        {
            verdict = "Засвечен как VPN/Proxy (возможна капча)";
        }
        else
        {
            verdict = "Чистый зарубежный ДЦ";
        }

        var notes = new List<string>();
        notes.Add(isHosting ? "Hosting/ДЦ: Да" : "Hosting/ДЦ: Нет (ISP)");
        notes.Add(isProxyOrVpn ? "Proxy/VPN база: Да" : "Proxy/VPN база: Чисто");
        if (highRuBleed)
        {
            notes.Add("Популярный у РФ-ВПН хостер (частый спуфинг Google GL=RU)");
        }
        if (high16Kb)
        {
            notes.Add("Крупное облако (требуется Reality XHTTP/Vision от 16 КБ)");
        }

        return (highRuBleed, high16Kb, verdict, string.Join(" · ", notes));
    }

    public static async Task<IpReputationConsensusReport> RunActiveOrManualInspectionAsync(
        HttpClient defaultHttp,
        IpReputationRoutingMode mode,
        string? manualIpOrHost = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(defaultHttp);

        string? resolvedManualIp = null;
        var channelLabel = "Прямой маршрут ОС / Активный TUN";
        HttpClient? customProxyClient = null;

        try
        {
            var activeHttp = defaultHttp;

            if (mode == IpReputationRoutingMode.ManualTargetIp)
            {
                if (string.IsNullOrWhiteSpace(manualIpOrHost))
                {
                    throw new ArgumentException("Введите IP-адрес или домен сервера для ручной проверки.", nameof(manualIpOrHost));
                }

                var cleanTarget = manualIpOrHost.Trim();
                if (IPAddress.TryParse(cleanTarget, out var parsedIp))
                {
                    resolvedManualIp = parsedIp.ToString();
                }
                else
                {
                    var addrs = await Dns.GetHostAddressesAsync(cleanTarget, ct).ConfigureAwait(false);
                    var chosen = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
                    resolvedManualIp = chosen?.ToString() ?? cleanTarget;
                }
                channelLabel = $"Ручная проверка узла ({cleanTarget} -> {resolvedManualIp})";
            }
            else if (mode == IpReputationRoutingMode.AutoLocalVpnProxy)
            {
                var ports = WindowsNetworkStackAuditor.ProbeLocalProxyPorts();
                var openPort = ports.FirstOrDefault(p => p.IsListening && p.Port is 10809 or 2080 or 7890)
                               ?? ports.FirstOrDefault(p => p.IsListening);
                if (openPort is not null)
                {
                    // Порты 10809 / 7890 / 2080 поддерживают HTTP proxy, 10808 / 1080 — SOCKS5
                    var isSocksOnly = openPort.Port is 10808 or 1080;
                    var proxyScheme = isSocksOnly ? "socks5" : "http";
                    var hostAddr = openPort.BindAddress is "0.0.0.0" or "::" or "[::]" or "—" or ""
                        ? "127.0.0.1"
                        : openPort.BindAddress;
                    var proxyUri = new Uri(string.Create(CultureInfo.InvariantCulture, $"{proxyScheme}://{hostAddr}:{openPort.Port}"));
                    var handler = new HttpClientHandler
                    {
                        Proxy = new WebProxy(proxyUri),
                        UseProxy = true,
                    };
                    customProxyClient = new HttpClient(handler, disposeHandler: true)
                    {
                        Timeout = TimeSpan.FromSeconds(10),
                    };
                    customProxyClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0");
                    activeHttp = customProxyClient;
                    channelLabel = string.Create(CultureInfo.InvariantCulture, $"Локальный прокси ВПН ({proxyScheme}://{hostAddr}:{openPort.Port} · {openPort.ExpectedClient})");
                }
                else
                {
                    channelLabel = "Локальный порт ВПН не найден (проверено через активный стек ОС)";
                }
            }

            var t1 = ProbeIpWhoIsAsync(activeHttp, resolvedManualIp, ct);
            var t2 = ProbeIpApiComAsync(activeHttp, resolvedManualIp, ct);
            var t3 = ProbeIpInfoAsync(activeHttp, resolvedManualIp, ct);
            var t4 = ProbeCloudflareTraceAsync(activeHttp, resolvedManualIp, ct);

            Task<(string? YtGl, string? GoogleGl, bool HasCaptcha)>? googleTask = null;
            if (mode != IpReputationRoutingMode.ManualTargetIp)
            {
                googleTask = ProbeLiveGoogleAndYouTubeGeoAsync(activeHttp, ct);
            }

            await Task.WhenAll(t1, t2, t3, t4).ConfigureAwait(false);

            var s1 = await t1.ConfigureAwait(false);
            var s2 = await t2.ConfigureAwait(false);
            var s3 = await t3.ConfigureAwait(false);
            var (s4, cfLoc) = await t4.ConfigureAwait(false);

            var samples = new List<GeoProviderSample> { s1, s2, s3, s4 };
            var tempConsensusCountry = samples
                .Where(s => s.Ok && !string.IsNullOrWhiteSpace(s.CountryCode))
                .Select(s => s.CountryCode!.Trim().ToUpperInvariant())
                .GroupBy(c => c, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Select(g => g.Key)
                .FirstOrDefault();

            GoogleGeoVerdict googleVerdict;
            if (googleTask is not null)
            {
                var (ytGl, gGl, captcha) = await googleTask.ConfigureAwait(false);
                googleVerdict = EvaluateGoogleGeoVerdict(
                    tempConsensusCountry,
                    ytGl,
                    gGl,
                    captcha,
                    channelLabel,
                    probeExecuted: true);
            }
            else
            {
                googleVerdict = EvaluateGoogleGeoVerdict(
                    tempConsensusCountry,
                    youtubeGl: null,
                    googleRegion: null,
                    hasCaptcha: false,
                    channelLabel,
                    probeExecuted: false);
            }

            return BuildConsensus(resolvedManualIp ?? "Активный выходной IP", samples, googleVerdict, cfLoc);
        }
        finally
        {
            customProxyClient?.Dispose();
        }
    }

    /// <summary>
    /// Извлекает все серверы из подписки или конфига, резолвит их доменные имена в IP и пакетно проверяет репутацию каждого сервера.
    /// </summary>
    public static async Task<IReadOnlyList<SubscriptionIpReputationRow>> ScanSubscriptionIpsAsync(
        HttpClient http,
        string rawConfig,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(http);

        var endpoints = ExtractAllEndpointsFromConfig(rawConfig);
        if (endpoints.Count == 0)
        {
            return [];
        }

        // 1. Параллельно резолвим все хосты в IPv4/IPv6
        var resolvedMap = new ConcurrentDictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        using var dnsGate = new SemaphoreSlim(12);
        var dnsTasks = endpoints.Select(e => e.RawHost).Distinct(StringComparer.OrdinalIgnoreCase).Select(async host =>
        {
            await dnsGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (IPAddress.TryParse(host, out var directIp))
                {
                    resolvedMap[host] = directIp.ToString();
                    return;
                }

                using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dnsCts.CancelAfter(3500);
                var addrs = await Dns.GetHostAddressesAsync(host, dnsCts.Token).ConfigureAwait(false);
                var chosen = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
                resolvedMap[host] = chosen?.ToString();
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
            {
                resolvedMap[host] = null;
            }
            finally
            {
                dnsGate.Release();
            }
        });

        await Task.WhenAll(dnsTasks).ConfigureAwait(false);

        // 2. Пакетный запрос к ip-api.com/batch для всех уникальных IP (до 100 за раз)
        var uniqueIps = resolvedMap.Values
            .Where(ip => !string.IsNullOrWhiteSpace(ip))
            .Select(ip => ip!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(100)
            .ToList();

        var batchGeoByIp = new ConcurrentDictionary<string, GeoProviderSample>(StringComparer.OrdinalIgnoreCase);
        if (uniqueIps.Count > 0)
        {
            await PopulateBatchGeoAsync(http, uniqueIps, batchGeoByIp, ct).ConfigureAwait(false);
        }

        // 3. Собираем итоговую таблицу по всем узлам подписки
        var rows = new List<SubscriptionIpReputationRow>(endpoints.Count);
        foreach (var ep in endpoints)
        {
            resolvedMap.TryGetValue(ep.RawHost, out var resolvedIp);
            GeoProviderSample? geo = null;
            if (!string.IsNullOrWhiteSpace(resolvedIp))
            {
                batchGeoByIp.TryGetValue(resolvedIp, out geo);
            }

            if (geo is null || !geo.Ok)
            {
                rows.Add(new SubscriptionIpReputationRow(
                    ep.Index,
                    ep.NodeName,
                    ep.ProtocolLabel,
                    ep.RawHost,
                    ep.Port,
                    resolvedIp,
                    CountryCode: null,
                    CountryName: "—",
                    Asn: "—",
                    Isp: resolvedIp is null ? "Ошибка DNS" : "Нет ответа GeoIP",
                    IsHosting: false,
                    IsProxyOrVpn: false,
                    HighRuGoogleBleedRisk: false,
                    High16KbRisk: false,
                    CleanlinessVerdict: resolvedIp is null ? "DNS не резолвится" : "Не проверен",
                    TechnicalNotes: resolvedIp is null ? "Домен сервера не вернул A/AAAA запись" : "Повторите проверку"));
                continue;
            }

            var isHosting = geo.IsHosting ?? false;
            var isProxy = geo.IsProxyOrVpn ?? false;
            var (highRuBleed, high16Kb, verdict, notes) = ClassifySubnetRisks(
                geo.CountryCode,
                geo.Asn,
                geo.Isp,
                isHosting,
                isProxy);

            rows.Add(new SubscriptionIpReputationRow(
                ep.Index,
                ep.NodeName,
                ep.ProtocolLabel,
                ep.RawHost,
                ep.Port,
                resolvedIp,
                geo.CountryCode,
                geo.CountryName ?? geo.CountryCode ?? "—",
                geo.Asn ?? "—",
                geo.Isp ?? "—",
                isHosting,
                isProxy,
                highRuBleed,
                high16Kb,
                verdict,
                notes));
        }

        return rows;
    }

    private static async Task PopulateBatchGeoAsync(
        HttpClient http,
        List<string> uniqueIps,
        ConcurrentDictionary<string, GeoProviderSample> results,
        CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var payloadJson = JsonSerializer.Serialize(uniqueIps);
            using var content = new StringContent(payloadJson, Encoding.UTF8, "application/json");
            using var resp = await http.PostAsync(IpApiBatchUri, content, cts.Token).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in doc.RootElement.EnumerateArray())
                    {
                        var queryIp = ReadString(item, "query");
                        if (string.IsNullOrWhiteSpace(queryIp)) continue;
                        var status = ReadString(item, "status");
                        if (!string.Equals(status, "success", StringComparison.OrdinalIgnoreCase)) continue;

                        var asRaw = ReadString(item, "as");
                        var (asn, ispFromAs) = SplitAsString(asRaw);
                        var isp = ReadString(item, "isp") ?? ReadString(item, "org") ?? ispFromAs;

                        results[queryIp] = new GeoProviderSample(
                            "ip-api.com (batch)",
                            Ok: true,
                            Ip: queryIp,
                            CountryCode: ReadString(item, "countryCode"),
                            CountryName: ReadString(item, "country"),
                            City: ReadString(item, "city"),
                            Asn: asn,
                            Isp: isp,
                            IsHosting: ReadBool(item, "hosting"),
                            IsProxyOrVpn: ReadBool(item, "proxy"),
                            ElapsedMs: 0);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            // Фолбэк на индивидуальные запросы ipwho.is ниже
        }

        var missingIps = uniqueIps.Where(ip => !results.ContainsKey(ip)).ToList();
        if (missingIps.Count == 0)
        {
            return;
        }

        using var gate = new SemaphoreSlim(6);
        var fallbackTasks = missingIps.Select(async ip =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var sample = await ProbeIpWhoIsAsync(http, ip, ct).ConfigureAwait(false);
                if (sample.Ok)
                {
                    results[ip] = sample;
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(fallbackTasks).ConfigureAwait(false);
    }

    private static async Task<GeoProviderSample> ProbeIpWhoIsAsync(
        HttpClient http,
        string? targetIp,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var uri = string.IsNullOrWhiteSpace(targetIp)
                ? IpWhoIsSelfUri
                : new Uri($"https://ipwho.is/{Uri.EscapeDataString(targetIp)}");

            var json = await http.GetStringAsync(uri, cts.Token).ConfigureAwait(false);
            sw.Stop();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("success", out var okEl) && okEl.ValueKind == JsonValueKind.False)
            {
                return new GeoProviderSample("ipwho.is", false, targetIp, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ReadString(root, "message") ?? "Отказ API");
            }

            var ip = ReadString(root, "ip") ?? targetIp;
            var countryCode = ReadString(root, "country_code");
            var country = ReadString(root, "country");
            var city = ReadString(root, "city");
            string? asn = null;
            string? isp = null;
            if (root.TryGetProperty("connection", out var conn) && conn.ValueKind == JsonValueKind.Object)
            {
                isp = ReadString(conn, "isp") ?? ReadString(conn, "org");
                if (conn.TryGetProperty("asn", out var asnEl) && asnEl.TryGetInt64(out var asnNum))
                {
                    asn = string.Create(CultureInfo.InvariantCulture, $"AS{asnNum}");
                }
            }

            bool? isHosting = null;
            bool? isProxy = null;
            if (root.TryGetProperty("security", out var sec) && sec.ValueKind == JsonValueKind.Object)
            {
                isHosting = ReadBool(sec, "hosting");
                var p = ReadBool(sec, "proxy") ?? false;
                var v = ReadBool(sec, "vpn") ?? false;
                var t = ReadBool(sec, "tor") ?? false;
                isProxy = p || v || t;
            }
            else if (!string.IsNullOrWhiteSpace(isp) || !string.IsNullOrWhiteSpace(asn))
            {
                isHosting = InferHostingFromOrg(asn, isp);
            }

            return new GeoProviderSample("ipwho.is", true, ip, countryCode, country, city, asn, isp, isHosting, isProxy, sw.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            sw.Stop();
            return new GeoProviderSample("ipwho.is", false, targetIp, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ex.Message);
        }
    }

    private static async Task<GeoProviderSample> ProbeIpApiComAsync(
        HttpClient http,
        string? targetIp,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var uri = string.IsNullOrWhiteSpace(targetIp)
                ? IpApiSelfUri
                : new Uri($"http://ip-api.com/json/{Uri.EscapeDataString(targetIp)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query");

            var json = await http.GetStringAsync(uri, cts.Token).ConfigureAwait(false);
            sw.Stop();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!string.Equals(ReadString(root, "status"), "success", StringComparison.OrdinalIgnoreCase))
            {
                return new GeoProviderSample("ip-api.com", false, targetIp, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ReadString(root, "message") ?? "Не удалось получить данные");
            }

            var ip = ReadString(root, "query") ?? targetIp;
            var (asn, ispFromAs) = SplitAsString(ReadString(root, "as"));
            var isp = ReadString(root, "isp") ?? ReadString(root, "org") ?? ispFromAs;

            return new GeoProviderSample(
                "ip-api.com",
                Ok: true,
                Ip: ip,
                CountryCode: ReadString(root, "countryCode"),
                CountryName: ReadString(root, "country"),
                City: ReadString(root, "city"),
                Asn: asn,
                Isp: isp,
                IsHosting: ReadBool(root, "hosting"),
                IsProxyOrVpn: ReadBool(root, "proxy"),
                ElapsedMs: sw.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            sw.Stop();
            return new GeoProviderSample("ip-api.com", false, targetIp, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ex.Message);
        }
    }

    private static async Task<GeoProviderSample> ProbeIpInfoAsync(
        HttpClient http,
        string? targetIp,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var uri = string.IsNullOrWhiteSpace(targetIp)
                ? IpInfoSelfUri
                : new Uri($"https://ipinfo.io/{Uri.EscapeDataString(targetIp)}/json");

            var json = await http.GetStringAsync(uri, cts.Token).ConfigureAwait(false);
            sw.Stop();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var ip = ReadString(root, "ip") ?? targetIp;
            var countryCode = ReadString(root, "country");
            var city = ReadString(root, "city");
            var (asn, isp) = SplitAsString(ReadString(root, "org"));

            bool? isHosting = InferHostingFromOrg(asn, isp);
            bool? isProxy = null;
            if (root.TryGetProperty("privacy", out var priv) && priv.ValueKind == JsonValueKind.Object)
            {
                isHosting = ReadBool(priv, "hosting") ?? isHosting;
                isProxy = (ReadBool(priv, "vpn") ?? false) || (ReadBool(priv, "proxy") ?? false) || (ReadBool(priv, "tor") ?? false);
            }

            return new GeoProviderSample(
                "ipinfo.io",
                Ok: !string.IsNullOrWhiteSpace(ip),
                Ip: ip,
                CountryCode: countryCode,
                CountryName: countryCode,
                City: city,
                Asn: asn,
                Isp: isp,
                IsHosting: isHosting,
                IsProxyOrVpn: isProxy,
                ElapsedMs: sw.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            sw.Stop();
            return new GeoProviderSample("ipinfo.io", false, targetIp, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ex.Message);
        }
    }

    private static async Task<(GeoProviderSample Sample, string? CfEdgeLoc)> ProbeCloudflareTraceAsync(
        HttpClient http,
        string? targetIp,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (!string.IsNullOrWhiteSpace(targetIp))
        {
            // При ручной проверке стороннего IP используем 4-м источником ipapi.co
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                var uri = new Uri($"https://ipapi.co/{Uri.EscapeDataString(targetIp)}/json/");
                var json = await http.GetStringAsync(uri, cts.Token).ConfigureAwait(false);
                sw.Stop();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var asn = ReadString(root, "asn");
                var isp = ReadString(root, "org");
                var cc = ReadString(root, "country_code");
                return (new GeoProviderSample(
                    "ipapi.co",
                    Ok: !string.IsNullOrWhiteSpace(cc),
                    Ip: ReadString(root, "ip") ?? targetIp,
                    CountryCode: cc,
                    CountryName: ReadString(root, "country_name") ?? cc,
                    City: ReadString(root, "city"),
                    Asn: asn,
                    Isp: isp,
                    IsHosting: InferHostingFromOrg(asn, isp),
                    IsProxyOrVpn: null,
                    ElapsedMs: sw.ElapsedMilliseconds), null);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
            {
                sw.Stop();
                return (new GeoProviderSample("ipapi.co", false, targetIp, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ex.Message), null);
            }
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var text = await http.GetStringAsync(CloudflareTraceUri, cts.Token).ConfigureAwait(false);
            sw.Stop();

            string? ip = null;
            string? loc = null;
            string? colo = null;
            foreach (var rawLine in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase)) ip = line[3..].Trim();
                else if (line.StartsWith("loc=", StringComparison.OrdinalIgnoreCase)) loc = line[4..].Trim().ToUpperInvariant();
                else if (line.StartsWith("colo=", StringComparison.OrdinalIgnoreCase)) colo = line[5..].Trim().ToUpperInvariant();
            }

            return (new GeoProviderSample(
                "Cloudflare Trace",
                Ok: !string.IsNullOrWhiteSpace(ip),
                Ip: ip,
                CountryCode: loc,
                CountryName: loc,
                City: colo is not null ? $"Edge {colo}" : null,
                Asn: null,
                Isp: colo is not null ? $"Cloudflare Edge ({colo})" : "Cloudflare Trace",
                IsHosting: null,
                IsProxyOrVpn: null,
                ElapsedMs: sw.ElapsedMilliseconds), colo);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            sw.Stop();
            return (new GeoProviderSample("Cloudflare Trace", false, null, null, null, null, null, null, null, null, sw.ElapsedMilliseconds, ex.Message), null);
        }
    }

    private static async Task<(string? YtGl, string? GoogleGl, bool HasCaptcha)> ProbeLiveGoogleAndYouTubeGeoAsync(
        HttpClient http,
        CancellationToken ct)
    {
        string? ytGl = null;
        string? googleGl = null;
        var hasCaptcha = false;

        // 1. YouTube INNERTUBE_CONTEXT_GL (sw.js_data + fallback на главную)
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, YouTubeSwDataUri);
            req.Headers.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            ytGl = ParseYouTubeGlCode(body);

            if (string.IsNullOrWhiteSpace(ytGl))
            {
                using var req2 = new HttpRequestMessage(HttpMethod.Get, YouTubeHomeUri);
                req2.Headers.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
                using var resp2 = await http.SendAsync(req2, cts.Token).ConfigureAwait(false);
                var body2 = await resp2.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                ytGl = ParseYouTubeGlCode(body2);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            // YouTube может быть заблокирован ТСПУ, если проверяется без ВПН — продолжаем к Google Search
        }

        // 2. Google Preferences / Search (проверка /sorry/ капчи и региона поиска)
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, GooglePrefsUri);
            req.Headers.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var finalUri = resp.RequestMessage?.RequestUri?.ToString();
            (googleGl, hasCaptcha) = ParseGoogleSearchRegionAndCaptcha(finalUri, (int)resp.StatusCode, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            // ignore
        }

        return (ytGl, googleGl, hasCaptcha);
    }

    private static (string? Asn, string? Isp) SplitAsString(string? rawAs)
    {
        if (string.IsNullOrWhiteSpace(rawAs))
        {
            return (null, null);
        }

        var trimmed = rawAs.Trim();
        if (trimmed.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
        {
            var space = trimmed.IndexOf(' ', StringComparison.Ordinal);
            if (space > 2)
            {
                return (trimmed[..space].ToUpperInvariant(), trimmed[(space + 1)..].Trim());
            }
            return (trimmed.ToUpperInvariant(), null);
        }

        return (null, trimmed);
    }

    private static bool? InferHostingFromOrg(string? asn, string? isp)
    {
        if (string.IsNullOrWhiteSpace(asn) && string.IsNullOrWhiteSpace(isp))
        {
            return null;
        }

        var text = $"{asn} {isp}".ToLowerInvariant();
        if (HighRuGeoBleedKeywords.Any(k => text.Contains(k, StringComparison.Ordinal)) ||
            High16KbCloudKeywords.Any(k => text.Contains(k, StringComparison.Ordinal)) ||
            text.Contains("hosting", StringComparison.Ordinal) ||
            text.Contains("cloud", StringComparison.Ordinal) ||
            text.Contains("datacenter", StringComparison.Ordinal) ||
            text.Contains("data center", StringComparison.Ordinal) ||
            text.Contains("vps", StringComparison.Ordinal) ||
            text.Contains("server", StringComparison.Ordinal) ||
            text.Contains("m247", StringComparison.Ordinal) ||
            text.Contains("melbicom", StringComparison.Ordinal) ||
            text.Contains("GCore", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static string? ReadString(JsonElement obj, string prop) =>
        obj.ValueKind == JsonValueKind.Object &&
        obj.TryGetProperty(prop, out var el) &&
        el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;

    private static bool? ReadBool(JsonElement obj, string prop) =>
        obj.ValueKind == JsonValueKind.Object &&
        obj.TryGetProperty(prop, out var el) &&
        el.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? el.GetBoolean()
            : null;
}
