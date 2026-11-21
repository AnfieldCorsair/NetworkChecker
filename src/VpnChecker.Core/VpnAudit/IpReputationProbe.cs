using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace VpnChecker.Core.VpnAudit;

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

public enum RuBleedRiskTier
{
    LowCleanIsp,
    MediumDatacenterUnverified,
    HighRisk,
    CriticalRu,
}

public sealed record RdapSubnetInfo(
    string? CountryCode,
    string? NetName,
    string? OrgOrMaintainer,
    bool HasRuFootprint,
    string? RuEvidence);

public sealed record GoogleSignalCheck(
    string SignalName,
    string StatusText,
    string Detail,
    bool IsAlert,
    bool IsPass);

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
    string TechnicalEvidence,
    bool? YouTubePremiumAvailable = null,
    bool? GeminiAccessible = null,
    string? GoogleFooterCountry = null,
    IReadOnlyList<GoogleSignalCheck>? SignalChecks = null,
    bool? AiStudioAccessible = null,
    string? AiStudioStatusDetail = null,
    string? GooglePlayCurrency = null,
    string? GooglePlayCountry = null,
    string? GoogleTermsCountry = null,
    bool AiAccessDivergesFromRuTag = false);

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
    string TechnicalNotes,
    RuBleedRiskTier RiskTier = RuBleedRiskTier.MediumDatacenterUnverified,
    string? RdapCountry = null,
    string? RdapOrgOrNetName = null,
    bool HasRuRdapFootprint = false);

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
    private static readonly Uri YouTubePremiumUri = new("https://www.youtube.com/premium?hl=en");
    private static readonly Uri YouTubeRedUri = new("https://www.youtube.com/red?hl=en");
    private static readonly Uri GooglePlayPaidAppUri = new("https://play.google.com/store/apps/details?id=com.mojang.minecraftpe&hl=en");
    private static readonly Uri GoogleTermsUri = new("https://policies.google.com/terms?hl=en");
    private static readonly Uri GeminiAppUri = new("https://gemini.google.com/app?hl=en");
    private static readonly Uri AiStudioWebUri = new("https://aistudio.google.com/prompts/new_chat");
    private static readonly Uri AiStudioApiProbeUri = new("https://generativelanguage.googleapis.com/v1beta/models");
    private static readonly Uri GoogleSearchHomeUri = new("https://www.google.com/?hl=en&gws_rd=cr");
    private static readonly Uri GooglePrefsUri = new("https://www.google.com/preferences?hl=en");
    private static readonly Uri IpApiBatchUri = new("http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org,as,proxy,hosting,query");

    // Cookie обхода EU-экрана согласия (consent.google.com / consent.youtube.com), чтобы на серверах DE/NL/FI возвращался реальный GL
    private const string GoogleConsentBypassCookie =
        "SOCS=CAESHAgBEhJnd3NfMjAyNDAxMDEtMF9SQzEaAmVuIAEaBgiA_LyaBg; CONSENT=YES+cb.20240101-00-p0.en+FX+999; PREF=hl=en";

    private const string DesktopChromeUserAgent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

    private static readonly string[] NonProxyOutboundTypes = ["freedom", "direct", "blackhole", "block", "dns"];

    // Расширенная база хостингов и ASN, где массово встречается «прокажённая метка RU» у Google (RU/СНГ LIR и популярные у РФ-ВПН площадки)
    private static readonly string[] HighRuGeoBleedKeywords =
    [
        "210644", "aeza",
        "44477", "pq hosting", "pq.hosting", "stark industries", "thehosting",
        "9123", "212317", "timeweb",
        "49505", "selectel",
        "197695", "reg.ru",
        "57043", "hostkey",
        "200019", "alexhost",
        "48666", "firstvds",
        "51004", "beget",
        "212238", "60068", "datacheap", "datacamp", "cdn77",
        "60781", "leaseweb",
        "204957", "213371", "vdsina", "hosting technology",
        "201776", "ruvds",
        "58271", "fornex",
        "202422", "adminvps",
        "209588", "zomro",
        "209372", "51040", "justhost",
        "215014", "spacecore",
        "49453", "42861", "veesp", "inferno",
        "216071", "play2go",
        "200350", "serverspace", "itglobal",
        "208091", "hostvds",
        "4vps", "mirhosting", "kvmka", "miran",
        "56630", "8849", "melbicom",
        "199524", "gcore", "g-core",
        "9009", "m247",
        "198610", "servers.com", "serverel",
        "35415", "webzilla", "xserver",
        "49981", "worldstream",
        "50673", "serverius",
        "62240", "clouvider",
        "57724", "ddos-guard",
        "206092", "207713", "ipv4depot", "smartape", "ishosting", "friendhosting",
        "50340", "vdscom", "cloud4box", "ufo.hosting",
    ];

    // Маркеры российского LIR / регистратора в ответе RIPE/RDAP WHOIS (даже если физически IP геолоцируется в NL/DE/FI)
    private static readonly string[] RdapRussianFootprintKeywords =
    [
        "russian federation", "moscow", "saint-petersburg", "saint petersburg", "novosibirsk", "ekaterinburg",
        "aeza", "timeweb", "selectel", "ruvds", "vdsina", "reg.ru", "firstvds", "beget", "hostkey",
        "ddos-guard", "stark-industries", "pq-hosting", "fornex", "adminvps", "zomro", "justhost",
        "spacecore", "veesp", "serverspace", "itglobal", "hostvds", "mirhosting", "melbicom", "miran",
        "ru-mnt", "mnt-ru", "ooo ", "pao ", "zao ",
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

    [GeneratedRegex("""(?:"INNERTUBE_CONTEXT_GL"|"countryCode"|"contentRegion"|"gl")\s*:\s*"(?<code>[A-Za-z]{2})" """, RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace)]
    private static partial Regex YouTubeGlRegex();

    [GeneratedRegex("""\[\s*"[a-z]{2}(?:-[A-Za-z0-9]+)?"\s*,\s*"(?<code>[A-Z]{2})"\s*,""", RegexOptions.None)]
    private static partial Regex YouTubeSwDataPositionalGlRegex();

    [GeneratedRegex("""(?:["']gl["']\s*:\s*["']|[?&]gl=)(?<code>[A-Za-z]{2})\b""", RegexOptions.IgnoreCase)]
    private static partial Regex GoogleGlRegex();

    [GeneratedRegex("""class\s*=\s*["'][^"']*uU7dJb[^"']*["'][^>]*>\s*(?<country>[^<]{2,60}?)\s*<""", RegexOptions.IgnoreCase)]
    private static partial Regex GoogleFooterCountryRegex();

    [GeneratedRegex("""(?:"priceCurrency"|"currencyCode")\s*:\s*"(?<cur>[A-Z]{3})" """, RegexOptions.IgnorePatternWhitespace)]
    private static partial Regex GooglePlayCurrencyJsonRegex();

    [GeneratedRegex("""itemprop\s*=\s*["']priceCurrency["'][^>]*content\s*=\s*["'](?<cur>[A-Z]{3})["']""", RegexOptions.IgnoreCase)]
    private static partial Regex GooglePlayCurrencyMetaRegex();

    [GeneratedRegex("""(?:Country\s+version|Версия\s+для\s+страны)\s*:\s*(?:<[^>]+>\s*)*(?<country>[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё\s'\-]{1,44})""", RegexOptions.IgnoreCase)]
    private static partial Regex GoogleTermsCountryRegex();

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

        var match = YouTubeGlRegex().Match(rawPayload);
        if (match.Success)
        {
            return match.Groups["code"].Value.ToUpperInvariant();
        }

        // В ответе youtube.com/sw.js_data часто идёт позиционный кортеж вида ["en","RU",...]
        var swMatch = YouTubeSwDataPositionalGlRegex().Match(rawPayload);
        if (swMatch.Success)
        {
            return swMatch.Groups["code"].Value.ToUpperInvariant();
        }

        return null;
    }

    public static bool? ParseYouTubePremiumAvailability(string? htmlBody)
    {
        if (string.IsNullOrWhiteSpace(htmlBody))
        {
            return null;
        }

        if (htmlBody.Contains("YouTube Premium is not available in your country", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("not available in your country", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("недоступна в вашей стране", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("недоступно в вашей стране", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("This offer is not available", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (htmlBody.Contains("Try 1 month", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("Try it free", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("Try YouTube Premium", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("Start free trial", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("Get YouTube Premium", StringComparison.OrdinalIgnoreCase) ||
            (htmlBody.Contains("Individual", StringComparison.OrdinalIgnoreCase) &&
             (htmlBody.Contains("/month", StringComparison.OrdinalIgnoreCase) ||
              htmlBody.Contains("EUR", StringComparison.OrdinalIgnoreCase) ||
              htmlBody.Contains("USD", StringComparison.OrdinalIgnoreCase))))
        {
            return true;
        }

        return null;
    }

    public static bool? ParseGeminiAvailability(string? finalUri, int statusCode, string? htmlBody)
    {
        if (statusCode == 403 || statusCode == 451)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(finalUri) &&
            (finalUri.Contains("/unsupported", StringComparison.OrdinalIgnoreCase) ||
             finalUri.Contains("region_not_supported", StringComparison.OrdinalIgnoreCase) ||
             finalUri.Contains("error/403", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(htmlBody) &&
            (htmlBody.Contains("isn't currently supported in your country", StringComparison.OrdinalIgnoreCase) ||
             htmlBody.Contains("not available in your country", StringComparison.OrdinalIgnoreCase) ||
             htmlBody.Contains("пока не поддерживается в вашей стране", StringComparison.OrdinalIgnoreCase) ||
             htmlBody.Contains("недоступен в вашей стране", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (statusCode is >= 200 and < 400 &&
            (!string.IsNullOrWhiteSpace(finalUri) &&
             (finalUri.Contains("gemini.google.com", StringComparison.OrdinalIgnoreCase) ||
              finalUri.Contains("accounts.google.com", StringComparison.OrdinalIgnoreCase))))
        {
            return true;
        }

        return null;
    }

    public static (string? CurrencyCode, string? CountryCode, bool? PaidAppsAvailable) ParseGooglePlayRegionAndCurrency(string? htmlBody)
    {
        if (string.IsNullOrWhiteSpace(htmlBody))
        {
            return (null, null, null);
        }

        bool? paidAvailable = null;
        if (htmlBody.Contains("This item isn't available in your country", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("item isn&#39;t available in your country", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("недоступен в вашей стране", StringComparison.OrdinalIgnoreCase) ||
            htmlBody.Contains("недоступно в вашей стране", StringComparison.OrdinalIgnoreCase))
        {
            paidAvailable = false;
        }

        string? currency = null;
        var curMeta = GooglePlayCurrencyMetaRegex().Match(htmlBody);
        if (curMeta.Success)
        {
            currency = curMeta.Groups["cur"].Value.ToUpperInvariant();
        }
        else
        {
            var curJson = GooglePlayCurrencyJsonRegex().Match(htmlBody);
            if (curJson.Success)
            {
                currency = curJson.Groups["cur"].Value.ToUpperInvariant();
            }
            else if (htmlBody.Contains('₽') || htmlBody.Contains("RUB", StringComparison.Ordinal))
            {
                currency = "RUB";
            }
        }

        string? country = currency switch
        {
            "RUB" => "RU",
            "USD" => "US",
            "GBP" => "GB",
            "TRY" => "TR",
            "KZT" => "KZ",
            "PLN" => "PL",
            "CHF" => "CH",
            "SEK" => "SE",
            "JPY" => "JP",
            "SGD" => "SG",
            "UAH" => "UA",
            "CAD" => "CA",
            "AUD" => "AU",
            _ => null,
        };

        if (string.IsNullOrWhiteSpace(country))
        {
            var glMatch = GoogleGlRegex().Match(htmlBody);
            if (glMatch.Success)
            {
                country = glMatch.Groups["code"].Value.ToUpperInvariant();
            }
        }

        if (paidAvailable is null && !string.IsNullOrWhiteSpace(currency) && !string.Equals(currency, "RUB", StringComparison.OrdinalIgnoreCase))
        {
            paidAvailable = true;
        }
        else if (paidAvailable is null && string.Equals(currency, "RUB", StringComparison.OrdinalIgnoreCase))
        {
            paidAvailable = false;
        }

        return (currency, country, paidAvailable);
    }

    public static (string? CountryCode, string? CountryLabel) ParseGoogleTermsCountry(string? htmlBody)
    {
        if (string.IsNullOrWhiteSpace(htmlBody))
        {
            return (null, null);
        }

        var match = GoogleTermsCountryRegex().Match(htmlBody);
        if (!match.Success)
        {
            return (null, null);
        }

        var rawLabel = match.Groups["country"].Value.Trim().TrimEnd('.', ',', ';');
        var iso = MapCountryNameToIso(rawLabel);
        return (iso, rawLabel);
    }

    public static (bool? Accessible, string Detail) ParseAiStudioAvailability(
        string? webFinalUri,
        int webStatusCode,
        string? webBody,
        int apiStatusCode,
        string? apiBody)
    {
        if (!string.IsNullOrWhiteSpace(apiBody))
        {
            if (apiBody.Contains("User location is not supported", StringComparison.OrdinalIgnoreCase) ||
                (apiBody.Contains("FAILED_PRECONDITION", StringComparison.OrdinalIgnoreCase) &&
                 apiBody.Contains("location", StringComparison.OrdinalIgnoreCase)))
            {
                return (false, "API gateway вернул «User location is not supported» (гео-блок AI Studio)");
            }

            if (apiBody.Contains("Method doesn't allow unregistered callers", StringComparison.OrdinalIgnoreCase) ||
                apiBody.Contains("API key not valid", StringComparison.OrdinalIgnoreCase) ||
                apiBody.Contains("API_KEY_INVALID", StringComparison.OrdinalIgnoreCase) ||
                apiStatusCode == 200)
            {
                return (true, "API gateway generativelanguage.googleapis.com пропустил IP без гео-блока");
            }
        }

        if (webStatusCode is 403 or 451)
        {
            return (false, string.Create(CultureInfo.InvariantCulture, $"aistudio.google.com вернул HTTP {webStatusCode} (гео-блокировка)"));
        }

        if (!string.IsNullOrWhiteSpace(webFinalUri) &&
            (webFinalUri.Contains("available-regions", StringComparison.OrdinalIgnoreCase) ||
             webFinalUri.Contains("available_regions", StringComparison.OrdinalIgnoreCase) ||
             webFinalUri.Contains("/unsupported", StringComparison.OrdinalIgnoreCase) ||
             webFinalUri.Contains("region_not_supported", StringComparison.OrdinalIgnoreCase)))
        {
            return (false, "aistudio.google.com перенаправил на страницу неподдерживаемых регионов");
        }

        if (!string.IsNullOrWhiteSpace(webBody) &&
            (webBody.Contains("not available in your country", StringComparison.OrdinalIgnoreCase) ||
             webBody.Contains("isn't currently supported in your country", StringComparison.OrdinalIgnoreCase) ||
             webBody.Contains("region is not supported", StringComparison.OrdinalIgnoreCase) ||
             webBody.Contains("недоступен в вашей стране", StringComparison.OrdinalIgnoreCase)))
        {
            return (false, "Страница AI Studio сообщила об ограничении по стране");
        }

        if (webStatusCode is >= 200 and < 400 &&
            !string.IsNullOrWhiteSpace(webFinalUri) &&
            (webFinalUri.Contains("aistudio.google.com", StringComparison.OrdinalIgnoreCase) ||
             webFinalUri.Contains("accounts.google.com", StringComparison.OrdinalIgnoreCase)))
        {
            return (true, "aistudio.google.com доступен без редиректа на страницу блокировки");
        }

        return (null, "Не удалось получить однозначный ответ от AI Studio");
    }

    public static RdapSubnetInfo ParseRdapIpResponse(string? jsonBody)
    {
        if (string.IsNullOrWhiteSpace(jsonBody))
        {
            return new RdapSubnetInfo(null, null, null, false, null);
        }

        try
        {
            using var doc = JsonDocument.Parse(jsonBody);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new RdapSubnetInfo(null, null, null, false, null);
            }

            var country = ReadString(root, "country")?.Trim().ToUpperInvariant();
            var netName = ReadString(root, "name")?.Trim();
            var handle = ReadString(root, "handle")?.Trim();

            var textTokens = new List<string>();
            if (!string.IsNullOrWhiteSpace(netName)) textTokens.Add(netName);
            if (!string.IsNullOrWhiteSpace(handle)) textTokens.Add(handle);

            string? primaryOrg = null;
            var ruEvidenceList = new List<string>();

            if (string.Equals(country, "RU", StringComparison.OrdinalIgnoreCase))
            {
                ruEvidenceList.Add("RIPE/RDAP country=RU");
            }

            if (root.TryGetProperty("remarks", out var remarksEl) && remarksEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var rem in remarksEl.EnumerateArray())
                {
                    if (rem.ValueKind == JsonValueKind.Object &&
                        rem.TryGetProperty("description", out var descArr) &&
                        descArr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var line in descArr.EnumerateArray())
                        {
                            if (line.ValueKind == JsonValueKind.String)
                            {
                                var s = line.GetString();
                                if (!string.IsNullOrWhiteSpace(s))
                                {
                                    textTokens.Add(s);
                                }
                            }
                        }
                    }
                }
            }

            if (root.TryGetProperty("entities", out var entitiesEl) && entitiesEl.ValueKind == JsonValueKind.Array)
            {
                CollectRdapEntities(entitiesEl, textTokens, ruEvidenceList, ref primaryOrg, depth: 0);
            }

            var combinedLower = string.Join(' ', textTokens).ToLowerInvariant();
            foreach (var kw in RdapRussianFootprintKeywords)
            {
                if (combinedLower.Contains(kw, StringComparison.Ordinal))
                {
                    ruEvidenceList.Add($"RDAP маркер: {kw.Trim()}");
                    break;
                }
            }

            var orgSummary = !string.IsNullOrWhiteSpace(primaryOrg) && !string.IsNullOrWhiteSpace(netName)
                ? $"{netName} · {primaryOrg}"
                : (netName ?? primaryOrg);

            var hasRu = ruEvidenceList.Count > 0;
            var evidence = hasRu ? string.Join(", ", ruEvidenceList.Distinct(StringComparer.OrdinalIgnoreCase).Take(2)) : null;

            return new RdapSubnetInfo(country, netName, orgSummary, hasRu, evidence);
        }
        catch (JsonException)
        {
            return new RdapSubnetInfo(null, null, null, false, null);
        }
    }

    private static void CollectRdapEntities(
        JsonElement entitiesArray,
        List<string> textTokens,
        List<string> ruEvidenceList,
        ref string? primaryOrg,
        int depth)
    {
        if (depth > 3)
        {
            return;
        }

        foreach (var ent in entitiesArray.EnumerateArray())
        {
            if (ent.ValueKind != JsonValueKind.Object) continue;
            var entHandle = ReadString(ent, "handle");
            if (!string.IsNullOrWhiteSpace(entHandle))
            {
                textTokens.Add(entHandle);
                if (entHandle.EndsWith("-RU", StringComparison.OrdinalIgnoreCase) ||
                    entHandle.Contains("-RU-", StringComparison.OrdinalIgnoreCase) ||
                    entHandle.StartsWith("RU-", StringComparison.OrdinalIgnoreCase))
                {
                    ruEvidenceList.Add($"LIR handle {entHandle}");
                }
            }

            if (ent.TryGetProperty("vcardArray", out var vcard) &&
                vcard.ValueKind == JsonValueKind.Array &&
                vcard.GetArrayLength() >= 2 &&
                vcard[1].ValueKind == JsonValueKind.Array)
            {
                foreach (var prop in vcard[1].EnumerateArray())
                {
                    if (prop.ValueKind != JsonValueKind.Array || prop.GetArrayLength() < 4) continue;
                    var propName = prop[0].ValueKind == JsonValueKind.String ? prop[0].GetString() : null;
                    var valEl = prop[3];

                    if (valEl.ValueKind == JsonValueKind.String)
                    {
                        var val = valEl.GetString();
                        if (!string.IsNullOrWhiteSpace(val))
                        {
                            textTokens.Add(val);
                            if (string.Equals(propName, "fn", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(primaryOrg))
                            {
                                primaryOrg = val.Trim();
                            }
                            if (string.Equals(propName, "email", StringComparison.OrdinalIgnoreCase) &&
                                (val.EndsWith(".ru", StringComparison.OrdinalIgnoreCase) || val.EndsWith(".su", StringComparison.OrdinalIgnoreCase)))
                            {
                                ruEvidenceList.Add($"контакт {val}");
                            }
                        }
                    }
                    else if (valEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var part in valEl.EnumerateArray())
                        {
                            if (part.ValueKind == JsonValueKind.String)
                            {
                                var s = part.GetString();
                                if (!string.IsNullOrWhiteSpace(s))
                                {
                                    textTokens.Add(s);
                                }
                            }
                        }
                    }
                }
            }

            if (ent.TryGetProperty("entities", out var nested) && nested.ValueKind == JsonValueKind.Array)
            {
                CollectRdapEntities(nested, textTokens, ruEvidenceList, ref primaryOrg, depth + 1);
            }
        }
    }

    public static (string? RegionCode, bool HasCaptcha) ParseGoogleSearchRegionAndCaptcha(
        string? finalUri,
        int statusCode,
        string? htmlBody)
    {
        var (regionCode, _, hasCaptcha) = ParseGoogleSearchRegionDetailed(finalUri, statusCode, htmlBody);
        return (regionCode, hasCaptcha);
    }

    public static (string? RegionCode, string? FooterLabel, bool HasCaptcha) ParseGoogleSearchRegionDetailed(
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
        string? footerLabel = null;

        if (!string.IsNullOrWhiteSpace(finalUri) &&
            finalUri.Contains("google.ru", StringComparison.OrdinalIgnoreCase))
        {
            region = "RU";
            footerLabel = "google.ru";
        }

        if (!string.IsNullOrWhiteSpace(htmlBody))
        {
            var footerMatch = GoogleFooterCountryRegex().Match(htmlBody);
            if (footerMatch.Success)
            {
                footerLabel = footerMatch.Groups["country"].Value.Trim();
                var mapped = MapCountryNameToIso(footerLabel);
                if (!string.IsNullOrWhiteSpace(mapped))
                {
                    region = mapped;
                }
            }

            if (string.IsNullOrWhiteSpace(region))
            {
                var m = GoogleGlRegex().Match(htmlBody);
                if (m.Success)
                {
                    region = m.Groups["code"].Value.ToUpperInvariant();
                }
            }
        }

        return (region, footerLabel, hasCaptcha);
    }

    private static string? MapCountryNameToIso(string? label)
    {
        if (string.IsNullOrWhiteSpace(label)) return null;
        var norm = label.Trim().ToLowerInvariant();
        if (norm.Contains("russia", StringComparison.Ordinal) || norm.Contains("россия", StringComparison.Ordinal)) return "RU";
        if (norm.Contains("netherlands", StringComparison.Ordinal) || norm.Contains("нидерланд", StringComparison.Ordinal)) return "NL";
        if (norm.Contains("germany", StringComparison.Ordinal) || norm.Contains("герман", StringComparison.Ordinal)) return "DE";
        if (norm.Contains("finland", StringComparison.Ordinal) || norm.Contains("финлянд", StringComparison.Ordinal)) return "FI";
        if (norm.Contains("united states", StringComparison.Ordinal) || norm.Contains("сша", StringComparison.Ordinal)) return "US";
        if (norm.Contains("united kingdom", StringComparison.Ordinal) || norm.Contains("великобритан", StringComparison.Ordinal)) return "GB";
        if (norm.Contains("sweden", StringComparison.Ordinal) || norm.Contains("швец", StringComparison.Ordinal)) return "SE";
        if (norm.Contains("poland", StringComparison.Ordinal) || norm.Contains("польш", StringComparison.Ordinal)) return "PL";
        if (norm.Contains("france", StringComparison.Ordinal) || norm.Contains("франц", StringComparison.Ordinal)) return "FR";
        if (norm.Contains("switzerland", StringComparison.Ordinal) || norm.Contains("швейцар", StringComparison.Ordinal)) return "CH";
        if (norm.Contains("latvia", StringComparison.Ordinal) || norm.Contains("латв", StringComparison.Ordinal)) return "LV";
        if (norm.Contains("estonia", StringComparison.Ordinal) || norm.Contains("эстон", StringComparison.Ordinal)) return "EE";
        if (norm.Contains("lithuania", StringComparison.Ordinal) || norm.Contains("литв", StringComparison.Ordinal)) return "LT";
        if (norm.Contains("turkey", StringComparison.Ordinal) || norm.Contains("türkiye", StringComparison.Ordinal) || norm.Contains("турц", StringComparison.Ordinal)) return "TR";
        if (norm.Contains("kazakhstan", StringComparison.Ordinal) || norm.Contains("казахстан", StringComparison.Ordinal)) return "KZ";
        if (norm.Contains("austria", StringComparison.Ordinal) || norm.Contains("австр", StringComparison.Ordinal)) return "AT";
        if (norm.Contains("singapore", StringComparison.Ordinal) || norm.Contains("сингапур", StringComparison.Ordinal)) return "SG";
        if (norm.Contains("japan", StringComparison.Ordinal) || norm.Contains("япон", StringComparison.Ordinal)) return "JP";
        if (norm.Contains("canada", StringComparison.Ordinal) || norm.Contains("канад", StringComparison.Ordinal)) return "CA";
        if (norm.Contains("spain", StringComparison.Ordinal) || norm.Contains("испан", StringComparison.Ordinal)) return "ES";
        if (norm.Contains("italy", StringComparison.Ordinal) || norm.Contains("итал", StringComparison.Ordinal)) return "IT";
        if (norm.Contains("czech", StringComparison.Ordinal) || norm.Contains("чех", StringComparison.Ordinal)) return "CZ";
        if (norm.Contains("norway", StringComparison.Ordinal) || norm.Contains("норвег", StringComparison.Ordinal)) return "NO";
        if (norm.Contains("ireland", StringComparison.Ordinal) || norm.Contains("ирланд", StringComparison.Ordinal)) return "IE";
        if (norm.Contains("bulgaria", StringComparison.Ordinal) || norm.Contains("болгар", StringComparison.Ordinal)) return "BG";
        if (norm.Contains("romania", StringComparison.Ordinal) || norm.Contains("румын", StringComparison.Ordinal)) return "RO";
        if (norm.Contains("moldova", StringComparison.Ordinal) || norm.Contains("молдов", StringComparison.Ordinal)) return "MD";
        if (norm.Contains("armenia", StringComparison.Ordinal) || norm.Contains("армен", StringComparison.Ordinal)) return "AM";
        if (norm.Contains("georgia", StringComparison.Ordinal) || norm.Contains("груз", StringComparison.Ordinal)) return "GE";
        return null;
    }

    public static GoogleGeoVerdict EvaluateGoogleGeoVerdict(
        string? physicalCountryCode,
        string? youtubeGl,
        string? googleRegion,
        bool hasCaptcha,
        string routingChannelUsed,
        bool probeExecuted,
        bool? youtubePremiumAvailable = null,
        bool? geminiAccessible = null,
        string? googleFooterCountry = null,
        bool? aiStudioAccessible = null,
        string? aiStudioDetail = null,
        string? googlePlayCurrency = null,
        string? googlePlayCountry = null,
        bool? googlePlayPaidAvailable = null,
        string? googleTermsCountry = null,
        string? googleTermsLabel = null)
    {
        var normPhysical = string.IsNullOrWhiteSpace(physicalCountryCode) ? null : physicalCountryCode.Trim().ToUpperInvariant();
        var normYt = string.IsNullOrWhiteSpace(youtubeGl) ? null : youtubeGl.Trim().ToUpperInvariant();
        var normTerms = string.IsNullOrWhiteSpace(googleTermsCountry) ? null : googleTermsCountry.Trim().ToUpperInvariant();
        var normGoogle = string.IsNullOrWhiteSpace(googleRegion) ? normTerms : googleRegion.Trim().ToUpperInvariant();
        var normPlayCountry = string.IsNullOrWhiteSpace(googlePlayCountry) ? null : googlePlayCountry.Trim().ToUpperInvariant();
        var normPlayCurrency = string.IsNullOrWhiteSpace(googlePlayCurrency) ? null : googlePlayCurrency.Trim().ToUpperInvariant();
        var effectiveSearchLabel = googleTermsLabel ?? googleFooterCountry;
        var detectedGl = normYt ?? normTerms ?? normGoogle ?? normPlayCountry;

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
                VerdictTitle: "Проверка стороннего IP (6-сигнальный зонд Google доступен для активного туннеля)",
                VerdictSummary: "Google определяет гео-метку RU, валюту Play Store и доступ к Gemini / AI Studio только по IP, с которого физически пришёл запрос. Подключитесь к нужному узлу и нажмите «Проверить вживую».",
                TechnicalEvidence: $"Режим: {routingChannelUsed} · Страна по базам GeoIP: {normPhysical ?? "—"}",
                YouTubePremiumAvailable: null,
                GeminiAccessible: null,
                GoogleFooterCountry: null,
                SignalChecks:
                [
                    new GoogleSignalCheck("1. YouTube INNERTUBE_CONTEXT_GL", "Не запускался", "Требуется активный туннель или прокси ВПН", false, false),
                    new GoogleSignalCheck("2. YouTube Premium", "Не запускался", "Требуется активный туннель или прокси ВПН", false, false),
                    new GoogleSignalCheck("3. Google Play (регион и валюта)", "Не запускался", "Требуется активный туннель или прокси ВПН", false, false),
                    new GoogleSignalCheck("4. Google Terms / Search и /sorry/", "Не запускался", "Требуется активный туннель или прокси ВПН", false, false),
                    new GoogleSignalCheck("5. Google Gemini Web", "Не запускался", "Требуется активный туннель или прокси ВПН", false, false),
                    new GoogleSignalCheck("6. Google AI Studio + API", "Не запускался", "Требуется активный туннель или прокси ВПН", false, false),
                ],
                AiStudioAccessible: null,
                AiStudioStatusDetail: null,
                GooglePlayCurrency: null,
                GooglePlayCountry: null,
                GoogleTermsCountry: null,
                AiAccessDivergesFromRuTag: false);
        }

        var isForeignPhysical = !string.IsNullOrWhiteSpace(normPhysical) &&
                                !string.Equals(normPhysical, "RU", StringComparison.OrdinalIgnoreCase);

        var playIndicatesRu = string.Equals(normPlayCountry, "RU", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(normPlayCurrency, "RUB", StringComparison.OrdinalIgnoreCase);

        var explicitRuCode = string.Equals(normYt, "RU", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(normGoogle, "RU", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(normTerms, "RU", StringComparison.OrdinalIgnoreCase) ||
                             playIndicatesRu;

        // Если на зарубежном IP заблокированы сразу два ключевых контура (например YouTube Premium + Gemini или Play + Premium)
        var servicesBlockedForRegion = (youtubePremiumAvailable == false && geminiAccessible == false) ||
                                       (youtubePremiumAvailable == false && googlePlayPaidAvailable == false) ||
                                       (youtubePremiumAvailable == false && aiStudioAccessible == false);

        var isRuPoisoned = isForeignPhysical && (explicitRuCode || servicesBlockedForRegion);
        var aiAccessDiverges = isRuPoisoned && (aiStudioAccessible == true || geminiAccessible == true);

        var signalChecks = BuildSignalChecks(
            normYt,
            youtubePremiumAvailable,
            normPlayCurrency,
            normPlayCountry,
            googlePlayPaidAvailable,
            normGoogle,
            effectiveSearchLabel,
            hasCaptcha,
            geminiAccessible,
            aiStudioAccessible,
            aiStudioDetail,
            isForeignPhysical);

        var probeSucceeded = detectedGl is not null ||
                             youtubePremiumAvailable.HasValue ||
                             geminiAccessible.HasValue ||
                             aiStudioAccessible.HasValue ||
                             normPlayCurrency is not null ||
                             googlePlayPaidAvailable.HasValue ||
                             hasCaptcha;

        var ytPremText = youtubePremiumAvailable switch
        {
            true => "Доступен",
            false => "Заблокирован в стране",
            _ => "—",
        };
        var playText = !string.IsNullOrWhiteSpace(normPlayCurrency)
            ? $"{normPlayCountry ?? "—"} ({normPlayCurrency})"
            : (googlePlayPaidAvailable == false ? "Платные приложения заблокированы" : "—");
        var geminiText = geminiAccessible switch
        {
            true => "Пускает",
            false => "Заблокирован",
            _ => "—",
        };
        var aiStudioText = aiStudioAccessible switch
        {
            true => "Пускает",
            false => "Заблокирован",
            _ => "—",
        };
        var searchText = !string.IsNullOrWhiteSpace(effectiveSearchLabel)
            ? $"{normGoogle ?? "—"} ({effectiveSearchLabel})"
            : (normGoogle ?? "—");

        var evidence = $"Канал: {routingChannelUsed} · GeoIP: {normPhysical ?? "—"} · YT GL: {normYt ?? "—"} · YT Premium: {ytPremText} · Play: {playText} · Terms/Search: {searchText} · Gemini: {geminiText} · AI Studio: {aiStudioText} · Капча /sorry/: {(hasCaptcha ? "ДА (429/sorry)" : "нет")}";

        if (isRuPoisoned)
        {
            var ruSources = new List<string>();
            if (string.Equals(normYt, "RU", StringComparison.OrdinalIgnoreCase)) ruSources.Add("YouTube GL=RU");
            if (youtubePremiumAvailable == false) ruSources.Add("YouTube Premium недоступен");
            if (playIndicatesRu) ruSources.Add($"Google Play ({normPlayCurrency ?? "RU"})");
            if (string.Equals(normTerms, "RU", StringComparison.OrdinalIgnoreCase) || string.Equals(normGoogle, "RU", StringComparison.OrdinalIgnoreCase))
            {
                ruSources.Add("Google Terms/Search=RU");
            }
            if (geminiAccessible == false) ruSources.Add("Gemini заблокирован");
            if (aiStudioAccessible == false) ruSources.Add("AI Studio заблокирован");

            var reason = ruSources.Count > 0
                ? $"Сигналы РФ на сервере {normPhysical}: {string.Join(", ", ruSources)}"
                : $"Сервисы Google определили зарубежный сервер {normPhysical} как регион РФ";

            var divergenceNote = aiStudioAccessible == true
                ? " При этом контур Google AI Studio сейчас пускает этот IP — у AI Studio и YouTube/Search разные гео-таблицы."
                : string.Empty;

            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: true,
                DetectedGlCode: explicitRuCode ? "RU" : (detectedGl ?? "RU*"),
                PhysicalCountryCode: normPhysical,
                IsRuGeoPoisoned: true,
                HasGoogleCaptchaBlock: hasCaptcha,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: aiStudioAccessible == true
                    ? $"МЕТКА RU ОБНАРУЖЕНА (сервер в {normPhysical}, но Google AI Studio пускает)"
                    : $"КРИТИЧНО: Обнаружена «прокажённая метка RU» у Google (сервер в {normPhysical}, но Google видит РФ)",
                VerdictSummary: $"{reason}.{divergenceNote} Причина: массовый трафик смартфонов из РФ или российский регистратор подсети (RIPE) заставили Google перепривязать IP к РФ.",
                TechnicalEvidence: evidence,
                YouTubePremiumAvailable: youtubePremiumAvailable,
                GeminiAccessible: geminiAccessible,
                GoogleFooterCountry: effectiveSearchLabel,
                SignalChecks: signalChecks,
                AiStudioAccessible: aiStudioAccessible,
                AiStudioStatusDetail: aiStudioDetail,
                GooglePlayCurrency: normPlayCurrency,
                GooglePlayCountry: normPlayCountry,
                GoogleTermsCountry: normTerms,
                AiAccessDivergesFromRuTag: aiAccessDiverges);
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
                VerdictSummary: "Принудительной метки RU нет, но сам IP перегружен запросами соседей по ВПН-серверу или числится в спам-листах дата-центра. При поиске в Google будет появляться reCAPTCHA.",
                TechnicalEvidence: evidence,
                YouTubePremiumAvailable: youtubePremiumAvailable,
                GeminiAccessible: geminiAccessible,
                GoogleFooterCountry: effectiveSearchLabel,
                SignalChecks: signalChecks,
                AiStudioAccessible: aiStudioAccessible,
                AiStudioStatusDetail: aiStudioDetail,
                GooglePlayCurrency: normPlayCurrency,
                GooglePlayCountry: normPlayCountry,
                GoogleTermsCountry: normTerms,
                AiAccessDivergesFromRuTag: false);
        }

        if (isForeignPhysical && (geminiAccessible == false || aiStudioAccessible == false || youtubePremiumAvailable == false))
        {
            var blocked = new List<string>();
            if (aiStudioAccessible == false) blocked.Add("Google AI Studio");
            if (geminiAccessible == false) blocked.Add("Google Gemini");
            if (youtubePremiumAvailable == false) blocked.Add("YouTube Premium");
            var blockedList = string.Join(" / ", blocked);

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
                VerdictTitle: $"ВНИМАНИЕ: Частичное гео-ограничение Google ({blockedList} заблокирован)",
                VerdictSummary: $"Явного кода GL=RU не обнаружено, но {blockedList} отклоняет эту подсеть (часто бывает на дата-центрах или подсетях на грани перепривязки к РФ). Проверьте независимые бейджи AI Studio и Gemini ниже.",
                TechnicalEvidence: evidence,
                YouTubePremiumAvailable: youtubePremiumAvailable,
                GeminiAccessible: geminiAccessible,
                GoogleFooterCountry: effectiveSearchLabel,
                SignalChecks: signalChecks,
                AiStudioAccessible: aiStudioAccessible,
                AiStudioStatusDetail: aiStudioDetail,
                GooglePlayCurrency: normPlayCurrency,
                GooglePlayCountry: normPlayCountry,
                GoogleTermsCountry: normTerms,
                AiAccessDivergesFromRuTag: false);
        }

        if (string.Equals(normPhysical, "RU", StringComparison.OrdinalIgnoreCase))
        {
            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: probeSucceeded,
                DetectedGlCode: detectedGl ?? "RU",
                PhysicalCountryCode: "RU",
                IsRuGeoPoisoned: false,
                HasGoogleCaptchaBlock: false,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: "Запрос ушёл напрямую с российского IP (RU) — зарубежный ВПН сейчас не перехватывает Google",
                VerdictSummary: "И базы GeoIP, и сервисы Google определяют ваш текущий IP как российский (RU). Если ВПН включён, проверьте режим TUN или выберите в Расширенном режиме проверку через «Авто-прокси клиента ВПН».",
                TechnicalEvidence: evidence,
                YouTubePremiumAvailable: youtubePremiumAvailable,
                GeminiAccessible: geminiAccessible,
                GoogleFooterCountry: effectiveSearchLabel,
                SignalChecks: signalChecks,
                AiStudioAccessible: aiStudioAccessible,
                AiStudioStatusDetail: aiStudioDetail,
                GooglePlayCurrency: normPlayCurrency,
                GooglePlayCountry: normPlayCountry,
                GoogleTermsCountry: normTerms,
                AiAccessDivergesFromRuTag: false);
        }

        if (probeSucceeded)
        {
            var shownRegion = detectedGl ?? normPhysical ?? "Зарубежный";
            return new GoogleGeoVerdict(
                ProbeExecuted: true,
                ProbeSucceeded: true,
                DetectedGlCode: shownRegion,
                PhysicalCountryCode: normPhysical,
                IsRuGeoPoisoned: false,
                HasGoogleCaptchaBlock: false,
                YouTubeCountryCode: normYt,
                GoogleSearchRegion: normGoogle,
                RoutingChannelUsed: routingChannelUsed,
                VerdictTitle: $"ОТЛИЧНО: Чистый зарубежный IP для Google (регион {shownRegion}, метки RU и капчи нет)",
                VerdictSummary: $"Все активные сигналы подтверждают чистую зарубежную репутацию подсети ({normPhysical ?? shownRegion}): YouTube, Google Play, Terms/Search, Gemini и AI Studio не видят привязки к РФ.",
                TechnicalEvidence: evidence,
                YouTubePremiumAvailable: youtubePremiumAvailable,
                GeminiAccessible: geminiAccessible,
                GoogleFooterCountry: effectiveSearchLabel,
                SignalChecks: signalChecks,
                AiStudioAccessible: aiStudioAccessible,
                AiStudioStatusDetail: aiStudioDetail,
                GooglePlayCurrency: normPlayCurrency,
                GooglePlayCountry: normPlayCountry,
                GoogleTermsCountry: normTerms,
                AiAccessDivergesFromRuTag: false);
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
            VerdictTitle: "Сервисы Google/YouTube не ответили в пределах таймаута",
            VerdictSummary: "Если ВПН выключен — ТСПУ блокирует прямой доступ к YouTube. Включите ВПН (TUN или системный прокси) и повторите проверку.",
            TechnicalEvidence: evidence,
            YouTubePremiumAvailable: null,
            GeminiAccessible: null,
            GoogleFooterCountry: null,
            SignalChecks: signalChecks,
            AiStudioAccessible: null,
            AiStudioStatusDetail: null,
            GooglePlayCurrency: null,
            GooglePlayCountry: null,
            GoogleTermsCountry: null,
            AiAccessDivergesFromRuTag: false);
    }

    private static IReadOnlyList<GoogleSignalCheck> BuildSignalChecks(
        string? ytGl,
        bool? ytPremium,
        string? playCurrency,
        string? playCountry,
        bool? playPaidAvailable,
        string? searchRegion,
        string? termsOrFooterLabel,
        bool hasCaptcha,
        bool? gemini,
        bool? aiStudio,
        string? aiStudioDetail,
        bool isForeignPhysical)
    {
        var ytIsRuAlert = isForeignPhysical && string.Equals(ytGl, "RU", StringComparison.OrdinalIgnoreCase);
        var ytCheck = new GoogleSignalCheck(
            "1. YouTube INNERTUBE_CONTEXT_GL",
            ytGl is null ? "Нет ответа" : (ytIsRuAlert ? "МЕТКА RU!" : $"Регион: {ytGl}"),
            ytGl is null
                ? "YouTube не вернул код страны (возможна блокировка ТСПУ без ВПН)"
                : (ytIsRuAlert ? "Критично: зарубежный IP, но YouTube определил регион РФ" : $"YouTube корректно определил страну {ytGl}"),
            IsAlert: ytIsRuAlert,
            IsPass: ytGl is not null && !ytIsRuAlert && !string.Equals(ytGl, "RU", StringComparison.OrdinalIgnoreCase));

        var premCheck = new GoogleSignalCheck(
            "2. Доступность YouTube Premium",
            ytPremium switch
            {
                true => "Доступен",
                false => "НЕДОСТУПЕН",
                _ => "Не определено",
            },
            ytPremium switch
            {
                true => "YouTube предлагает зарубежную подписку Premium — регион чистый",
                false => "YouTube сообщил «недоступна в вашей стране» (признак метки RU/санкций)",
                _ => "Не удалось прочитать страницу /premium (таймаут или блокировка)",
            },
            IsAlert: ytPremium == false,
            IsPass: ytPremium == true);

        var playIsRu = string.Equals(playCurrency, "RUB", StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(playCountry, "RU", StringComparison.OrdinalIgnoreCase);
        var playIsAlert = (isForeignPhysical && playIsRu) || playPaidAvailable == false;
        var playStatus = playIsRu
            ? $"МЕТКА RU ({playCurrency ?? "RUB"})!"
            : (playPaidAvailable == false
                ? "ПОКУПКИ БЛОК"
                : (!string.IsNullOrWhiteSpace(playCurrency)
                    ? $"{playCountry ?? "OK"} · {playCurrency}"
                    : "Не определено"));
        var playDetail = playIsRu
            ? "Витрина Google Play переключилась на Россию / валюту RUB на зарубежном IP"
            : (playPaidAvailable == false
                ? "Google Play скрыл/заблокировал платные приложения (признак региона РФ)"
                : (!string.IsNullOrWhiteSpace(playCurrency)
                    ? $"Google Play открыл зарубежную витрину с валютой {playCurrency}"
                    : "Не удалось определить валюту витрины Google Play"));
        var playCheck = new GoogleSignalCheck(
            "3. Google Play (регион и валюта)",
            playStatus,
            playDetail,
            IsAlert: playIsAlert,
            IsPass: !playIsAlert && (!string.IsNullOrWhiteSpace(playCurrency) || playPaidAvailable == true));

        var searchIsRuAlert = isForeignPhysical && string.Equals(searchRegion, "RU", StringComparison.OrdinalIgnoreCase);
        var searchStatus = hasCaptcha
            ? "КАПЧА 429"
            : (searchIsRuAlert ? "МЕТКА RU!" : (searchRegion is not null ? $"Регион: {searchRegion}" : "Чисто (без капчи)"));
        var searchDetail = hasCaptcha
            ? "Google перенаправил запрос на /sorry/ (reCAPTCHA из-за перегруженного IP)"
            : (searchIsRuAlert
                ? $"Google Terms / Search показал Россию ({termsOrFooterLabel ?? "RU"}) на зарубежном IP"
                : (!string.IsNullOrWhiteSpace(termsOrFooterLabel)
                    ? $"Google Terms / Search определил юрисдикцию «{termsOrFooterLabel}», капчи нет"
                    : "Поиск Google доступен без капчи /sorry/"));
        var searchCheck = new GoogleSignalCheck(
            "4. Google Terms / Search и /sorry/",
            searchStatus,
            searchDetail,
            IsAlert: hasCaptcha || searchIsRuAlert,
            IsPass: !hasCaptcha && !searchIsRuAlert && (searchRegion is not null || !string.IsNullOrWhiteSpace(termsOrFooterLabel)));

        var geminiCheck = new GoogleSignalCheck(
            "5. Google Gemini Web",
            gemini switch
            {
                true => "ПУСКАЕТ",
                false => "ЗАБЛОКИРОВАН",
                _ => "Не определено",
            },
            gemini switch
            {
                true => "gemini.google.com принимает подключения с этого IP без гео-блокировки",
                false => "Gemini отклонил IP по региону (/unsupported или HTTP 403)",
                _ => "Нет однозначного ответа от gemini.google.com",
            },
            IsAlert: gemini == false,
            IsPass: gemini == true);

        var aiStudioCheck = new GoogleSignalCheck(
            "6. Google AI Studio + API",
            aiStudio switch
            {
                true => "ПУСКАЕТ",
                false => "ЗАБЛОКИРОВАН",
                _ => "Не определено",
            },
            !string.IsNullOrWhiteSpace(aiStudioDetail)
                ? aiStudioDetail
                : (aiStudio switch
                {
                    true => "aistudio.google.com и API-шлюз не блокируют этот IP по региону",
                    false => "Google AI Studio отклонил IP (User location is not supported / 403)",
                    _ => "Нет ответа от aistudio.google.com / generativelanguage.googleapis.com",
                }),
            IsAlert: aiStudio == false,
            IsPass: aiStudio == true);

        return [ytCheck, premCheck, playCheck, searchCheck, geminiCheck, aiStudioCheck];
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
        var (_, highRuBleed, high16Kb, verdict, notes) = ClassifySubnetRisksDetailed(
            countryCode,
            asn,
            isp,
            isHosting,
            isProxyOrVpn,
            rdap: null);
        return (highRuBleed, high16Kb, verdict, notes);
    }

    public static (RuBleedRiskTier RiskTier, bool HighRuGoogleBleedRisk, bool High16KbRisk, string CleanlinessVerdict, string TechnicalNotes)
        ClassifySubnetRisksDetailed(
            string? countryCode,
            string? asn,
            string? isp,
            bool isHosting,
            bool isProxyOrVpn,
            RdapSubnetInfo? rdap)
    {
        var combined = $"{asn} {isp}".ToLowerInvariant();
        var isRuCountry = string.Equals(countryCode, "RU", StringComparison.OrdinalIgnoreCase);

        var ruHosterKeyword = !isRuCountry && HighRuGeoBleedKeywords.Any(k => combined.Contains(k, StringComparison.Ordinal));
        var rdapHasRu = rdap?.HasRuFootprint == true;
        var high16Kb = High16KbCloudKeywords.Any(k => combined.Contains(k, StringComparison.Ordinal));

        RuBleedRiskTier tier;
        string verdict;

        if (isRuCountry)
        {
            tier = RuBleedRiskTier.CriticalRu;
            verdict = "Локация РФ (Google = RU)";
        }
        else if (rdapHasRu)
        {
            tier = RuBleedRiskTier.CriticalRu;
            verdict = "Критичный риск метки RU (российский блок RIPE/RDAP)";
        }
        else if (ruHosterKeyword)
        {
            tier = RuBleedRiskTier.HighRisk;
            verdict = "Высокий риск метки Google RU (RU/СНГ-популярный хостер)";
        }
        else if (isProxyOrVpn)
        {
            tier = RuBleedRiskTier.HighRisk;
            verdict = "Высокий риск метки RU / капчи (база VPN/Proxy)";
        }
        else if (isHosting)
        {
            tier = RuBleedRiskTier.MediumDatacenterUnverified;
            verdict = "Дата-центр · нужен живой тест (Google часто метит VPS как RU)";
        }
        else
        {
            tier = RuBleedRiskTier.LowCleanIsp;
            verdict = "Низкий риск (резидентный / чистый ISP)";
        }

        // Для обратной совместимости флаг HighRuGoogleBleedRisk = true для CriticalRu и HighRisk (не для чистого РФ-сервера, если GeoIP уже RU)
        var highRuBleed = !isRuCountry && tier is RuBleedRiskTier.CriticalRu or RuBleedRiskTier.HighRisk;

        var notes = new List<string>
        {
            isHosting ? "Hosting/ДЦ: Да" : "Hosting/ДЦ: Нет (ISP)",
            isProxyOrVpn ? "Proxy/VPN база: Да" : "Proxy/VPN база: Чисто",
        };
        if (rdap is not null && !string.IsNullOrWhiteSpace(rdap.CountryCode))
        {
            notes.Add($"RIPE/RDAP: {rdap.CountryCode}{(string.IsNullOrWhiteSpace(rdap.NetName) ? string.Empty : $" ({rdap.NetName})")}");
        }
        if (rdapHasRu && !string.IsNullOrWhiteSpace(rdap?.RuEvidence))
        {
            notes.Add($"След РФ в WHOIS: {rdap.RuEvidence}");
        }
        else if (ruHosterKeyword)
        {
            notes.Add("Популярный у РФ-ВПН хостер (высокая вероятность GL=RU)");
        }
        else if (tier == RuBleedRiskTier.MediumDatacenterUnverified)
        {
            notes.Add("Без живого запроса в Google нельзя гарантировать отсутствие метки RU — подключитесь к узлу и нажмите «Проверить вживую»");
        }

        if (high16Kb)
        {
            notes.Add("Крупное облако (требуется Reality XHTTP/Vision от 16 КБ)");
        }

        return (tier, highRuBleed, high16Kb, verdict, string.Join(" · ", notes));
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
                    HttpClientHandler? handler = null;
                    try
                    {
                        handler = new HttpClientHandler
                        {
                            Proxy = new WebProxy(proxyUri),
                            UseProxy = true,
                            AutomaticDecompression = DecompressionMethods.All,
                        };
                        customProxyClient = new HttpClient(handler, disposeHandler: true)
                        {
                            Timeout = TimeSpan.FromSeconds(10),
                        };
                        handler = null;
                    }
                    finally
                    {
                        handler?.Dispose();
                    }
                    customProxyClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", DesktopChromeUserAgent);
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

            Task<LiveGoogleProbeBundle>? googleTask = null;
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
                var bundle = await googleTask.ConfigureAwait(false);
                googleVerdict = EvaluateGoogleGeoVerdict(
                    tempConsensusCountry,
                    bundle.YtGl,
                    bundle.GoogleGl,
                    bundle.HasCaptcha,
                    channelLabel,
                    probeExecuted: true,
                    youtubePremiumAvailable: bundle.YtPremium,
                    geminiAccessible: bundle.GeminiOk,
                    googleFooterCountry: bundle.FooterCountry,
                    aiStudioAccessible: bundle.AiStudioOk,
                    aiStudioDetail: bundle.AiStudioDetail,
                    googlePlayCurrency: bundle.PlayCurrency,
                    googlePlayCountry: bundle.PlayCountry,
                    googlePlayPaidAvailable: bundle.PlayPaidAvailable,
                    googleTermsCountry: bundle.TermsCountry,
                    googleTermsLabel: bundle.TermsLabel);
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
    /// Извлекает все серверы из подписки или конфига, резолвит их доменные имена в IP и пакетно проверяет репутацию (GeoIP + RIPE/RDAP WHOIS).
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

        // 2. Пакетный запрос к ip-api.com/batch + параллельный RIPE/RDAP WHOIS для уникальных IP
        var uniqueIps = resolvedMap.Values
            .Where(ip => !string.IsNullOrWhiteSpace(ip))
            .Select(ip => ip!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(100)
            .ToList();

        var batchGeoByIp = new ConcurrentDictionary<string, GeoProviderSample>(StringComparer.OrdinalIgnoreCase);
        var rdapByIp = new ConcurrentDictionary<string, RdapSubnetInfo>(StringComparer.OrdinalIgnoreCase);
        if (uniqueIps.Count > 0)
        {
            var geoTask = PopulateBatchGeoAsync(http, uniqueIps, batchGeoByIp, ct);
            var rdapTask = PopulateBatchRdapAsync(http, uniqueIps.Take(40).ToList(), rdapByIp, ct);
            await Task.WhenAll(geoTask, rdapTask).ConfigureAwait(false);
        }

        // 3. Собираем итоговую таблицу по всем узлам подписки с честной 4-уровневой шкалой риска
        var rows = new List<SubscriptionIpReputationRow>(endpoints.Count);
        foreach (var ep in endpoints)
        {
            resolvedMap.TryGetValue(ep.RawHost, out var resolvedIp);
            GeoProviderSample? geo = null;
            RdapSubnetInfo? rdap = null;
            if (!string.IsNullOrWhiteSpace(resolvedIp))
            {
                batchGeoByIp.TryGetValue(resolvedIp, out geo);
                rdapByIp.TryGetValue(resolvedIp, out rdap);
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
                    TechnicalNotes: resolvedIp is null ? "Домен сервера не вернул A/AAAA запись" : "Повторите проверку",
                    RiskTier: RuBleedRiskTier.MediumDatacenterUnverified,
                    RdapCountry: rdap?.CountryCode,
                    RdapOrgOrNetName: rdap?.OrgOrMaintainer,
                    HasRuRdapFootprint: rdap?.HasRuFootprint ?? false));
                continue;
            }

            var isHosting = geo.IsHosting ?? InferHostingFromOrg(geo.Asn, geo.Isp) ?? false;
            var isProxy = geo.IsProxyOrVpn ?? false;
            var (tier, highRuBleed, high16Kb, verdict, notes) = ClassifySubnetRisksDetailed(
                geo.CountryCode,
                geo.Asn,
                geo.Isp,
                isHosting,
                isProxy,
                rdap);

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
                notes,
                RiskTier: tier,
                RdapCountry: rdap?.CountryCode,
                RdapOrgOrNetName: rdap?.OrgOrMaintainer,
                HasRuRdapFootprint: rdap?.HasRuFootprint ?? false));
        }

        return rows;
    }

    private static async Task PopulateBatchRdapAsync(
        HttpClient http,
        List<string> ips,
        ConcurrentDictionary<string, RdapSubnetInfo> results,
        CancellationToken ct)
    {
        using var gate = new SemaphoreSlim(6);
        var tasks = ips.Select(async ip =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var info = await ProbeRdapSubnetAsync(http, ip, ct).ConfigureAwait(false);
                if (info is not null)
                {
                    results[ip] = info;
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private static async Task<RdapSubnetInfo?> ProbeRdapSubnetAsync(
        HttpClient http,
        string ip,
        CancellationToken ct)
    {
        var escaped = Uri.EscapeDataString(ip);
        Uri[] uris =
        [
            new Uri($"https://rdap.db.ripe.net/ip/{escaped}"),
            new Uri($"https://rdap.org/ip/{escaped}"),
        ];

        foreach (var uri in uris)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(4));
                using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                req.Headers.TryAddWithoutValidation("Accept", "application/rdap+json, application/json");
                using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    continue;
                }

                var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                var parsed = ParseRdapIpResponse(json);
                if (!string.IsNullOrWhiteSpace(parsed.CountryCode) || !string.IsNullOrWhiteSpace(parsed.NetName) || parsed.HasRuFootprint)
                {
                    return parsed;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
            {
                // Пробуем следующий RDAP-шлюз
            }
        }

        return null;
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

    private static void ApplyGoogleProbeHeaders(HttpRequestMessage req)
    {
        req.Headers.TryAddWithoutValidation("User-Agent", DesktopChromeUserAgent);
        req.Headers.TryAddWithoutValidation("Accept-Language", "en-US,en;q=0.9");
        req.Headers.TryAddWithoutValidation("Cookie", GoogleConsentBypassCookie);
    }

    private sealed record LiveGoogleProbeBundle(
        string? YtGl,
        string? GoogleGl,
        string? FooterCountry,
        bool HasCaptcha,
        bool? YtPremium,
        bool? GeminiOk,
        bool? AiStudioOk,
        string? AiStudioDetail,
        string? PlayCurrency,
        string? PlayCountry,
        bool? PlayPaidAvailable,
        string? TermsCountry,
        string? TermsLabel);

    private static async Task<LiveGoogleProbeBundle> ProbeLiveGoogleAndYouTubeGeoAsync(
        HttpClient http,
        CancellationToken ct)
    {
        var ytGlTask = ProbeYouTubeGlSignalAsync(http, ct);
        var ytPremTask = ProbeYouTubePremiumSignalAsync(http, ct);
        var playTask = ProbeGooglePlaySignalAsync(http, ct);
        var termsTask = ProbeGoogleTermsSignalAsync(http, ct);
        var searchTask = ProbeGoogleSearchSignalAsync(http, ct);
        var geminiTask = ProbeGeminiSignalAsync(http, ct);
        var aiStudioTask = ProbeAiStudioSignalAsync(http, ct);

        await Task.WhenAll(ytGlTask, ytPremTask, playTask, termsTask, searchTask, geminiTask, aiStudioTask).ConfigureAwait(false);

        var ytGl = await ytGlTask.ConfigureAwait(false);
        var ytPrem = await ytPremTask.ConfigureAwait(false);
        var (playCurrency, playCountry, playPaidAvailable) = await playTask.ConfigureAwait(false);
        var (termsCountry, termsLabel) = await termsTask.ConfigureAwait(false);
        var (googleGl, footerCountry, hasCaptcha) = await searchTask.ConfigureAwait(false);
        var geminiOk = await geminiTask.ConfigureAwait(false);
        var (aiStudioOk, aiStudioDetail) = await aiStudioTask.ConfigureAwait(false);

        return new LiveGoogleProbeBundle(
            ytGl,
            googleGl ?? termsCountry,
            footerCountry,
            hasCaptcha,
            ytPrem,
            geminiOk,
            aiStudioOk,
            aiStudioDetail,
            playCurrency,
            playCountry,
            playPaidAvailable,
            termsCountry,
            termsLabel);
    }

    private static async Task<string?> ProbeYouTubeGlSignalAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            using var req = new HttpRequestMessage(HttpMethod.Get, YouTubeSwDataUri);
            ApplyGoogleProbeHeaders(req);
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var gl = ParseYouTubeGlCode(body);
            if (!string.IsNullOrWhiteSpace(gl))
            {
                return gl;
            }

            using var req2 = new HttpRequestMessage(HttpMethod.Get, YouTubeHomeUri);
            ApplyGoogleProbeHeaders(req2);
            using var resp2 = await http.SendAsync(req2, cts.Token).ConfigureAwait(false);
            var body2 = await resp2.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            gl = ParseYouTubeGlCode(body2);
            if (!string.IsNullOrWhiteSpace(gl))
            {
                return gl;
            }

            using var req3 = new HttpRequestMessage(HttpMethod.Get, YouTubeRedUri);
            ApplyGoogleProbeHeaders(req3);
            using var resp3 = await http.SendAsync(req3, cts.Token).ConfigureAwait(false);
            var body3 = await resp3.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseYouTubeGlCode(body3);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<bool?> ProbeYouTubePremiumSignalAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, YouTubePremiumUri);
            ApplyGoogleProbeHeaders(req);
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var avail = ParseYouTubePremiumAvailability(body);
            if (avail.HasValue)
            {
                return avail;
            }

            using var req2 = new HttpRequestMessage(HttpMethod.Get, YouTubeRedUri);
            ApplyGoogleProbeHeaders(req2);
            using var resp2 = await http.SendAsync(req2, cts.Token).ConfigureAwait(false);
            var body2 = await resp2.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseYouTubePremiumAvailability(body2);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<(string? CurrencyCode, string? CountryCode, bool? PaidAppsAvailable)> ProbeGooglePlaySignalAsync(
        HttpClient http,
        CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, GooglePlayPaidAppUri);
            ApplyGoogleProbeHeaders(req);
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseGooglePlayRegionAndCurrency(body);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return (null, null, null);
        }
    }

    private static async Task<(string? CountryCode, string? CountryLabel)> ProbeGoogleTermsSignalAsync(
        HttpClient http,
        CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, GoogleTermsUri);
            ApplyGoogleProbeHeaders(req);
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseGoogleTermsCountry(body);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return (null, null);
        }
    }

    private static async Task<bool?> ProbeGeminiSignalAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, GeminiAppUri);
            ApplyGoogleProbeHeaders(req);
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var finalUri = resp.RequestMessage?.RequestUri?.ToString();
            return ParseGeminiAvailability(finalUri, (int)resp.StatusCode, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<(bool? Accessible, string Detail)> ProbeAiStudioSignalAsync(HttpClient http, CancellationToken ct)
    {
        string? webFinalUri = null;
        var webStatus = 0;
        string? webBody = null;
        var apiStatus = 0;
        string? apiBody = null;

        var webTask = Task.Run(async () =>
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                using var req = new HttpRequestMessage(HttpMethod.Get, AiStudioWebUri);
                ApplyGoogleProbeHeaders(req);
                using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
                webStatus = (int)resp.StatusCode;
                webFinalUri = resp.RequestMessage?.RequestUri?.ToString();
                webBody = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
            {
                // Продолжаем с API-зондом
            }
        }, ct);

        var apiTask = Task.Run(async () =>
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                using var req = new HttpRequestMessage(HttpMethod.Get, AiStudioApiProbeUri);
                req.Headers.TryAddWithoutValidation("User-Agent", DesktopChromeUserAgent);
                using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
                apiStatus = (int)resp.StatusCode;
                apiBody = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
            {
                // Продолжаем с веб-зондом
            }
        }, ct);

        await Task.WhenAll(webTask, apiTask).ConfigureAwait(false);
        return ParseAiStudioAvailability(webFinalUri, webStatus, webBody, apiStatus, apiBody);
    }

    private static async Task<(string? RegionCode, string? FooterLabel, bool HasCaptcha)> ProbeGoogleSearchSignalAsync(
        HttpClient http,
        CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Get, GoogleSearchHomeUri);
            ApplyGoogleProbeHeaders(req);
            using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var finalUri = resp.RequestMessage?.RequestUri?.ToString();
            var detailed = ParseGoogleSearchRegionDetailed(finalUri, (int)resp.StatusCode, body);
            if (detailed.RegionCode is not null || detailed.HasCaptcha)
            {
                return detailed;
            }

            using var req2 = new HttpRequestMessage(HttpMethod.Get, GooglePrefsUri);
            ApplyGoogleProbeHeaders(req2);
            using var resp2 = await http.SendAsync(req2, cts.Token).ConfigureAwait(false);
            var body2 = await resp2.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var finalUri2 = resp2.RequestMessage?.RequestUri?.ToString();
            var fallback = ParseGoogleSearchRegionDetailed(finalUri2, (int)resp2.StatusCode, body2);
            return (
                fallback.RegionCode ?? detailed.RegionCode,
                fallback.FooterLabel ?? detailed.FooterLabel,
                detailed.HasCaptcha || fallback.HasCaptcha);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return (null, null, false);
        }
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
