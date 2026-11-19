using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetworkChecker.Core.VpnAudit;

public enum DnsCoreTarget
{
    SingBox112,
    XrayCore,
    ClashMihomo,
}

public enum DnsOutputScope
{
    DnsBlockOnly,
    FullDnsAndRouting,
}

public enum DnsProviderProfile
{
    NinjaPrivacy,     // Njalla (dns.njal.la) + LibreDNS (doh.libredns.gr)
    MullvadQuad9,     // Mullvad (dns.mullvad.net) + Quad9 (dns.quad9.net)
    CloudflareGoogle, // Cloudflare (1.1.1.1) + Google (8.8.8.8)
    ComssAdGuard,     // Comss.one + AdGuard DNS
}

public sealed record DnsArchitectOptions(
    DnsCoreTarget Core = DnsCoreTarget.XrayCore,
    bool RfSplitTunneling = true,
    bool UseFakeIp = false,
    bool Ipv4Only = false,
    bool BlockAds = false,
    DnsProviderProfile ProviderProfile = DnsProviderProfile.NinjaPrivacy,
    DnsOutputScope OutputScope = DnsOutputScope.DnsBlockOnly);

/// <summary>
/// Конструктор, хирургический патчер и аудитор блока DNS:
/// - Поддержка приватных («Ninja» / No-Log) DoH-провайдеров: Njalla (dns.njal.la), LibreDNS (doh.libredns.gr), Mullvad, Quad9;
/// - Режим «Только блок DNS (без нижних секций)» и режим «Полный блок DNS + Routing»;
/// - Точечная врезка блока "dns" в одиночный JSON-конфиг или во все узлы JSON-массива подписки [...] без изменения outbounds/routing/remarks;
/// - Умный аудит роли "localhost" и гео-правил 77.88.8.8 (geosite:category-ru, geosite:category-gov-ru).
/// </summary>
public static class DnsConfigArchitect
{
    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly string[] SingBoxRuDomainSuffixes = [".ru", ".su", ".xn--p1ai"];
    private static readonly string[] SingBoxRuRuleSets = ["geosite-category-ru", "geosite-category-gov-ru"];
    private static readonly string[] QueryTypeIpv4Only = ["A"];
    private static readonly string[] QueryTypeDualStack = ["A", "AAAA"];
    private static readonly string[] XrayFakeDnsNonCn = ["geosite:geolocation-!cn"];
    private static readonly string[] XrayFakeDnsAll = ["geosite:all"];
    private static readonly string[] XrayRuDomains = ["geosite:category-ru", "geosite:category-gov-ru"];
    private static readonly string[] XrayInboundRemote = ["dns-remote"];
    private static readonly string[] XrayInboundDirect = ["dns-direct"];
    private static readonly string[] XrayInboundBootstrap = ["dns-bootstrap"];
    private static readonly string[] XrayGeoIpPrivate = ["geoip:private", "geoip:ru"];

    public const string NinjaSampleJson = """
        {
          "dns": {
            "queryStrategy": "UseIP",
            "servers": [
              {
                "address": "77.88.8.8",
                "domains": [
                  "geosite:category-ru",
                  "geosite:category-gov-ru"
                ],
                "skipFallback": true
              },
              "https://dns.njal.la/dns-query",
              "https://doh.libredns.gr/dns-query",
              "localhost"
            ]
          }
        }
        """;

    public static (string PrimaryDohUrl, string SecondaryDohUrl, string PrimaryHost, string Label) GetProviderEndpoints(
        DnsProviderProfile provider) =>
        provider switch
        {
            DnsProviderProfile.NinjaPrivacy => (
                "https://dns.njal.la/dns-query",
                "https://doh.libredns.gr/dns-query",
                "dns.njal.la",
                "Ninja Privacy (Njalla + LibreDNS)"),
            DnsProviderProfile.MullvadQuad9 => (
                "https://dns.mullvad.net/dns-query",
                "https://dns.quad9.net/dns-query",
                "dns.mullvad.net",
                "Приватный Mullvad + Quad9"),
            DnsProviderProfile.ComssAdGuard => (
                "https://dns.comss.one/dns-query",
                "https://dns.adguard-dns.com/dns-query",
                "dns.comss.one",
                "Comss.one + AdGuard DoH"),
            _ => (
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
                "1.1.1.1",
                "Классический Cloudflare + Google"),
        };

    public static string GenerateOptimalBlock(DnsArchitectOptions? options = null)
    {
        var opt = options ?? new DnsArchitectOptions();
        return opt.Core switch
        {
            DnsCoreTarget.SingBox112 => GenerateSingBox112(opt),
            DnsCoreTarget.XrayCore => GenerateXray(opt),
            DnsCoreTarget.ClashMihomo => GenerateClashYaml(opt),
            _ => GenerateXray(opt),
        };
    }

    /// <summary>
    /// Точечно заменяет только свойство "dns" внутри JSON-конфига или JSON-массива подписки [...],
    /// вообще не трогая outbounds, inbounds, routing, burstObservatory и remarks.
    /// Если передан targetNodeIndex для JSON-массива и extractSingleNode = true — возвращает только этот один исправленный узел.
    /// </summary>
    public static bool TryInjectDnsIntoJsonConfig(
        string rawConfigOrSubscription,
        DnsArchitectOptions? options,
        out string patchedJson,
        out string summaryMessage,
        int? targetNodeIndex = null,
        bool extractSingleNodeOnly = false)
    {
        patchedJson = rawConfigOrSubscription;
        summaryMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(rawConfigOrSubscription))
        {
            summaryMessage = "Конфиг пуст — сначала загрузите подписку или вставьте JSON-конфиг.";
            return false;
        }

        var opt = (options ?? new DnsArchitectOptions()) with { OutputScope = DnsOutputScope.DnsBlockOnly };
        var dnsWrapperJson = GenerateOptimalBlock(opt);

        JsonNode? dnsBlockNode;
        try
        {
            var parsedWrapper = JsonNode.Parse(dnsWrapperJson);
            dnsBlockNode = parsedWrapper?["dns"]?.DeepClone();
        }
        catch (JsonException ex)
        {
            summaryMessage = $"Не удалось подготовить JSON-узел DNS: {ex.Message}";
            return false;
        }

        if (dnsBlockNode is null)
        {
            summaryMessage = "Сгенерированный блок не содержит секции \"dns\".";
            return false;
        }

        // Проверяем, не Base64 ли это
        var trimmed = rawConfigOrSubscription.Trim();
        if (!trimmed.StartsWith('{') && !trimmed.StartsWith('['))
        {
            if (TryDecodeBase64Json(trimmed, out var decoded))
            {
                trimmed = decoded;
            }
        }

        try
        {
            var root = JsonNode.Parse(trimmed);
            if (root is JsonObject singleObj)
            {
                singleObj["dns"] = dnsBlockNode.DeepClone();
                patchedJson = singleObj.ToJsonString(PrettyJson);
                var (_, _, _, providerLabel) = GetProviderEndpoints(opt.ProviderProfile);
                summaryMessage = $"Блок \"dns\" ({providerLabel}) точечно обновлён. Все остальные секции ниже (outbounds, routing, inbounds) оставлены без изменений.";
                return true;
            }

            if (root is JsonArray arr && arr.Count > 0)
            {
                var targetZeroIdx = targetNodeIndex.HasValue
                    ? Math.Clamp(targetNodeIndex.Value > 0 ? targetNodeIndex.Value - 1 : 0, 0, arr.Count - 1)
                    : (int?)null;

                if (extractSingleNodeOnly)
                {
                    var idx = targetZeroIdx ?? 0;
                    if (arr[idx] is JsonObject selectedObj)
                    {
                        var clone = selectedObj.DeepClone().AsObject();
                        clone["dns"] = dnsBlockNode.DeepClone();
                        patchedJson = clone.ToJsonString(PrettyJson);
                        var remarks = clone["remarks"]?.GetValue<string>() ?? $"Узел #{idx + 1}";
                        summaryMessage = $"Готов исправленный конфиг для локации «{remarks}» с новым блоком DNS (нижние секции не тронуты).";
                        return true;
                    }
                }

                var updatedCount = 0;
                for (var i = 0; i < arr.Count; i++)
                {
                    if (targetZeroIdx.HasValue && targetZeroIdx.Value != i)
                    {
                        continue;
                    }

                    if (arr[i] is JsonObject itemObj)
                    {
                        itemObj["dns"] = dnsBlockNode.DeepClone();
                        updatedCount++;
                    }
                }

                patchedJson = arr.ToJsonString(PrettyJson);
                var (_, _, _, providerLabel) = GetProviderEndpoints(opt.ProviderProfile);
                summaryMessage = targetZeroIdx.HasValue
                    ? $"Блок \"dns\" ({providerLabel}) точечно обновлён в выбранном узле #{targetZeroIdx.Value + 1} подписки."
                    : $"Блок \"dns\" ({providerLabel}) точечно вшит во все {updatedCount} локаций подписки (секция outbounds и маршруты ниже не тронуты).";
                return true;
            }
        }
        catch (JsonException)
        {
            // Не JSON — например vless:// ссылка
        }

        summaryMessage = "Точечная врезка блока \"dns\" работает для JSON-конфигов и JSON-подписок (Happ / Xray / Sing-box). Для одиночной ссылки vless:// сначала откройте её JSON-профиль или используйте готовый блок DNS слева.";
        return false;
    }

    private static bool TryDecodeBase64Json(string input, out string decodedJson)
    {
        decodedJson = string.Empty;
        try
        {
            var clean = input.Replace('-', '+').Replace('_', '/').Trim();
            switch (clean.Length % 4)
            {
                case 2: clean += "=="; break;
                case 3: clean += "="; break;
            }
            var bytes = Convert.FromBase64String(clean);
            var text = Encoding.UTF8.GetString(bytes).Trim();
            if (text.StartsWith('{') || text.StartsWith('['))
            {
                decodedJson = text;
                return true;
            }
        }
        catch (FormatException)
        {
            // ignore non-base64 input
        }
        return false;
    }

    public static IReadOnlyList<VpnAuditFinding> AuditDnsBlock(string rawDns)
    {
        var findings = new List<VpnAuditFinding>();
        if (string.IsNullOrWhiteSpace(rawDns)) return findings;
        var lower = rawDns.ToLowerInvariant();

        var isDnsOnlySnippet = !lower.Contains("\"outbounds\"", StringComparison.Ordinal) &&
                               !lower.Contains("\"inbounds\"", StringComparison.Ordinal) &&
                               !lower.Contains("\"routing\"", StringComparison.Ordinal) &&
                               !lower.Contains("\"route\"", StringComparison.Ordinal) &&
                               !lower.Contains("tun:", StringComparison.Ordinal);

        // 1. Проверка приватных ("Ninja" / No-Log) DoH-резолверов
        var ninjaHits = new List<string>();
        if (lower.Contains("dns.njal.la", StringComparison.Ordinal)) ninjaHits.Add("Njalla (dns.njal.la)");
        if (lower.Contains("doh.libredns.gr", StringComparison.Ordinal)) ninjaHits.Add("LibreDNS (doh.libredns.gr)");
        if (lower.Contains("dns.mullvad.net", StringComparison.Ordinal)) ninjaHits.Add("Mullvad (dns.mullvad.net)");
        if (lower.Contains("dns.quad9.net", StringComparison.Ordinal)) ninjaHits.Add("Quad9 (dns.quad9.net)");
        if (lower.Contains("dns.comss.one", StringComparison.Ordinal)) ninjaHits.Add("Comss.one DoH");
        if (lower.Contains("dns.adguard-dns.com", StringComparison.Ordinal)) ninjaHits.Add("AdGuard DoH");

        if (ninjaHits.Count > 0)
        {
            findings.Add(new VpnAuditFinding(
                "dns-ninja-privacy-ok",
                AuditCategory.Security,
                AuditSeverity.Ok,
                $"Подключены приватные No-Log DNS-серверы ({string.Join(" + ", ninjaHits)})",
                "Запросы к зарубежным сайтам идут через независимые зашифрованные DoH-резолверы без логирования и цензуры.",
                $"Обнаружены приватные DoH-эндпоинты: {string.Join(", ", ninjaHits)}. Они реже попадают под точечные блокировки по IP, чем стандартные 1.1.1.1 и 8.8.8.8.",
                string.Join(", ", ninjaHits),
                "Отличный выбор для приватности и обхода DNS-фильтрации."));
        }

        // 2. Проверка зашифрованного транспорта DoH/DoT в целом
        var hasEncrypted = lower.Contains("https://", StringComparison.Ordinal) ||
                           lower.Contains("https+local://", StringComparison.Ordinal) ||
                           lower.Contains("\"type\": \"https\"", StringComparison.Ordinal) ||
                           lower.Contains("tls://", StringComparison.Ordinal);

        if (hasEncrypted && ninjaHits.Count == 0)
        {
            findings.Add(new VpnAuditFinding(
                "dns-doh-encrypted-ok",
                AuditCategory.Leaks,
                AuditSeverity.Ok,
                "Основной DNS защищён шифрованием (DoH / DoT)",
                "Провайдер не сможет перехватить или подменить ответы DNS по обычному порту 53.",
                "Найдены серверы с протоколом https:// или tls://.",
                "DoH / DoT активен",
                "Для ещё большей приватности можно переключиться на пресет «Ninja Privacy (Njalla + LibreDNS)»."));
        }
        else if (!hasEncrypted)
        {
            findings.Add(new VpnAuditFinding(
                "dns-plain-udp",
                AuditCategory.Leaks,
                AuditSeverity.Critical,
                "Нет ни одного зашифрованного DoH/DoT сервера — риск подмены сайтов провайдером",
                "Обычные UDP DNS-запросы (порт 53) легко перехватываются и подменяются оборудованием ТСПУ.",
                "В списке servers отсутствуют https:// или tls:// резолверы.",
                "Только открытый UDP DNS",
                "Добавьте https://dns.njal.la/dns-query, https://doh.libredns.gr/dns-query или https://1.1.1.1/dns-query."));
        }

        // 3. Проверка российского сплит-правила 77.88.8.8 (geosite:category-ru / geosite:category-gov-ru)
        var hasRuSplitDns = lower.Contains("77.88.8.8", StringComparison.Ordinal) &&
                            (lower.Contains("geosite:category-ru", StringComparison.Ordinal) ||
                             lower.Contains("geosite-category-ru", StringComparison.Ordinal) ||
                             lower.Contains("domain:ru", StringComparison.Ordinal) ||
                             lower.Contains(".ru", StringComparison.Ordinal));

        if (hasRuSplitDns)
        {
            var hasSkipFallback = lower.Contains("\"skipfallback\": true", StringComparison.Ordinal) ||
                                  lower.Contains("\"skipfallback\":true", StringComparison.Ordinal);
            findings.Add(new VpnAuditFinding(
                "dns-ru-scoped-ok",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                "Яндекс DNS (77.88.8.8) изолирован строго для сайтов РФ и Госуслуг",
                "Российские банки, Госуслуги и маркетплейсы получают родные российские IP-адреса и открываются быстро без капчи, а зарубежные сайты не утекают на 77.88.8.8.",
                $"Привязка к доменам: geosite:category-ru / geosite:category-gov-ru, skipFallback={(hasSkipFallback ? "true (изолирован от общих запросов)" : "не указан")}.",
                "77.88.8.8 -> geosite:category-ru",
                hasSkipFallback
                    ? "Идеальная настройка раздельного DNS для РФ."
                    : "Рекомендуется добавить \"skipFallback\": true в блок 77.88.8.8, чтобы он никогда не опрашивался для зарубежных сайтов."));
        }

        // 4. Разбор роли "localhost" в массиве servers Xray
        if (lower.Contains("\"localhost\"", StringComparison.Ordinal))
        {
            if (hasEncrypted)
            {
                findings.Add(new VpnAuditFinding(
                    "dns-localhost-explained",
                    AuditCategory.Routing,
                    AuditSeverity.Ok,
                    "Объяснение записи \"localhost\" в конце списка DNS: системный bootstrap-резолвер",
                    "Зачем здесь нужен \"localhost\": так как приватные DNS заданы доменными именами (dns.njal.la, doh.libredns.gr), клиенту Xray на старте нужно сначала узнать IP-адрес самих этих DNS-серверов через системный DNS Windows.",
                    "В Xray-core запись \"localhost\" в конце массива servers служит резервным/стартовым резолвером ОС. Пока вышестоящие DoH-серверы (Njalla / LibreDNS) отвечают, обычные запросы до \"localhost\" не доходят. Для полной изоляции можно добавить \"disableFallbackIfMatch\": true.",
                    "\"localhost\" (после DoH-серверов)",
                    "Это штатный приём для доменных DoH (Njalla / LibreDNS). Оставляйте \"localhost\" последним в списке servers."));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "dns-localhost-leak",
                    AuditCategory.Leaks,
                    AuditSeverity.Warning,
                    "Используется системный DNS (\"localhost\") без защищённых DoH-серверов",
                    "Все запросы уходят на DNS вашего интернет-провайдера.",
                    "Запись \"localhost\" обращается к системному резолверу ОС.",
                    "\"localhost\"",
                    "Добавьте перед \"localhost\" защищённые DoH-серверы (например Njalla и LibreDNS)."));
            }
        }

        // 5. Разбор queryStrategy (UseIP vs UseIPv4)
        if (lower.Contains("\"querystrategy\"", StringComparison.Ordinal))
        {
            var isIpv4Only = lower.Contains("\"useipv4\"", StringComparison.Ordinal);
            findings.Add(new VpnAuditFinding(
                "dns-query-strategy-info",
                AuditCategory.Leaks,
                AuditSeverity.Ok,
                isIpv4Only
                    ? "Стратегия queryStrategy: UseIPv4 (жёсткая защита от утечек IPv6)"
                    : "Стратегия queryStrategy: UseIP (поддержка IPv4 + IPv6)",
                isIpv4Only
                    ? "Запрашиваются только IPv4-адреса (A-записи), что полностью исключает утечки через IPv6 провайдера."
                    : "Разрешены и IPv4, и IPv6 адреса. Если у вашего провайдера есть IPv6, а ВПН-сервер работает только по IPv4, лучше сменить UseIP на UseIPv4.",
                isIpv4Only ? "queryStrategy = UseIPv4" : "queryStrategy = UseIP",
                isIpv4Only ? "\"queryStrategy\": \"UseIPv4\"" : "\"queryStrategy\": \"UseIP\"",
                "При зависании сайтов на мобильных сетях переключите на UseIPv4."));
        }

        // Если пользователь проверяет только изолированный блок "dns": { ... }, подтверждаем что он готов к точечной вставке
        if (isDnsOnlySnippet)
        {
            findings.Add(new VpnAuditFinding(
                "dns-isolated-block-ok",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                "Изолированный блок \"dns\" (без затрагивания нижних секций конфига)",
                "Этот фрагмент содержит только настройки DNS и готов к точечной вставке в существующий конфиг или подписку.",
                "Секции outbounds, inbounds и routing не включены в этот фрагмент, поэтому при врезке ваши серверы и правила маршрутизации ниже останутся нетронутыми.",
                "Режим: Только блок DNS",
                "Нажмите «Вшить этот DNS в конфиг / подписку на Шаге 1», чтобы обновить только секцию dns."));
            return findings;
        }

        // Дополнительные проверки для полного конфига (когда присутствуют route/routing/inbounds)
        var hasProxyDetour = lower.Contains("\"detour\": \"proxy\"", StringComparison.Ordinal) ||
                             lower.Contains("#proxy", StringComparison.Ordinal) ||
                             lower.Contains("\"outboundtag\": \"proxy\"", StringComparison.Ordinal) ||
                             hasEncrypted;
        if (!hasProxyDetour)
        {
            findings.Add(new VpnAuditFinding(
                "dns-no-proxy-detour",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Зарубежный DNS не привязан к ВПН-туннелю",
                "Прямые запросы к зарубежным DNS из РФ могут блокироваться провайдером.",
                "Не найдены detour: proxy / #PROXY / outboundTag: proxy.",
                "Отсутствует привязка к proxy",
                "Маршрутизируйте зарубежный DoH через proxy."));
        }

        return findings;
    }

    private static string GenerateXray(DnsArchitectOptions opt)
    {
        var (primaryDoh, secondaryDoh, _, _) = GetProviderEndpoints(opt.ProviderProfile);
        var servers = new List<object>();

        if (opt.UseFakeIp)
        {
            servers.Add(new
            {
                address = "fakedns",
                domains = opt.RfSplitTunneling ? XrayFakeDnsNonCn : XrayFakeDnsAll,
            });
        }

        if (opt.RfSplitTunneling)
        {
            servers.Add(new
            {
                address = "77.88.8.8",
                domains = XrayRuDomains,
                skipFallback = true,
            });
        }

        // В режиме "Только блок DNS" используем лаконичный формат строк DoH (как в Happ / Xray конфигах с Njalla и LibreDNS)
        if (opt.OutputScope == DnsOutputScope.DnsBlockOnly)
        {
            servers.Add(primaryDoh);
            servers.Add(secondaryDoh);
            servers.Add("localhost");

            var dnsOnlyDoc = new
            {
                dns = new
                {
                    queryStrategy = opt.Ipv4Only ? "UseIPv4" : "UseIP",
                    servers,
                },
            };
            return JsonSerializer.Serialize(dnsOnlyDoc, PrettyJson);
        }

        // Полный блок DNS + Routing с тегами
        servers.Add(new { address = primaryDoh, tag = "dns-remote" });
        servers.Add(new { address = secondaryDoh, tag = "dns-remote-backup" });
        servers.Add("localhost");

        var routingRules = new List<object>
        {
            new { type = "field", inboundTag = XrayInboundRemote, outboundTag = "proxy" },
            new { type = "field", inboundTag = opt.RfSplitTunneling ? XrayInboundDirect : XrayInboundBootstrap, outboundTag = "direct" },
            new { type = "field", domain = XrayRuDomains, outboundTag = "direct" },
            new { type = "field", ip = XrayGeoIpPrivate, outboundTag = "direct" },
        };

        var fullDoc = new
        {
            dns = new
            {
                queryStrategy = opt.Ipv4Only ? "UseIPv4" : "UseIP",
                servers,
            },
            routing = new
            {
                domainStrategy = "IPIfNonMatch",
                rules = routingRules,
            },
        };
        return JsonSerializer.Serialize(fullDoc, PrettyJson);
    }

    private static string GenerateSingBox112(DnsArchitectOptions opt)
    {
        var (_, _, primaryHost, _) = GetProviderEndpoints(opt.ProviderProfile);
        var strategy = opt.Ipv4Only ? "ipv4_only" : "prefer_ipv4";
        var servers = new List<object>
        {
            new { tag = "dns-remote", type = "https", server = primaryHost, server_port = 443, path = "/dns-query", detour = "proxy" },
            new { tag = "dns-direct", type = "udp", server = "77.88.8.8", detour = "direct" },
        };
        if (opt.UseFakeIp)
        {
            servers.Add(new { tag = "dns-fakeip", type = "fakeip", inet4_range = "198.18.0.0/15" });
        }

        var dnsRules = new List<object>();
        if (opt.BlockAds) dnsRules.Add(new { rule_set = "geosite-category-ads-all", action = "reject" });
        if (opt.RfSplitTunneling)
        {
            dnsRules.Add(new { domain_suffix = SingBoxRuDomainSuffixes, rule_set = SingBoxRuRuleSets, server = "dns-direct" });
        }
        if (opt.UseFakeIp) dnsRules.Add(new { query_type = opt.Ipv4Only ? QueryTypeIpv4Only : QueryTypeDualStack, server = "dns-fakeip" });

        var dnsObject = new
        {
            servers,
            rules = dnsRules,
            final = "dns-remote",
            strategy,
            independent_cache = true,
            reverse_mapping = true,
        };

        if (opt.OutputScope == DnsOutputScope.DnsBlockOnly)
        {
            return JsonSerializer.Serialize(new { dns = dnsObject }, PrettyJson);
        }

        var doc = new
        {
            dns = dnsObject,
            route = new
            {
                default_domain_resolver = "dns-direct",
                auto_detect_interface = true,
                rules = new object[]
                {
                    new { action = "sniff" },
                    new { protocol = "dns", action = "hijack-dns" },
                    new { ip_is_private = true, outbound = "direct" },
                },
                final = "proxy",
            },
        };
        return JsonSerializer.Serialize(doc, PrettyJson);
    }

    private static string GenerateClashYaml(DnsArchitectOptions opt)
    {
        var (primaryDoh, secondaryDoh, _, _) = GetProviderEndpoints(opt.ProviderProfile);
        var sb = new StringBuilder();
        if (opt.OutputScope == DnsOutputScope.FullDnsAndRouting)
        {
            sb.AppendLine(opt.Ipv4Only ? "ipv6: false" : "ipv6: true");
            sb.AppendLine("sniffer:\n  enable: true\n  parse-pure-ip: true");
            sb.AppendLine("tun:\n  enable: true\n  stack: mixed\n  auto-route: true\n  dns-hijack: [\"any:53\", \"tcp://any:53\"]");
        }
        sb.AppendLine("dns:");
        sb.AppendLine("  enable: true");
        sb.AppendLine(opt.Ipv4Only ? "  ipv6: false" : "  ipv6: true");
        sb.AppendLine("  respect-rules: true");
        sb.AppendLine(opt.UseFakeIp ? "  enhanced-mode: fake-ip" : "  enhanced-mode: redir-host");
        sb.AppendLine("  default-nameserver:\n    - 77.88.8.8");
        sb.AppendLine("  nameserver:\n    - " + primaryDoh + "#PROXY\n    - " + secondaryDoh + "#PROXY");
        if (opt.RfSplitTunneling)
        {
            sb.AppendLine("  nameserver-policy:\n    \"geosite:category-ru,geosite:category-gov-ru,+.ru,+.su,+.xn--p1ai\":\n      - 77.88.8.8#DIRECT");
        }
        return sb.ToString();
    }
}
