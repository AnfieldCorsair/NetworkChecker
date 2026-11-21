using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VpnChecker.Core.VpnAudit;

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
    DnsPropertySnippet,
    DnsInnerBodyOnly,
}

public enum DnsProviderProfile
{
    CloudflareGoogle, // Классика DoH: Cloudflare (1.1.1.1) + Google (8.8.8.8)
    NinjaPrivacy,     // Приватный No-Log: Njalla (dns.njal.la) + LibreDNS (doh.libredns.gr)
    MullvadQuad9,     // Приватный No-Log: Mullvad (dns.mullvad.net) + Quad9 (dns.quad9.net)
    ComssAdGuard,     // Comss.one + AdGuard DNS
}

public sealed record DnsArchitectOptions(
    DnsCoreTarget Core = DnsCoreTarget.XrayCore,
    bool RfSplitTunneling = true,
    bool UseFakeIp = false,
    bool Ipv4Only = false,
    bool BlockAds = false,
    DnsProviderProfile ProviderProfile = DnsProviderProfile.CloudflareGoogle,
    DnsOutputScope OutputScope = DnsOutputScope.DnsBlockOnly);

/// <summary>
/// Конструктор, авто-патчер и аудитор блока DNS:
/// - Два базовых ориентира: Классика DoH (Cloudflare 1.1.1.1 + Google 8.8.8.8) по умолчанию и Приватный Ninja (Njalla + LibreDNS) для ценителей приватности;
/// - Режим «Только блок dns (нижние секции не трогаем)» и «Полный блок dns + routing»;
/// - Автоопределение диалекта каждого узла (Sing-box vs Xray/Happ) и обязательная строгая проверка JSON (запятые и скобки) после врезки;
/// - Умный аудит роли "localhost", гео-правил 77.88.8.8 (geosite:category-ru, geosite:category-gov-ru) и синтаксиса JSON.
/// </summary>
public static class DnsConfigArchitect
{
    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly JsonDocumentOptions TolerantInputJson = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    private static readonly JsonDocumentOptions StrictValidationJson = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
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

    public const string ClassicSampleJson = """
        {
          "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [
              {
                "address": "77.88.8.8",
                "domains": [
                  "geosite:category-ru",
                  "geosite:category-gov-ru"
                ],
                "skipFallback": true
              },
              "https://1.1.1.1/dns-query",
              "https://8.8.8.8/dns-query",
              "localhost"
            ]
          }
        }
        """;

    public const string NinjaSampleJson = """
        {
          "dns": {
            "queryStrategy": "UseIPv4",
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
                "Приватный Ninja (Njalla + LibreDNS)"),
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
                "Классика DoH (Cloudflare + Google)"),
        };

    /// <summary>
    /// Строго проверяет синтаксис JSON (без висячих запятых и комментариев),
    /// гарантируя, что конфиг без ошибок прочитается в Happ, v2rayN, Xray-core и Sing-box.
    /// </summary>
    public static bool ValidateStrictJson(string json, out string message)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            message = "Пустой JSON.";
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(json, StrictValidationJson);
            message = "JSON проверен: запятые и скобки валидны.";
            return doc.RootElement.ValueKind is JsonValueKind.Object or JsonValueKind.Array;
        }
        catch (JsonException ex)
        {
            message = string.Create(CultureInfo.InvariantCulture, $"Ошибка синтаксиса JSON (строка {ex.LineNumber + 1}, позиция {ex.BytePositionInLine + 1}): {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Проверяет как полный JSON-документ ({ ... } / [ ... ]), так и фрагмент свойства для вставки внутрь готового конфига
    /// ("dns": { ... }, без внешних фигурных скобок и с запятой в конце).
    /// </summary>
    public static bool ValidateDnsJsonOrSnippet(string raw, out string message, out bool isPropertySnippet)
    {
        isPropertySnippet = false;
        if (string.IsNullOrWhiteSpace(raw))
        {
            message = "Пустой JSON.";
            return false;
        }

        var trimmed = raw.Trim();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            return ValidateStrictJson(trimmed, out message);
        }

        if (trimmed.StartsWith('"'))
        {
            isPropertySnippet = true;
            var bodyWithoutTrailingComma = trimmed.EndsWith(',')
                ? trimmed[..^1].TrimEnd()
                : trimmed;

            var wrapped = "{\n" + bodyWithoutTrailingComma + "\n}";
            try
            {
                using var doc = JsonDocument.Parse(wrapped, StrictValidationJson);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    message = "Фрагмент должен быть парой \"dns\": { ... },";
                    return false;
                }

                message = trimmed.EndsWith(',')
                    ? "Фрагмент для вставки проверен: внешние { } убраны, запятая в конце на месте — можно вставлять прямо в конфиг."
                    : "Фрагмент для вставки проверен (без внешних { } и без запятой в конце — подходит для последней секции конфига).";
                return true;
            }
            catch (JsonException ex)
            {
                var lineNum = Math.Max(1, ex.LineNumber);
                message = string.Create(CultureInfo.InvariantCulture, $"Ошибка синтаксиса фрагмента JSON (строка {lineNum}, позиция {ex.BytePositionInLine + 1}): {ex.Message}");
                return false;
            }
        }

        message = "Нераспознанный формат JSON (ожидается { ... } или \"dns\": { ... },).";
        return false;
    }

    /// <summary>
    /// Преобразует валидный JSON-объект вида { "dns": { ... } } во фрагмент для прямой вставки внутрь готового конфига:
    /// убирает внешние { и }, выравнивает отступы и ставит запятую в конце ("dns": { ... },).
    /// </summary>
    public static string FormatAsPropertySnippet(string standaloneJsonObject, bool includeTrailingComma = true)
    {
        if (string.IsNullOrWhiteSpace(standaloneJsonObject))
        {
            return string.Empty;
        }

        var trimmed = standaloneJsonObject.Trim();
        if (trimmed.StartsWith('"'))
        {
            var baseSnippet = trimmed.EndsWith(',') ? trimmed[..^1].TrimEnd() : trimmed;
            return includeTrailingComma ? baseSnippet + "," : baseSnippet;
        }

        // Парсим и пересобираем через System.Text.Json, гарантируя 100% ровные скобки и запятые
        using var doc = JsonDocument.Parse(trimmed, TolerantInputJson);
        var pretty = JsonSerializer.Serialize(doc.RootElement, PrettyJson);
        var lines = pretty.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length < 3 || lines[0].Trim() != "{" || lines[^1].Trim() != "}")
        {
            return pretty;
        }

        var innerLines = new List<string>(lines.Length - 2);
        for (var i = 1; i < lines.Length - 1; i++)
        {
            var line = lines[i];
            innerLines.Add(line.StartsWith("  ", StringComparison.Ordinal) ? line[2..] : line);
        }

        if (includeTrailingComma && innerLines.Count > 0 && !innerLines[^1].TrimEnd().EndsWith(','))
        {
            innerLines[^1] = innerLines[^1].TrimEnd() + ",";
        }

        return string.Join(Environment.NewLine, innerLines);
    }

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
    /// автоматически подбирая формат (Sing-box vs Xray) под каждый узел и строго проверяя итоговый JSON на запятые/скобки.
    /// Все остальные секции (outbounds, inbounds, routing, burstObservatory, remarks) остаются нетронутыми.
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

        var baseOpt = (options ?? new DnsArchitectOptions()) with { OutputScope = DnsOutputScope.DnsBlockOnly };
        var (_, _, _, providerLabel) = GetProviderEndpoints(baseOpt.ProviderProfile);

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
            var root = JsonNode.Parse(trimmed, nodeOptions: null, TolerantInputJson);
            if (root is JsonObject singleObj)
            {
                if (!ApplyDialectMatchedDns(singleObj, baseOpt, out var dialectName, out var prepError))
                {
                    summaryMessage = prepError;
                    return false;
                }

                var candidate = singleObj.ToJsonString(PrettyJson);
                if (!ValidateStrictJson(candidate, out var validationError))
                {
                    summaryMessage = $"Интеграция остановлена: {validationError}";
                    return false;
                }

                patchedJson = candidate;
                summaryMessage = $"Блок \"dns\" ({providerLabel}, формат {dialectName}) точечно обновлён и прошёл строгую проверку JSON (запятые и скобки в порядке).";
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
                        if (!ApplyDialectMatchedDns(clone, baseOpt, out var dialectName, out var prepError))
                        {
                            summaryMessage = prepError;
                            return false;
                        }

                        var candidate = clone.ToJsonString(PrettyJson);
                        if (!ValidateStrictJson(candidate, out var validationError))
                        {
                            summaryMessage = $"Интеграция остановлена: {validationError}";
                            return false;
                        }

                        patchedJson = candidate;
                        var remarks = clone["remarks"]?.GetValue<string>() ?? string.Create(CultureInfo.InvariantCulture, $"Узел #{idx + 1}");
                        summaryMessage = $"Готов конфиг «{remarks}» с блоком DNS ({providerLabel}, {dialectName}) — JSON строго проверен.";
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
                        if (!ApplyDialectMatchedDns(itemObj, baseOpt, out _, out var prepError))
                        {
                            summaryMessage = prepError;
                            return false;
                        }
                        updatedCount++;
                    }
                }

                if (updatedCount == 0)
                {
                    summaryMessage = "В JSON-массиве подписки не найдено объектов профилей для обновления DNS.";
                    return false;
                }

                var candidateArray = arr.ToJsonString(PrettyJson);
                if (!ValidateStrictJson(candidateArray, out var arrValidationError))
                {
                    summaryMessage = $"Интеграция остановлена: {arrValidationError}";
                    return false;
                }

                patchedJson = candidateArray;
                summaryMessage = targetZeroIdx.HasValue
                    ? string.Create(CultureInfo.InvariantCulture, $"Блок \"dns\" ({providerLabel}) точечно обновлён в узле #{targetZeroIdx.Value + 1} — JSON проверен.")
                    : string.Create(CultureInfo.InvariantCulture, $"Блок \"dns\" ({providerLabel}) точечно вшит во все {updatedCount} локаций подписки (формат подобран автоматически, JSON проверен).");
                return true;
            }
        }
        catch (JsonException ex)
        {
            summaryMessage = $"Не удалось разобрать входной JSON: {ex.Message}";
            return false;
        }

        summaryMessage = "Точечная врезка блока \"dns\" работает для JSON-конфигов и JSON-подписок (Happ / Xray / Sing-box). Для одиночной ссылки vless:// используйте готовый блок DNS слева.";
        return false;
    }

    private static bool ApplyDialectMatchedDns(
        JsonObject targetObj,
        DnsArchitectOptions baseOpt,
        out string dialectLabel,
        out string errorMessage)
    {
        var isSingBox = IsSingBoxJsonObject(targetObj);
        var effectiveCore = isSingBox ? DnsCoreTarget.SingBox112 : DnsCoreTarget.XrayCore;
        dialectLabel = isSingBox ? "Sing-box" : "Xray/Happ";

        var dnsWrapperJson = GenerateOptimalBlock(baseOpt with { Core = effectiveCore, OutputScope = DnsOutputScope.DnsBlockOnly });
        try
        {
            var parsedWrapper = JsonNode.Parse(dnsWrapperJson);
            var dnsNode = parsedWrapper?["dns"]?.DeepClone();
            if (dnsNode is null)
            {
                errorMessage = "Сгенерированный блок не содержит секции \"dns\".";
                return false;
            }

            targetObj["dns"] = dnsNode;
            errorMessage = string.Empty;
            return true;
        }
        catch (JsonException ex)
        {
            errorMessage = $"Не удалось подготовить JSON-узел DNS: {ex.Message}";
            return false;
        }
    }

    private static bool IsSingBoxJsonObject(JsonObject obj)
    {
        if (obj["outbounds"] is JsonArray outbounds)
        {
            foreach (var item in outbounds)
            {
                if (item is JsonObject ob &&
                    ob.ContainsKey("type") &&
                    !ob.ContainsKey("protocol"))
                {
                    return true;
                }
            }
        }

        return obj.ContainsKey("route") && !obj.ContainsKey("routing");
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
        var trimmed = rawDns.Trim();
        var lower = trimmed.ToLowerInvariant();

        // 0. Проверка валидности JSON (как полного { ... }, так и фрагмента "dns": { ... },)
        if (trimmed.StartsWith('{') || trimmed.StartsWith('[') || trimmed.StartsWith('"'))
        {
            if (!ValidateDnsJsonOrSnippet(trimmed, out var jsonErr, out var isSnippet))
            {
                findings.Add(new VpnAuditFinding(
                    "dns-invalid-json",
                    AuditCategory.Routing,
                    AuditSeverity.Critical,
                    "Нарушен синтаксис JSON (лишняя или пропущенная запятая / скобка)",
                    "Клиенты Happ, v2rayN, Xray и Sing-box не смогут прочитать конфигурацию с ошибкой JSON.",
                    jsonErr,
                    "Невалидный JSON",
                    "Нажмите «Сбросить к выбранному» или проверьте запятые в конце строк и закрывающие скобки."));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "dns-valid-json-ok",
                    AuditCategory.Routing,
                    AuditSeverity.Ok,
                    isSnippet
                        ? "Фрагмент для вставки проверен: внешние { } сняты, запятая на месте"
                        : "Синтаксис JSON проверен: запятые и скобки в порядке",
                    isSnippet
                        ? "Этот фрагмент можно сразу вставлять на место секции \"dns\" внутри готового конфига (Happ / Xray / Sing-box) без ручной правки скобок и запятых."
                        : "Блок корректно читается стандартным JSON-парсером без ошибок.",
                    jsonErr,
                    isSnippet ? "Фрагмент \"dns\": { ... }, валиден" : "JSON валиден",
                    isSnippet
                        ? "Если вставляете в самый конец конфига (после блока нет других секций), уберите последнюю запятую или нажмите «Вшить в выбранный узел»."
                        : "Можно безопасно вшивать в подписку или конфиг."));
            }
        }

        var isDnsOnlySnippet = !lower.Contains("\"outbounds\"", StringComparison.Ordinal) &&
                               !lower.Contains("\"inbounds\"", StringComparison.Ordinal) &&
                               !lower.Contains("\"routing\"", StringComparison.Ordinal) &&
                               !lower.Contains("\"route\"", StringComparison.Ordinal) &&
                               !lower.Contains("tun:", StringComparison.Ordinal);

        // 1. Проверка классических и приватных DoH-резолверов
        var ninjaHits = new List<string>();
        if (lower.Contains("dns.njal.la", StringComparison.Ordinal)) ninjaHits.Add("Njalla (dns.njal.la)");
        if (lower.Contains("doh.libredns.gr", StringComparison.Ordinal)) ninjaHits.Add("LibreDNS (doh.libredns.gr)");
        if (lower.Contains("dns.mullvad.net", StringComparison.Ordinal)) ninjaHits.Add("Mullvad (dns.mullvad.net)");
        if (lower.Contains("dns.quad9.net", StringComparison.Ordinal)) ninjaHits.Add("Quad9 (dns.quad9.net)");
        if (lower.Contains("dns.comss.one", StringComparison.Ordinal)) ninjaHits.Add("Comss.one DoH");
        if (lower.Contains("dns.adguard-dns.com", StringComparison.Ordinal)) ninjaHits.Add("AdGuard DoH");

        var classicHits = new List<string>();
        if (lower.Contains("https://1.1.1.1", StringComparison.Ordinal) || lower.Contains("cloudflare-dns.com", StringComparison.Ordinal) || (lower.Contains("\"type\": \"https\"", StringComparison.Ordinal) && lower.Contains("\"1.1.1.1\"", StringComparison.Ordinal)))
            classicHits.Add("Cloudflare DoH (1.1.1.1)");
        if (lower.Contains("https://8.8.8.8", StringComparison.Ordinal) || lower.Contains("dns.google", StringComparison.Ordinal) || (lower.Contains("\"type\": \"https\"", StringComparison.Ordinal) && lower.Contains("\"8.8.8.8\"", StringComparison.Ordinal)))
            classicHits.Add("Google DoH (8.8.8.8)");

        if (ninjaHits.Count > 0)
        {
            findings.Add(new VpnAuditFinding(
                "dns-ninja-privacy-ok",
                AuditCategory.Security,
                AuditSeverity.Ok,
                $"Подключён приватный No-Log DNS ({string.Join(" + ", ninjaHits)})",
                "Хороший базовый вариант для ценителей приватности: запросы идут по зашифрованному DoH без логов. При желании всегда можно подстроить под скорость вашего провайдера.",
                $"Обнаружены приватные DoH-эндпоинты: {string.Join(", ", ninjaHits)}.",
                string.Join(", ", ninjaHits),
                "Подходит как приватный вариант. Если нужна максимальная скорость отклика — можно также сравнить с классикой DoH (Cloudflare + Google)."));
        }

        // 2. Проверка зашифрованного транспорта DoH/DoT в целом
        var hasEncrypted = lower.Contains("https://", StringComparison.Ordinal) ||
                           lower.Contains("https+local://", StringComparison.Ordinal) ||
                           lower.Contains("\"type\": \"https\"", StringComparison.Ordinal) ||
                           lower.Contains("tls://", StringComparison.Ordinal);

        if (classicHits.Count > 0 && ninjaHits.Count == 0)
        {
            findings.Add(new VpnAuditFinding(
                "dns-doh-encrypted-ok",
                AuditCategory.Leaks,
                AuditSeverity.Ok,
                $"Подключена классика DoH ({string.Join(" + ", classicHits)})",
                "Надёжный и быстрый базовый вариант с шифрованием DoH — провайдер не сможет подменить ответы DNS по порту 53.",
                $"Обнаружены классические DoH-резолверы: {string.Join(", ", classicHits)}.",
                string.Join(", ", classicHits),
                "Хорошая рабочая база. Для ценителей повышенной приватности рядом доступен вариант «Приватный Ninja (Njalla + LibreDNS)»."));
        }
        else if (hasEncrypted && ninjaHits.Count == 0)
        {
            findings.Add(new VpnAuditFinding(
                "dns-doh-encrypted-ok",
                AuditCategory.Leaks,
                AuditSeverity.Ok,
                "Основной DNS защищён шифрованием (DoH / DoT)",
                "Провайдер не сможет перехватить или подменить ответы DNS по обычному порту 53.",
                "Найдены серверы с протоколом https:// или tls://.",
                "DoH / DoT активен",
                "Базовая защита DNS активна; при желании можно выбрать классику DoH или приватный пресет."));
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
                "Добавьте классический DoH (https://1.1.1.1/dns-query и https://8.8.8.8/dns-query) или приватный вариант (Njalla / LibreDNS)."));
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
                    ? "Раздельный DNS для РФ настроен аккуратно."
                    : "Рекомендуется добавить \"skipFallback\": true в блок 77.88.8.8, чтобы он не опрашивался для зарубежных сайтов."));
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
                    "Запись \"localhost\" в конце списка DNS: системный bootstrap / резерв",
                    "Зачем нужен \"localhost\": когда DoH-серверы заданы доменными именами (например dns.njal.la, doh.libredns.gr), Xray нужен стартовый резолвер ОС, чтобы узнать их IP.",
                    "В Xray-core запись \"localhost\" в конце массива servers служит стартовым и резервным резолвером. Пока вышестоящие DoH-серверы отвечают, обычные запросы до \"localhost\" не доходят.",
                    "\"localhost\" (после DoH-серверов)",
                    "Оставляйте \"localhost\" последним элементом списка servers."));
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
                    "Добавьте перед \"localhost\" защищённые DoH-серверы (Cloudflare/Google или Njalla/LibreDNS)."));
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
                    ? "Стратегия queryStrategy: UseIPv4 (защита от утечек IPv6)"
                    : "Стратегия queryStrategy: UseIP (поддержка IPv4 + IPv6)",
                isIpv4Only
                    ? "Запрашиваются только IPv4-адреса (A-записи), что снижает риск утечек через IPv6 провайдера."
                    : "Разрешены и IPv4, и IPv6 адреса. Если у вашего провайдера есть IPv6, а ВПН-сервер работает только по IPv4, лучше сменить UseIP на UseIPv4.",
                isIpv4Only ? "queryStrategy = UseIPv4" : "queryStrategy = UseIP",
                isIpv4Only ? "\"queryStrategy\": \"UseIPv4\"" : "\"queryStrategy\": \"UseIP\"",
                "При зависании сайтов на мобильных сетях переключите на UseIPv4."));
        }

        if (isDnsOnlySnippet)
        {
            findings.Add(new VpnAuditFinding(
                "dns-isolated-block-ok",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                "Изолированный блок \"dns\" (без затрагивания нижних секций конфига)",
                "Этот фрагмент содержит только настройки DNS и готов к автоматической врезке в конфиг или подписку.",
                "Секции outbounds, inbounds и routing не включены в этот фрагмент, поэтому ваши серверы и маршруты ниже останутся нетронутыми.",
                "Режим: Только блок DNS",
                "Нажмите «Вшить в выбранный узел» или «Вшить во всю подписку» — формат и запятые проверятся автоматически."));
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
        var isFullRouting = opt.OutputScope == DnsOutputScope.FullDnsAndRouting;

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
            if (isFullRouting)
            {
                servers.Add(new
                {
                    address = "77.88.8.8",
                    tag = "dns-direct",
                    domains = XrayRuDomains,
                    skipFallback = true,
                });
            }
            else
            {
                servers.Add(new
                {
                    address = "77.88.8.8",
                    domains = XrayRuDomains,
                    skipFallback = true,
                });
            }
        }

        if (!isFullRouting)
        {
            servers.Add(primaryDoh);
            servers.Add(secondaryDoh);
            servers.Add("localhost");

            var dnsInnerObj = new
            {
                queryStrategy = opt.Ipv4Only ? "UseIPv4" : "UseIP",
                servers,
            };

            if (opt.OutputScope == DnsOutputScope.DnsInnerBodyOnly)
            {
                return JsonSerializer.Serialize(dnsInnerObj, PrettyJson);
            }

            var standalone = JsonSerializer.Serialize(new { dns = dnsInnerObj }, PrettyJson);
            return opt.OutputScope == DnsOutputScope.DnsPropertySnippet
                ? FormatAsPropertySnippet(standalone, includeTrailingComma: true)
                : standalone;
        }

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

        if (opt.OutputScope == DnsOutputScope.DnsInnerBodyOnly)
        {
            return JsonSerializer.Serialize(dnsObject, PrettyJson);
        }

        if (opt.OutputScope is DnsOutputScope.DnsBlockOnly or DnsOutputScope.DnsPropertySnippet)
        {
            var standalone = JsonSerializer.Serialize(new { dns = dnsObject }, PrettyJson);
            return opt.OutputScope == DnsOutputScope.DnsPropertySnippet
                ? FormatAsPropertySnippet(standalone, includeTrailingComma: true)
                : standalone;
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
