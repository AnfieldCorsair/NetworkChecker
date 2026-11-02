using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkChecker.Core.Models;

namespace NetworkChecker.Core.Reputation;

/// <summary>Как расшифрован ответ одной DNSBL-зоны.</summary>
public enum DnsblKind
{
    /// <summary>NXDOMAIN: адреса в списке нет.</summary>
    Clean,
    Spam,
    Exploit,
    Drop,
    /// <summary>PBL: динамический диапазон провайдера, не spam и не повод для тревоги.</summary>
    Policy,
    Unknown,
    /// <summary>Источник не ответил или отказал (публичный резолвер, лимит, ошибка зоны).</summary>
    Unavailable,
}

public sealed record DnsblVerdict(DnsblKind Kind, string Status, string? Detail);

/// <summary>Нормализованное чтение одного JSON-источника репутации.</summary>
public sealed record ReputationReading(string Status, string? Detail, ReputationTone Tone, int? Score);

/// <summary>
/// Чистые парсеры: без сети и без состояния. Отделены от сервиса, чтобы каждую
/// гипотезу о формате ответа можно было проверить юнит-тестом.
/// </summary>
public static class ReputationParsers
{
    private const int GlScanLimit = 200_000;

#pragma warning disable SYSLIB1045 // парсер должен читаться человеком, генерация здесь не нужна
    private static readonly Regex GlPattern = new(
        @"[""'](?:INNERTUBE_CONTEXT_GL|GL|gl)[""']\s*:\s*[""']([A-Za-z]{2})[""']",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));
#pragma warning restore SYSLIB1045

    /// <summary>
    /// DNSBL-имя: перевёрнутые октеты IPv4 + зона. Для Spamhaus с DQS-ключом ключ
    /// ставится между адресом и зоной: 2.0.0.127.&lt;key&gt;.zen.dq.spamhaus.net.
    /// IPv6 здесь не запрашивается: у зон свои форматы, «нет данных» честнее догадки.
    /// </summary>
    public static string? DnsQuery(string? ip, string zone, string? spamhausKey = null)
    {
        if (string.IsNullOrWhiteSpace(zone) || !IPAddress.TryParse(ip, out var parsed) ||
            parsed.AddressFamily != AddressFamily.InterNetwork)
        {
            return null;
        }
        var reversed = string.Join(".", parsed.GetAddressBytes().Reverse()
            .Select(b => b.ToString(CultureInfo.InvariantCulture)));
        if (!string.IsNullOrWhiteSpace(spamhausKey) &&
            zone.Equals("zen.spamhaus.org", StringComparison.OrdinalIgnoreCase))
        {
            return $"{reversed}.{spamhausKey}.zen.dq.spamhaus.net";
        }
        return $"{reversed}.{zone}";
    }

    public static DnsblVerdict ClassifyDnsbl(bool found, IReadOnlyList<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        if (!found || addresses.Count == 0)
        {
            return new DnsblVerdict(DnsblKind.Clean, "не в списке",
                "NXDOMAIN: у зоны нет записи для этого адреса. Это не доказательство «чистого» IP.");
        }

        var codes = addresses.Select(LastOctet).Where(c => c is not null).Select(c => c!.Value).ToList();
        if (codes.Count == 0)
        {
            return new DnsblVerdict(DnsblKind.Unavailable, "нет данных",
                "Зона вернула адрес вне 127.0.0.0/8; такой ответ не интерпретируется как листинг.");
        }

        // 127.255.255.x — это НЕ листинг, а отказ самого сервиса.
        var refused = addresses.Where(a => a.StartsWith("127.255.255.", StringComparison.Ordinal)).ToList();
        if (refused.Count == addresses.Count)
        {
            var detail = refused.Any(a => a.EndsWith(".254", StringComparison.Ordinal))
                ? "Spamhaus не обслуживает публичные резолверы (8.8.8.8, 1.1.1.1 и подобные). Нужен DQS-ключ или другой резолвер."
                : "Источник отказал в обслуживании: лимит запросов или ошибка имени зоны.";
            return new DnsblVerdict(DnsblKind.Unavailable, "нет данных", detail);
        }

        if (codes.Contains(9)) return Listed(DnsblKind.Drop, "DROP/EDROP", "Диапазон помечен как полностью захваченный спам-сетью.");
        if (codes.Any(c => c is 2 or 3)) return Listed(DnsblKind.Spam, "спам-листинг (SBL/CSS)", "Источник спама или автоматически пониженная репутация отправителя.");
        if (codes.Any(c => c is >= 4 and <= 7)) return Listed(DnsblKind.Exploit, "XBL/CBL", "Заражённый хост, открытый прокси или участник ботнета; «открытый прокси» здесь про почтовый трафик, не про VPN.");
        if (codes.Any(c => c is 10 or 11)) return new DnsblVerdict(DnsblKind.Policy, "PBL (не спам)", "Динамический диапазон провайдера: норма для домашнего подключения, в риск не входит.");
        return new DnsblVerdict(DnsblKind.Unknown, "неизвестный код", "Зона вернула код, для которого нет документированной расшифровки.");
    }

    private static DnsblVerdict Listed(DnsblKind kind, string status, string detail) =>
        new(kind, status, detail);

    private static int? LastOctet(string text) =>
        IPAddress.TryParse(text, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork
            ? parsed.GetAddressBytes()[3]
            : null;

    // ---- JSON-источники --------------------------------------------------------

    public static ReputationReading AbuseIpDb(string? json)
    {
        if (!TryRoot(json, out var root) || !root.TryGetProperty("data", out var data))
            return Unavailable("AbuseIPDB не вернул поле data (квота, ключ или формат ответа).");

        var score = Int(data, "abuseConfidenceScore");
        var reports = Int(data, "totalReports");
        var last = Str(data, "lastReportedAt");
        var isp = Str(data, "isp");
        if (score is null) return Unavailable("В ответе нет abuseConfidenceScore.");

        var tone = score >= 75 ? ReputationTone.Bad : score >= 25 ? ReputationTone.Warn
            : score > 0 ? ReputationTone.Neutral : ReputationTone.Good;
        return new ReputationReading($"abuse {score}/100",
            $"жалоб: {reports?.ToString(CultureInfo.InvariantCulture) ?? "нет данных"}; " +
            $"последняя: {last ?? "нет данных"}; {isp ?? "оператор неизвестен"}",
            tone, score);
    }

    public static ReputationReading IpQualityScore(string? json)
    {
        if (!TryRoot(json, out var root)) return Unavailable("IPQualityScore не вернул JSON.");
        if (Bool(root, "success") == false)
            return Unavailable($"IPQualityScore: {Str(root, "message") ?? "запрос отклонён"}.");

        var score = Int(root, "fraud_score");
        if (score is null) return Unavailable("В ответе нет fraud_score.");
        var flags = new List<string>();
        if (Bool(root, "vpn") == true) flags.Add("VPN");
        if (Bool(root, "tor") == true) flags.Add("Tor");
        if (Bool(root, "recent_abuse") == true) flags.Add("свежий абьюз");
        if (Bool(root, "bot_status") == true) flags.Add("бот-активность");
        var connection = Str(root, "connection_type");

        var tone = score >= 85 ? ReputationTone.Bad : score >= 75 ? ReputationTone.Warn
            : score >= 40 ? ReputationTone.Neutral : ReputationTone.Good;
        return new ReputationReading($"fraud {score}/100",
            $"{connection ?? "тип соединения неизвестен"}; {(flags.Count == 0 ? "флагов нет" : string.Join(", ", flags))}",
            tone, score);
    }

    public static ReputationReading ProxyCheck(string? json, string? ip)
    {
        if (!TryRoot(json, out var root)) return Unavailable("proxycheck.io не вернул JSON.");
        var status = Str(root, "status");
        if (status is not null && !status.Equals("ok", StringComparison.OrdinalIgnoreCase))
            return Unavailable($"proxycheck.io: {status} (квота или блокировка запроса).");

        JsonElement node = root;
        if (ip is not null && root.TryGetProperty(ip, out var exact)) node = exact;
        else
        {
            foreach (var property in root.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Object) { node = property.Value; break; }
            }
        }
        if (node.ValueKind != JsonValueKind.Object) return Unavailable("В ответе нет блока с данными об адресе.");

        var risk = Int(node, "risk");
        var proxy = Str(node, "proxy");
        var type = Str(node, "type");
        if (risk is null && proxy is null) return Unavailable("Ответ proxycheck.io не удалось разобрать.");

        var tone = risk >= 74 || proxy?.Equals("yes", StringComparison.OrdinalIgnoreCase) == true
            ? ReputationTone.Bad
            : risk >= 50 ? ReputationTone.Warn : ReputationTone.Good;
        return new ReputationReading(
            $"risk {risk?.ToString(CultureInfo.InvariantCulture) ?? "?"}/100",
            $"proxy: {proxy ?? "?"}; тип: {type ?? "неизвестен"}",
            tone, risk);
    }

    public static ReputationReading Scamalytics(string? json)
    {
        if (!TryRoot(json, out var root) || !root.TryGetProperty("scamalytics", out var data))
            return Unavailable("Scamalytics не вернул блок scamalytics.");
        var score = Int(data, "scamalytics_score");
        if (score is null) return Unavailable("Scamalytics: нет scamalytics_score.");
        var risk = Str(data, "scamalytics_risk");
        var blacklisted = Bool(data, "is_blacklisted_external");
        var tone = score >= 70 ? ReputationTone.Bad : score >= 40 ? ReputationTone.Warn : ReputationTone.Good;
        return new ReputationReading($"fraud {score}/100",
            $"уровень: {risk ?? "?"}; внешние чёрные списки: {(blacklisted == true ? "да" : blacklisted == false ? "нет" : "нет данных")}",
            tone, score);
    }

    public static ReputationReading IpApiIs(string? json)
    {
        if (!TryRoot(json, out var root)) return Unavailable("ipapi.is не вернул JSON.");
        var flags = new List<string>();
        if (Bool(root, "is_abuser") == true) flags.Add("абьюз");
        if (Bool(root, "is_vpn") == true) flags.Add("VPN");
        if (Bool(root, "is_tor") == true) flags.Add("Tor");
        if (Bool(root, "is_proxy") == true) flags.Add("прокси");
        if (Bool(root, "is_datacenter") == true) flags.Add("датацентр");
        if (!root.TryGetProperty("is_abuser", out _))
            return Unavailable("Без ключа ipapi.is отдаёт только владельца и географию; флаги репутации недоступны.");

        var tone = flags.Count >= 2 ? ReputationTone.Bad : flags.Count == 1 ? ReputationTone.Warn : ReputationTone.Good;
        return new ReputationReading(flags.Count == 0 ? "флагов нет" : string.Join(", ", flags),
            "Флаги самой базы ipapi.is; они не доказывают использование VPN конкретным браузером.",
            tone, null);
    }

    // ---- Метка региона Google -------------------------------------------------

    /// <summary>
    /// GL из ytcfg/INNERTUBE_CONTEXT на странице YouTube. Это собственная карта
    /// соответствия Google, а не GeoIP: она может не совпадать со страной по IP.
    /// </summary>
    public static string? GoogleRegion(string? html)
    {
        if (string.IsNullOrWhiteSpace(html)) return null;
        var head = html.Length > GlScanLimit ? html[..GlScanLimit] : html;
        var match = GlPattern.Match(head);
        return match.Success ? match.Groups[1].Value.ToUpperInvariant() : null;
    }

    /// <summary>
    /// true — переход на страницу «Available regions», false — обычный ответ,
    /// null — данных нет (вход в аккаунт, ошибка, капризная страница).
    /// </summary>
    public static bool? AiStudioRegionPage(string? finalUri, string? body)
    {
        if (finalUri is not null &&
            finalUri.Contains("/gemini-api/docs/available-regions", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (finalUri is not null &&
            (finalUri.Contains("accounts.google.com", StringComparison.OrdinalIgnoreCase) ||
             finalUri.Contains("/ServiceLogin", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }
        if (body is not null &&
            (body.Contains("not available in your region", StringComparison.OrdinalIgnoreCase) ||
             body.Contains("your region may not be supported", StringComparison.OrdinalIgnoreCase) ||
             body.Contains("If you reached this page while trying to open", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
        return false;
    }

    private static ReputationReading Unavailable(string reason) =>
        new("нет данных", reason, ReputationTone.Unknown, null);

    private static bool TryRoot(string? json, out JsonElement root)
    {
        root = default;
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object) { document.Dispose(); return false; }
            root = document.RootElement.Clone();
            document.Dispose();
            return true;
        }
        catch (JsonException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private static string? Str(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int? Int(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt32(out var number) => number,
            JsonValueKind.String when int.TryParse(value.GetString(), NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => null,
        };
    }

    private static bool? Bool(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(value.GetString(), out var parsed) => parsed,
            JsonValueKind.Number when value.TryGetInt32(out var number) => number != 0,
            _ => null,
        };
    }
}
