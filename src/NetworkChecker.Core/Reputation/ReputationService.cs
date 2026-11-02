using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;

namespace NetworkChecker.Core.Reputation;

/// <summary>
/// Собирает блок «Репутация в целом»: DNSBL, жалобы/риск-скоры и метка региона Google.
/// Ничего не пишет в историю и не меняет настройки. Результат короткое время кешируется,
/// чтобы модуль проверки и вкладка интерфейса не расходовали квоту дважды за один прогон.
/// </summary>
public sealed class ReputationService(IHttpProbe http, IExternalProbe external) : IDisposable
{
    public const string GroupBlacklists = "Спам-базы (DNSBL)";
    public const string GroupAbuse = "Жалобы и абьюз";
    public const string GroupRisk = "Риск и анонимность";
    public const string GroupGoogle = "Метка Google";

    private const string MobileUserAgent =
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";

    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(3);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private ReputationReport? _last;
    private string _signature = string.Empty;
    private DateTimeOffset _lastAt;

    /// <summary>Последний отчёт (без сетевых запросов) — для вкладки до первого прогона.</summary>
    public ReputationReport? Last => _last;

    public void Invalidate()
    {
        _last = null;
        _signature = string.Empty;
    }

    public async Task<ReputationReport> InspectAsync(RknOptions options, bool force = false, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var signature = Signature(options);
            if (!force && _last is not null && signature == _signature &&
                DateTimeOffset.UtcNow - _lastAt < CacheTtl)
            {
                return _last;
            }
            var report = await BuildAsync(options, ct).ConfigureAwait(false);
            _last = report;
            _signature = signature;
            _lastAt = DateTimeOffset.UtcNow;
            return report;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private static string Signature(RknOptions o) => string.Join("|",
        o.OfflineMode ? "1" : "0",
        o.ReputationEnabled ? "1" : "0",
        o.GoogleRegionEnabled ? "1" : "0",
        o.RequestTimeoutSeconds.ToString(CultureInfo.InvariantCulture),
        string.Join(",", o.DnsblZones),
        o.SpamhausDqsKey ?? string.Empty,
        o.AbuseIpDbKey ?? string.Empty,
        o.IpQualityScoreKey ?? string.Empty,
        o.ProxyCheckKey ?? string.Empty,
        o.IpApiIsKey ?? string.Empty,
        o.ScamalyticsUser ?? string.Empty,
        o.ScamalyticsKey ?? string.Empty,
        o.GoogleRegionUrl,
        o.GoogleAiStudioUrl,
        o.GoogleRegionWatchCode);

    private sealed record KeyedProbe(
        string Name,
        string Group,
        ExternalProbeRequest Request,
        Func<string?, ReputationReading> Parse,
        string? Link);

    private async Task<ReputationReport> BuildAsync(RknOptions o, CancellationToken ct)
    {
        if (o.OfflineMode)
        {
            return ReputationReport.Disabled(
                "Офлайн-режим включён: внешний IP никуда не отправлялся. Отсутствие данных не означает «чистый адрес».",
                offline: true);
        }
        if (!o.ReputationEnabled && !o.GoogleRegionEnabled)
        {
            return ReputationReport.Disabled(
                "Проверка репутации и метки Google выключена в настройках. Это не результат проверки.",
                offline: false);
        }

        var timeout = TimeSpan.FromSeconds(Math.Clamp(o.RequestTimeoutSeconds, 3, 12));
        var identity = await ReadIdentityAsync(o, timeout, ct).ConfigureAwait(false);

        var sources = new List<ReputationSource>();
        var scores = new List<int>();
        var spamHits = 0;

        if (o.ReputationEnabled)
        {
            if (identity.Ip is null)
            {
                sources.Add(new ReputationSource(GroupAbuse, "Внешний адрес", "нет данных",
                    "Не удалось получить внешний IP: базы и DNSBL не опрашивались.", ReputationTone.Unknown, null));
            }
            else
            {
                var ip = identity.Ip!;
                await AddDnsblAsync(o, ip, sources, count => spamHits = count, ct).ConfigureAwait(false);
                await AddKeyedAsync(o, identity, timeout, sources, scores, ct).ConfigureAwait(false);
            }
        }
        else
        {
            sources.Add(new ReputationSource(GroupAbuse, "Базы репутации", "выключено",
                "Проверка баз отключена в настройках; метка Google проверяется отдельно.", ReputationTone.Unknown, null));
        }

        var google = await ReadGoogleAsync(o, timeout, identity.Country, sources, ct).ConfigureAwait(false);

        var risk = 0;
        if (spamHits > 0) risk += Math.Min(40, 20 + spamHits * 10);
        foreach (var score in scores) risk += Math.Min(30, score / 3);
        if (google.RuMarked == true && google.RegionDiffersFromGeo == true) risk += 25;
        else if (google.RuMarked == true) risk += 10;
        if (google.AiStudioRedirect == true) risk += 15;
        risk = Math.Clamp(risk, 0, 100);

        var hasSourceData = sources.Any(s => s.Tone != ReputationTone.Unknown);
        var riskAvailable = hasSourceData || google.Region is not null || google.AiStudioRedirect is not null;
        var state = riskAvailable ? ReputationReportState.Ok : ReputationReportState.NoData;

        var headline = HeadlineOf(o, google, risk, riskAvailable);
        var summary = SummaryOf(o, identity, google, riskAvailable);

        return new ReputationReport(
            DateTimeOffset.Now,
            identity.Ip,
            state,
            riskAvailable,
            risk,
            headline,
            summary,
            sources,
            google,
            [.. ReputationReport.DefaultCaveats()]);
    }

    private async Task<(string? Ip, string? Country, string? Body)> ReadIdentityAsync(
        RknOptions o, TimeSpan timeout, CancellationToken ct)
    {
        foreach (var url in new List<string> { o.EgressIpProvider, o.EgressIpFallback })
        {
            ct.ThrowIfCancellationRequested();
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
            var response = await http.GetAsync(uri, timeout, ignoreProxy: false, ct).ConfigureAwait(false);
            if (!response.Success || response.Body is null) continue;
            var geo = GeoIpParser.Parse(response.Body);
            if (geo?.Ip is not null) return (geo.Ip, geo.Country, response.Body);
        }
        return (null, null, null);
    }

    private async Task AddDnsblAsync(
        RknOptions o, string ip, List<ReputationSource> sources, Action<int> reportSpam, CancellationToken ct)
    {
        var zones = o.DnsblZones.Take(Math.Clamp(o.DnsblMaxZones, 1, 24)).ToList();
        using var gate = new SemaphoreSlim(Math.Clamp(o.DnsblParallelism, 1, 12));
        var tasks = zones.Select(async zone =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var query = ReputationParsers.DnsQuery(ip, zone, o.SpamhausDqsKey);
                if (query is null) return (zone, new DnsblVerdict(DnsblKind.Unavailable, "нет данных", "IPv6: зона не опрашивалась."));
                var answer = await external.ResolveAAsync(query, ct).ConfigureAwait(false);
                var nxdomain = !answer.Found && (answer.Error is null ||
                    answer.Error.Contains("HostNotFound", StringComparison.OrdinalIgnoreCase) ||
                    answer.Error.Contains("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ||
                    answer.Error.Contains("не найден", StringComparison.OrdinalIgnoreCase));
                if (!answer.Found && !nxdomain)
                {
                    // Настоящая ошибка резолвера, а не NXDOMAIN.
                    return (zone, new DnsblVerdict(DnsblKind.Unavailable, "нет данных", answer.Error));
                }
                return (zone, ReputationParsers.ClassifyDnsbl(answer.Found, answer.Addresses));
            }
            catch (Exception ex)
            {
                return (zone, new DnsblVerdict(DnsblKind.Unavailable, "нет данных", ex.GetBaseException().Message));
            }
            finally
            {
                gate.Release();
            }
        }).ToArray();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        var spam = 0;
        foreach (var (zone, verdict) in results)
        {
            var tone = verdict.Kind switch
            {
                DnsblKind.Spam or DnsblKind.Exploit or DnsblKind.Drop => ReputationTone.Bad,
                DnsblKind.Policy or DnsblKind.Clean => ReputationTone.Good,
                DnsblKind.Unknown => ReputationTone.Warn,
                _ => ReputationTone.Unknown,
            };
            if (verdict.Kind is DnsblKind.Spam or DnsblKind.Exploit or DnsblKind.Drop) spam++;
            var link = zone.Contains("spamhaus", StringComparison.OrdinalIgnoreCase)
                ? "https://www.spamhaus.org/"
                : null;
            sources.Add(new ReputationSource(GroupBlacklists, zone, verdict.Status, verdict.Detail, tone, link));
        }
        reportSpam(spam);
    }

    private async Task AddKeyedAsync(
        RknOptions o,
        (string? Ip, string? Country, string? Body) identity,
        TimeSpan timeout,
        List<ReputationSource> sources,
        List<int> scores,
        CancellationToken ct)
    {
        var ip = identity.Ip!;
        var probes = new List<KeyedProbe>();

        // proxycheck.io работает и без ключа (100 проверок в день на IP-источник).
        var proxyUrl = string.IsNullOrWhiteSpace(o.ProxyCheckKey)
            ? $"https://proxycheck.io/v2/{Uri.EscapeDataString(ip)}?risk=1&vpn=1"
            : $"https://proxycheck.io/v2/{Uri.EscapeDataString(ip)}?key={Uri.EscapeDataString(o.ProxyCheckKey)}&risk=1&vpn=1";
        probes.Add(new KeyedProbe("proxycheck.io", GroupRisk,
            new ExternalProbeRequest(new Uri(proxyUrl), timeout),
            body => ReputationParsers.ProxyCheck(body, ip), "https://proxycheck.io/"));

        if (!string.IsNullOrWhiteSpace(o.AbuseIpDbKey))
        {
            var url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90";
            var headers = new Dictionary<string, string>(StringComparer.Ordinal) { ["Key"] = o.AbuseIpDbKey };
            probes.Add(new KeyedProbe("AbuseIPDB", GroupAbuse,
                new ExternalProbeRequest(new Uri(url), timeout, Headers: headers),
                ReputationParsers.AbuseIpDb, "https://www.abuseipdb.com/"));
        }
        else
        {
            sources.Add(new ReputationSource(GroupAbuse, "AbuseIPDB", "ключ не задан",
                "Бесплатный ключ даёт 1 000 проверок в день; без него вопрос «есть ли жалобы» остаётся без ответа.",
                ReputationTone.Unknown, "https://www.abuseipdb.com/"));
        }

        if (!string.IsNullOrWhiteSpace(o.IpQualityScoreKey))
        {
            var url = $"https://www.ipqualityscore.com/api/json/ip/{Uri.EscapeDataString(o.IpQualityScoreKey)}/{Uri.EscapeDataString(ip)}?strictness=1";
            probes.Add(new KeyedProbe("IPQualityScore", GroupRisk,
                new ExternalProbeRequest(new Uri(url), timeout),
                ReputationParsers.IpQualityScore, "https://www.ipqualityscore.com/"));
        }

        if (!string.IsNullOrWhiteSpace(o.ScamalyticsUser) && !string.IsNullOrWhiteSpace(o.ScamalyticsKey))
        {
            var url = $"https://api12.scamalytics.com/v3/{Uri.EscapeDataString(o.ScamalyticsUser)}" +
                      $"?key={Uri.EscapeDataString(o.ScamalyticsKey)}&ip={Uri.EscapeDataString(ip)}";
            probes.Add(new KeyedProbe("Scamalytics", GroupRisk,
                new ExternalProbeRequest(new Uri(url), timeout),
                ReputationParsers.Scamalytics, "https://scamalytics.com/"));
        }

        if (!string.IsNullOrWhiteSpace(o.IpApiIsKey))
        {
            var url = $"https://api.ipapi.is/?q={Uri.EscapeDataString(ip)}&key={Uri.EscapeDataString(o.IpApiIsKey)}";
            probes.Add(new KeyedProbe("ipapi.is (флаги)", GroupAbuse,
                new ExternalProbeRequest(new Uri(url), timeout),
                ReputationParsers.IpApiIs, "https://ipapi.is/"));
        }
        else
        {
            var reading = ReputationParsers.IpApiIs(identity.Body);
            AddReading(sources, scores, GroupAbuse, "ipapi.is (флаги)", reading, "https://ipapi.is/");
        }

        using var gate = new SemaphoreSlim(Math.Clamp(o.DnsblParallelism, 1, 12));
        var tasks = probes.Select(async probe =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var response = await external.GetAsync(probe.Request, ct).ConfigureAwait(false);
                var reading = response.Success
                    ? probe.Parse(response.Body)
                    : new ReputationReading("нет данных",
                        $"{probe.Name}: {response.Error ?? "нет ответа"} (квота, ключ или сеть).",
                        ReputationTone.Unknown, null);
                return (probe, reading);
            }
            catch (Exception ex)
            {
                return (probe, new ReputationReading("нет данных", ex.GetBaseException().Message,
                    ReputationTone.Unknown, null));
            }
            finally
            {
                gate.Release();
            }
        }).ToArray();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        foreach (var (probe, reading) in results)
            AddReading(sources, scores, probe.Group, probe.Name, reading, probe.Link);
    }

    private static void AddReading(
        List<ReputationSource> sources, List<int> scores, string group, string name,
        ReputationReading reading, string? link)
    {
        sources.Add(new ReputationSource(group, name, reading.Status, reading.Detail, reading.Tone, link));
        if (reading.Score is { } score) scores.Add(score);
    }

    private async Task<GoogleRegionInfo> ReadGoogleAsync(
        RknOptions o, TimeSpan timeout, string? geoCountry, List<ReputationSource> sources, CancellationToken ct)
    {
        if (!o.GoogleRegionEnabled)
        {
            sources.Add(new ReputationSource(GroupGoogle, "Проверка Google", "выключено",
                "Включите «Проверять метку Google» в настройках.", ReputationTone.Unknown, null));
            return new GoogleRegionInfo(null, geoCountry, null, null, null, "не проверялось", null, "не проверялось", null);
        }

        string? gl = null;
        string ytStatus;
        if (Uri.TryCreate(o.GoogleRegionUrl, UriKind.Absolute, out var ytUri))
        {
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Accept-Language"] = "en-US,en;q=0.9",
            };
            var response = await external.GetAsync(
                new ExternalProbeRequest(ytUri, timeout, UserAgent: MobileUserAgent, Headers: headers), ct)
                .ConfigureAwait(false);
            gl = response.Success ? ReputationParsers.GoogleRegion(response.Body) : null;
            ytStatus = !response.Success ? $"нет данных ({response.Error ?? "нет ответа"})"
                : gl is null ? "GL не найден в разметке" : "прочитан из ytcfg";
        }
        else
        {
            ytStatus = "некорректный URL в настройках";
        }

        bool? redirect = null;
        string aiStatus;
        string? finalUri = null;
        if (Uri.TryCreate(o.GoogleAiStudioUrl, UriKind.Absolute, out var aiUri))
        {
            var response = await external.GetAsync(new ExternalProbeRequest(aiUri, timeout), ct).ConfigureAwait(false);
            finalUri = response.FinalUri;
            redirect = response.Success
                ? ReputationParsers.AiStudioRegionPage(response.FinalUri, response.Body)
                : null;
            aiStatus = !response.Success ? $"нет данных ({response.Error ?? "нет ответа"})"
                : redirect == true ? "переход на страницу регионов"
                : redirect == false ? "страница открылась"
                : "требуется вход в аккаунт";
        }
        else
        {
            aiStatus = "некорректный URL в настройках";
        }

        var watch = string.IsNullOrWhiteSpace(o.GoogleRegionWatchCode) ? "RU" : o.GoogleRegionWatchCode.Trim();
        bool? ruMarked = gl is null ? null : gl.Equals(watch, StringComparison.OrdinalIgnoreCase);
        bool? differs = gl is null || geoCountry is null
            ? null
            : !gl.Equals(geoCountry, StringComparison.OrdinalIgnoreCase);

        var glTone = ruMarked == true && differs == true ? ReputationTone.Bad
            : ruMarked == true ? ReputationTone.Warn
            : gl is null ? ReputationTone.Unknown : ReputationTone.Good;

        sources.Add(new ReputationSource(GroupGoogle, "YouTube / регион GL", gl ?? "нет данных",
            "Собственная карта регионов Google из ytcfg. Зонд без cookies и аккаунта: видна только сетевая часть метки.",
            glTone, "https://www.youtube.com/"));
        sources.Add(new ReputationSource(GroupGoogle, $"Метка {watch}", ruMarked == true ? "да" : ruMarked == false ? "нет" : "нет данных",
            ruMarked == true && differs == true
                ? $"Google считает адрес {watch}, а GeoIP — {geoCountry ?? "неизвестно"}. Это и есть «метка на иностранном IP»."
                : "Проверяется код, который обычно мешает Google AI Studio и меняет регион YouTube.",
            glTone, null));
        sources.Add(new ReputationSource(GroupGoogle, "GL против GeoIP",
            differs is null ? "нет данных" : differs == true ? $"{gl} ≠ {geoCountry}" : $"совпадает ({geoCountry})",
            "Расхождение — не ошибка GeoIP: у Google своя эвристическая карта соответствия IP и региона.",
            differs == true ? ReputationTone.Warn : differs == false ? ReputationTone.Good : ReputationTone.Unknown, null));
        sources.Add(new ReputationSource(GroupGoogle, "Google AI Studio", aiStatus,
            "России нет в списке доступных регионов (ai.google.dev, обновлено 2026-10-22). Редирект бывает и из-за аккаунта, возраста или платёжного профиля.",
            redirect == true ? ReputationTone.Warn : redirect == false ? ReputationTone.Good : ReputationTone.Unknown,
            "https://ai.google.dev/gemini-api/docs/available-regions"));
        sources.Add(new ReputationSource(GroupGoogle, "Капчи и «доверие Google»", "прямого API нет",
            "reCAPTCHA v3 считается для конкретного сайта по поведению и fingerprint'у; Postmaster Tools v2 не отдаёт репутацию IP. Здесь показаны только косвенные корреляты, а не мнение Google.",
            ReputationTone.Neutral, "https://ai.google.dev/gemini-api/docs/available-regions"));

        return new GoogleRegionInfo(gl, geoCountry, ruMarked, differs, redirect, aiStatus, finalUri, ytStatus,
            "Метка GL может зависеть от аккаунта, cookies, языка и прошлой активности; зонд без cookies видит только сетевую часть.");
    }

    private static string HeadlineOf(RknOptions o, GoogleRegionInfo google, int risk, bool riskAvailable)
    {
        if (!riskAvailable) return "Данных недостаточно для вывода о репутации";
        if (google.RuMarked == true && google.RegionDiffersFromGeo == true)
            return $"Метка {o.GoogleRegionWatchCode} при зарубежном адресе";
        if (google.AiStudioRedirect == true) return "Google AI Studio перенаправляет на страницу регионов";
        if (google.RuMarked == true) return $"Google определяет регион как {o.GoogleRegionWatchCode}";
        if (risk >= 60) return "Повышенный риск по публичным базам";
        if (risk > 0) return "Есть отдельные замечания по репутации IP";
        return "Явных проблем в доступных базах не найдено";
    }

    private static string SummaryOf(
        RknOptions o,
        (string? Ip, string? Country, string? Body) identity,
        GoogleRegionInfo google,
        bool riskAvailable)
    {
        var parts = new List<string>();
        if (!riskAvailable)
        {
            parts.Add("Источники не вернули данных: часть сервисов требует ключей, часть может быть недоступна из этой сети. Отсутствие ответа не означает «чисто».");
        }
        else if (google.RuMarked == true && google.RegionDiffersFromGeo == true)
        {
            parts.Add($"Google/YouTube присвоил адресу метку {o.GoogleRegionWatchCode}, хотя GeoIP определяет страну как {google.GeoCountry ?? "неизвестно"}. " +
                      "Это похоже на описанную «прокажённую метку»: она меняет регион YouTube и, как правило, закрывает Google AI Studio.");
        }
        else if (google.AiStudioRedirect == true)
        {
            parts.Add("Запрос к Google AI Studio ушёл на страницу «Available regions». Чаще всего это регион, но причиной могут быть возраст аккаунта, платёжный профиль или политики Workspace.");
        }
        else
        {
            parts.Add("Собраны ответы спам-баз и доступных репутационных сервисов; индекс ниже — условная сумма, а не вероятность и не оценка Google.");
        }
        if (identity.Ip is null)
            parts.Add("Внешний IP получить не удалось, поэтому DNSBL и базы с ключами не опрашивались.");
        return string.Join(" ", parts);
    }
}
