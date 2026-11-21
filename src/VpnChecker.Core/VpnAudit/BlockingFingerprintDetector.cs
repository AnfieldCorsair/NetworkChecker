using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;

namespace VpnChecker.Core.VpnAudit;

public enum BlockingFingerprintStatus
{
    Detected,
    Suspected,
    Clear,
    Inconclusive,
}

public sealed record BlockingTargetProbe(
    string Label,
    string Host,
    string Group,
    bool Ok,
    int LatencyMs,
    string? Error = null);

public sealed record CutoffStepProbe(
    int BytesTarget,
    int BytesReceived,
    bool Ok,
    int LatencyMs,
    string? Error = null);

public sealed record DnsSpoofProbe(
    string Domain,
    IReadOnlyList<string> SystemIps,
    IReadOnlyList<string> DohIps,
    bool IsFakeIpActive,
    bool Suspicious,
    string Summary);

public sealed record BlockingFingerprintMatch(
    string Id,
    BlockingFingerprintStatus Status,
    int Confidence,
    string Title,
    string Mechanism,
    string Recommendation,
    IReadOnlyList<string> Evidence);

public sealed record BlockingScanResult(
    DateTimeOffset ScannedAt,
    IReadOnlyList<BlockingTargetProbe> Targets,
    IReadOnlyList<CutoffStepProbe> CutoffSteps,
    IReadOnlyList<BlockingFingerprintMatch> Fingerprints,
    IReadOnlyList<DnsSpoofProbe>? DnsProbes = null);

/// <summary>
/// Нативный детектор отпечатков блокировок провайдеров РФ и ТСПУ (2025–2026) для Windows-десктопа:
/// - Режим «Белых списков» (Яндекс/ВК/Госуслуги/Ozon vs Wikipedia/GitHub/Cloudflare)
/// - Отсечка потока ~16 КБ (4 КБ → 16 КБ → 64 КБ → 512 КБ)
/// - Блокировка TLS ECH (cloudflare-ech.com) и точечный L7 SNI (Discord/YouTube)
/// - Проверка DNS-спуфинга / подмены DNS провайдером (системный DNS ОС vs DoH) с учётом FakeIP 198.18.0.0/15
/// </summary>
public static class BlockingFingerprintDetector
{
    private static readonly (string Label, string Host, string Url, string Group)[] DefaultTargets =
    [
        ("Яндекс", "ya.ru", "https://ya.ru/favicon.ico", "ru_whitelist"),
        ("ВКонтакте", "vk.com", "https://vk.com/favicon.ico", "ru_whitelist"),
        ("Госуслуги", "www.gosuslugi.ru", "https://www.gosuslugi.ru/favicon.ico", "ru_whitelist"),
        ("Ozon", "www.ozon.ru", "https://www.ozon.ru/favicon.ico", "ru_whitelist"),
        ("Wikipedia", "www.wikipedia.org", "https://www.wikipedia.org/static/favicon/wikipedia.ico", "global_infra"),
        ("GitHub", "github.com", "https://github.com/favicon.ico", "global_infra"),
        ("Cloudflare", "www.cloudflare.com", "https://www.cloudflare.com/favicon.ico", "global_infra"),
        ("Discord", "discord.com", "https://discord.com/favicon.ico", "restricted_rf"),
        ("YouTube", "www.youtube.com", "https://www.youtube.com/favicon.ico", "restricted_rf"),
        ("Cloudflare ECH", "cloudflare-ech.com", "https://cloudflare-ech.com/cdn-cgi/trace", "ech_cdn"),
    ];

    private static readonly string[] DnsSpoofDomains =
    [
        "discord.com",
        "www.youtube.com",
        "www.cloudflare.com",
    ];

    private static readonly int[] CutoffStepSizes = [4096, 16384, 65536, 524288];

    private static readonly string[] StubHostMarkers =
    [
        "warning.rt.ru",
        "block.",
        "zapret",
        "rkn.",
        "fz139",
        "eais",
    ];

    public static async Task<BlockingScanResult> RunAsync(
        HttpClient httpClient,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);

        var targetTasks = DefaultTargets.Select(t => ProbeTargetAsync(httpClient, t.Label, t.Host, t.Url, t.Group, cancellationToken));
        var dnsTasks = DnsSpoofDomains.Select(d => ProbeDnsSpoofingAsync(httpClient, d, cancellationToken));

        var targetsTask = Task.WhenAll(targetTasks);
        var dnsTask = Task.WhenAll(dnsTasks);
        var cutoffTask = Probe16KbCutoffAsync(httpClient, cancellationToken);

        await Task.WhenAll(targetsTask, dnsTask, cutoffTask).ConfigureAwait(false);

        var targets = await targetsTask.ConfigureAwait(false);
        var dnsProbes = await dnsTask.ConfigureAwait(false);
        var cutoff = await cutoffTask.ConfigureAwait(false);
        var fingerprints = Classify(targets, cutoff, dnsProbes);

        return new BlockingScanResult(DateTimeOffset.UtcNow, targets, cutoff, fingerprints, dnsProbes);
    }

    public static IReadOnlyList<BlockingFingerprintMatch> Classify(
        IReadOnlyList<BlockingTargetProbe> targets,
        IReadOnlyList<CutoffStepProbe> cutoffSteps,
        IReadOnlyList<DnsSpoofProbe>? dnsProbes = null)
    {
        var ru = targets.Where(t => t.Group == "ru_whitelist").ToArray();
        var gl = targets.Where(t => t.Group == "global_infra").ToArray();
        var rf = targets.Where(t => t.Group == "restricted_rf").ToArray();
        var ech = targets.FirstOrDefault(t => t.Group == "ech_cdn");

        var ruOk = ru.Count(t => t.Ok);
        var glOk = gl.Count(t => t.Ok);
        var rfOk = rf.Count(t => t.Ok);

        var list = new List<BlockingFingerprintMatch>();

        // 1. Whitelist mode
        var strongWhitelist = ruOk >= 3 && glOk <= 1 && rfOk == 0;
        var suspectWhitelist = ruOk >= 2 && glOk < ruOk && rfOk == 0;
        list.Add(new BlockingFingerprintMatch(
            "whitelist_mode",
            strongWhitelist ? BlockingFingerprintStatus.Detected
                : suspectWhitelist ? BlockingFingerprintStatus.Suspected
                : BlockingFingerprintStatus.Clear,
            strongWhitelist ? 92 : suspectWhitelist ? 65 : 10,
            "Режим «Белых списков» (Allowlist / мобильный шатдаун)",
            "L3 CIDR-фильтрация и L7 SNI-белый список: пропускаются только РФ-сервисы.",
            "Используйте каскад через РФ-мост либо смените тип сети.",
            [$"РФ-домены: {ruOk}/{ru.Length}", $"Глобальные домены: {glOk}/{gl.Length}", $"Ограниченные РФ: {rfOk}/{rf.Length}"]));

        // 2. 16 KB Cutoff
        var step4k = cutoffSteps.FirstOrDefault(s => s.BytesTarget == 4096);
        var step64k = cutoffSteps.FirstOrDefault(s => s.BytesTarget == 65536);
        var step512k = cutoffSteps.FirstOrDefault(s => s.BytesTarget == 524288);
        var freeze16k = step4k is { Ok: true } && (step64k is { Ok: false } || step512k is { Ok: false });
        list.Add(new BlockingFingerprintMatch(
            "cutoff_16kb",
            freeze16k ? BlockingFingerprintStatus.Detected : BlockingFingerprintStatus.Clear,
            freeze16k ? 94 : 10,
            "Отсечка потока на ~16 КБ (ТСПУ TCP/TLS Freeze)",
            "ТСПУ пропускает первые 10–14 пакетов (~16 КБ) и замораживает поток до Cloudflare/Hetzner/OVH.",
            "Смените ASN хостинга или используйте VLESS XHTTP (split downloadSettings / каскад).",
            cutoffSteps.Select(s => string.Create(
                CultureInfo.InvariantCulture,
                $"{s.BytesTarget / 1024} КБ: {(s.Ok ? $"OK ({s.LatencyMs} мс)" : $"Сбой после {s.BytesReceived / 1024.0:F1} КБ")}")).ToArray()));

        // 3. L7 SNI Blacklist
        var sniBlacklist = ruOk >= 2 && glOk >= 2 && rfOk < rf.Length;
        var blockedRfNames = rf.Where(x => !x.Ok).Select(x => x.Label).ToArray();
        list.Add(new BlockingFingerprintMatch(
            "sni_blacklist",
            sniBlacklist ? BlockingFingerprintStatus.Detected : BlockingFingerprintStatus.Clear,
            sniBlacklist ? 90 : 10,
            "Точечная L7 SNI / DPI-блокировка (Чёрный список ТСПУ)",
            "Сброс соединений по полю SNI в TLS ClientHello для выборочных доменов.",
            "Решается VLESS + Reality (TCP Vision или XHTTP) с нейтральным SNI TLS 1.3 + h2.",
            [blockedRfNames.Length > 0 ? $"Недоступны: {string.Join(", ", blockedRfNames)}" : "Все тестовые домены ответили"]));

        // 4. TLS ECH blocking
        var echBlocked = ech is { Ok: false } && glOk >= 2;
        list.Add(new BlockingFingerprintMatch(
            "ech_blocking",
            echBlocked ? BlockingFingerprintStatus.Detected : BlockingFingerprintStatus.Clear,
            echBlocked ? 88 : 10,
            "Блокировка TLS ECH (Encrypted Client Hello)",
            "ТСПУ распознаёт TLS-расширение ECH (0xFE0D) / cloudflare-ech.com и обрывает handshake.",
            "Отключите ECH для прямых запросов; используйте VLESS Reality.",
            [ech is null ? "Не проверялся" : $"cloudflare-ech.com: {(ech.Ok ? $"OK ({ech.LatencyMs} мс)" : ech.Error ?? "сбой")}"]));

        // 5. DNS Spoofing / Provider DNS interception
        if (dnsProbes is { Count: > 0 })
        {
            var suspiciousCount = dnsProbes.Count(p => p.Suspicious);
            var fakeIpActive = dnsProbes.Any(p => p.IsFakeIpActive);
            var status = suspiciousCount >= 2
                ? BlockingFingerprintStatus.Detected
                : suspiciousCount == 1
                    ? BlockingFingerprintStatus.Suspected
                    : BlockingFingerprintStatus.Clear;

            var confidence = status switch
            {
                BlockingFingerprintStatus.Detected => 91,
                BlockingFingerprintStatus.Suspected => 68,
                _ => 12,
            };

            var recommendation = suspiciousCount > 0
                ? "Переведите DNS-клиента на DoH через proxy (вкладка «DNS-архитектор») и включите hijack-dns."
                : fakeIpActive
                    ? "Обнаружен активный FakeIP (198.18.0.0/15) — DNS перехватывается вашим ВПН-клиентом корректно."
                    : "Системный DNS возвращает валидные публичные адреса без признаков подмены.";

            list.Add(new BlockingFingerprintMatch(
                "dns_spoofing",
                status,
                confidence,
                "Подмена или блокировка DNS провайдером (DNS-спуфинг)",
                "Сравнение системного DNS ОС с защищённым DoH: выявляет подмену на 127.0.0.1/0.0.0.0, приватные IP-заглушки или ложный NXDOMAIN.",
                recommendation,
                dnsProbes.Select(p => $"{p.Domain}: {p.Summary}").ToArray()));
        }

        return list;
    }

    private static async Task<DnsSpoofProbe> ProbeDnsSpoofingAsync(
        HttpClient http,
        string domain,
        CancellationToken ct)
    {
        var sysIps = new List<string>();
        try
        {
            using var sysCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            sysCts.CancelAfter(3000);
            var addrs = await Dns.GetHostAddressesAsync(domain, sysCts.Token).ConfigureAwait(false);
            sysIps.AddRange(addrs
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.ToString())
                .Distinct(StringComparer.Ordinal));
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            // sysIps remains empty
        }

        var dohIps = await QueryDohAAsync(http, domain, ct).ConfigureAwait(false);

        // Проверяем, работает ли FakeIP самого ВПН-клиента (198.18.0.0/15) — это НЕ спуфинг провайдера!
        var isFakeIp = sysIps.Any(ip => ip.StartsWith("198.18.", StringComparison.Ordinal) || ip.StartsWith("198.19.", StringComparison.Ordinal));
        if (isFakeIp)
        {
            return new DnsSpoofProbe(domain, sysIps, dohIps, IsFakeIpActive: true, Suspicious: false, $"FakeIP ВПН ({sysIps[0]})");
        }

        // Проверяем подмену на заглушки (127.x, 0.0.0.0, приватные 10.x/192.168.x/172.16-31.x)
        var hasBogusIp = sysIps.Any(IsBogusOrPrivateStubIp);
        if (hasBogusIp)
        {
            return new DnsSpoofProbe(domain, sysIps, dohIps, IsFakeIpActive: false, Suspicious: true, $"Подмена на заглушку ({string.Join(", ", sysIps)})");
        }

        // Системный DNS не смог разрезолвить домен, тогда как DoH вернул валидный IP
        if (sysIps.Count == 0 && dohIps.Count > 0)
        {
            return new DnsSpoofProbe(domain, sysIps, dohIps, IsFakeIpActive: false, Suspicious: true, $"Системный DNS: NXDOMAIN (DoH: {dohIps[0]})");
        }

        if (sysIps.Count == 0 && dohIps.Count == 0)
        {
            return new DnsSpoofProbe(domain, sysIps, dohIps, IsFakeIpActive: false, Suspicious: false, "Нет ответа DNS и DoH");
        }

        return new DnsSpoofProbe(
            domain,
            sysIps,
            dohIps,
            IsFakeIpActive: false,
            Suspicious: false,
            dohIps.Count > 0 ? $"OK ({sysIps[0]} / DoH OK)" : $"OK ({sysIps[0]})");
    }

    private static async Task<IReadOnlyList<string>> QueryDohAAsync(HttpClient http, string domain, CancellationToken ct)
    {
        Uri[] endpoints =
        [
            new($"https://1.1.1.1/dns-query?name={Uri.EscapeDataString(domain)}&type=A"),
            new($"https://dns.google/resolve?name={Uri.EscapeDataString(domain)}&type=A"),
        ];

        foreach (var uri in endpoints)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(3500);
                using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));

                using var res = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
                if (!res.IsSuccessStatusCode) continue;

                var json = await res.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty("Answer", out var ans) &&
                    ans.ValueKind == JsonValueKind.Array)
                {
                    var ips = new List<string>();
                    foreach (var item in ans.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.Object) continue;
                        if (item.TryGetProperty("type", out var tEl) && tEl.TryGetInt32(out var recType) && recType != 1)
                        {
                            continue;
                        }
                        if (item.TryGetProperty("data", out var dEl) && dEl.ValueKind == JsonValueKind.String)
                        {
                            var ipStr = dEl.GetString();
                            if (!string.IsNullOrWhiteSpace(ipStr) && IPAddress.TryParse(ipStr, out _))
                            {
                                ips.Add(ipStr);
                            }
                        }
                    }

                    if (ips.Count > 0) return ips;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
            {
                // try next DoH provider
            }
        }

        return [];
    }

    private static bool IsBogusOrPrivateStubIp(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var b = ip.GetAddressBytes();
        if (b[0] is 0 or 10 or 127) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        return false;
    }

    private static async Task<BlockingTargetProbe> ProbeTargetAsync(
        HttpClient http,
        string label,
        string host,
        string url,
        string group,
        CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(4200);
        var sw = Stopwatch.StartNew();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(url));
            req.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            sw.Stop();

            if ((int)res.StatusCode == 451)
            {
                return new BlockingTargetProbe(label, host, group, false, Math.Max(1, (int)sw.ElapsedMilliseconds), "HTTP 451 (блокировка)");
            }

            var finalHost = res.RequestMessage?.RequestUri?.Host ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(finalHost) &&
                StubHostMarkers.Any(m => finalHost.Contains(m, StringComparison.OrdinalIgnoreCase)))
            {
                return new BlockingTargetProbe(label, host, group, false, Math.Max(1, (int)sw.ElapsedMilliseconds), $"Редирект на заглушку ({finalHost})");
            }

            return new BlockingTargetProbe(label, host, group, true, Math.Max(1, (int)sw.ElapsedMilliseconds));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            sw.Stop();
            return new BlockingTargetProbe(label, host, group, false, (int)sw.ElapsedMilliseconds, SimplifyNetworkError(ex));
        }
    }

    private static string SimplifyNetworkError(Exception ex)
    {
        if (ex is TaskCanceledException or OperationCanceledException)
        {
            return "таймаут (сброс/тишина)";
        }

        var msg = ex.Message;
        if (msg.Contains("SSL", StringComparison.OrdinalIgnoreCase) || msg.Contains("TLS", StringComparison.OrdinalIgnoreCase))
        {
            return "сброс TLS-рукопожатия";
        }
        if (msg.Contains("No such host", StringComparison.OrdinalIgnoreCase) || msg.Contains("Name or service", StringComparison.OrdinalIgnoreCase))
        {
            return "ошибка DNS (NXDOMAIN)";
        }
        if (msg.Contains("forcibly closed", StringComparison.OrdinalIgnoreCase) || msg.Contains("reset", StringComparison.OrdinalIgnoreCase))
        {
            return "TCP RST от сети";
        }

        return msg.Length > 48 ? $"{msg[..48]}…" : msg;
    }

    private static async Task<IReadOnlyList<CutoffStepProbe>> Probe16KbCutoffAsync(
        HttpClient http,
        CancellationToken ct)
    {
        var results = new List<CutoffStepProbe>(CutoffStepSizes.Length);

        foreach (var target in CutoffStepSizes)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(target >= 65536 ? 5500 : 4000);
            var sw = Stopwatch.StartNew();
            var received = 0;

            try
            {
                var uri = new Uri(string.Create(CultureInfo.InvariantCulture, $"https://speed.cloudflare.com/__down?bytes={target}"));
                using var res = await http.GetAsync(
                    uri,
                    HttpCompletionOption.ResponseHeadersRead,
                    cts.Token).ConfigureAwait(false);
                res.EnsureSuccessStatusCode();

                await using var stream = await res.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                var buffer = new byte[8192];
                int read;
                while ((read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false)) > 0)
                {
                    received += read;
                }

                sw.Stop();
                results.Add(new CutoffStepProbe(target, received, received >= target * 0.9, Math.Max(1, (int)sw.ElapsedMilliseconds)));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or IOException)
            {
                sw.Stop();
                results.Add(new CutoffStepProbe(target, received, false, (int)sw.ElapsedMilliseconds, SimplifyNetworkError(ex)));
            }
        }

        return results;
    }
}
