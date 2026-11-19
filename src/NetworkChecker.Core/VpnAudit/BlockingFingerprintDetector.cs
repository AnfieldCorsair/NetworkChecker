using System.Diagnostics;
using System.Net.Http.Headers;

namespace NetworkChecker.Core.VpnAudit;

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
    IReadOnlyList<BlockingFingerprintMatch> Fingerprints);

/// <summary>
/// Нативный детектор отпечатков блокировок провайдеров РФ и ТСПУ (2025–2026) для Windows-десктопа:
/// - Режим «Белых списков» (Яндекс/ВК/Госуслуги/Ozon vs Wikipedia/GitHub/Cloudflare)
/// - Отсечка потока ~16 КБ (4 КБ → 16 КБ → 64 КБ → 512 КБ)
/// - Блокировка TLS ECH (cloudflare-ech.com) и точечный L7 SNI (Discord/YouTube)
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

    public static async Task<BlockingScanResult> RunAsync(
        HttpClient httpClient,
        CancellationToken cancellationToken = default)
    {
        var targetTasks = DefaultTargets.Select(t => ProbeTargetAsync(httpClient, t.Label, t.Host, t.Url, t.Group, cancellationToken));
        var targets = await Task.WhenAll(targetTasks).ConfigureAwait(false);
        var cutoff = await Probe16KbCutoffAsync(httpClient, cancellationToken).ConfigureAwait(false);
        var fingerprints = Classify(targets, cutoff);

        return new BlockingScanResult(DateTimeOffset.UtcNow, targets, cutoff, fingerprints);
    }

    public static IReadOnlyList<BlockingFingerprintMatch> Classify(
        IReadOnlyList<BlockingTargetProbe> targets,
        IReadOnlyList<CutoffStepProbe> cutoffSteps)
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
            cutoffSteps.Select(s => $"{s.BytesTarget / 1024} КБ: {(s.Ok ? $"OK ({s.LatencyMs} мс)" : $"Сбой после {s.BytesReceived / 1024.0:F1} КБ")}").ToArray()));

        // 3. L7 SNI Blacklist
        var sniBlacklist = ruOk >= 2 && glOk >= 2 && rfOk < rf.Length;
        list.Add(new BlockingFingerprintMatch(
            "sni_blacklist",
            sniBlacklist ? BlockingFingerprintStatus.Detected : BlockingFingerprintStatus.Clear,
            sniBlacklist ? 90 : 10,
            "Точечная L7 SNI / DPI-блокировка (Чёрный список ТСПУ)",
            "Сброс соединений по полю SNI в TLS ClientHello для выборочных доменов.",
            "Решается VLESS + Reality (TCP Vision или XHTTP) с нейтральным SNI TLS 1.3 + h2.",
            [$"Недоступны: {string.Join(", ", rf.Where(x => !x.Ok).Select(x => x.Label))}"]));

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

        return list;
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
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return new BlockingTargetProbe(label, host, group, true, Math.Max(1, (int)sw.ElapsedMilliseconds));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            sw.Stop();
            return new BlockingTargetProbe(label, host, group, false, (int)sw.ElapsedMilliseconds, ex.Message);
        }
    }

    private static async Task<IReadOnlyList<CutoffStepProbe>> Probe16KbCutoffAsync(
        HttpClient http,
        CancellationToken ct)
    {
        int[] steps = [4096, 16384, 65536, 524288];
        var results = new List<CutoffStepProbe>(steps.Length);

        foreach (var target in steps)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(target >= 65536 ? 5500 : 4000);
            var sw = Stopwatch.StartNew();
            var received = 0;

            try
            {
                using var res = await http.GetAsync(
                    $"https://speed.cloudflare.com/__down?bytes={target}",
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
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
            {
                sw.Stop();
                results.Add(new CutoffStepProbe(target, received, false, (int)sw.ElapsedMilliseconds, ex.Message));
            }
        }

        return results;
    }
}
