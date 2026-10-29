using System.Diagnostics;
using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// Локальные средства обхода: открытые порты прокси на loopback, SOCKS5/HTTP-прокси,
/// REST-API Xray и Clash/sing-box, плюс признак активного tun2socks.
/// Аналог BypassChecker (Android).
/// </summary>
public sealed class BypassCheck(IHttpProbe http) : ICheck
{
    private readonly IHttpProbe _http = http;

    public CheckCategory Category => CheckCategory.Bypass;
    public string Title => "Локальный обход";
    public string Subtitle => "Прокси на 127.0.0.1, Xray/Clash API, tun2socks";
    public int Weight => 30;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromMilliseconds(700);

        var openPorts = new List<(int Port, string Kind, string? Banner)>();
        var probeTasks = context.Options.LocalProxyPorts.Select(async port =>
        {
            var socks = await ConnectivityProbes.IsSocks5Async("127.0.0.1", port, timeout, ct).ConfigureAwait(false);
            if (socks) return (port, "SOCKS5", (string?)null);

            var http = await ConnectivityProbes.IsHttpProxyAsync("127.0.0.1", port, timeout, ct).ConfigureAwait(false);
            if (http) return (port, "HTTP-прокси", (string?)null);

            var banner = await ConnectivityProbes.ReadBannerAsync("127.0.0.1", port, timeout, ct).ConfigureAwait(false);
            return (port, banner is null ? "" : "сервис", banner);
        }).ToArray();

        var results = await Task.WhenAll(probeTasks).ConfigureAwait(false);
        foreach (var (port, kind, banner) in results)
        {
            if (kind is "") continue;
            openPorts.Add((port, kind, banner));
        }

        metrics.Add(new Metric("Портов проверено", context.Options.LocalProxyPorts.Count.ToString(CultureInfo.InvariantCulture)));
        metrics.Add(new Metric("Открыто на loopback", openPorts.Count.ToString(CultureInfo.InvariantCulture),
            openPorts.Count == 0 ? "не найдено" : string.Join(", ", openPorts.Select(p => p.Port))));

        foreach (var (port, kind, banner) in openPorts)
        {
            findings.Add(Finding.Critical(
                $"Локальный прокси на 127.0.0.1:{port}",
                $"{kind}. Открытый локальный прокси — главный косвенный признак клиента обхода на ПК.",
                banner));
        }

        // --- REST-API панели Xray ---
        var xray = await ProbeJsonApiAsync("http://127.0.0.1:10085/", timeout, ct).ConfigureAwait(false);
        if (xray)
        {
            findings.Add(Finding.Critical("Отвечает gRPC/REST API Xray",
                "Порт 10085 — стандартный API Xray-core, через него управляется маршрутизация.", "127.0.0.1:10085"));
        }

        // --- Clash / sing-box external controller ---
        foreach (var port in new[] { 9090, 9091 })
        {
            var uri = new Uri($"http://127.0.0.1:{port}/version");
            var response = await _http.GetAsync(uri, TimeSpan.FromSeconds(1), ignoreProxy: true, ct).ConfigureAwait(false);
            if (!response.Success || response.Body is null) continue;
            if (!response.Body.Contains("\"version\"", StringComparison.OrdinalIgnoreCase)) continue;
            findings.Add(Finding.Critical(
                $"Отвечает API Clash/Mihomo на порту {port}",
                "External controller клиента Clash доступен без авторизации — значит клиент запущен.",
                response.Body.Length > 120 ? response.Body[..120] : response.Body));
            break;
        }

        // --- tun2socks / локальный SOCKS + TUN ---
        var hasSocks = openPorts.Any(p => p.Kind == "SOCKS5");
        if (hasSocks)
        {
            findings.Add(Finding.Notice("Комбинация SOCKS5 + TUN",
                "Связка «локальный SOCKS5 + туннельный интерфейс» — типовая схема tun2socks/v2rayN."));
        }

        if (openPorts.Count == 0)
        {
            findings.Add(Finding.Info("Локальные прокси не обнаружены",
                "На типовых портах (1080, 1087, 2080, 7890, 8080, 9050...) никто не ответил."));
        }

        var detected = findings.Any(f => f.Severity == Severity.Critical);
        var review = findings.Any(f => f.Severity == Severity.Notice);

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = detected ? CheckStatus.Detected : review ? CheckStatus.NeedsReview : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }

    private async Task<bool> ProbeJsonApiAsync(string url, TimeSpan timeout, CancellationToken ct)
    {
        var response = await _http.GetAsync(new Uri(url), timeout, ignoreProxy: true, ct).ConfigureAwait(false);
        return response.StatusCode is 200 or 403 or 404 or 405;
    }
}
