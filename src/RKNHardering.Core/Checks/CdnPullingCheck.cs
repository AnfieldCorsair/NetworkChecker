using System.Diagnostics;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;

namespace RKNHardering.Core.Checks;

/// <summary>
/// CDN/redirector/echo-эндпоинты: сравнивает то, что сервис видит о клиенте
/// (country, ip, colo, proxy-заголовки), и ищет расхождения с GeoIP.
/// </summary>
public sealed class CdnPullingCheck : ICheck
{
    private readonly IHttpProbe _http;

    public CdnPullingCheck(IHttpProbe http) => _http = http;

    public CheckCategory Category => CheckCategory.CdnPulling;
    public string Title => "CDN и redirector";
    public string Subtitle => "Что о вас знают edge-сервисы: страна, colo, заголовки";
    public int Weight => 5;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromSeconds(context.Options.RequestTimeoutSeconds);

        if (context.Options.OfflineMode)
        {
            return new CheckResult
            {
                Category = Category, Title = Title, Subtitle = Subtitle, Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("Офлайн-режим")],
                Duration = sw.Elapsed,
            };
        }

        foreach (var url in context.Options.CdnProbeUrls)
        {
            ct.ThrowIfCancellationRequested();
            var response = await _http.GetAsync(new Uri(url), timeout, ignoreProxy: false, ct).ConfigureAwait(false);
            if (!response.Success || string.IsNullOrWhiteSpace(response.Body)) continue;

            var trace = ParseTrace(response.Body);
            if (trace.Count == 0) continue;

            var host = new Uri(url).Host;
            if (trace.TryGetValue("ip", out var ip))
            {
                context.CollectIp($"CDN · {host}", ip, trace.TryGetValue("loc", out var loc) ? loc == "RU" : null, trace.GetValueOrDefault("colo"));
                metrics.Add(new Metric($"{host}", Masking.Ip(ip),
                    trace.TryGetValue("loc", out var country) ? $"страна {country}, colo {trace.GetValueOrDefault("colo")}" : null));

                if (trace.TryGetValue("loc", out var c) && c != "RU")
                {
                    findings.Add(Finding.Notice($"Edge-CDN определяет страну как {c}",
                        $"Для {host} запрос пришёл не из России. Вместе с geo-данными это подтверждает иностранный выход.",
                        Masking.Ip(ip)));
                }
            }
        }

        // Заголовки, которые выдают присутствие прокси
        var probe = await _http.GetAsync(new Uri("https://httpbin.org/headers"), timeout, ignoreProxy: false, ct).ConfigureAwait(false);
        if (probe.Success && probe.Body is not null)
        {
            var sniffed = new List<string>();
            foreach (var header in new[] { "Via", "X-Forwarded-For", "Forwarded", "Proxy-Connection", "X-Real-Ip" })
            {
                if (probe.Body.Contains($"\"{header}\"", StringComparison.OrdinalIgnoreCase)) sniffed.Add(header);
            }
            if (sniffed.Count > 0)
            {
                findings.Add(Finding.Critical(
                    "Сервер видит прокси-заголовки",
                    "Среди ваших заголовков присутствуют поля, которые добавляют прокси-серверы.",
                    string.Join(", ", sniffed)));
                metrics.Add(new Metric("Прокси-заголовки", string.Join(", ", sniffed)));
            }
            else
            {
                metrics.Add(new Metric("Прокси-заголовки", "не обнаружены"));
            }
        }

        if (findings.Count == 0)
        {
            findings.Add(Finding.Info("Аномалий на edge-сервисах не обнаружено"));
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

    private static Dictionary<string, string> ParseTrace(string body)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // cloudflare cdn-cgi/trace: "key=value" построчно
        foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var index = line.IndexOf('=');
            if (index <= 0 || index == line.Length - 1) continue;
            var key = line[..index].Trim();
            var value = line[(index + 1)..].Trim();
            if (key.Length <= 16 && value.Length > 0) map[key] = value;
        }
        if (map.Count > 20) return new Dictionary<string, string>(); // это точно не trace
        return map;
    }
}
