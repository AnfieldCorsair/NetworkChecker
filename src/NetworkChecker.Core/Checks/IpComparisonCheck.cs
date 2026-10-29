using System.Diagnostics;
using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// Сравнение IP-ответов разных источников. Диагностический модуль (weight = 0):
/// напрямую в вердикт не входит, но питает IpConsensusBuilder и выявляет расщепление трафика.
/// </summary>
public sealed class IpComparisonCheck(IHttpProbe http) : ICheck
{
    private static readonly (string Name, string Url, string JsonPath)[] Endpoints =
    [
        ("ipify", "https://api.ipify.org?format=json", "ip"),
        ("myip.com", "https://api.myip.com", "ip"),
        ("ipapi.is", "https://api.ipapi.is/", "ip"),
        ("cloudflare-trace", "https://www.cloudflare.com/cdn-cgi/trace", "text"),
    ];

    private readonly IHttpProbe _http = http;

    public CheckCategory Category => CheckCategory.IpComparison;
    public string Title => "Сравнение IP-источников";
    public string Subtitle => "Один ли адрес видят разные сервисы (HTTP, CDN, STUN)";
    public int Weight => 0;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var metrics = new List<Metric>();
        var findings = new List<Finding>();
        var timeout = TimeSpan.FromSeconds(context.Options.RequestTimeoutSeconds);
        var seen = new List<(string Source, string Ip)>();

        if (context.Options.OfflineMode)
        {
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("Офлайн-режим", "Внешние запросы отключены.")],
                Duration = sw.Elapsed,
            };
        }

        foreach (var (name, url, mode) in Endpoints)
        {
            var response = await _http.GetAsync(new Uri(url), timeout, ignoreProxy: false, ct).ConfigureAwait(false);
            if (!response.Success || response.Body is null) continue;
            string? ip = null;
            if (mode == "text")
            {
                var line = response.Body.Split('\n').FirstOrDefault(l => l.StartsWith("ip=", StringComparison.Ordinal));
                ip = line?[3..].Trim();
            }
            else
            {
                var info = GeoIpParser.Parse(response.Body);
                ip = info?.Ip;
            }
            if (string.IsNullOrWhiteSpace(ip)) continue;
            seen.Add((name, ip!));
            context.CollectIp($"IP comparison · {name}", ip!, null);
        }

        // UDP-путь: STUN показывает адрес, который видит NAT, и часто расходится с HTTP через прокси.
        foreach (var server in context.Options.StunServers.Take(2))
        {
            var endpoint = await StunClient.BindAsync(server, timeout, ct).ConfigureAwait(false);
            if (endpoint is null) continue;
            seen.Add(($"STUN {server.Split(':')[0]}", endpoint.Address.ToString()));
            context.CollectIp($"STUN · {server.Split(':')[0]}", endpoint.Address.ToString(), null, "UDP-путь");
            break;
        }

        if (seen.Count < 2)
        {
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("Недостаточно данных", "Меньше двух источников ответили адресом.")],
                Metrics = [.. seen.Select(s => new Metric(s.Source, Masking.Ip(s.Ip)))],
                Duration = sw.Elapsed,
            };
        }

        var distinct = seen.Select(s => s.Ip).Distinct().ToList();
        metrics.Add(new Metric("Источников", seen.Count.ToString(CultureInfo.InvariantCulture)));
        metrics.Add(new Metric("Разных адресов", distinct.Count.ToString(CultureInfo.InvariantCulture)));
        foreach (var group in seen.GroupBy(s => s.Ip))
        {
            metrics.Add(new Metric(Masking.Ip(group.Key), string.Join(", ", group.Select(g => g.Source))));
        }

        CheckStatus status;
        if (distinct.Count == 1)
        {
            findings.Add(Finding.Info("Все источники видят один адрес", Masking.Ip(distinct[0]), "признак «прямого» выхода"));
            status = CheckStatus.Clean;
        }
        else
        {
            findings.Add(Finding.Warning(
                "Источники видят разные IP",
                "Расхождение означает, что часть трафика идёт разными маршрутами: split tunneling, цепочка прокси или прозрачный перехват.",
                string.Join("; ", seen.Select(s => $"{s.Source}={Masking.Ip(s.Ip)}"))));

            var httpAddresses = seen.Where(s => !s.Source.StartsWith("STUN", StringComparison.Ordinal))
                .Select(s => s.Ip).Distinct().ToList();
            if (httpAddresses.Count == 1 && distinct.Count > 1)
            {
                findings.Add(Finding.Notice(
                    "UDP и TCP выходят через разные адреса",
                    "STUN (UDP) и HTTP (TCP) возвращают разные адреса — характерно для прокси, перехватывающего только TCP.",
                    Masking.Ip(httpAddresses[0])));
            }
            status = CheckStatus.Detected;
        }

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = status,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }
}
