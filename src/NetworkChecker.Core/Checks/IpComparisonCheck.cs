using System.Diagnostics;
using System.Globalization;
using System.Net;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Verdict;

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
            if (!IPAddress.TryParse(ip, out var parsed)) continue;
            ip = (parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed).ToString();
            seen.Add((name, ip));
            context.CollectIp($"IP comparison · {name}", ip!, null, channel: IpChannel.Web);
        }

        // UDP-путь: STUN показывает адрес, который видит NAT, и часто расходится с HTTP через прокси.
        foreach (var server in context.Options.StunServers.Take(2))
        {
            var endpoint = await StunClient.BindAsync(server, timeout, ct).ConfigureAwait(false);
            if (endpoint is null) continue;
            seen.Add(($"STUN {server.Split(':')[0]}", endpoint.Address.ToString()));
            context.CollectIp($"STUN · {server.Split(':')[0]}", endpoint.Address.ToString(), null, "UDP-путь", IpChannel.Udp);
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

        var comparison = IpConsensusBuilder.Build(seen.Select(s => new IpObservation(s.Source, s.Ip, null,
            Channel: s.Source.StartsWith("STUN", StringComparison.Ordinal) ? IpChannel.Udp : IpChannel.Web)).ToArray());
        var comparableCount = seen.GroupBy(s => IPAddress.Parse(s.Ip).AddressFamily).Max(g => g.Count());
        CheckStatus status;
        if (comparableCount < 2)
        {
            findings.Add(Finding.Info("Недостаточно сопоставимых источников",
                "IPv4 и IPv6 не сравниваются друг с другом; нужно минимум два наблюдения одного семейства."));
            status = CheckStatus.Skipped;
        }
        else if (!comparison.IsSplit)
        {
            findings.Add(Finding.Info("Нет расхождений внутри одного семейства IP",
                "IPv4 и IPv6 не сравниваются друг с другом; один источник на семейство не подтверждает совпадение."));
            status = CheckStatus.Clean;
        }
        else
        {
            findings.Add(Finding.Warning("Источники видят разные IP одного семейства",
                "Возможны разные маршруты, балансировка, NAT или настройки прокси. По одному расхождению причину установить нельзя.",
                string.Join("; ", seen.Select(s => $"{s.Source}={Masking.Ip(s.Ip)}"))));
            status = CheckStatus.NeedsReview;
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
