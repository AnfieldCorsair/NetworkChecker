using System.Diagnostics;
using System.Net;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Core.Options;
using RKNHardering.Core.Platform;

namespace RKNHardering.Core.NetInfo;

public sealed record HostLatency(string Host, string? Address, double? MedianMs, double JitterMs, double LossPercent, int Ttl, string Method = "ICMP")
{
    public string MedianText => MedianMs is null ? "—" : $"{MedianMs:F0} мс";
    public string JitterText => MedianMs is null ? "—" : $"{JitterMs:F0} мс";
    public string LossText => $"{LossPercent:F0}%";
    public string StatusText => MedianMs is null ? "нет ответа" : LossPercent > 60 ? "потери" : "ок";
    public string MethodText => Method;
}

public sealed record MtuProbe(string Target, int? PathMtu)
{
    public string ResultText => PathMtu is null ? "не определён" : $"{PathMtu} байт";
    public bool Suspicious => PathMtu is not null && PathMtu < 1400;
}

public sealed record DnsProbeResult(string Label, string Server, string? Answer, double ElapsedMs, string? Error)
{
    public string StatusText => Error is null ? "ok" : "ошибка";
}

public sealed record TlsProbe(string Host, string? Issuer, string? Subject, DateTime? NotAfter, string? Protocol, bool Success, double ElapsedMs, string? Error)
{
    public string IssuerShort
    {
        get
        {
            if (Issuer is null) return "—";
            var cn = Issuer.Split(',', StringSplitOptions.TrimEntries).FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
            return cn?[3..] ?? Issuer;
        }
    }
}

public sealed class NetworkOverview
{
    public IReadOnlyList<AdapterInfo> Adapters { get; init; } = Array.Empty<AdapterInfo>();
    public IReadOnlyList<RouteInfo> Routes { get; init; } = Array.Empty<RouteInfo>();
    public DnsConfiguration Dns { get; init; } = new();
    public ProxySettings Proxy { get; init; } = new();
    public string? ExternalIp { get; init; }
    public string? Country { get; init; }
    public string? City { get; init; }
    public string? Isp { get; init; }
    public string? Asn { get; init; }
    public string? StunIp { get; init; }
    public DateTimeOffset RefreshedAt { get; init; } = DateTimeOffset.Now;

    public IReadOnlyList<RouteInfo> DefaultRoutes => Routes.Where(r => r.IsDefault).ToList();
    public IReadOnlyList<AdapterInfo> ActiveAdapters => Adapters.Where(a => a.IsUp).ToList();
    public AdapterInfo? PrimaryAdapter => ActiveAdapters
        .Where(a => a.Kind is AdapterKind.Ethernet or AdapterKind.Wifi or AdapterKind.Cellular)
        .OrderByDescending(a => a.Gateways.Count)
        .FirstOrDefault();
    public string GatewaysText => PrimaryAdapter is null ? "—" : string.Join(", ", PrimaryAdapter.Gateways);
    public string MtuText => PrimaryAdapter is null ? "—" : PrimaryAdapter.Mtu.ToString();
}

public sealed class NetworkDiagnostics
{
    public IReadOnlyList<HostLatency> Latency { get; init; } = Array.Empty<HostLatency>();
    public IReadOnlyList<MtuProbe> Mtu { get; init; } = Array.Empty<MtuProbe>();
    public IReadOnlyList<DnsProbeResult> Dns { get; init; } = Array.Empty<DnsProbeResult>();
    public IReadOnlyList<TlsProbe> Tls { get; init; } = Array.Empty<TlsProbe>();
    public TimeSpan Duration { get; init; }
}

public sealed record TraceResult(string Target, IReadOnlyList<TraceHop> Hops, TimeSpan Duration, string? Error)
{
    public string Mode { get; init; } = "ICMP";
}

/// <summary>Вкладка «Сеть»: обзор, диагностика и трассировка. Всё локально, без агентов.</summary>
public sealed class NetworkInfoService
{
    private readonly IPlatformProbe _platform;
    private readonly IHttpProbe _http;
    private readonly PingTools _ping;
    private readonly DnsClientLite _dns;
    private readonly AsnLookup _asn;
    private readonly TraceTool _tracer;

    public NetworkInfoService(IPlatformProbe platform, IHttpProbe http, PingTools ping, DnsClientLite dns, AsnLookup asn, TraceTool tracer)
    {
        _tracer = tracer;
        _platform = platform;
        _http = http;
        _ping = ping;
        _dns = dns;
        _asn = asn;
    }

    public async Task<NetworkOverview> GetOverviewAsync(RknOptions options, bool includeExternal, CancellationToken ct)
    {
        var adapters = await _platform.GetAdaptersAsync(ct).ConfigureAwait(false);
        var routes = await _platform.GetRoutesAsync(ct).ConfigureAwait(false);
        var dns = await _platform.GetDnsConfigurationAsync(ct).ConfigureAwait(false);
        var proxy = await _platform.GetSystemProxyAsync(ct).ConfigureAwait(false);

        string? ip = null, country = null, city = null, isp = null, asn = null, stun = null;
        if (includeExternal && !options.OfflineMode)
        {
            var timeout = TimeSpan.FromSeconds(options.RequestTimeoutSeconds);
            var response = await _http.GetAsync(new Uri("https://api.ipapi.is/"), timeout, false, ct).ConfigureAwait(false);
            if (response.Success && response.Body is not null)
            {
                var info = GeoIpParser.Parse(response.Body);
                ip = info?.Ip;
                country = info?.Country;
                city = info?.City;
                isp = info?.Isp;
                asn = info?.Asn is null ? null : $"AS{info.Asn.TrimStart('A', 'S')} {info.Org}";
            }

            foreach (var server in options.StunServers.Take(2))
            {
                var endpoint = await StunClient.BindAsync(server, TimeSpan.FromSeconds(4), ct).ConfigureAwait(false);
                if (endpoint is null) continue;
                stun = endpoint.Address.ToString();
                break;
            }
        }

        return new NetworkOverview
        {
            Adapters = adapters,
            Routes = routes,
            Dns = dns,
            Proxy = proxy,
            ExternalIp = ip,
            Country = country,
            City = city,
            Isp = isp,
            Asn = asn,
            StunIp = stun,
        };
    }

    public async Task<NetworkDiagnostics> RunDiagnosticsAsync(
        RknOptions options,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        var hostTasks = options.ReachabilityTargets.Take(4).Concat(options.RttRussianHosts.Take(2)).Distinct()
            .Select(async host =>
            {
                progress?.Report($"Задержка: {host}");
                var (samples, method) = await _ping.SampleLatencyOrTcpAsync(host, 5, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                var addresses = await ConnectivityProbes.ResolveAsync(host, ct).ConfigureAwait(false);
                var summary = PingTools.Summarize(samples, 5);
                var ping = samples.Count > 0 && method == "ICMP"
                    ? await _ping.PingAsync(host, TimeSpan.FromSeconds(2), 128, 32, false, ct).ConfigureAwait(false)
                    : null;
                return new HostLatency(
                    host,
                    addresses.FirstOrDefault()?.ToString(),
                    summary is null || double.IsNaN(summary.Value.median) ? null : summary.Value.median,
                    summary?.jitter is null or double.NaN ? 0 : summary.Value.jitter,
                    summary?.loss ?? 100,
                    ping?.Ttl ?? 0,
                    method);
            }).ToArray();

        var mtuTasks = options.ReachabilityTargets.Take(2)
            .Select(async target =>
            {
                progress?.Report($"MTU: {target}");
                var mtu = await _ping.ProbePathMtuAsync(target, 1500, 576, ct).ConfigureAwait(false);
                return new MtuProbe(target, mtu);
            }).ToArray();

        var dnsServers = (await _platform.GetDnsConfigurationAsync(ct).ConfigureAwait(false)).Servers
            .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().Take(3).ToList();
        if (dnsServers.Count == 0) dnsServers.Add("1.1.1.1");

        var dnsTasks = dnsServers.Select(async server =>
        {
            progress?.Report($"DNS {server}");
            var querySw = Stopwatch.StartNew();
            var endpoint = IPAddress.TryParse(server, out var parsed) ? new IPEndPoint(parsed, 53) : null;
            var answer = await _dns.QueryAsync("example.com", DnsRecordType.A, endpoint, TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            querySw.Stop();
            var ip = answer.FirstOrDefault(a => a.Type == DnsRecordType.A)?.Value;
            return new DnsProbeResult("example.com", server, ip, querySw.Elapsed.TotalMilliseconds,
                ip is null ? "нет ответа" : null);
        }).ToArray();

        var dohTask = ProbeDohAsync(options, ct);

        var tlsTasks = new[] { "cloudflare.com", "ya.ru", "github.com" }.Select(async host =>
        {
            progress?.Report($"TLS: {host}");
            var result = await ConnectivityProbes.TlsHandshakeAsync(host, 443, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            return new TlsProbe(host, result.Issuer, result.Subject, result.NotAfter, result.NegotiatedProtocol,
                result.Success, result.Elapsed.TotalMilliseconds, result.Error);
        }).ToArray();

        await Task.WhenAll(hostTasks).ConfigureAwait(false);
        await Task.WhenAll(mtuTasks).ConfigureAwait(false);
        await Task.WhenAll(tlsTasks).ConfigureAwait(false);

        var dnsResults = await Task.WhenAll(dnsTasks).ConfigureAwait(false);
        var doh = await dohTask.ConfigureAwait(false);
        var dnsList = dnsResults.ToList();
        if (doh is not null) dnsList.Add(doh);

        return new NetworkDiagnostics
        {
            Latency = hostTasks.Select(t => t.Result).ToList(),
            Mtu = mtuTasks.Select(t => t.Result).ToList(),
            Dns = dnsList,
            Tls = tlsTasks.Select(t => t.Result).ToList(),
            Duration = sw.Elapsed,
        };
    }

    private async Task<DnsProbeResult?> ProbeDohAsync(RknOptions options, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var answers = await _dns.QueryDohAsync("example.com", DnsRecordType.A, TimeSpan.FromSeconds(4), ct).ConfigureAwait(false);
        sw.Stop();
        var value = answers.FirstOrDefault()?.Value;
        return new DnsProbeResult("DoH (cloudflare)", "cloudflare-dns.com", value, sw.Elapsed.TotalMilliseconds,
            value is null ? "нет ответа" : null);
    }

    public async Task<TraceResult> TraceAsync(string target, int maxHops, IProgress<TraceHop>? progress, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // Прогресс отдаём уже обогащёнными данными (с ASN), иначе хоп попадёт в UI дважды.
            var (hops, mode) = await _tracer.TraceAsync(target, maxHops, 3, 1500, null, ct).ConfigureAwait(false);
            var modeText = mode;
            var enriched = new List<TraceHop>();
            foreach (var hop in hops)
            {
                if (hop.Address is null)
                {
                    enriched.Add(hop);
                }
                else
                {
                    var (asn, name) = await _asn.LookupAsync(hop.Address, ct).ConfigureAwait(false);
                    var updated = hop with { Asn = asn, AsName = name };
                    enriched.Add(updated);
                }
                progress?.Report(enriched[^1]);
            }
            return new TraceResult(target, enriched, sw.Elapsed, null) { Mode = modeText };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new TraceResult(target, Array.Empty<TraceHop>(), sw.Elapsed, ex.GetBaseException().Message);
        }
    }
}
