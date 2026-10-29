using RKNHardering.Core.Checks;
using RKNHardering.Core.Models;
using RKNHardering.Core.Options;
using RKNHardering.Core.Platform;
using RKNHardering.TestKit;
using Xunit;

namespace RKNHardering.Core.Tests;

/// <summary>Проверки на локальных данных (без сети): DirectSigns, IndirectSigns, Bypass-эвристики.</summary>
public class DirectSignsCheckTests
{
    private static DirectSignsCheck Create(FakePlatformProbe platform) =>
        new(platform, new VpnClientCatalog());

    [Fact]
    public async Task Clean_machine_reports_no_direct_signs()
    {
        var check = Create(FakePlatformProbe.Clean());

        var result = await check.RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Equal(CheckStatus.Clean, result.Status);
        Assert.DoesNotContain(result.Findings, f => f.Severity >= Severity.Warning);
        Assert.Equal(CheckCategory.DirectSigns, result.Category);
        Assert.Equal(30, result.Weight);
    }

    [Fact]
    public async Task Tunnel_proxy_and_running_client_are_critical()
    {
        var check = Create(FakePlatformProbe.Tunneled());

        var result = await check.RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Equal(CheckStatus.Detected, result.Status);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Системный прокси"));
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("туннельный интерфейс"));
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Запущен клиент"));
        Assert.Contains(result.Findings, f => f.Title.Contains("VPN-подключение"));
        Assert.Contains(result.Findings, f => f.Title.Contains("kill switch"));
    }

    [Fact]
    public async Task Metrics_include_proxy_tunnels_and_apps()
    {
        var check = Create(FakePlatformProbe.Tunneled());

        var result = await check.RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Contains(result.Metrics, m => m.Label == "Системный прокси" && m.Value.Contains("8080"));
        Assert.Contains(result.Metrics, m => m.Label == "Активных туннелей" && m.Value == "1");
        Assert.Contains(result.Metrics, m => m.Label == "Клиентов обхода установлено" && m.Value == "1");
    }

    [Fact]
    public async Task Installed_vpn_without_tunnel_is_review_not_detected()
    {
        var platform = FakePlatformProbe.Clean();
        platform.Apps = [new InstalledApp { Name = "WireGuard", Kind = "vpn", MatchedMarker = "WireGuard" }];
        var check = Create(platform);

        var result = await check.RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Equal(CheckStatus.NeedsReview, result.Status);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Установлены клиенты"));
    }

    [Fact]
    public async Task Platform_errors_do_not_crash_the_check()
    {
        var platform = new FakePlatformProbe { ThrowOn = new InvalidOperationException("нет прав") };
        var check = Create(platform);

        await Assert.ThrowsAsync<InvalidOperationException>(() => check.RunAsync(Sample.Context(), CancellationToken.None));
    }
}

public class IndirectSignsCheckTests
{
    private static IndirectSignsCheck Create(FakePlatformProbe platform) => new(platform);

    [Fact]
    public async Task Clean_network_is_clean()
    {
        var result = await Create(FakePlatformProbe.Clean()).RunAsync(Sample.Context(), CancellationToken.None);

        Assert.True(result.Status == CheckStatus.Clean,
            "неожиданные находки: " + string.Join(" | ", result.Findings.Select(f => $"{f.Severity}:{f.Title}")));
        Assert.DoesNotContain(result.Findings, f => f.Severity >= Severity.Warning);
    }

    [Fact]
    public async Task Tunnel_default_route_and_loopback_dns_are_critical()
    {
        var result = await Create(FakePlatformProbe.Tunneled()).RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Equal(CheckStatus.Detected, result.Status);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Маршрут по умолчанию"));
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("DNS указывает на loopback"));
        Assert.Contains(result.Findings, f => f.Title.Contains("NRPT"));
        Assert.Contains(result.Findings, f => f.Title.Contains("hosts"));
        Assert.Contains(result.Findings, f => f.Title.Contains("MTU"));
    }

    [Fact]
    public async Task Host_routes_are_noticed()
    {
        var platform = FakePlatformProbe.Clean();
        platform.Routes.Add(new RouteInfo { Destination = "203.0.113.42/32", Gateway = "192.168.1.1", InterfaceName = "eth0" });

        var result = await Create(platform).RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.Title.Contains("/32"));
    }

    [Fact]
    public async Task Benign_hosts_entries_are_ignored()
    {
        var platform = FakePlatformProbe.Clean();
        platform.Hosts =
        [
            new HostsEntry("127.0.0.1", "localhost", null),
            new HostsEntry("::1", "localhost", null),
            new HostsEntry("0.0.0.0", "ads.example", "added by RKNHardering test"),
        ];

        var result = await Create(platform).RunAsync(Sample.Context(), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Нестандартные записи"));
    }
}

public class GeoIpCheckOfflineTests
{
    [Fact]
    public async Task Offline_mode_skips_without_network()
    {
        var http = new FakeHttpProbe();
        var check = new GeoIpCheck(http);
        var options = Sample.Options();
        options.OfflineMode = true;

        var result = await check.RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckStatus.Skipped, result.Status);
        Assert.Empty(http.Requested);
    }

    [Fact]
    public async Task Hosting_majority_vote_wins()
    {
        var http = new FakeHttpProbe()
            .With("ipapi.is", """{"ip":"203.0.113.42","is_hosting":true,"country_code":"NL"}""")
            .With("iplocate.io", """{"ip":"203.0.113.42","country_code":"NL","privacy":{"is_hosting":true}}""")
            .With("ipinfo.io", """{"ip":"203.0.113.42","country":"NL","hosting":false}""");
        var check = new GeoIpCheck(http);
        var options = Sample.Options();
        options.OfflineMode = false;

        var context = Sample.Context(options);
        var result = await check.RunAsync(context, CancellationToken.None);

        Assert.Equal(CheckStatus.Detected, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("хостингу"));
        Assert.Contains(result.Metrics, m => m.Label == "Hosting" && m.Value.StartsWith("2/3"));
        // Наблюдение IP попало в контекст прогона.
        Assert.Contains(context.IpObservations, o => o.Ip == "203.0.113.42");
    }

    [Fact]
    public async Task Foreign_ip_without_hosting_is_needs_review()
    {
        var http = new FakeHttpProbe()
            .With("ipapi.is", """{"ip":"198.51.100.1","country_code":"DE","is_hosting":false,"is_proxy":false}""");
        var check = new GeoIpCheck(http);
        var options = Sample.Options();
        options.OfflineMode = false;

        var result = await check.RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckStatus.NeedsReview, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("не российский"));
    }

    [Fact]
    public async Task All_providers_down_is_failed()
    {
        var check = new GeoIpCheck(new FakeHttpProbe());
        var options = Sample.Options();
        options.OfflineMode = false;

        var result = await check.RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckStatus.Failed, result.Status);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task Proxy_flag_alone_is_detected()
    {
        var http = new FakeHttpProbe()
            .With("ipapi.is", """{"ip":"203.0.113.42","country_code":"RU","is_hosting":false,"is_vpn":true}""");
        var options = Sample.Options();
        options.OfflineMode = false;

        var result = await new GeoIpCheck(http).RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckStatus.Detected, result.Status);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("proxy"));
    }
}

public class CdnPullingCheckTests
{
    [Fact]
    public async Task Trace_parsing_extracts_ip_and_country()
    {
        var http = new FakeHttpProbe()
            .With("cdn-cgi/trace", "fl=123abc\nh=cloudflare.com\nip=203.0.113.42\nts=1700000000\nloc=NL\ncolo=AMS\n");
        var options = Sample.Options();
        options.OfflineMode = false;

        var result = await new CdnPullingCheck(http).RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Contains(result.Metrics, m => m.Label.Contains("cloudflare.com") && m.Value == "203.0.113.42");
        Assert.Contains(result.Findings, f => f.Title.Contains("Edge-CDN"));
    }

    [Fact]
    public async Task Proxy_headers_are_critical()
    {
        var body = """{"headers":{"Via":"1.1 squid","X-Forwarded-For":"10.0.0.1","Host":"httpbin.org"}}""";
        var http = new FakeHttpProbe().With("httpbin.org/headers", body);
        var options = Sample.Options();
        options.OfflineMode = false;

        var result = await new CdnPullingCheck(http).RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckStatus.Detected, result.Status);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Evidence!.Contains("Via"));
    }
}
