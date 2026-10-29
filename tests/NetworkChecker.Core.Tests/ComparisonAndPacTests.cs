using NetworkChecker.Core.Comparison;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Platform;
using NetworkChecker.Core.Verdict;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class RunComparerTests
{
    private static CheckRunResult Run(params (CheckCategory Category, string Title, CheckStatus Status, string[] Findings)[] checks)
    {
        var results = checks.Select(c => new CheckResult
        {
            Category = c.Category,
            Title = c.Title,
            Subtitle = "тест",
            Status = c.Status,
            Weight = 10,
            Findings = [.. c.Findings.Select(f => Finding.Info(f))],
        }).ToList();
        var consensus = IpConsensusBuilder.Build([]);
        return new CheckRunResult
        {
            StartedAt = DateTimeOffset.Now,
            FinishedAt = DateTimeOffset.Now,
            Checks = results,
            Verdict = VerdictEngine.Build(results, consensus),
            IpConsensus = consensus,
            Environment = new EnvironmentSnapshot { OsDescription = "тест" },
        };
    }

    [Fact]
    public void Identical_runs_have_no_changes()
    {
        var before = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []));
        var after = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []));

        var comparison = RunComparer.Compare(before, after);

        Assert.Equal(ChangeDirection.Same, comparison.Direction);
        Assert.Empty(comparison.MeaningfulChanges);
        Assert.Contains("не изменилось", comparison.Summary);
    }

    [Fact]
    public void Worse_status_is_reported_as_worse()
    {
        var before = Run((CheckCategory.DirectSigns, "Прямые признаки", CheckStatus.Clean, []));
        var after = Run((CheckCategory.DirectSigns, "Прямые признаки", CheckStatus.Detected, ["Системный прокси включён"]));

        var comparison = RunComparer.Compare(before, after);

        Assert.Equal(ChangeDirection.Worse, comparison.Direction);
        var change = Assert.Single(comparison.MeaningfulChanges);
        Assert.Equal(CheckStatus.Clean, change.Before);
        Assert.Equal(CheckStatus.Detected, change.After);
        Assert.Contains("Системный прокси включён", change.Appeared);
        Assert.Contains("Стало хуже", comparison.Summary);
    }

    [Fact]
    public void Better_status_is_reported_as_better()
    {
        var before = Run((CheckCategory.Bypass, "Локальный обход", CheckStatus.Detected, ["Прокси на 127.0.0.1:1080"]));
        var after = Run((CheckCategory.Bypass, "Локальный обход", CheckStatus.Clean, []));

        var comparison = RunComparer.Compare(before, after);

        Assert.Equal(ChangeDirection.Better, comparison.Direction);
        var change = Assert.Single(comparison.MeaningfulChanges);
        Assert.Contains("Прокси на 127.0.0.1:1080", change.Disappeared);
    }

    [Fact]
    public void Score_delta_is_computed_in_the_right_direction()
    {
        var before = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []));
        var after = Run(
            (CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []),
            (CheckCategory.DirectSigns, "Прямые признаки", CheckStatus.Detected, ["Прокси"]));

        var comparison = RunComparer.Compare(before, after);

        Assert.True(comparison.ScoreDelta > 0);
        Assert.Equal(comparison.ScoreAfter - comparison.ScoreBefore, comparison.ScoreDelta);
    }

    [Fact]
    public void Mixed_changes_mention_both_sides()
    {
        var before = Run(
            (CheckCategory.GeoIp, "GeoIP", CheckStatus.Detected, ["Хостинг"]),
            (CheckCategory.Bypass, "Обад", CheckStatus.Clean, []));
        var after = Run(
            (CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []),
            (CheckCategory.Bypass, "Обад", CheckStatus.Detected, ["Найден SOCKS5"]));

        var comparison = RunComparer.Compare(before, after);

        Assert.Equal(2, comparison.MeaningfulChanges.Count);
        Assert.Equal(1, comparison.Changes.Count(c => c.Direction == ChangeDirection.Worse));
        Assert.Equal(1, comparison.Changes.Count(c => c.Direction == ChangeDirection.Better));
        Assert.Contains("Смешанные изменения", comparison.Summary);
    }

    [Fact]
    public void Module_missing_in_one_run_is_marked_unknown_not_crash()
    {
        var before = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []));
        var after = Run(
            (CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []),
            (CheckCategory.CdnPulling, "CDN", CheckStatus.Clean, []));

        var comparison = RunComparer.Compare(before, after);

        var added = Assert.Single(comparison.Changes, c => c.Title == "CDN");
        Assert.Equal(ChangeDirection.Unknown, added.Direction);
    }

    [Fact]
    public void Findings_are_compared_by_title()
    {
        var before = Run((CheckCategory.IndirectSigns, "Косвенные", CheckStatus.NeedsReview, ["Хостовые маршруты"]));
        var after = Run((CheckCategory.IndirectSigns, "Косвенные", CheckStatus.NeedsReview, ["Хостовые маршруты", "DNS на loopback"]));

        var comparison = RunComparer.Compare(before, after);
        var change = comparison.Changes.Single(c => c.Title == "Косвенные");

        Assert.Equal(CheckStatus.NeedsReview, change.After);
        Assert.Equal(["DNS на loopback"], change.Appeared);
        Assert.Empty(change.Disappeared);
        Assert.Equal(ChangeDirection.Worse, change.Direction);
    }

    [Fact]
    public void Skipped_module_is_unknown_not_better()
    {
        var before = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Detected, ["Хостинг"]));
        var after = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Skipped, ["Офлайн-режим"]));

        var comparison = RunComparer.Compare(before, after);

        var change = comparison.Changes.Single(c => c.Title == "GeoIP");
        Assert.Equal(ChangeDirection.Unknown, change.Direction);
        Assert.Equal(0, comparison.Changes.Count(c => c.Direction == ChangeDirection.Better));
        Assert.Equal(ChangeDirection.Unknown, comparison.Direction);
        Assert.Contains("Сравнивать нечего", comparison.Summary);
    }

    [Fact]
    public void Ordering_puts_worse_changes_first()
    {
        var before = Run(
            (CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []),
            (CheckCategory.Bypass, "Обход", CheckStatus.Detected, ["x"]));
        var after = Run(
            (CheckCategory.GeoIp, "GeoIP", CheckStatus.Detected, ["y"]),
            (CheckCategory.Bypass, "Обход", CheckStatus.Clean, []));

        var comparison = RunComparer.Compare(before, after);

        Assert.Equal("GeoIP", comparison.Changes[0].Title);
    }

    [Fact]
    public void Null_arguments_are_rejected()
    {
        var run = Run((CheckCategory.GeoIp, "GeoIP", CheckStatus.Clean, []));
        Assert.Throws<ArgumentNullException>(() => RunComparer.Compare(null!, run));
        Assert.Throws<ArgumentNullException>(() => RunComparer.Compare(run, null!));
    }
}

public class PacInspectorTests
{
    [Fact]
    public void Empty_script_gives_empty_analysis()
    {
        var analysis = PacInspector.Parse(null);

        Assert.False(analysis.LooksLikePac);
        Assert.Empty(analysis.Proxies);
        Assert.False(analysis.RoutesThroughProxy);
    }

    [Fact]
    public void Local_proxy_directive_is_found_and_flagged_as_loopback()
    {
        const string script = """
            function FindProxyForURL(url, host) {
              return "PROXY 127.0.0.1:1080; DIRECT";
            }
            """;

        var analysis = PacInspector.Parse(script);

        Assert.True(analysis.LooksLikePac);
        Assert.True(analysis.HasLoopbackProxy);
        Assert.True(analysis.AllowsDirect);
        var proxy = Assert.Single(analysis.Proxies);
        Assert.Equal("PROXY", proxy.Kind);
        Assert.Equal(1080, proxy.Port);
        Assert.Contains(analysis.Indicators, i => i.Contains("локальный порт", StringComparison.Ordinal));
    }

    [Fact]
    public void Remote_proxy_with_subnet_rules_is_recognised()
    {
        const string script = """
            function FindProxyForURL(url, host) {
              if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";
              return "SOCKS5 proxy.corp.example:1080";
            }
            """;

        var analysis = PacInspector.Parse(script);

        Assert.True(analysis.RoutesThroughProxy);
        Assert.False(analysis.HasLoopbackProxy);
        Assert.Equal("SOCKS5", analysis.Proxies[0].Kind);
        Assert.Equal("proxy.corp.example", analysis.Proxies[0].Host);
        Assert.Contains(analysis.Indicators, i => i.Contains("подсетям", StringComparison.Ordinal));
    }

    [Fact]
    public void Multiple_directives_are_deduplicated()
    {
        const string script = """
            var p = "PROXY 10.1.1.1:3128";
            function FindProxyForURL(u, h) { return "PROXY 10.1.1.1:3128; PROXY 10.1.1.2:3128"; }
            """;

        var analysis = PacInspector.Parse(script);

        Assert.Equal(2, analysis.Proxies.Count);
    }

    [Fact]
    public void Port_out_of_range_is_ignored()
    {
        var analysis = PacInspector.Parse("""function FindProxyForURL(u,h){return "PROXY 1.2.3.4:99999";}""");

        Assert.Empty(analysis.Proxies);
        Assert.Contains(analysis.Indicators, i => i.Contains("не задаёт прокси", StringComparison.Ordinal));
    }

    [Fact]
    public void Html_or_plain_text_is_not_a_pac()
    {
        var analysis = PacInspector.Parse("<html><body>404 Not Found</body></html>");

        Assert.False(analysis.LooksLikePac);
        Assert.Contains("не похож на PAC", analysis.Indicators[0]);
    }

    [Fact]
    public void Ipv6_loopback_endpoint_counts_as_local()
    {
        var analysis = PacInspector.Parse("""function FindProxyForURL(u,h){return "PROXY [::1]:2080";}""");

        Assert.True(analysis.HasLoopbackProxy);
    }

    [Fact]
    public void Direct_only_script_is_reported()
    {
        var analysis = PacInspector.Parse("""function FindProxyForURL(u,h){return "DIRECT";}""");

        Assert.True(analysis.LooksLikePac);
        Assert.False(analysis.RoutesThroughProxy);
        Assert.True(analysis.AllowsDirect);
    }
}

public class ProxySettingsTests
{
    [Fact]
    public void Empty_settings_are_not_a_proxy()
    {
        var settings = new ProxySettings();

        Assert.False(settings.HasProxy);
        Assert.False(settings.HasMachineWideProxy);
        Assert.False(settings.PacPointsToLocalhost);
        Assert.Equal("не настроен", settings.Display);
    }

    [Fact]
    public void Machine_wide_proxy_is_visible_even_without_user_proxy()
    {
        var settings = new ProxySettings { WinHttpProxy = "proxy.local:8080" };

        Assert.True(settings.HasProxy);
        Assert.True(settings.HasMachineWideProxy);
        Assert.Contains("WinHTTP", settings.Display);
    }

    [Fact]
    public void Pac_on_localhost_is_detected()
    {
        Assert.True(new ProxySettings { PacUrl = "http://127.0.0.1:8080/proxy.pac" }.PacPointsToLocalhost);
        Assert.True(new ProxySettings { PacUrl = "http://localhost/proxy.pac" }.PacPointsToLocalhost);
        Assert.False(new ProxySettings { PacUrl = "http://wpad.corp/proxy.pac" }.PacPointsToLocalhost);
    }

    [Fact]
    public void Display_lists_all_configured_layers()
    {
        var settings = new ProxySettings
        {
            HttpProxy = "http://10.0.0.1:3128",
            SocksProxy = "10.0.0.2:1080",
            WinHttpProxy = "10.0.0.3:8080",
            PacUrl = "http://wpad/proxy.pac",
        };

        var display = settings.Display;

        Assert.Contains("10.0.0.1:3128", display);
        Assert.Contains("SOCKS", display);
        Assert.Contains("WinHTTP", display);
        Assert.Contains("PAC", display);
    }
}
