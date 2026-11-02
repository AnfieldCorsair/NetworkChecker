using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Export;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Reputation;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>Парсеры блока репутации: форматы ответов проверяются без сети.</summary>
public class ReputationParserTests
{
    [Fact]
    public void Dnsbl_query_reverses_ipv4_and_supports_dqs_key()
    {
        Assert.Equal("7.113.0.203.zen.spamhaus.org",
            ReputationParsers.DnsQuery("203.0.113.7", "zen.spamhaus.org"));
        Assert.Equal("7.113.0.203.mykey.zen.dq.spamhaus.net",
            ReputationParsers.DnsQuery("203.0.113.7", "zen.spamhaus.org", "mykey"));
        Assert.Null(ReputationParsers.DnsQuery("2001:db8::1", "zen.spamhaus.org"));
        Assert.Null(ReputationParsers.DnsQuery(null, "zen.spamhaus.org"));
    }

    [Fact]
    public void Nxdomain_is_clean_but_not_a_proof_of_clean_ip()
    {
        var verdict = ReputationParsers.ClassifyDnsbl(false, []);

        Assert.Equal(DnsblKind.Clean, verdict.Kind);
        Assert.Contains("не доказательство", verdict.Detail);
    }

    [Theory]
    [InlineData("127.0.0.2", DnsblKind.Spam)]
    [InlineData("127.0.0.3", DnsblKind.Spam)]
    [InlineData("127.0.0.4", DnsblKind.Exploit)]
    [InlineData("127.0.0.9", DnsblKind.Drop)]
    [InlineData("127.0.0.10", DnsblKind.Policy)]
    [InlineData("127.0.0.11", DnsblKind.Policy)]
    public void Dnsbl_codes_are_decoded(string code, DnsblKind expected)
    {
        Assert.Equal(expected, ReputationParsers.ClassifyDnsbl(true, [code]).Kind);
    }

    [Fact]
    public void Public_resolver_refusal_is_no_data_not_a_listing()
    {
        var verdict = ReputationParsers.ClassifyDnsbl(true, ["127.255.255.254"]);

        Assert.Equal(DnsblKind.Unavailable, verdict.Kind);
        Assert.Contains("публичные резолверы", verdict.Detail);
    }

    [Fact]
    public void Abuseipdb_score_and_reports_are_read()
    {
        const string json = """
            {"data":{"ipAddress":"203.0.113.7","abuseConfidenceScore":87,"totalReports":42,
                     "lastReportedAt":"2026-10-01T12:00:00+00:00","isp":"Example Hosting"}}
            """;

        var reading = ReputationParsers.AbuseIpDb(json);

        Assert.Equal("abuse 87/100", reading.Status);
        Assert.Equal(87, reading.Score);
        Assert.Equal(ReputationTone.Bad, reading.Tone);
        Assert.Contains("Example Hosting", reading.Detail);
        Assert.Equal(ReputationTone.Unknown, ReputationParsers.AbuseIpDb("{}").Tone);
    }

    [Fact]
    public void Fraud_scores_are_read_from_three_vendors()
    {
        var ipqs = ReputationParsers.IpQualityScore(
            "{\"success\":true,\"fraud_score\":92,\"vpn\":true,\"recent_abuse\":true,\"connection_type\":\"Data Center\"}");
        Assert.Equal(92, ipqs.Score);
        Assert.Equal(ReputationTone.Bad, ipqs.Tone);

        var proxy = ReputationParsers.ProxyCheck(
            "{\"status\":\"ok\",\"203.0.113.7\":{\"proxy\":\"yes\",\"type\":\"VPN\",\"risk\":73}}", "203.0.113.7");
        Assert.Equal(73, proxy.Score);
        Assert.Contains("VPN", proxy.Detail);

        var scam = ReputationParsers.Scamalytics(
            "{\"scamalytics\":{\"status\":\"ok\",\"scamalytics_score\":71,\"scamalytics_risk\":\"high\",\"is_blacklisted_external\":true}}");
        Assert.Equal(71, scam.Score);
        Assert.Contains("внешние чёрные списки: да", scam.Detail);
    }

    [Fact]
    public void Ipapi_is_without_key_has_no_reputation_flags()
    {
        var minimal = ReputationParsers.IpApiIs("{\"ip\":\"203.0.113.7\",\"company\":\"Example\"}");
        Assert.Equal(ReputationTone.Unknown, minimal.Tone);
        Assert.Contains("Без ключа", minimal.Detail);

        var full = ReputationParsers.IpApiIs("{\"ip\":\"203.0.113.7\",\"is_abuser\":true,\"is_vpn\":false}");
        Assert.Contains("абьюз", full.Status);
        Assert.Equal(ReputationTone.Warn, full.Tone);
    }

    [Fact]
    public void Gl_is_read_from_ytcfg_and_innertube()
    {
        Assert.Equal("RU", ReputationParsers.GoogleRegion("ytcfg.set({\"GL\":\"RU\",\"HL\":\"en\"});"));
        Assert.Equal("US", ReputationParsers.GoogleRegion("\"INNERTUBE_CONTEXT_GL\":\"US\""));
        Assert.Equal("DE", ReputationParsers.GoogleRegion("\"INNERTUBE_CONTEXT\":{\"client\":{\"gl\":\"DE\"}}"));
        Assert.Null(ReputationParsers.GoogleRegion("<html>no config here</html>"));
    }

    [Fact]
    public void Ai_studio_redirect_is_distinguished_from_signin_and_failure()
    {
        Assert.True(ReputationParsers.AiStudioRegionPage(
            "https://ai.google.dev/gemini-api/docs/available-regions", null));
        Assert.True(ReputationParsers.AiStudioRegionPage(null, "Google AI Studio is not available in your region."));
        Assert.Null(ReputationParsers.AiStudioRegionPage("https://accounts.google.com/ServiceLogin", null));
        Assert.False(ReputationParsers.AiStudioRegionPage("https://aistudio.google.com/", "<html>app</html>"));
    }
}

/// <summary>Сервис и модуль проверки целиком на заглушках.</summary>
public class ReputationServiceTests
{
    private static FakeHttpProbe Identity() =>
        new FakeHttpProbe().With("api.ipapi.is", "{\"ip\":\"203.0.113.7\",\"country\":\"DE\"}");

    private static FakeExternalProbe RuLabelProbe()
    {
        var probe = new FakeExternalProbe()
            .With("m.youtube.com", "ytcfg.set({\"GL\":\"RU\",\"INNERTUBE_CONTEXT_GL\":\"RU\"});")
            .WithRedirect("aistudio.google.com",
                "https://ai.google.dev/gemini-api/docs/available-regions?hl=en",
                "If you reached this page while trying to open Google AI Studio, your region may not be supported.")
            .With("proxycheck.io", "{\"status\":\"ok\",\"203.0.113.7\":{\"proxy\":\"no\",\"type\":\"Business\",\"risk\":0}}");
        probe.WithDns("spamcop", true, "127.0.0.2");
        probe.WithDns("sorbs", true, "127.0.0.10");
        return probe;
    }

    private static RknOptions Online()
    {
        var options = new RknOptions { OfflineMode = false };
        return options;
    }

    [Fact]
    public async Task Ru_label_on_foreign_ip_and_ai_studio_redirect_are_detected()
    {
        var external = RuLabelProbe();
        var service = new ReputationService(Identity(), external);

        var report = await service.InspectAsync(Online(), force: true, CancellationToken.None);

        Assert.Equal("203.0.113.7", report.Ip);
        Assert.Equal("RU", report.Google.Region);
        Assert.Equal("DE", report.Google.GeoCountry);
        Assert.True(report.Google.RuMarked);
        Assert.True(report.Google.RegionDiffersFromGeo);
        Assert.True(report.Google.AiStudioRedirect);
        Assert.Contains("Метка RU", report.Headline);
        Assert.Equal(ReputationReportState.Ok, report.State);
        Assert.Contains(report.Sources, s => s.Name == "YouTube / регион GL" && s.Tone == ReputationTone.Bad);
        Assert.Contains(report.Sources, s => s.Name.Contains("bl.spamcop") && s.Status.Contains("спам"));
        Assert.Contains(report.Sources, s => s.Name.Contains("sorbs") && s.Status == "PBL (не спам)");
        Assert.Contains(report.Caveats, c => c.Contains("Postmaster Tools v2"));
        Assert.True(report.Risk > 0);
    }

    [Fact]
    public async Task Offline_mode_makes_no_external_requests()
    {
        var external = new FakeExternalProbe();
        var http = Identity();
        var service = new ReputationService(http, external);
        var options = new RknOptions { OfflineMode = true };

        var report = await service.InspectAsync(options, force: true, CancellationToken.None);

        Assert.Equal(ReputationReportState.Offline, report.State);
        Assert.False(report.RiskAvailable);
        Assert.Empty(external.Requested);
        Assert.Empty(external.DnsRequested);
        Assert.Empty(http.Requested);
    }

    [Fact]
    public async Task Api_keys_never_appear_in_the_report()
    {
        var external = RuLabelProbe();
        external.With("api.abuseipdb.com",
            "{\"data\":{\"abuseConfidenceScore\":0,\"totalReports\":0,\"isp\":\"Example\"}}");
        var service = new ReputationService(Identity(), external);
        var options = Online();
        options.AbuseIpDbKey = "super-secret-key-42";

        var report = await service.InspectAsync(options, force: true, CancellationToken.None);
        var json = ResultExport.ToJson(RunWith(report));

        Assert.DoesNotContain("super-secret-key-42", json);
        Assert.DoesNotContain("super-secret-key-42", ResultExport.ToMarkdown(RunWith(report)));
        Assert.Contains(report.Sources, s => s.Name == "AbuseIPDB");
    }

    [Fact]
    public async Task Reputation_check_has_zero_weight_and_carries_the_report()
    {
        var service = new ReputationService(Identity(), RuLabelProbe());
        var check = new ReputationCheck(service);

        var result = await check.RunAsync(Sample.Context(Online()), CancellationToken.None);

        Assert.Equal(CheckCategory.Reputation, result.Category);
        Assert.Equal(0, result.Weight);
        Assert.NotNull(result.Reputation);
        Assert.Contains(result.Metrics, m => m.Label == "Регион GL (YouTube)" && m.Value == "RU");
    }

    [Fact]
    public async Task Cache_avoids_duplicate_quota_usage_within_one_run()
    {
        var external = RuLabelProbe();
        var service = new ReputationService(Identity(), external);
        var options = Online();

        await service.InspectAsync(options, force: false, CancellationToken.None);
        var first = external.Requested.Count;
        await service.InspectAsync(options, force: false, CancellationToken.None);

        Assert.Equal(first, external.Requested.Count);
        service.Invalidate();
        await service.InspectAsync(options, force: false, CancellationToken.None);
        Assert.True(external.Requested.Count > first);
    }

    [Fact]
    public void Clone_copies_dnsbl_zones()
    {
        var options = new RknOptions();
        var clone = options.Clone();

        clone.DnsblZones.Add("extra.test");

        Assert.DoesNotContain("extra.test", options.DnsblZones);
    }

    [Fact]
    public void Private_projection_drops_the_whole_reputation_report()
    {
        var safe = PrivateRunProjection.Create(RunWith(ReputationReport.Disabled("тест", offline: false)));

        Assert.Null(Assert.Single(safe.Checks).Reputation);
        Assert.Null(safe.IpConsensus.ConsensusIp);
    }

    [Fact]
    public void Markdown_export_contains_the_reputation_section()
    {
        var report = ReputationReport.Disabled("тест", offline: false);

        var markdown = ResultExport.ToMarkdown(RunWith(report));

        Assert.Contains("## Репутация IP", markdown);
        Assert.Contains("### Оговорки", markdown);
        Assert.Contains("Условный индекс риска", markdown);
    }

    private static CheckRunResult RunWith(ReputationReport report)
    {
        var now = DateTimeOffset.UtcNow;
        var check = new CheckResult
        {
            Category = CheckCategory.Reputation,
            Title = "Репутация IP и метка Google",
            Status = CheckStatus.Clean,
            Weight = 0,
            Reputation = report,
        };
        return new CheckRunResult
        {
            StartedAt = now,
            FinishedAt = now.AddSeconds(2),
            Checks = [check],
            Verdict = new VerdictResult
            {
                Level = RiskLevel.Clean,
                Score = 0,
                Headline = "Тест",
                Summary = "Тест",
            },
            Environment = new EnvironmentSnapshot { OsDescription = "test" },
        };
    }
}

/// <summary>Заглушка внешнего зонда должна уметь отвечать и на HTTP, и на DNSBL.</summary>
public class FakeExternalProbeContractTests
{
    [Fact]
    public async Task Returns_configured_body_and_dns_answers()
    {
        var probe = new FakeExternalProbe()
            .With("example.test", "ok")
            .WithDns("zen.spamhaus.org", true, "127.0.0.2");

        var http = await probe.GetAsync(new ExternalProbeRequest(new Uri("https://example.test/x"), TimeSpan.FromSeconds(1)));
        var dns = await probe.ResolveAAsync("7.113.0.203.zen.spamhaus.org");

        Assert.True(http.Success);
        Assert.Equal("ok", http.Body);
        Assert.True(dns.Found);
        Assert.Equal("127.0.0.2", Assert.Single(dns.Addresses));
    }
}
