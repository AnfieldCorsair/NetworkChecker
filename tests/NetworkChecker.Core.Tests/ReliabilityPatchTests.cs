using System.Net;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Verdict;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class ReliabilityPatchTests
{
    [Fact]
    public void Dual_stack_is_not_a_split_and_ipv6_is_normalized()
    {
        var result = IpConsensusBuilder.Build([
            new("one", "198.51.100.1", null, Channel: IpChannel.Web),
            new("two", "2001:0DB8:0:0:0:0:0:1", null, Channel: IpChannel.Web),
            new("three", "2001:db8::1", null, Channel: IpChannel.Udp)]);
        Assert.False(result.IsSplit);
        Assert.False(result.CrossChannelMismatch);
        Assert.Equal("2001:db8::1", result.Observations[1].Ip);
    }

    [Fact]
    public void Channel_comparison_distinguishes_within_and_between()
    {
        var result = IpConsensusBuilder.Build([
            new("one", "198.51.100.1", null, Channel: IpChannel.Web),
            new("two", "198.51.100.2", null, Channel: IpChannel.Web),
            new("three", "198.51.100.3", null, Channel: IpChannel.Udp)]);
        Assert.True(result.IsSplit);
        Assert.True(result.WithinChannelConflict);
        Assert.True(result.CrossChannelMismatch);
    }

    [Fact]
    public void Invalid_addresses_are_ignored_and_mapped_ipv4_normalized()
    {
        var result = IpConsensusBuilder.Build([new("bad", "not-ip", null), new("blank", " ", null),
            new("v4", "192.0.2.1", null), new("mapped", "::ffff:192.0.2.1", null)]);
        Assert.False(result.IsSplit);
        Assert.Equal(2, result.Observations.Count);
        Assert.Equal("192.0.2.1", result.ConsensusIp);
        Assert.False(IpConsensusBuilder.Build([new("bad", " ", null)]).HasConsensus);
    }

    [Fact]
    public void Ties_are_deterministic_regardless_of_arrival_order()
    {
        var first = new IpObservation("a", "192.0.2.1", null);
        var second = new IpObservation("b", "192.0.2.2", null);
        Assert.Equal(IpConsensusBuilder.Build([first, second]).ConsensusIp,
            IpConsensusBuilder.Build([second, first]).ConsensusIp);
    }

    [Fact]
    public async Task Dual_stack_ip_comparison_is_not_detected()
    {
        var options = Sample.Options(); options.OfflineMode = false; options.StunServers = [];
        var probe = new FakeHttpProbe().With("api.ipify.org", "{\"ip\":\"198.51.100.1\"}")
            .With("api.myip.com", "{\"ip\":\"2001:db8::1\"}");
        var result = await new IpComparisonCheck(probe).RunAsync(Sample.Context(options), CancellationToken.None);
        Assert.Equal(CheckStatus.Skipped, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("сопоставимых"));
    }

    [Fact]
    public async Task Offline_mode_skips_every_network_only_module_before_any_http()
    {
        var options = Sample.Options(); options.OfflineMode = true;
        var probe = new FakeHttpProbe();
        ICheck[] checks = [new GeoIpCheck(probe), new IpComparisonCheck(probe), new CdnPullingCheck(probe),
            new CallTransportCheck(probe), new DomainReachabilityCheck(), new RttTriangulationCheck(), new IcmpSpoofingCheck()];
        foreach (var check in checks)
        {
            var result = await check.RunAsync(Sample.Context(options), CancellationToken.None);
            Assert.Equal(CheckStatus.Skipped, result.Status);
        }
        Assert.Empty(probe.Requested);
    }

    [Fact]
    public async Task Only_typed_configuration_facts_can_produce_detected()
    {
        var direct = await new DirectSignsCheck(FakePlatformProbe.Tunneled(), new VpnClientCatalog())
            .RunAsync(Sample.Context(), CancellationToken.None);
        Assert.Contains(direct.Findings, f => f.Kind == EvidenceKind.ConfiguredProxy);
        Assert.Contains(direct.Findings, f => f.Kind == EvidenceKind.ConnectedWindowsVpn);
        var verdict = VerdictEngine.Build([direct], new IpConsensus());
        Assert.Equal(RiskLevel.Detected, verdict.Level);
        Assert.Contains("браузер", verdict.Summary);
        Assert.Contains("не вероятность", verdict.Summary);
    }

    [Fact]
    public void Failed_module_cannot_supply_a_strong_fact()
    {
        var failed = new CheckResult
        {
            Category = CheckCategory.DirectSigns,
            Title = "test",
            Weight = 30,
            Status = CheckStatus.Failed,
            Findings = [Finding.Critical("proxy") with { Kind = EvidenceKind.ConfiguredProxy }]
        };
        var verdict = VerdictEngine.Build([failed], new IpConsensus());
        Assert.NotEqual(RiskLevel.Detected, verdict.Level);
        Assert.Equal(0, verdict.Score);
    }

    [Fact]
    public void Skipped_checks_are_not_treated_as_zero_signal_in_index()
    {
        var check = new CheckResult { Category = CheckCategory.Bypass, Title = "x", Weight = 30, Status = CheckStatus.NeedsReview };
        var skipped = new CheckResult { Category = CheckCategory.GeoIp, Title = "y", Weight = 20, Status = CheckStatus.Skipped };
        Assert.Equal(VerdictEngine.Build([check], new IpConsensus()).Score,
            VerdictEngine.Build([check, skipped], new IpConsensus()).Score);
    }

    [Fact]
    public void Stun_parser_validates_transaction_type_and_attribute_bounds()
    {
        byte[] request = [0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] response = [1, 1, 0, 12, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            0, 0x20, 0, 8, 0, 1, 0x3b, 0xe3, 0xe1, 0x12, 0xa6, 0x43];
        var ep = StunClient.ParseXorMapped(response, request);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), ep?.Address);
        Assert.Equal(6897, ep?.Port);
        var wrongId = (byte[])response.Clone(); wrongId[8] ^= 1;
        Assert.Null(StunClient.ParseXorMapped(wrongId, request));
        var wrongType = (byte[])response.Clone(); wrongType[1] = 0x11;
        Assert.Null(StunClient.ParseXorMapped(wrongType, request));
        var truncated = response[..^1];
        Assert.Null(StunClient.ParseXorMapped(truncated, request));
        var badAttribute = (byte[])response.Clone(); badAttribute[23] = 4;
        Assert.Null(StunClient.ParseXorMapped(badAttribute, request));
    }
    [Theory]
    [InlineData(200)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(405)]
    public async Task Arbitrary_http_status_on_10085_is_not_xray_evidence(int code)
    {
        var options = Sample.Options(); options.LocalProxyPorts = [];
        var result = await new BypassCheck(new PortStatusProbe(code))
            .RunAsync(Sample.Context(options), CancellationToken.None);
        Assert.Equal(CheckStatus.Clean, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("10085") && f.Detail.Contains("не подтверждает"));
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Any_true_vpn_flag_is_not_hidden_by_false_proxy_flag()
    {
        var parsed = GeoIpParser.Parse("{\"ip\":\"192.0.2.1\",\"is_proxy\":false,\"is_vpn\":true,\"is_abuser\":true}");
        Assert.True(parsed?.Proxy);
        var abuseOnly = GeoIpParser.Parse("{\"ip\":\"192.0.2.1\",\"is_abuser\":true}");
        Assert.Null(abuseOnly?.Proxy);
    }

    [Fact]
    public async Task Geoip_does_not_combine_reputation_from_different_addresses()
    {
        var options = Sample.Options(); options.OfflineMode = false;
        options.GeoIpProviders = ["https://one.example", "https://two.example"];
        var probe = new FakeHttpProbe()
            .With("one.example", "{\"ip\":\"192.0.2.1\",\"country\":\"RU\",\"is_proxy\":false}")
            .With("two.example", "{\"ip\":\"192.0.2.2\",\"country\":\"NL\",\"is_proxy\":true}");
        var result = await new GeoIpCheck(probe).RunAsync(Sample.Context(options), CancellationToken.None);
        Assert.Equal(CheckStatus.NeedsReview, result.Status);
        Assert.DoesNotContain(result.Findings, f => f.Title == "IP помечен как proxy/VPN/Tor");
        Assert.Contains(result.Findings, f => f.Title.Contains("разные IP"));
    }

    [Fact]
    public async Task Missing_reputation_is_not_reported_clean()
    {
        var options = Sample.Options(); options.OfflineMode = false;
        options.GeoIpProviders = ["https://one.example"];
        var probe = new FakeHttpProbe().With("one.example", "{\"ip\":\"192.0.2.1\",\"country\":\"RU\"}");
        var result = await new GeoIpCheck(probe).RunAsync(Sample.Context(options), CancellationToken.None);
        Assert.Equal(CheckStatus.NeedsReview, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("неполные"));
    }

    [Fact]
    public async Task Unavailable_edge_services_are_not_clean()
    {
        var options = Sample.Options(); options.OfflineMode = false;
        var result = await new CdnPullingCheck(new FakeHttpProbe()).RunAsync(Sample.Context(options), CancellationToken.None);
        Assert.Equal(CheckStatus.Failed, result.Status);
    }

    [Fact]
    public async Task Tls_self_signed_certificate_is_not_reported_as_trusted()
    {
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=localhost", key,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var ssl = new System.Net.Security.SslStream(client.GetStream());
            await ssl.AuthenticateAsServerAsync(cert);
        });
        try
        {
            var probe = await ConnectivityProbes.TlsHandshakeAsync("localhost", port, TimeSpan.FromSeconds(5));
            Assert.True(probe.Success);
            Assert.False(probe.ChainValid);
            await server;
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public void Tcp_fallback_does_not_display_misleading_packet_loss()
    {
        var sample = new NetworkChecker.Core.NetInfo.HostLatency("example", null, 10, 0, 40, 0, "TCP");
        Assert.Equal("—", sample.LossText);
    }

    [Theory]
    [InlineData("Disconnected")]
    [InlineData("Не подключено")]
    [InlineData("Connecting")]
    public async Task Disconnected_vpn_is_not_a_connected_fact(string status)
    {
        var platform = FakePlatformProbe.Clean();
        platform.VpnConnections.Add(new NetworkChecker.Core.Platform.VpnConnectionInfo { Name = "test", Status = status });
        var result = await new DirectSignsCheck(platform, new VpnClientCatalog()).RunAsync(Sample.Context(), CancellationToken.None);
        Assert.DoesNotContain(result.Findings, f => f.Kind == EvidenceKind.ConnectedWindowsVpn);
        Assert.NotEqual(RiskLevel.Detected, VerdictEngine.Build([result], new IpConsensus()).Level);
    }

    [Fact]
    public void No_completed_weighted_checks_means_no_numeric_index()
    {
        var skipped = new CheckResult { Category = CheckCategory.GeoIp, Title = "x", Weight = 20, Status = CheckStatus.Skipped };
        var verdict = VerdictEngine.Build([skipped], new IpConsensus());
        Assert.False(verdict.ScoreAvailable);
        Assert.Equal("не рассчитан", verdict.ScoreText);
    }

    [Fact]
    public void Stun_parser_accepts_ipv6_xor_address()
    {
        byte[] request = [0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var address = IPAddress.Parse("2001:db8::5").GetAddressBytes();
        var response = new byte[44];
        response[0] = 1; response[1] = 1; response[3] = 24;
        Array.Copy(request, 4, response, 4, 16);
        response[21] = 0x20; response[23] = 20; response[25] = 2;
        response[26] = 0x21; response[27] = 0x12;
        for (var i = 0; i < 16; i++) response[28 + i] = (byte)(address[i] ^ request[4 + i]);
        Assert.Equal(IPAddress.Parse("2001:db8::5"), StunClient.ParseXorMapped(response, request)?.Address);
    }

    private sealed class PortStatusProbe(int status) : IHttpProbe
    {
        public string UserAgent => "test";
        public Task<HttpProbeResult> GetAsync(Uri uri, TimeSpan timeout, bool ignoreProxy, CancellationToken ct = default) =>
            Task.FromResult(uri.Port == 10085
                ? new HttpProbeResult(status == 200, status, null, null, TimeSpan.Zero, null, null)
                : new HttpProbeResult(false, 0, null, null, TimeSpan.Zero, null, null));
    }
}
