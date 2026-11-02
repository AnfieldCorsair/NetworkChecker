using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>Заглушка транспортных проб: вся логика проверяется без реальной сети.</summary>
public sealed class FakeTransportProbes : ITransportProbes
{
    public Dictionary<string, IReadOnlyList<string>> SystemAnswers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IReadOnlyList<string>> DohAnswers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, TlsProbeOutcome> TlsOutcomes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool UdpResponds { get; set; }
    public List<string> SniCalls { get; } = [];

    public Task<IReadOnlyList<string>> ResolveSystemAsync(string name, CancellationToken ct = default) =>
        Task.FromResult(SystemAnswers.GetValueOrDefault(name) ?? Array.Empty<string>());

    public Task<IReadOnlyList<string>> ResolveDohAsync(string name, TimeSpan timeout, CancellationToken ct = default) =>
        Task.FromResult(DohAnswers.GetValueOrDefault(name) ?? Array.Empty<string>());

    public Task<UdpProbeResult> UdpAsync(string host, int port, byte[] payload, TimeSpan timeout, CancellationToken ct = default) =>
        Task.FromResult(new UdpProbeResult(UdpResponds, TimeSpan.FromMilliseconds(12), UdpResponds ? null : "ответа нет"));

    public Task<TlsProbeOutcome> TlsAsync(string host, string sni, TimeSpan timeout, CancellationToken ct = default)
    {
        SniCalls.Add(sni);
        return Task.FromResult(TlsOutcomes.GetValueOrDefault(sni) ?? new TlsProbeOutcome(true, TimeSpan.FromMilliseconds(20), null));
    }
}

public class TransportObservationTests
{
    private static RknOptions OnlineOptions()
    {
        var options = Sample.Options();
        options.OfflineMode = false;
        return options;
    }

    private static FakeHttpProbe HttpWithEgress() =>
        new FakeHttpProbe().With("api.ipify.org", "{\"ip\":\"203.0.113.7\"}");

    [Fact]
    public void Doh_parser_selects_only_a_records()
    {
        const string json = """
            {"Answer":[{"name":"example.com","type":1,"data":"93.184.215.14"},
                       {"name":"example.com","type":5,"data":"cname.example"},
                       {"name":"example.com","type":1,"data":"not-an-ip"}]}
            """;

        var addresses = DohAnswerParser.Parse(json);

        Assert.Single(addresses);
        Assert.Equal("93.184.215.14", addresses[0]);
        Assert.Empty(DohAnswerParser.Parse("not json"));
    }

    [Fact]
    public async Task Offline_mode_skips_all_transport_probes()
    {
        var probes = new FakeTransportProbes();
        var check = new TransportObservationCheck(new FakeHttpProbe(), probes);

        var result = await check.RunAsync(Sample.Context(), CancellationToken.None);

        Assert.Equal(CheckStatus.Skipped, result.Status);
        Assert.Equal(0, result.Weight);
        Assert.Empty(probes.SniCalls);
    }

    [Fact]
    public async Task Dns_leak_dns_mismatch_and_sni_difference_are_reported()
    {
        var probes = new FakeTransportProbes();
        probes.SystemAnswers["whoami.akamai.net"] = ["198.51.100.10"];
        probes.SystemAnswers["o-o.myaddr.l.google.com"] = ["198.51.100.10"];
        probes.SystemAnswers["example.com"] = ["93.184.215.14"];
        probes.DohAnswers["example.com"] = ["93.184.216.34"];
        probes.TlsOutcomes["cloudflare.com"] = new TlsProbeOutcome(true, TimeSpan.FromMilliseconds(20), null);
        probes.TlsOutcomes["rutracker.org"] = new TlsProbeOutcome(false, TimeSpan.FromSeconds(3), "сброс");
        var check = new TransportObservationCheck(HttpWithEgress(), probes);

        var result = await check.RunAsync(Sample.Context(OnlineOptions()), CancellationToken.None);

        Assert.Equal(CheckStatus.NeedsReview, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("DNS-резолвер отличается"));
        Assert.Contains(result.Findings, f => f.Title.Contains("вернули разные адреса"));
        Assert.Contains(result.Findings, f => f.Title.Contains("TLS с SNI"));
        Assert.Contains(result.Findings, f => f.Title.Contains("молчание не равно блокировке"));
        Assert.Contains(result.Metrics, m => m.Label.StartsWith("UDP/443", StringComparison.Ordinal));
        Assert.Contains(probes.SniCalls, sni => sni == "rutracker.org");
    }

    [Fact]
    public async Task Missing_data_does_not_become_a_positive_signal()
    {
        var probes = new FakeTransportProbes();
        probes.TlsOutcomes["cloudflare.com"] = new TlsProbeOutcome(false, TimeSpan.Zero, "нет сети");
        var check = new TransportObservationCheck(new FakeHttpProbe(), probes);

        var result = await check.RunAsync(Sample.Context(OnlineOptions()), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("DNS-резолвер отличается"));
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("вернули разные адреса"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Контрольное TLS-соединение не завершилось"));
        Assert.Contains(result.Metrics, m => m.Label == "Внешний адрес для сравнения" && m.Value == "нет данных");
    }

    [Fact]
    public async Task Matching_resolver_and_egress_is_only_information()
    {
        var probes = new FakeTransportProbes();
        probes.SystemAnswers["whoami.akamai.net"] = ["203.0.113.7"];
        probes.SystemAnswers["example.com"] = ["93.184.215.14"];
        probes.DohAnswers["example.com"] = ["93.184.215.14"];
        var check = new TransportObservationCheck(HttpWithEgress(), probes);

        var result = await check.RunAsync(Sample.Context(OnlineOptions()), CancellationToken.None);

        Assert.Equal(CheckStatus.Clean, result.Status);
        Assert.Contains(result.Findings, f => f.Title.Contains("Резолвер совпадает"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Ответы DNS и DoH пересекаются"));
    }

    [Fact]
    public void Clone_copies_new_collections()
    {
        var options = new RknOptions();
        var clone = options.Clone();

        clone.LocalProxyPortRanges.Add("20000-20010");
        clone.DnsCompareDomains.Add("extra.test");
        clone.QuicProbeTargets.Add("extra.test");
        clone.SniProbeNames.Add("extra.test");

        Assert.DoesNotContain("20000-20010", options.LocalProxyPortRanges);
        Assert.DoesNotContain("extra.test", options.DnsCompareDomains);
        Assert.DoesNotContain("extra.test", options.QuicProbeTargets);
        Assert.DoesNotContain("extra.test", options.SniProbeNames);
        Assert.True(options.ScanListeningSockets);
    }
}
