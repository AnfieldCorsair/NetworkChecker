using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>Порты и диапазоны из опубликованной методики, системные LISTEN и каталог клиентов.</summary>
public class LocalPortScannerTests
{
    [Fact]
    public void Parses_methodology_range_16000_16100()
    {
        var ports = LocalPortScanner.ParseRange("16000-16100");

        Assert.Equal(101, ports.Count);
        Assert.Equal(16000, ports[0]);
        Assert.Equal(16100, ports[ports.Count - 1]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("не-числа")]
    [InlineData("100-50")]
    [InlineData("0-10")]
    [InlineData("65000-70000")]
    [InlineData("1-9000")]
    public void Rejects_invalid_ranges(string range)
    {
        Assert.Empty(LocalPortScanner.ParseRange(range));
    }

    [Fact]
    public void Configured_ports_include_values_from_methodology()
    {
        var ports = LocalPortScanner.ConfiguredPorts(new RknOptions());

        Assert.Contains(1080, ports);
        Assert.Contains(5555, ports);
        Assert.Contains(9000, ports);
        Assert.Contains(9150, ports);
        Assert.Contains(16000, ports);
        Assert.Contains(16100, ports);
        Assert.DoesNotContain(0, ports);
    }

    [Fact]
    public void Configured_ports_are_capped_by_option()
    {
        var options = new RknOptions { MaxLocalProxyPorts = 12 };

        var ports = LocalPortScanner.ConfiguredPorts(options);

        Assert.Equal(12, ports.Count);
    }

    [Fact]
    public void Merge_deduplicates_and_respects_limit()
    {
        var merged = LocalPortScanner.Merge([1080, 8080], [8080, 2080, 3128], maxPorts: 3);

        Assert.True(merged.SequenceEqual(new[] { 1080, 8080, 2080 }));
    }

    [Fact]
    public async Task Bypass_probes_ports_reported_by_the_os()
    {
        var options = Sample.Options();
        options.LocalProxyPorts = [];
        options.LocalProxyPortRanges = [];
        options.MaxLocalProxyPorts = 10;
        options.ScanListeningSockets = true;
        var check = new BypassCheck(new FakeHttpProbe(), () => [12345, 12346]);

        var result = await check.RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Contains(result.Metrics, m => m.Label == "Портов проверено" && m.Value == "2");
        Assert.Contains(result.Metrics, m => m.Label == "Из системных LISTEN" && m.Value == "2");
    }

    [Fact]
    public async Task Disabled_listener_enumeration_falls_back_to_configured_list()
    {
        var options = Sample.Options();
        options.LocalProxyPorts = [1, 2];
        options.LocalProxyPortRanges = [];
        options.ScanListeningSockets = false;
        var check = new BypassCheck(new FakeHttpProbe(), () => [12345]);

        var result = await check.RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Contains(result.Metrics, m => m.Label == "Портов проверено" && m.Value == "2");
        Assert.Contains(result.Metrics, m => m.Label == "Из системных LISTEN" && m.Value == "0");
    }

    [Theory]
    [InlineData("amneziawg", "vpn")]
    [InlineData("hysteria2", "proxy")]
    [InlineData("naiveproxy", "proxy")]
    [InlineData("trojan-go", "proxy")]
    [InlineData("shadowtls", "proxy")]
    [InlineData("windivert", "driver")]
    public void Catalog_matches_clients_from_2026_reports(string text, string category)
    {
        var entry = new VpnClientCatalog().Match(text);

        Assert.NotNull(entry);
        Assert.Equal(category, entry!.Category);
    }

    [Fact]
    public void False_positive_catalog_explains_virtualization_and_corporate_vpn()
    {
        Assert.Contains("Hyper-V", FalsePositiveCatalog.Match("Hyper-V Virtual Ethernet Adapter")!);
        Assert.Contains("Корпоративный", FalsePositiveCatalog.Match("Cisco AnyConnect")!);
        Assert.Null(FalsePositiveCatalog.Match("Microsoft Word"));
        Assert.NotEmpty(FalsePositiveCatalog.ContextNotes);
    }
}
