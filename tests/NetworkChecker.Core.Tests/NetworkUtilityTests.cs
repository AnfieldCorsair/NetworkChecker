using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Platform;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class InterfaceNamingTests
{
    [Theory]
    [InlineData("tun0", true)]
    [InlineData("wg0", true)]
    [InlineData("utun3", true)]
    [InlineData("WireGuard Tunnel", true)]
    [InlineData("Clash-Adapter", true)]
    [InlineData("NordLynx", true)]
    [InlineData("Ethernet", false)]
    [InlineData("Wi-Fi", false)]
    [InlineData("eth0", false)]
    public void Vpn_like_names(string name, bool expected)
    {
        Assert.Equal(expected, InterfaceNaming.IsVpnLikeName(name));
    }

    [Theory]
    [InlineData("vEthernet (WSL)", true)]
    [InlineData("VMware Network Adapter VMnet1", true)]
    [InlineData("docker0", true)]
    [InlineData("Ethernet 2", false)]
    public void Virtual_names(string name, bool expected)
    {
        Assert.Equal(expected, InterfaceNaming.IsVirtualName(name));
    }
}

public class DnsConfigurationTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("8.8.8.8", false)]
    public void Loopback_detection(string server, bool expected)
    {
        Assert.Equal(expected, DnsConfiguration.IsLoopback(server));
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.5.4", true)]
    [InlineData("172.32.5.4", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("1.1.1.1", false)]
    public void Private_detection(string server, bool expected)
    {
        Assert.Equal(expected, DnsConfiguration.IsPrivate(server));
    }
}

public class VpnCatalogTests
{
    private readonly VpnClientCatalog _catalog = new();

    [Theory]
    [InlineData("Xray-core", "proxy")]
    [InlineData("nekoray.exe", "proxy")]
    [InlineData("Clash Verge", "proxy")]
    [InlineData("GoodbyeDPI", "anti-censor")]
    [InlineData("Amnezia VPN", "vpn")]
    [InlineData("wintun.sys", "driver")]
    public void Matches_known_clients(string text, string category)
    {
        var entry = _catalog.Match(text);
        Assert.NotNull(entry);
        Assert.Equal(category, entry!.Category);
    }

    [Theory]
    [InlineData("Microsoft Word")]
    [InlineData("Steam")]
    [InlineData("Notepad++")]
    [InlineData("")]
    public void Does_not_match_ordinary_apps(string text)
    {
        Assert.Null(_catalog.Match(text));
    }
}

public class DnsWireTests
{
    [Fact]
    public void Query_header_is_well_formed()
    {
        var query = DnsWire.BuildQuery("example.com", DnsRecordType.A, 0x1234);

        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);
        Assert.Equal(0x01, query[2]);           // recursion desired
        Assert.Equal(1, query[4] * 256 + query[5]); // QDCOUNT = 1
        Assert.Contains((byte)0, query);        // terminator
    }

    [Fact]
    public void Parses_minimal_a_record_response()
    {
        // header: id=0x1234, flags=0x8180, qd=1, an=1
        var data = new List<byte>
        {
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        };
        // question: example.com A IN
        foreach (var label in "example.com".Split('.'))
        {
            data.Add((byte)label.Length);
            data.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        data.AddRange([0x00, 0x00, 0x01, 0x00, 0x01]);
        // answer: pointer to name, type A, class IN, ttl, rdlength 4, 93.184.216.34
        data.AddRange([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
        data.AddRange([93, 184, 216, 34]);

        var answers = DnsWire.ParseResponse([.. data]);

        var answer = Assert.Single(answers);
        Assert.Equal("example.com", answer.Name);
        Assert.Equal("93.184.216.34", answer.Value);
        Assert.Equal(300u, answer.Ttl);
    }

    [Fact]
    public void Parses_txt_record()
    {
        var data = new List<byte> { 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
        foreach (var label in "origin.asn.cymru.com".Split('.'))
        {
            data.Add((byte)label.Length);
            data.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        data.AddRange([0x00, 0x00, 0x10, 0x00, 0x01]);
        var txt = System.Text.Encoding.ASCII.GetBytes("15169 | 8.8.8.0/24 | US | arin");
        data.AddRange([0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        var rdLength = txt.Length + 1; // префикс длины строки входит в RDATA
        data.Add((byte)(rdLength >> 8));
        data.Add((byte)(rdLength & 0xFF));
        data.Add((byte)txt.Length);
        data.AddRange(txt);

        var answers = DnsWire.ParseResponse([.. data]);

        Assert.Single(answers);
        Assert.StartsWith("15169", answers[0].Value);
    }
}

public class MaskingTests
{
    [Fact]
    public void Masks_ipv4_last_octets()
    {
        Masking.Enabled = true;
        try
        {
            Assert.Equal("136.87.•••.•••", Masking.Ip("136.87.97.153"));
            Assert.Equal("—", Masking.Ip(null));
        }
        finally
        {
            Masking.Enabled = false;
        }
    }

    [Fact]
    public void Keeps_ip_when_disabled()
    {
        Masking.Enabled = false;
        Assert.Equal("136.87.97.153", Masking.Ip("136.87.97.153"));
        Assert.Equal("AA:BB:CC:DD:EE:FF", Masking.Mac("AA:BB:CC:DD:EE:FF"));
    }
}
