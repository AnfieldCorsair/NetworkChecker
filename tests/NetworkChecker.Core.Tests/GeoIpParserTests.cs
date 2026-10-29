using NetworkChecker.Core.Net;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class GeoIpParserTests
{
    [Fact]
    public void Parses_ipapi_is_shape()
    {
        const string json = """
        {
          "ip": "45.12.220.10",
          "is_hosting": true,
          "is_proxy": false,
          "asn": {"asn": 207100, "org": "Some Hosting"},
          "location": {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam"}
        }
        """;

        var info = GeoIpParser.Parse(json);

        Assert.NotNull(info);
        Assert.Equal("45.12.220.10", info!.Ip);
        Assert.Equal("NL", info.Country);
        Assert.True(info.Hosting);
        Assert.False(info.Proxy);
        Assert.Equal("Amsterdam", info.City);
        Assert.False(info.IsRussian);
    }

    [Fact]
    public void Parses_iplocate_shape_without_hosting_but_with_privacy()
    {
        const string json = """
        {"ip":"5.5.5.5","country":"Russia","country_code":"RU","privacy":{"is_hosting":false,"is_vpn":true}}
        """;

        var info = GeoIpParser.Parse(json);

        Assert.NotNull(info);
        Assert.Equal("RU", info.Country);
        Assert.True(info.IsRussian);
        Assert.False(info.Hosting);
        Assert.True(info.Proxy); // is_vpn раскрывается как proxy-сигнал
    }

    [Fact]
    public void Parses_plain_shape_myip_com()
    {
        var info = GeoIpParser.Parse("""{"ip":"8.8.8.8","country":"US","cc":"us"}""");
        Assert.NotNull(info);
        Assert.Equal("8.8.8.8", info!.Ip);
        Assert.Equal("US", info.Country);
        Assert.Null(info.Hosting);
        Assert.Null(info.Proxy);
    }

    [Fact]
    public void Returns_null_on_garbage()
    {
        Assert.Null(GeoIpParser.Parse("not json at all"));
        Assert.Null(GeoIpParser.Parse(""));
    }

    [Theory]
    [InlineData("russia", "RU")]
    [InlineData("Netherlands", "NL")]
    [InlineData("США", null)]
    public void Country_name_to_code(string name, string? expected)
    {
        Assert.Equal(expected, GeoCountries.ToCode(name));
    }

    [Fact]
    public void Country_name_lookup_is_localized()
    {
        Assert.Equal("Россия", GeoCountries.Name("RU"));
        Assert.Equal("Нидерланды", GeoCountries.Name("NL"));
        Assert.Equal("ZZ", GeoCountries.Name("ZZ"));
    }
}
