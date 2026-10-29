using NetworkChecker.Core.Net;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class TraceGraphTests
{
    [Theory]
    [InlineData("15169", "AS15169")]
    [InlineData("as0015169", "AS15169")]
    [InlineData("AS0", null)]
    [InlineData("—", null)]
    [InlineData("15169 123", null)]
    [InlineData("4294967296", null)]
    [InlineData(null, null)]
    public void Normalizes_valid_numeric_asns(string? input, string? expected) =>
        Assert.Equal(expected, TraceGraph.NormalizeAsn(input));

    [Fact]
    public void Same_asn_has_stable_color_and_unknown_is_gray()
    {
        Assert.Equal(TraceGraph.ColorForAsn("AS15169"), TraceGraph.ColorForAsn("15169"));
        Assert.Equal("#8090A4", TraceGraph.ColorForAsn(null));
        Assert.NotEqual("#8090A4", TraceGraph.ColorForAsn("AS15169"));
    }
}
