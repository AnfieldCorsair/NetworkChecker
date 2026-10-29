using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Platform;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>
/// Эвристики «нормально / подозрительно». Ошибка здесь стоит дорого: ложное «требует проверки»
/// на обычной домашней сети выглядит хуже, чем пропущенная мелочь, поэтому границы проверяем явно.
/// </summary>
public class NetworkHeuristicsTests
{
    private static HostsEntry Hosts(string address, string name, string? comment = null) =>
        new(address, name, comment);

    [Theory]
    [InlineData("10.8.0.5")]
    [InlineData("203.0.113.10")]
    [InlineData("203.0.113.10/32")]
    [InlineData("2a00:1450:4010::1/128")]
    public void Real_host_route_is_suspicious(string destination) =>
        Assert.True(NetworkHeuristics.IsSuspiciousHostRoute(destination));

    [Theory]
    [InlineData("169.254.0.20")]
    [InlineData("169.254.1.1/32")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    [InlineData("127.0.0.1")]
    [InlineData("224.0.0.251")]
    [InlineData("0.0.0.0")]
    public void Service_address_routes_are_not_suspicious(string destination) =>
        Assert.False(NetworkHeuristics.IsSuspiciousHostRoute(destination));

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("0.0.0.0/0")]
    [InlineData("192.168.0.0/16")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("не-адрес")]
    [InlineData(null)]
    public void Subnet_routes_and_garbage_are_ignored(string? destination) =>
        Assert.False(NetworkHeuristics.IsSuspiciousHostRoute(destination));

    [Theory]
    [InlineData("127.0.0.1", "localhost")]
    [InlineData("::1", "ip6-localhost")]
    [InlineData("ff00::", "ip6-mcastprefix")]
    [InlineData("fe00::", "ip6-localnet")]
    [InlineData("0.0.0.0", "wpad")]
    [InlineData("192.168.1.10", "printer.local")]
    public void Standard_hosts_entries_are_benign(string address, string name) =>
        Assert.True(NetworkHeuristics.IsBenignHostsEntry(Hosts(address, name)));

    [Fact]
    public void Our_own_marker_in_comment_marks_entry_as_ours() =>
        Assert.True(NetworkHeuristics.IsBenignHostsEntry(
            Hosts("0.0.0.0", "telemetry.example.com", "added by NetworkChecker")));

    [Theory]
    [InlineData("0.0.0.0", "vk.com")]
    [InlineData("127.0.0.1", "api.telegram.org")]
    [InlineData("10.8.0.1", "gosuslugi.ru")]
    public void Redirecting_a_real_domain_is_not_benign(string address, string name) =>
        Assert.False(NetworkHeuristics.IsBenignHostsEntry(Hosts(address, name)));

    [Fact]
    public void Benign_entry_requires_an_entry()
    {
        Assert.Throws<ArgumentNullException>(() => NetworkHeuristics.IsBenignHostsEntry(null!));
    }
}
