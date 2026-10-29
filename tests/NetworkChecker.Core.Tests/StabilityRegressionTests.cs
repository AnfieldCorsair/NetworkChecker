using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class StabilityRegressionTests
{
    [Fact]
    public async Task Duplicate_categories_keep_both_results_in_declared_order()
    {
        var runner = new CheckRunner([
            new FakeCheck(CheckCategory.GeoIp, title: "first"),
            new FakeCheck(CheckCategory.GeoIp, title: "second")], FakePlatformProbe.Clean());
        var run = await runner.RunAsync(Sample.Options(), false, CancellationToken.None);
        Assert.Equal(2, run.Checks.Count);
        Assert.Equal("first", run.Checks[0].Title);
        Assert.Equal("second", run.Checks[1].Title);
    }

    [Fact]
    public async Task Cancellation_is_not_misreported_as_network_failure()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        using var http = new HttpProbe();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => http.GetAsync(new Uri("http://127.0.0.1:1"), TimeSpan.FromSeconds(2), true, cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ConnectivityProbes.ResolveAsync("127.0.0.1", cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ConnectivityProbes.TcpConnectAsync("127.0.0.1", 1, TimeSpan.FromSeconds(2), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ConnectivityProbes.IsSocks5Async("127.0.0.1", 1, TimeSpan.FromSeconds(2), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => StunClient.BindAsync("127.0.0.1:3478", TimeSpan.FromSeconds(2), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsClientLite.QueryAsync("example.com", DnsRecordType.A, new IPEndPoint(IPAddress.Loopback, 53), ct: cts.Token));
    }

    [Fact]
    public async Task Dns_ignores_mismatched_transaction_and_accepts_matching_response()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = (IPEndPoint)udp.Client.LocalEndPoint!;
        var server = Task.Run(async () =>
        {
            var req = await udp.ReceiveAsync();
            var response = Reply(req.Buffer, truncated: false);
            var wrong = (byte[])response.Clone();
            wrong[0] ^= 0xFF;
            await udp.SendAsync(wrong, req.RemoteEndPoint);
            await udp.SendAsync(response, req.RemoteEndPoint);
        });
        var answers = await DnsClientLite.QueryAsync("example.com", DnsRecordType.A, endpoint, TimeSpan.FromSeconds(3));
        await server;
        Assert.Equal("192.0.2.8", Assert.Single(answers).Value);
    }

    [Fact]
    public async Task Truncated_udp_dns_retries_over_tcp()
    {
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var endpoint = (IPEndPoint)tcp.LocalEndpoint;
        using var udp = new UdpClient(endpoint);
        var server = Task.Run(async () =>
        {
            var datagram = await udp.ReceiveAsync();
            await udp.SendAsync(Reply(datagram.Buffer, truncated: true), datagram.RemoteEndPoint);
            using var client = await tcp.AcceptTcpClientAsync();
            var stream = client.GetStream();
            var prefix = new byte[2];
            await stream.ReadExactlyAsync(prefix);
            var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
            await stream.ReadExactlyAsync(query);
            var response = Reply(query, truncated: false);
            BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)response.Length);
            await stream.WriteAsync(prefix);
            await stream.WriteAsync(response);
        });
        var answers = await DnsClientLite.QueryAsync("example.com", DnsRecordType.A, endpoint, TimeSpan.FromSeconds(3));
        await server.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal("192.0.2.8", Assert.Single(answers).Value);
    }

    [Theory]
    [InlineData("[2001:db8::1]:3479", "2001:db8::1", 3479)]
    [InlineData("2001:db8::1", "2001:db8::1", 3478)]
    [InlineData("stun.example:1234", "stun.example", 1234)]
    public void Stun_server_supports_ipv6_and_ports(string input, string expectedHost, int expectedPort)
    {
        Assert.True(StunClient.TryParseServer(input, out var host, out var port));
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
        Assert.False(StunClient.TryParseServer("stun.example:99999", out _, out _));
    }

    [Fact]
    public void Icmp_echo_requires_matching_sender_identifier_and_sequence()
    {
        var target = IPAddress.Parse("192.0.2.1");
        byte[] reply = [0, 0, 0, 0, 0x12, 0x34, 0, 7];
        Assert.Equal(IcmpStatus.EchoReply, RawIcmp.ParseReply(reply, target, target, 0x1234, 7));
        Assert.Null(RawIcmp.ParseReply(reply, target, IPAddress.Loopback, 0x1234, 7));
        Assert.Null(RawIcmp.ParseReply(reply, target, target, 0x1234, 8));
        Assert.Null(RawIcmp.ParseReply(reply, target, target, 0x1235, 7));
    }

    [Fact]
    public void Icmp_error_must_quote_the_expected_request_and_destination()
    {
        var target = IPAddress.Parse("192.0.2.1");
        var packet = new byte[8 + 24 + 8]; // ICMP error + IPv4 с опциями + исходный ICMP
        packet[0] = 11;
        packet[8] = 0x46;
        packet[17] = 1; // IPv4 protocol ICMP
        target.GetAddressBytes().CopyTo(packet, 24);
        packet[32] = 8;
        packet[36] = 0x12; packet[37] = 0x34; packet[39] = 7;
        Assert.Equal(IcmpStatus.TtlExpired, RawIcmp.ParseReply(packet, target, IPAddress.Loopback, 0x1234, 7));
        Assert.Null(RawIcmp.ParseReply(packet, target, IPAddress.Loopback, 0x1234, 8));
        packet[27] = 2;
        Assert.Null(RawIcmp.ParseReply(packet, target, IPAddress.Loopback, 0x1234, 7));
        Assert.Null(RawIcmp.ParseReply(packet.AsSpan(0, 12), target, IPAddress.Loopback, 0x1234, 7));
    }

    private static byte[] Reply(byte[] query, bool truncated)
    {
        var response = query.ToList();
        response[2] = truncated ? (byte)0x83 : (byte)0x81;
        response[3] = 0x80;
        if (!truncated)
        {
            response[7] = 1;
            response.AddRange([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 8]);
        }
        return [.. response];
    }
}
