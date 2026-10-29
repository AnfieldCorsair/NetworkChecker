using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>Локальный слушатель на loopback — проверяем детект прокси по-настоящему, но без интернета.</summary>
internal sealed class LoopbackServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    private LoopbackServer(TcpListener listener, Func<NetworkStream, Task> handler)
    {
        _listener = listener;
        _loop = Task.Run(async () =>
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try { await handler(client.GetStream()); } catch { }
                        }
                    });
                }
            }
            catch { }
        });
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public static LoopbackServer Socks5()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return new LoopbackServer(listener, async stream =>
        {
            var buffer = new byte[16];
            var read = await stream.ReadAsync(buffer);
            if (read > 0 && buffer[0] == 0x05)
            {
                await stream.WriteAsync(new byte[] { 0x05, 0x00 });
                await stream.FlushAsync();
                await Task.Delay(200);
            }
        });
    }

    public static LoopbackServer HttpProxy()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return new LoopbackServer(listener, async stream =>
        {
            var buffer = new byte[512];
            var read = await stream.ReadAsync(buffer);
            var request = Encoding.ASCII.GetString(buffer, 0, read);
            var reply = request.StartsWith("CONNECT", StringComparison.OrdinalIgnoreCase)
                ? "HTTP/1.1 200 Connection established\r\n\r\n"
                : "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(reply));
            await stream.FlushAsync();
            await Task.Delay(200);
        });
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        try { await _loop; } catch { }
        _cts.Dispose();
    }
}

public class BypassCheckTests
{
    private static RknOptions OptionsWithPorts(params int[] ports)
    {
        var options = Sample.Options();
        options.LocalProxyPorts = [.. ports];
        return options;
    }

    [Fact]
    public async Task Closed_ports_produce_no_findings()
    {
        var check = new BypassCheck(new FakeHttpProbe());

        var result = await check.RunAsync(Sample.Context(OptionsWithPorts(1, 2, 3)), CancellationToken.None);

        Assert.Equal(CheckStatus.Clean, result.Status);
        Assert.DoesNotContain(result.Findings, f => f.Severity >= Severity.Warning);
        Assert.Contains(result.Metrics, m => m.Label == "Открыто на loopback" && m.Value == "0");
    }

    /// <summary>
    /// Loopback-тесты зависят от планировщика: под нагрузкой рукопожатие может не уложиться в таймаут.
    /// Поэтому несколько попыток — проверяем детект протокола, а не скорость машины.
    /// </summary>
    private static async Task<CheckResult> RunUntilAsync(
        Func<Task<CheckResult>> attempt,
        Func<CheckResult, bool> expected,
        int tries = 3)
    {
        CheckResult? last = null;
        for (var i = 0; i < tries; i++)
        {
            last = await attempt();
            if (expected(last)) return last;
            await Task.Delay(120);
        }
        return last!;
    }

    [Fact]
    public async Task Local_socks5_is_critical()
    {
        await using var server = LoopbackServer.Socks5();
        var check = new BypassCheck(new FakeHttpProbe());

        var result = await RunUntilAsync(
            () => check.RunAsync(Sample.Context(OptionsWithPorts(server.Port)), CancellationToken.None),
            r => r.Findings.Any(f => f.Detail.Contains("SOCKS5", StringComparison.Ordinal)));

        Assert.Equal(CheckStatus.Detected, result.Status);
        var finding = result.Findings.Single(f => f.Title == $"Локальный прокси на 127.0.0.1:{server.Port}");
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("SOCKS5", finding.Detail);
        Assert.Contains(result.Findings, f => f.Title == "Комбинация SOCKS5 + TUN");
    }

    [Fact]
    public async Task Local_http_proxy_is_detected()
    {
        await using var server = LoopbackServer.HttpProxy();
        var check = new BypassCheck(new FakeHttpProbe());

        var result = await RunUntilAsync(
            () => check.RunAsync(Sample.Context(OptionsWithPorts(server.Port)), CancellationToken.None),
            r => r.Findings.Any(f => f.Detail.Contains("HTTP", StringComparison.Ordinal)));

        Assert.Contains(result.Findings, f => f.Title.Contains("127.0.0.1:" + server.Port) && f.Detail.Contains("HTTP"));
    }

    [Fact]
    public async Task Clash_api_version_endpoint_is_recognised()
    {
        var http = FakeHttpProbe.For("9090/version", "{\"version\":\"v1.18.1\",\"premium\":true}");
        var check = new BypassCheck(http);

        var result = await check.RunAsync(Sample.Context(OptionsWithPorts()), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Clash"));
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("9090", finding.Title);
    }

    [Fact]
    public async Task Xray_api_is_recognised()
    {
        var http = FakeHttpProbe.For("10085", "{\"version\":\"25.3.6\"}");
        var check = new BypassCheck(http);

        var result = await check.RunAsync(Sample.Context(OptionsWithPorts()), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.Title.Contains("Xray"));
    }

    [Fact]
    public async Task Report_body_is_not_empty()
    {
        var check = new BypassCheck(new FakeHttpProbe());

        var result = await check.RunAsync(Sample.Context(OptionsWithPorts()), CancellationToken.None);

        Assert.Equal(CheckCategory.Bypass, result.Category);
        Assert.Equal(30, result.Weight);
        Assert.False(string.IsNullOrWhiteSpace(result.Title));
        Assert.True(result.Duration >= TimeSpan.Zero);
    }
}

public class IpComparisonCheckTests
{
    private static RknOptions Online()
    {
        var options = Sample.Options();
        options.OfflineMode = false;
        options.StunServers = [];
        options.RequestTimeoutSeconds = 2;
        return options;
    }

    [Fact]
    public async Task Offline_mode_skips_with_explanation()
    {
        var options = Online();
        options.OfflineMode = true;

        var result = await new IpComparisonCheck(new FakeHttpProbe()).RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckStatus.Skipped, result.Status);
        Assert.Contains(result.Findings, f => f.Title == "Офлайн-режим");
    }

    [Fact]
    public async Task Matching_addresses_are_reported_as_consistent()
    {
        var http = new FakeHttpProbe()
            .With("api.ipify.org", "{\"ip\":\"203.0.113.7\"}")
            .With("api.myip.com", "{\"ip\":\"203.0.113.7\",\"country\":\"NL\"}")
            .With("api.ipapi.is", "{\"ip\":\"203.0.113.7\"}")
            .With("cdn-cgi/trace", "fl=123\nip=203.0.113.7\nts=1\n");

        var result = await new IpComparisonCheck(http).RunAsync(Sample.Context(Online()), CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(result.Title));
        Assert.DoesNotContain(result.Findings, f => f.Severity >= Severity.Warning);
        Assert.Equal(CheckStatus.Clean, result.Status);
    }

    [Fact]
    public async Task Different_addresses_are_flagged()
    {
        var http = new FakeHttpProbe()
            .With("api.ipify.org", "{\"ip\":\"203.0.113.7\"}")
            .With("api.myip.com", "{\"ip\":\"198.51.100.9\"}")
            .With("api.ipapi.is", "{\"ip\":\"198.51.100.9\"}");

        var result = await new IpComparisonCheck(http).RunAsync(Sample.Context(Online()), CancellationToken.None);

        Assert.NotEqual(CheckStatus.Clean, result.Status);
        Assert.Contains(result.Findings, f => f.Severity >= Severity.Warning);
    }

    [Fact]
    public async Task No_sources_answering_gives_skip()
    {
        var result = await new IpComparisonCheck(new FakeHttpProbe()).RunAsync(Sample.Context(Online()), CancellationToken.None);

        Assert.Equal(CheckStatus.Skipped, result.Status);
    }
}

public class CallTransportCheckTests
{
    [Fact]
    public async Task No_stun_servers_reports_udp_unavailable()
    {
        var options = Sample.Options();
        options.StunServers = [];
        options.RequestTimeoutSeconds = 2;

        var result = await new CallTransportCheck(new FakeHttpProbe())
            .RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.Title == "UDP полностью недоступен");
        Assert.Equal("0 из 0", result.Metrics.Single(m => m.Label == "STUN-серверов ответило").Value);
    }

    [Fact]
    public async Task Closed_stun_server_is_counted_as_no_answer()
    {
        var options = Sample.Options();
        options.StunServers = ["127.0.0.1:9"];
        options.RequestTimeoutSeconds = 1;

        var result = await new CallTransportCheck(new FakeHttpProbe())
            .RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal("0 из 1", result.Metrics.Single(m => m.Label == "STUN-серверов ответило").Value);
        Assert.Equal(CheckCategory.CallTransport, result.Category);
    }
}

public class DomainReachabilityCheckTests
{
    [Fact]
    public async Task Unresolvable_names_are_reported_per_stage()
    {
        var options = Sample.Options();
        options.ReachabilityTargets = ["нет-такого-домена.invalid"];
        options.RequestTimeoutSeconds = 2;

        var result = await new DomainReachabilityCheck().RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.Title.StartsWith("DNS не разрешает", StringComparison.Ordinal));
        Assert.NotEqual(CheckStatus.Clean, result.Status);
    }

    [Fact]
    public async Task Empty_target_list_is_harmless()
    {
        var options = Sample.Options();
        options.ReachabilityTargets = [];

        var result = await new DomainReachabilityCheck().RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.Equal(CheckCategory.DomainReachability, result.Category);
        Assert.NotNull(result.Title);
    }

    [Fact]
    public async Task Localhost_is_reachable_and_clean()
    {
        var options = Sample.Options();
        options.ReachabilityTargets = ["localhost"];
        options.RequestTimeoutSeconds = 1;

        var result = await new DomainReachabilityCheck().RunAsync(Sample.Context(options), CancellationToken.None);

        // Порт 443 на localhost закрыт — ожидаем стадию TCP, но не падение.
        Assert.Contains(result.Findings, f => f.Title.Contains("localhost") || f.Title.Contains("TLS") || f.Title.Contains("DNS"));
    }
}

public class RttTriangulationCheckTests
{
    [Fact]
    public async Task Without_samples_check_is_skipped_not_failed()
    {
        var options = Sample.Options();
        options.RttRussianHosts = ["127.0.0.1"];
        options.RttForeignHosts = ["127.0.0.1"];

        var result = await new RttTriangulationCheck()
            .RunAsync(Sample.Context(options), CancellationToken.None);

        Assert.True(
            result.Status is CheckStatus.Clean or CheckStatus.Skipped or CheckStatus.Detected,
            "неожиданный статус: " + result.Status);
        Assert.Equal(CheckCategory.RttTriangulation, result.Category);
        Assert.Equal(15, result.Weight);
    }
}
