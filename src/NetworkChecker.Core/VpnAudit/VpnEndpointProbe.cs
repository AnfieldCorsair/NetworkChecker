using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace NetworkChecker.Core.VpnAudit;

/// <summary>
/// Локальная (с машины пользователя Windows) проверка эндпоинта ВПН и Reality SNI:
/// DNS -> TCP -> TLS 1.3 + ALPN h2 + проверка сертификата.
/// </summary>
public sealed class VpnEndpointProbe
{
    private readonly TimeSpan _defaultTimeout;

    public VpnEndpointProbe()
        : this(TimeSpan.FromSeconds(5))
    {
    }

    public VpnEndpointProbe(TimeSpan defaultTimeout)
    {
        _defaultTimeout = defaultTimeout;
    }

    public Task<VpnEndpointProbeResult> ProbeAsync(
        string host,
        int port,
        string? sni,
        bool checkTls,
        int timeoutMs,
        CancellationToken ct = default) =>
        ProbeAsync(host, port, sni, checkTls, TimeSpan.FromMilliseconds(timeoutMs), ct);

    public async Task<VpnEndpointProbeResult> ProbeAsync(
        string host,
        int port,
        string? sni = null,
        bool checkTls = true,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        var effectiveTimeout = timeout ?? _defaultTimeout;
        var targetSni = string.IsNullOrWhiteSpace(sni) ? host.Trim() : sni.Trim();

        // 1. DNS
        var swDns = Stopwatch.StartNew();
        IPAddress[] addresses;
        try
        {
            using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            dnsCts.CancelAfter(effectiveTimeout);
            addresses = await Dns.GetHostAddressesAsync(host.Trim(), dnsCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return new VpnEndpointProbeResult(
                host, port, targetSni, false, [], swDns.ElapsedMilliseconds,
                false, null, false, false, null, null, null, null, null, false,
                $"Сбой DNS: {ex.Message}");
        }
        swDns.Stop();

        var resolved = addresses.Select(a => a.ToString()).Distinct(StringComparer.Ordinal).ToArray();
        var targetIp = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();
        if (targetIp is null)
        {
            return new VpnEndpointProbeResult(
                host, port, targetSni, false, [], swDns.ElapsedMilliseconds,
                false, null, false, false, null, null, null, null, null, false,
                "DNS не вернул ни одного адреса.");
        }

        // 2. TCP
        using var tcp = new TcpClient(targetIp.AddressFamily);
        var swTcp = Stopwatch.StartNew();
        try
        {
            using var tcpCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            tcpCts.CancelAfter(effectiveTimeout);
            await tcp.ConnectAsync(targetIp, port, tcpCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return new VpnEndpointProbeResult(
                host, port, targetSni, true, resolved, swDns.ElapsedMilliseconds,
                false, swTcp.ElapsedMilliseconds, false, false, null, null, null, null, null, false,
                $"Сбой TCP :{port}: {ex.Message}");
        }
        swTcp.Stop();

        if (!checkTls)
        {
            return new VpnEndpointProbeResult(
                host, port, targetSni, true, resolved, swDns.ElapsedMilliseconds,
                true, swTcp.ElapsedMilliseconds, false, false, null, null, null, null, null, false, null);
        }

        // 3. TLS + ALPN h2 (проверка пригодности SNI для VLESS Reality)
        var swTls = Stopwatch.StartNew();
        try
        {
            // Диагностическое рукопожатие без передачи прикладных данных: требуется прочитать сертификат и ALPN даже при самоподписанном/несовпадающем сертификате.
#pragma warning disable CA5359
            await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
#pragma warning restore CA5359
            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            tlsCts.CancelAfter(effectiveTimeout);

            var authOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetSni,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols =
                [
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11,
                ],
            };

            await ssl.AuthenticateAsClientAsync(authOptions, tlsCts.Token).ConfigureAwait(false);
            swTls.Stop();

            var isTls13 = ssl.SslProtocol == SslProtocols.Tls13;
            if (!isTls13)
            {
                var rawTls = await SubnetSniScanner.ProbeRawTls13Async(
                        targetIp,
                        targetSni,
                        (int)Math.Min(effectiveTimeout.TotalMilliseconds, 1800),
                        ct)
                    .ConfigureAwait(false);
                if (rawTls is { IsTls13: true })
                {
                    isTls13 = true;
                }
            }

            var protocolName = isTls13 ? "TLSv1.3" : ssl.SslProtocol.ToString();
            var alpn = ssl.NegotiatedApplicationProtocol.Protocol.Length > 0
                ? System.Text.Encoding.ASCII.GetString(ssl.NegotiatedApplicationProtocol.Protocol.Span)
                : null;

            string? certSubject = null;
            int? daysRemaining = null;
            if (ssl.RemoteCertificate is not null)
            {
                using var cert2 = new X509Certificate2(ssl.RemoteCertificate);
                certSubject = cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                daysRemaining = (int)Math.Floor((cert2.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);
            }

            var realitySuitable = isTls13 &&
                                  string.Equals(alpn, "h2", StringComparison.OrdinalIgnoreCase);

            return new VpnEndpointProbeResult(
                host, port, targetSni, true, resolved, swDns.ElapsedMilliseconds,
                true, swTcp.ElapsedMilliseconds, true, true, swTls.ElapsedMilliseconds,
                protocolName, alpn, certSubject, daysRemaining, realitySuitable, null);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
        {
            return new VpnEndpointProbeResult(
                host, port, targetSni, true, resolved, swDns.ElapsedMilliseconds,
                true, swTcp.ElapsedMilliseconds, true, false, swTls.ElapsedMilliseconds,
                null, null, null, null, false, $"Сбой TLS: {ex.Message}");
        }
    }
}
