using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetworkChecker.Core.Net;

public sealed record TcpProbeResult(bool Success, TimeSpan Elapsed, string? Error, string? RemoteAddress);

public sealed record TlsProbeResult(
    bool Success,
    TimeSpan Elapsed,
    string? Error,
    string? Subject,
    string? Issuer,
    DateTime? NotAfter,
    string? NegotiatedProtocol,
    string? RemoteAddress,
    bool ChainValid);

/// <summary>TCP/TLS-пробы без использования системного прокси: показывают, что реально видит сеть.</summary>
public static class ConnectivityProbes
{
    public static async Task<TcpProbeResult> TcpConnectAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var addresses = await ResolveAsync(host, ct).ConfigureAwait(false);
            if (addresses.Count == 0) return new TcpProbeResult(false, sw.Elapsed, "DNS не разрешил имя", null);
            Exception? last = null;
            foreach (var ip in addresses)
            {
                using var client = new TcpClient(ip.AddressFamily);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);
                try
                {
                    await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
                    return new TcpProbeResult(true, sw.Elapsed, null, ip.ToString());
                }
                catch (Exception ex)
                {
                    last = ex;
                }
            }
            return new TcpProbeResult(false, sw.Elapsed, Describe(last), null);
        }
        catch (Exception ex)
        {
            return new TcpProbeResult(false, sw.Elapsed, Describe(ex), null);
        }
    }

    public static async Task<TlsProbeResult> TlsHandshakeAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var addresses = await ResolveAsync(host, ct).ConfigureAwait(false);
            if (addresses.Count == 0)
                return new TlsProbeResult(false, sw.Elapsed, "DNS не разрешил имя", null, null, null, null, null, false);

            var ip = addresses[0];
            using var client = new TcpClient(ip.AddressFamily);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            // TLS-зонд: сертификат нам нужен как данные (издатель, срок), а не как доверие.
            // Валидацию сознательно отключаем — иначе MITM-сертификат не прочитать.
#pragma warning disable CA5359
            using var ssl = new SslStream(client.GetStream(), false, static (_, _, _, _) => true);
#pragma warning restore CA5359
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }, cts.Token).ConfigureAwait(false);

            var cert = ssl.RemoteCertificate as X509Certificate2 ?? new X509Certificate2(ssl.RemoteCertificate!);
            var chainValid = cert.NotAfter > DateTime.Now;
            return new TlsProbeResult(true, sw.Elapsed, null, cert.Subject, cert.Issuer, cert.NotAfter.ToLocalTime(),
                ssl.SslProtocol.ToString(), ip.ToString(), chainValid);
        }
        catch (Exception ex)
        {
            return new TlsProbeResult(false, sw.Elapsed, Describe(ex), null, null, null, null, null, false);
        }
    }

    public static async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct = default)
    {
        if (IPAddress.TryParse(host, out var direct)) return [direct];
        try
        {
            var result = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return [.. result.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Take(2)];
        }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }

    /// <summary>Проверка, что на порту действительно SOCKS5 (приветствие 0x05 0x01 0x00).</summary>
    public static async Task<bool> IsSocks5Async(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cts.Token).ConfigureAwait(false);
            var response = new byte[2];
            await stream.ReadExactlyAsync(response, cts.Token).ConfigureAwait(false);
            return response[0] == 0x05;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Проверка HTTP-прокси через CONNECT.</summary>
    public static async Task<bool> IsHttpProxyAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            var request = Encoding.ASCII.GetBytes($"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            await stream.WriteAsync(request, cts.Token).ConfigureAwait(false);
            var buffer = new byte[32];
            var read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
            if (read < 8) return false;
            var text = Encoding.ASCII.GetString(buffer, 0, read);
            return text.StartsWith("HTTP/1.", StringComparison.OrdinalIgnoreCase) && (text.Contains("200") || text.Contains("403") || text.Contains("407"));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Читает баннер (например, «SSH»/«HTTP») для идентификации сервиса на localhost.</summary>
    public static async Task<string?> ReadBannerAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"), cts.Token).ConfigureAwait(false);
            var buffer = new byte[256];
            var read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
            return read > 0 ? Encoding.ASCII.GetString(buffer, 0, Math.Min(read, 120)).Split('\r')[0] : null;
        }
        catch
        {
            return null;
        }
    }

    public static string Describe(Exception? ex) => ex switch
    {
        null => "неизвестно",
        SocketException se => se.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => "соединение отклонено",
            SocketError.TimedOut => "таймаут",
            SocketError.HostUnreachable => "хост недоступен",
            SocketError.NetworkUnreachable => "сеть недоступна",
            SocketError.ConnectionReset => "соединение сброшено",
            _ => se.SocketErrorCode.ToString(),
        },
        _ => ex.GetBaseException().Message,
    };
}

/// <summary>STUN binding-запрос: какой внешний адрес видит сеть при UDP.</summary>
public static class StunClient
{
    private const uint MagicCookie = 0x2112A442;

    public static async Task<IPEndPoint?> BindAsync(string server, TimeSpan timeout, CancellationToken ct = default)
    {
        var parts = server.Split(':');
        var host = parts[0];
        var port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 3478;
        try
        {
            var addresses = await ConnectivityProbes.ResolveAsync(host, ct).ConfigureAwait(false);
            if (addresses.Count == 0) return null;

            using var udp = new UdpClient(addresses[0].AddressFamily);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var request = BuildBindingRequest();
            await udp.SendAsync(request, request.Length, new IPEndPoint(addresses[0], port)).ConfigureAwait(false);
            var response = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
            return ParseXorMapped(response.Buffer);
        }
        catch
        {
            return null;
        }
    }

    private static byte[] BuildBindingRequest()
    {
        var buffer = new byte[20];
        buffer[0] = 0x00; buffer[1] = 0x01; // Binding Request
        buffer[2] = 0x00; buffer[3] = 0x00; // length
        Buffer.BlockCopy(BitConverter.GetBytes(MagicCookie).Reverse().ToArray(), 0, buffer, 4, 4);
        var transaction = new byte[12];
        Random.Shared.NextBytes(transaction);
        Buffer.BlockCopy(transaction, 0, buffer, 8, 12);
        return buffer;
    }

    private static IPEndPoint? ParseXorMapped(byte[] data)
    {
        if (data.Length < 20) return null;
        var length = (data[2] << 8) | data[3];
        var offset = 20;
        while (offset + 4 <= 20 + length && offset + 4 <= data.Length)
        {
            var type = (data[offset] << 8) | data[offset + 1];
            var attrLen = (data[offset + 2] << 8) | data[offset + 3];
            var value = offset + 4;
            if (type == 0x0020 && value + 8 <= data.Length) // XOR-MAPPED-ADDRESS
            {
                var family = data[value + 1];
                var port = ((data[value + 2] << 8) | data[value + 3]) ^ 0x2112;
                if (family == 0x01)
                {
                    var ipBytes = new byte[4];
                    for (var i = 0; i < 4; i++) ipBytes[i] = (byte)(data[value + 4 + i] ^ data[4 + i]);
                    return new IPEndPoint(new IPAddress(ipBytes), port);
                }
            }
            offset = value + attrLen + ((4 - attrLen % 4) % 4);
        }
        return null;
    }
}
