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
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            var addresses = await ResolveAsync(host, deadline.Token).ConfigureAwait(false);
            if (addresses.Count == 0) return new TcpProbeResult(false, sw.Elapsed, "DNS не разрешил имя", null);
            Exception? last = null;
            foreach (var ip in addresses)
            {
                using var client = new TcpClient(ip.AddressFamily);
                try
                {
                    await client.ConnectAsync(ip, port, deadline.Token).ConfigureAwait(false);
                    return new TcpProbeResult(true, sw.Elapsed, null, ip.ToString());
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    last = ex;
                }
            }
            return new TcpProbeResult(false, sw.Elapsed, Describe(last), null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return new TcpProbeResult(false, sw.Elapsed, "таймаут", null); }
        catch (Exception ex)
        {
            return new TcpProbeResult(false, sw.Elapsed, Describe(ex), null);
        }
    }

    public static async Task<TlsProbeResult> TlsHandshakeAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            var addresses = await ResolveAsync(host, deadline.Token).ConfigureAwait(false);
            if (addresses.Count == 0)
                return new TlsProbeResult(false, sw.Elapsed, "DNS не разрешил имя", null, null, null, null, null, false);

            var ip = addresses[0];
            using var client = new TcpClient(ip.AddressFamily);
            await client.ConnectAsync(ip, port, deadline.Token).ConfigureAwait(false);
            // TLS-зонд: сертификат нам нужен как данные (издатель, срок), а не как доверие.
            // Валидацию сознательно отключаем — иначе MITM-сертификат не прочитать.
#pragma warning disable CA5359
            SslPolicyErrors validationErrors = SslPolicyErrors.None;
            using var ssl = new SslStream(client.GetStream(), false, (_, _, _, errors) =>
            {
                validationErrors = errors;
                return true; // Диагностический сбор сертификата, не доверенное соединение.
            });
#pragma warning restore CA5359
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }, deadline.Token).ConfigureAwait(false);

            var cert = ssl.RemoteCertificate as X509Certificate2 ?? new X509Certificate2(ssl.RemoteCertificate!);
            var chainValid = validationErrors == SslPolicyErrors.None;
            return new TlsProbeResult(true, sw.Elapsed, null, cert.Subject, cert.Issuer, cert.NotAfter.ToLocalTime(),
                ssl.SslProtocol.ToString(), ip.ToString(), chainValid);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return new TlsProbeResult(false, sw.Elapsed, "таймаут", null, null, null, null, null, false); }
        catch (Exception ex)
        {
            return new TlsProbeResult(false, sw.Elapsed, Describe(ex), null, null, null, null, null, false);
        }
    }

    public static async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (IPAddress.TryParse(host, out var direct)) return [direct];
        try
        {
            var result = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return [.. result.Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).Take(4)];
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
            return response[0] == 0x05 && response[1] == 0x00;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
            var firstLine = text.Split('\r', '\n')[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return firstLine.Length >= 2 && firstLine[0].StartsWith("HTTP/1.", StringComparison.OrdinalIgnoreCase)
                && firstLine[1] == "200";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
        if (!TryParseServer(server, out var host, out var port)) return null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            var addresses = await ConnectivityProbes.ResolveAsync(host, deadline.Token).ConfigureAwait(false);
            if (addresses.Count == 0) return null;

            using var udp = new UdpClient(addresses[0].AddressFamily);
            var request = BuildBindingRequest();
            udp.Connect(addresses[0], port);
            await udp.SendAsync(request, deadline.Token).ConfigureAwait(false);
            var response = await udp.ReceiveAsync(deadline.Token).ConfigureAwait(false);
            return ParseXorMapped(response.Buffer, request);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch
        {
            return null;
        }
    }

    internal static bool TryParseServer(string server, out string host, out int port)
    {
        host = "";
        port = 3478;
        var value = server.Trim();
        if (value.StartsWith('['))
        {
            var end = value.IndexOf(']');
            if (end <= 1 || !IPAddress.TryParse(value[1..end], out var ipv6) || ipv6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            host = ipv6.ToString();
            if (end == value.Length - 1) return true;
            return value[end + 1] == ':' && int.TryParse(value[(end + 2)..], out port) && port is > 0 and <= 65535;
        }
        if (IPAddress.TryParse(value, out var address)) { host = address.ToString(); return true; }
        var separator = value.IndexOf(':');
        if (separator < 0) { host = value; return host.Length > 0; }
        host = value[..separator];
        return host.Length > 0 && int.TryParse(value[(separator + 1)..], out port) && port is > 0 and <= 65535;
    }

    private static byte[] BuildBindingRequest()
    {
        var buffer = new byte[20];
        buffer[0] = 0x00; buffer[1] = 0x01; // Binding Request
        buffer[2] = 0x00; buffer[3] = 0x00; // length
        Buffer.BlockCopy(BitConverter.GetBytes(MagicCookie).Reverse().ToArray(), 0, buffer, 4, 4);
        var transaction = new byte[12];
        System.Security.Cryptography.RandomNumberGenerator.Fill(transaction);
        Buffer.BlockCopy(transaction, 0, buffer, 8, 12);
        return buffer;
    }

    internal static IPEndPoint? ParseXorMapped(byte[] data, byte[] request)
    {
        // Проверяются тип Binding Success, cookie, transaction ID и полная длина.
        // Это не аутентификация STUN-сервера; она не предусмотрена данной пробой.
        if (request.Length < 20 || data.Length < 20 || data[0] != 0x01 || data[1] != 0x01 ||
            !data.AsSpan(4, 4).SequenceEqual(request.AsSpan(4, 4)) ||
            !data.AsSpan(8, 12).SequenceEqual(request.AsSpan(8, 12))) return null;
        var length = (data[2] << 8) | data[3];
        if (length % 4 != 0 || length > data.Length - 20) return null;
        var end = 20 + length;
        for (var offset = 20; offset + 4 <= end;)
        {
            var type = (data[offset] << 8) | data[offset + 1];
            var attrLen = (data[offset + 2] << 8) | data[offset + 3];
            var value = offset + 4;
            var padded = (attrLen + 3) & ~3;
            if (value + padded > end) return null;
            if (type == 0x0020 && attrLen >= 8 && data[value] == 0)
            {
                var family = data[value + 1];
                var size = family == 1 ? 4 : family == 2 ? 16 : 0;
                if (size == 0 || attrLen < 4 + size) return null;
                var port = ((data[value + 2] << 8) | data[value + 3]) ^ 0x2112;
                var bytes = new byte[size];
                for (var i = 0; i < size; i++) bytes[i] = (byte)(data[value + 4 + i] ^ request[4 + i]);
                return new IPEndPoint(new IPAddress(bytes), port);
            }
            offset = value + padded;
        }
        return null;
    }
}
