using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkChecker.Core.Abstractions;

namespace NetworkChecker.Core.Net;

public enum DnsRecordType : ushort
{
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Reverse = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Https = 65,
}

public sealed record DnsAnswer(string Name, DnsRecordType Type, uint Ttl, string Value);

/// <summary>Минимальный DNS-клиент (UDP + TCP fallback) — нужен для запросов к конкретному серверу.</summary>
public static class DnsWire
{
    public static byte[] BuildQuery(string name, DnsRecordType type, ushort id)
    {
        var buffer = new List<byte>(64)
        {
            (byte)(id >> 8),
            (byte)(id & 0xFF),
            0x01, // RD
            0x00,
            0,
            1 // QDCOUNT
        };
        for (var i = 0; i < 3; i++) { buffer.Add(0); buffer.Add(0); }

        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }
        buffer.Add(0);
        buffer.Add((byte)((ushort)type >> 8));
        buffer.Add((byte)((ushort)type & 0xFF));
        buffer.Add(0); buffer.Add(1); // IN
        return [.. buffer];
    }

    public static IReadOnlyList<DnsAnswer> ParseResponse(byte[] data)
    {
        var answers = new List<DnsAnswer>();
        if (data.Length < 12) return answers;
        var qdCount = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4));
        var anCount = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(6));
        var offset = 12;
        for (var i = 0; i < qdCount; i++)
        {
            offset = SkipName(data, offset);
            offset += 4;
        }
        for (var i = 0; i < anCount && offset + 10 <= data.Length; i++)
        {
            var name = ReadName(data, ref offset);
            if (offset + 10 > data.Length) break;
            var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset));
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset + 4));
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 8));
            offset += 10;
            if (offset + rdLength > data.Length) break;
            var rdata = data.AsSpan(offset, rdLength);

            switch (type)
            {
                case DnsRecordType.A when rdLength == 4:
                    answers.Add(new DnsAnswer(name, type, ttl, new IPAddress(rdata.ToArray()).ToString()));
                    break;
                case DnsRecordType.Aaaa when rdLength == 16:
                    answers.Add(new DnsAnswer(name, type, ttl, new IPAddress(rdata.ToArray()).ToString()));
                    break;
                case DnsRecordType.Cname:
                    {
                        var pos = offset;
                        answers.Add(new DnsAnswer(name, type, ttl, ReadName(data, ref pos)));
                        break;
                    }
                case DnsRecordType.Txt:
                    {
                        var pos = 0;
                        var sb = new StringBuilder();
                        while (pos < rdata.Length)
                        {
                            var len = rdata[pos];
                            if (pos + 1 + len > rdata.Length) break;
                            sb.Append(Encoding.ASCII.GetString(rdata.Slice(pos + 1, len)));
                            pos += 1 + len;
                        }
                        answers.Add(new DnsAnswer(name, type, ttl, sb.ToString().Trim()));
                        break;
                    }
            }
            offset += rdLength;
        }
        return answers;
    }

    private static int SkipName(byte[] data, int offset)
    {
        while (offset < data.Length)
        {
            var len = data[offset];
            if (len == 0) return offset + 1;
            if ((len & 0xC0) == 0xC0) return offset + 2;
            offset += len + 1;
        }
        return offset;
    }

    private static string ReadName(byte[] data, ref int offset)
    {
        var parts = new List<string>();
        var jumps = 0;
        var pos = offset;
        var next = offset;
        while (pos < data.Length && jumps < 16)
        {
            var len = data[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= data.Length) break;
                var pointer = ((len & 0x3F) << 8) | data[pos + 1];
                if (jumps == 0) next = pos + 2;
                pos = pointer;
                jumps++;
                continue;
            }
            if (pos + 1 + len > data.Length) break;
            parts.Add(Encoding.ASCII.GetString(data, pos + 1, len));
            pos += len + 1;
            if (jumps == 0) next = pos;
        }
        offset = jumps > 0 ? next : pos;
        return string.Join('.', parts);
    }
}

/// <summary>Запросы к конкретному DNS-серверу: UDP, при обрезке — TCP, плюс DoH.</summary>
public sealed class DnsClientLite(IHttpProbe http) : IDisposable
{
    private readonly IHttpProbe _http = http;

    public static async Task<IReadOnlyList<DnsAnswer>> QueryAsync(
        string name,
        DnsRecordType type,
        IPEndPoint? server = null,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        server ??= new IPEndPoint(IPAddress.Parse(DefaultResolver()), 53);
        var id = (ushort)System.Security.Cryptography.RandomNumberGenerator.GetInt32(65536);
        var query = DnsWire.BuildQuery(name, type, id);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout ?? TimeSpan.FromSeconds(4));
        try
        {
            using var udp = new UdpClient(server.AddressFamily);
            // Подключённый UDP-сокет принимает ответы только от выбранного сервера.
            udp.Connect(server);
            await udp.SendAsync(query, deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var received = await udp.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                if (!IsMatchingResponse(received.Buffer, query)) continue;
                if ((received.Buffer[3] & 0x0F) != 0) return Array.Empty<DnsAnswer>();
                if ((received.Buffer[2] & 0x02) != 0)
                    return await QueryTcpAsync(query, server, deadline.Token).ConfigureAwait(false);
                return DnsWire.ParseResponse(received.Buffer);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Array.Empty<DnsAnswer>(); }
        catch (SocketException)
        {
            try { return await QueryTcpAsync(query, server, deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { return Array.Empty<DnsAnswer>(); }
        }
    }

    // Проверка корреляции не является криптографической аутентификацией DNS.
    private static bool IsMatchingResponse(byte[] response, byte[] query)
    {
        if (response.Length < query.Length || response.Length < 12 ||
            response[0] != query[0] || response[1] != query[1] ||
            (response[2] & 0xF8) != 0x80 ||
            response[4] != 0 || response[5] != 1) return false;
        for (var i = 12; i < query.Length; i++)
        {
            var a = response[i];
            var b = query[i];
            if (i < query.Length - 4)
            {
                if (a is >= (byte)'A' and <= (byte)'Z') a += 32;
                if (b is >= (byte)'A' and <= (byte)'Z') b += 32;
            }
            if (a != b) return false;
        }
        return true;
    }

    private static async Task<IReadOnlyList<DnsAnswer>> QueryTcpAsync(byte[] query, IPEndPoint server, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient(server.AddressFamily);
            await tcp.ConnectAsync(server.Address, server.Port, ct).ConfigureAwait(false);
            var stream = tcp.GetStream();
            var framed = new byte[query.Length + 2];
            framed[0] = (byte)(query.Length >> 8);
            framed[1] = (byte)(query.Length & 0xFF);
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed, ct).ConfigureAwait(false);
            var lenBuf = new byte[2];
            await stream.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
            var len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
            var response = new byte[len];
            await stream.ReadExactlyAsync(response, ct).ConfigureAwait(false);
            return IsMatchingResponse(response, query) && (response[2] & 0x02) == 0 && (response[3] & 0x0F) == 0
                ? DnsWire.ParseResponse(response) : Array.Empty<DnsAnswer>();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            return Array.Empty<DnsAnswer>();
        }
    }

    /// <summary>DNS-over-HTTPS запрос (Cloudflare JSON API).</summary>
    public async Task<IReadOnlyList<DnsAnswer>> QueryDohAsync(string name, DnsRecordType type, TimeSpan timeout, CancellationToken ct = default)
    {
        var typeParam = type switch
        {
            DnsRecordType.A => "A",
            DnsRecordType.Txt => "TXT",
            DnsRecordType.Aaaa => "AAAA",
            _ => "A",
        };
        var uri = new Uri($"https://cloudflare-dns.com/dns-query?name={Uri.EscapeDataString(name)}&type={typeParam}");
        var result = await _http.GetAsync(uri, timeout, ignoreProxy: false, ct).ConfigureAwait(false);
        if (!result.Success || string.IsNullOrWhiteSpace(result.Body)) return Array.Empty<DnsAnswer>();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(result.Body);
            if (!doc.RootElement.TryGetProperty("Answer", out var answer)) return Array.Empty<DnsAnswer>();
            var list = new List<DnsAnswer>();
            foreach (var item in answer.EnumerateArray())
            {
                var t = (DnsRecordType)item.GetProperty("type").GetInt32();
                var data = item.GetProperty("data").GetString() ?? string.Empty;
                var ttl = item.TryGetProperty("TTL", out var ttlEl) ? ttlEl.GetUInt32() : 0;
                list.Add(new DnsAnswer(name, t, ttl, data.Trim('"')));
            }
            return list;
        }
        catch
        {
            return Array.Empty<DnsAnswer>();
        }
    }

    private static string DefaultResolver()
    {
        try
        {
            var props = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
            var server = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(n => n.GetIPProperties().DnsAddresses)
                .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
            return server?.ToString() ?? "1.1.1.1";
        }
        catch
        {
            return "1.1.1.1";
        }
    }

    public void Dispose() { }
}
