using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetworkChecker.Core.Net;

public enum IcmpStatus
{
    Timeout = 0,
    EchoReply = 1,
    TtlExpired = 2,
    Unreachable = 3,
    Error = 4,
}

public sealed record IcmpReply(IcmpStatus Status, string? Address, double RttMs, int Ttl, string? Error = null);

/// <summary>
/// ICMP через raw-сокет. На Windows требует прав администратора (и часто блокируется),
/// на Linux/macOS нужен CAP_NET_RAW. Если недоступен — вызывающий код использует Ping.
/// </summary>
public sealed class RawIcmp : IDisposable
{
    private readonly Socket? _socket;
    private readonly ushort _identifier;
    private ushort _sequence;

    public RawIcmp()
    {
        _identifier = (ushort)(Environment.ProcessId & 0xFFFF);
        try
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp)
            {
                ReceiveTimeout = 3000
            };
            IsAvailable = true;
        }
        catch
        {
            _socket = null;
            IsAvailable = false;
        }
    }

    public bool IsAvailable { get; }

    /// <summary>Эхо-запрос с заданным TTL. Блокирующий, вызывать из фонового потока.</summary>
    public IcmpReply SendEcho(string address, int ttl, int payloadSize, int timeoutMs)
    {
        if (_socket is null) return new IcmpReply(IcmpStatus.Error, null, 0, ttl, "raw-сокет недоступен");
        if (!IPAddress.TryParse(address, out var ip))
        {
            var resolved = Dns.GetHostAddresses(address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (resolved is null) return new IcmpReply(IcmpStatus.Error, null, 0, ttl, "DNS не разрешил имя");
            ip = resolved;
        }

        var sequence = _sequence++;
        var packet = BuildPacket(_identifier, sequence, Math.Clamp(payloadSize, 8, 1400));
        var endpoint = new IPEndPoint(ip, 0);
        var sw = Stopwatch.StartNew();
        try
        {
            _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, Math.Clamp(ttl, 1, 255));
            _socket.SendTo(packet, endpoint);

            var buffer = new byte[1500];
            _socket.ReceiveTimeout = Math.Max(200, timeoutMs);
            var deadline = Environment.TickCount64 + Math.Max(200, timeoutMs);
            while (Environment.TickCount64 <= deadline)
            {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int read;
                try
                {
                    read = _socket.ReceiveFrom(buffer, ref from);
                }
                catch (SocketException)
                {
                    break;
                }
                if (read < 20) continue;

                var reply = ParseReply(buffer, read, ip);
                if (reply is null) continue;
                var elapsed = sw.Elapsed.TotalMilliseconds;

                // На Linux ответ приходит с IP-заголовком, на Windows — без него.
                var type = buffer[0] == 0x45 ? buffer[20] : buffer[0];
                if (type is 0) return new IcmpReply(IcmpStatus.EchoReply, (from as IPEndPoint)?.Address.ToString(), elapsed, ttl);
                if (type is 11) return new IcmpReply(IcmpStatus.TtlExpired, (from as IPEndPoint)?.Address.ToString(), elapsed, ttl);
                if (type is 3) return new IcmpReply(IcmpStatus.Unreachable, (from as IPEndPoint)?.Address.ToString(), elapsed, ttl, "destination unreachable");
            }
            return new IcmpReply(IcmpStatus.Timeout, null, sw.Elapsed.TotalMilliseconds, ttl);
        }
        catch (Exception ex)
        {
            return new IcmpReply(IcmpStatus.Error, null, 0, ttl, ex.Message);
        }
    }

    private static IcmpReply? ParseReply(byte[] buffer, int read, IPAddress target)
    {
        // Проверяем корректность структуры: либо с IP-заголовком, либо без.
        var withIpHeader = buffer[0] == 0x45;
        var icmpOffset = withIpHeader ? 20 : 0;
        if (read < icmpOffset + 8) return null;
        var type = buffer[icmpOffset];
        if (type is not (0 or 3 or 11)) return null;
        return new IcmpReply(IcmpStatus.EchoReply, null, 0, 0);
    }

    private static byte[] BuildPacket(ushort identifier, ushort sequence, int payloadSize)
    {
        var payload = new byte[Math.Max(16, payloadSize)];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)('a' + i % 26);

        var packet = new byte[8 + payload.Length];
        packet[0] = 8; // echo request
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        packet[4] = (byte)(identifier >> 8);
        packet[5] = (byte)(identifier & 0xFF);
        packet[6] = (byte)(sequence >> 8);
        packet[7] = (byte)(sequence & 0xFF);
        payload.CopyTo(packet, 8);

        var checksum = Checksum(packet);
        packet[2] = (byte)(checksum >> 8);
        packet[3] = (byte)(checksum & 0xFF);
        return packet;
    }

    private static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var index = 0;
        while (index + 1 < data.Length)
        {
            sum += (uint)((data[index] << 8) | data[index + 1]);
            index += 2;
        }
        if (index < data.Length) sum += (uint)(data[index] << 8);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public void Dispose()
    {
        _socket?.Dispose();
    }
}

/// <summary>
/// Трассировка: raw ICMP, если он доступен, иначе последовательный Ping с нарастающим TTL.
/// Второй режим не требует прав и работает везде, где ICMP не запрещён файрволом.
/// </summary>
public static class TraceTool
{
    public static async Task<(IReadOnlyList<TraceHop> Hops, string Mode)> TraceAsync(
        string target,
        int maxHops,
        int attempts,
        int timeoutMs,
        IProgress<TraceHop>? progress,
        CancellationToken ct)
    {
        using var raw = new RawIcmp();
        if (raw.IsAvailable)
        {
            var viaRaw = await TraceRawAsync(raw, target, maxHops, attempts, timeoutMs, progress, ct).ConfigureAwait(false);
            if (viaRaw.Count > 0 && viaRaw.Any(h => h.Address is not null))
                return (viaRaw, "ICMP raw-сокет");
        }

        var hops = new List<TraceHop>();
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var samples = new List<TimeSpan>();
            string? address = null;
            var reached = false;
            for (var attempt = 0; attempt < attempts; attempt++)
            {
                var reply = await PingTools.PingAsync(target, TimeSpan.FromMilliseconds(timeoutMs), ttl, 32, false, ct)
                    .ConfigureAwait(false);
                if (reply.Address is not null) address ??= reply.Address;
                if (reply.Success)
                {
                    samples.Add(reply.Roundtrip);
                    reached = true;
                    break;
                }
                if (reply.Error == "ttl-expired" && reply.Address is not null)
                {
                    address = reply.Address;
                    break;
                }
            }

            var hop = new TraceHop(ttl, address, samples, null, null);
            hops.Add(hop);
            progress?.Report(hop);
            if (reached) break;
            if (address is null && hops.Count(h => h.Address is null) >= 3) break;
        }
        return (hops, "ICMP через Ping");
    }

    private static async Task<List<TraceHop>> TraceRawAsync(
        RawIcmp raw,
        string target,
        int maxHops,
        int attempts,
        int timeoutMs,
        IProgress<TraceHop>? progress,
        CancellationToken ct)
    {
        var hops = new List<TraceHop>();
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            var samples = new List<TimeSpan>();
            string? address = null;
            var reached = false;
            for (var attempt = 0; attempt < attempts; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                var reply = await Task.Run(() => raw.SendEcho(target, ttl, 32, timeoutMs), ct).ConfigureAwait(false);
                if (reply.Status == IcmpStatus.EchoReply)
                {
                    address ??= reply.Address;
                    samples.Add(TimeSpan.FromMilliseconds(reply.RttMs));
                    reached = true;
                    break;
                }
                if (reply.Status == IcmpStatus.TtlExpired && reply.Address is not null)
                {
                    address = reply.Address;
                    samples.Add(TimeSpan.FromMilliseconds(reply.RttMs));
                    break;
                }
            }
            var hop = new TraceHop(ttl, address, samples, null, null);
            hops.Add(hop);
            progress?.Report(hop);
            if (reached) break;
            if (address is null && hops.Count(h => h.Address is null) >= 3) break;
        }
        return hops;
    }
}
