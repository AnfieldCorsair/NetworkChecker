using System.Net;
using System.Net.NetworkInformation;

namespace NetworkChecker.Core.Net;

public sealed record PingResult(bool Success, TimeSpan Roundtrip, int Ttl, string? Address, string? Error);

public sealed record TraceHop(int Index, string? Address, IReadOnlyList<TimeSpan> Samples, string? Asn, string? AsName)
{
    public TimeSpan? BestRtt => Samples.Count == 0 ? null : Samples.Min();
    public bool TimedOut => Address is null;
    public bool IsTerminal => !TimedOut && Samples.Count > 0;
    public string RttText => BestRtt is null ? "* * *" : $"{BestRtt.Value.TotalMilliseconds:F0} мс";
    public string HostText => Address ?? "нет ответа";
}

/// <summary>ICMP-инструменты: пинг, трассировка по TTL, проба пути MTU.</summary>
public static class PingTools
{
    public static async Task<PingResult> PingAsync(string host, TimeSpan timeout, int ttl = 128, int bufferSize = 32, bool dontFragment = false, CancellationToken ct = default)
    {
        try
        {
            using var ping = new Ping();
            var options = new PingOptions(ttl, dontFragment);
            var buffer = new byte[bufferSize];
            Random.Shared.NextBytes(buffer);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var reply = await ping.SendPingAsync(host, timeout, buffer, options, cts.Token).ConfigureAwait(false);
            return reply.Status switch
            {
                IPStatus.Success => new PingResult(true, reply.RoundtripTime >= 0 ? TimeSpan.FromMilliseconds(reply.RoundtripTime) : TimeSpan.Zero,
                    reply.Options?.Ttl ?? ttl, reply.Address?.ToString(), null),
                IPStatus.TtlExpired => new PingResult(false, TimeSpan.FromMilliseconds(Math.Max(0, reply.RoundtripTime)), reply.Options?.Ttl ?? ttl, reply.Address?.ToString(), "ttl-expired"),
                IPStatus.TimedOut => new PingResult(false, TimeSpan.Zero, ttl, null, "таймаут"),
                _ => new PingResult(false, TimeSpan.Zero, ttl, reply.Address?.ToString(), reply.Status.ToString()),
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return new PingResult(false, TimeSpan.Zero, ttl, null, ex.GetBaseException().Message);
        }
    }

    /// <summary>Трассировка по ICMP с нарастающим TTL (работает без прав администратора).</summary>
    public static async Task<IReadOnlyList<TraceHop>> TraceAsync(
        string target,
        int maxHops,
        TimeSpan timeoutPerHop,
        Func<int, Task>? onHop = null,
        CancellationToken ct = default)
    {
        var hops = new List<TraceHop>();
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var samples = new List<TimeSpan>();
            string? address = null;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var result = await PingAsync(target, timeoutPerHop, ttl, 32, false, ct).ConfigureAwait(false);
                if (result.Address is not null) address ??= result.Address;
                if (result.Success || result.Error == "ttl-expired")
                {
                    address ??= result.Address;
                    if (result.Roundtrip > TimeSpan.Zero) samples.Add(result.Roundtrip);
                    if (result.Success) break;
                }
            }
            hops.Add(new TraceHop(ttl, address, samples, null, null));
            if (onHop is not null) await onHop(ttl).ConfigureAwait(false);
            var last = hops[^1];
            if (last.Address is not null && samples.Count > 0)
            {
                var resolved = await ConnectivityProbes.ResolveAsync(target, ct).ConfigureAwait(false);
                if (resolved.Any(ip => ip.ToString() == last.Address)) break;
            }
            if (address is null && hops.Count(h => h.Address is null) >= 3) break;
        }
        return hops;
    }

    /// <summary>Бинарный поиск MTU пути при помощи ICMP с флагом Don't Fragment.</summary>
    public static async Task<int?> ProbePathMtuAsync(string host, int maxMtu = 1500, int minMtu = 576, CancellationToken ct = default)
    {
        var low = minMtu;
        var high = maxMtu;
        int? best = null;
        var overhead = 28; // IP 20 + ICMP 8
        while (low <= high)
        {
            ct.ThrowIfCancellationRequested();
            var mid = (low + high) / 2;
            var payload = Math.Max(0, mid - overhead);
            var result = await PingAsync(host, TimeSpan.FromSeconds(3), 64, payload, true, ct).ConfigureAwait(false);
            if (result.Success)
            {
                best = mid;
                low = mid + 1;
            }
            else
            {
                high = mid - 1;
            }
        }
        return best;
    }

    /// <summary>N пингов подряд: значение для оценки jitter и стабильности.</summary>
    public static async Task<IReadOnlyList<TimeSpan>> SampleLatencyAsync(string host, int samples, TimeSpan timeout, CancellationToken ct = default)
    {
        var list = new List<TimeSpan>();
        for (var i = 0; i < samples; i++)
        {
            var result = await PingAsync(host, timeout, 128, 32, false, ct).ConfigureAwait(false);
            if (result.Success) list.Add(result.Roundtrip);
            await Task.Delay(60, ct).ConfigureAwait(false);
        }
        return list;
    }

    /// <summary>
    /// Латентность «как получится»: ICMP, а при его блокировке — TCP :443.
    /// Возвращает метод, которым измерено, чтобы UI не врал.
    /// </summary>
    public static async Task<(IReadOnlyList<TimeSpan> Samples, string Method)> SampleLatencyOrTcpAsync(
        string host, int count, TimeSpan timeout, CancellationToken ct = default)
    {
        var icmp = await SampleLatencyAsync(host, count, timeout, ct).ConfigureAwait(false);
        if (icmp.Count > 0) return (icmp, "ICMP");

        var tcp = new List<TimeSpan>();
        for (var i = 0; i < Math.Max(2, count - 2); i++)
        {
            var probe = await ConnectivityProbes.TcpConnectAsync(host, 443, timeout, ct).ConfigureAwait(false);
            if (!probe.Success) probe = await ConnectivityProbes.TcpConnectAsync(host, 80, timeout, ct).ConfigureAwait(false);
            if (probe.Success) tcp.Add(probe.Elapsed);
            await Task.Delay(40, ct).ConfigureAwait(false);
        }
        return (tcp, tcp.Count > 0 ? "TCP" : "нет");
    }

    public static (double median, double jitter, double loss)? Summarize(IReadOnlyList<TimeSpan> samples, int attempts)
    {
        if (attempts == 0) return null;
        var loss = (attempts - samples.Count) / (double)attempts * 100;
        if (samples.Count == 0) return (double.NaN, double.NaN, loss);
        var ordered = samples.Select(s => s.TotalMilliseconds).OrderBy(v => v).ToArray();
        var median = ordered[ordered.Length / 2];
        var mean = ordered.Average();
        var jitter = Math.Sqrt(ordered.Average(v => Math.Pow(v - mean, 2)));
        return (median, jitter, loss);
    }
}

/// <summary>Определение ASN по IP через DNS-сервис Team Cymru (без внешних API-ключей).</summary>
public static class AsnLookup
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (string Asn, string AsName)> Cache = new();

    // Кэш живёт на процесс: ASN для адреса не меняется, повторные запросы в трассировке бессмысленны.
    public static async Task<(string Asn, string AsName)> LookupAsync(string ip, CancellationToken ct = default)
    {
        if (Cache.TryGetValue(ip, out var cached)) return cached;
        if (!IPAddress.TryParse(ip, out var address) || IPAddress.IsLoopback(address))
            return ("—", "локальный адрес");

        string query;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var parts = ip.Split('.');
            query = $"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com";
        }
        else
        {
            return ("—", "IPv6 не поддержан");
        }

        var answer = await DnsClientLite.QueryAsync(query, DnsRecordType.Txt, timeout: TimeSpan.FromSeconds(3), ct: ct).ConfigureAwait(false);
        var txt = answer.Count > 0 ? answer[0].Value : null;
        if (string.IsNullOrWhiteSpace(txt)) return Cache[ip] = ("—", "нет данных");

        // Формат: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
        var fields = txt.Split('|');
        var asn = fields.Length > 0 ? fields[0].Trim() : "—";
        var nameAnswer = await DnsClientLite.QueryAsync($"AS{asn}.asn.cymru.com", DnsRecordType.Txt, timeout: TimeSpan.FromSeconds(3), ct: ct).ConfigureAwait(false);
        var asName = nameAnswer.Count > 0 ? nameAnswer[0].Value : null;
        if (!string.IsNullOrWhiteSpace(asName))
        {
            var parts = asName.Split('|');
            asName = parts.Length > 4 ? parts[4].Trim() : asName;
        }
        return Cache[ip] = (asn, asName ?? "—");
    }
}
