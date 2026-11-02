using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using NetworkChecker.Core.Abstractions;

namespace NetworkChecker.Core.Net;

/// <summary>Парсер JSON-ответа DoH-резолвера (формат Google DNS / RFC 8484 JSON).</summary>
public static class DohAnswerParser
{
    public static IReadOnlyList<string> Parse(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return Array.Empty<string>();
        try
        {
            using var document = JsonDocument.Parse(body);
            if (!document.RootElement.TryGetProperty("Answer", out var answers) ||
                answers.ValueKind != JsonValueKind.Array)
            {
                return Array.Empty<string>();
            }
            var result = new List<string>();
            foreach (var item in answers.EnumerateArray())
            {
                if (!item.TryGetProperty("type", out var type) || !type.TryGetInt32(out var recordType) || recordType != 1) continue;
                if (!item.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.String) continue;
                var text = data.GetString();
                if (IPAddress.TryParse(text, out var parsed)) result.Add(parsed.ToString());
            }
            return result.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch (JsonException) { return Array.Empty<string>(); }
        catch (InvalidOperationException) { return Array.Empty<string>(); }
    }
}

/// <summary>
/// Реализация <see cref="ITransportProbes"/> на системных сокетах и HTTP-зонде приложения.
/// Все пробы наблюдательные: они не пытаются обойти фильтрацию и не меняют настройки ОС.
/// </summary>
public sealed class SystemTransportProbes(IHttpProbe http) : ITransportProbes
{
    private readonly IHttpProbe _http = http;

    public async Task<IReadOnlyList<string>> ResolveSystemAsync(string name, CancellationToken ct = default)
    {
        var addresses = await ConnectivityProbes.ResolveAsync(name, ct).ConfigureAwait(false);
        return addresses.Select(a => a.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public async Task<IReadOnlyList<string>> ResolveDohAsync(string name, TimeSpan timeout, CancellationToken ct = default)
    {
        var url = $"https://dns.google/resolve?name={Uri.EscapeDataString(name)}&type=A";
        var response = await _http.GetAsync(new Uri(url), timeout, ignoreProxy: false, ct).ConfigureAwait(false);
        return response.Success && response.Body is not null
            ? DohAnswerParser.Parse(response.Body)
            : Array.Empty<string>();
    }

    public async Task<UdpProbeResult> UdpAsync(string host, int port, byte[] payload, TimeSpan timeout, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var sw = Stopwatch.StartNew();
        try
        {
            var addresses = await ConnectivityProbes.ResolveAsync(host, ct).ConfigureAwait(false);
            if (addresses.Count == 0) return new UdpProbeResult(false, sw.Elapsed, "DNS не разрешил имя");

            using var client = new UdpClient(addresses[0].AddressFamily);
            client.Connect(addresses[0], port);
            await client.SendAsync(payload, payload.Length).ConfigureAwait(false);
            var pending = client.ReceiveAsync();
            var reply = await pending.WaitAsync(timeout, ct).ConfigureAwait(false);
            return new UdpProbeResult(reply.Buffer.Length > 0, sw.Elapsed, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (TimeoutException) { return new UdpProbeResult(false, sw.Elapsed, "ответа нет"); }
        catch (Exception ex)
        {
            return new UdpProbeResult(false, sw.Elapsed, ConnectivityProbes.Describe(ex));
        }
    }

    public async Task<TlsProbeOutcome> TlsAsync(string host, string sni, TimeSpan timeout, CancellationToken ct = default)
    {
        var result = await ConnectivityProbes.TlsHandshakeAsync(host, 443, sni, timeout, ct).ConfigureAwait(false);
        return new TlsProbeOutcome(result.Success, result.Elapsed, result.Error);
    }
}
