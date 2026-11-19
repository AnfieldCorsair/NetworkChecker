using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetworkChecker.Core.VpnAudit;

public sealed record RttSample(int Attempt, bool Ok, int? Ms, string? Error = null);

public sealed record RttBenchmarkResult(
    string Host,
    int Port,
    string? TargetIp,
    int DnsMs,
    int Attempts,
    int Succeeded,
    int LossPct,
    int? MinMs,
    int? AvgMs,
    int? P95Ms,
    int? MaxMs,
    int? JitterMs,
    IReadOnlyList<RttSample> Samples);

/// <summary>
/// Серийный замер TCP RTT (Round Trip Time) напрямую с локального ПК Windows.
/// Позволяет сравнивать реальную задержку и джиттер разных узлов VLESS до и после патчей.
/// </summary>
public static class RttBenchmarkProbe
{
    public static async Task<RttBenchmarkResult> RunAsync(
        string host,
        int port = 443,
        int attempts = 6,
        int timeoutMs = 4000,
        CancellationToken cancellationToken = default)
    {
        var count = Math.Clamp(attempts, 3, 10);
        var dnsSw = Stopwatch.StartNew();
        IPAddress targetIp;

        if (!IPAddress.TryParse(host, out targetIp!))
        {
            var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            targetIp = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                       ?? addresses.First();
        }
        dnsSw.Stop();

        var samples = new List<RttSample>(count);
        for (var i = 1; i <= count; i++)
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            var sw = Stopwatch.StartNew();
            try
            {
                await client.ConnectAsync(targetIp, port, cts.Token).ConfigureAwait(false);
                sw.Stop();
                samples.Add(new RttSample(i, true, Math.Max(1, (int)sw.ElapsedMilliseconds)));
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                sw.Stop();
                samples.Add(new RttSample(i, false, null, ex.Message));
            }
        }

        var okValues = samples.Where(s => s.Ok && s.Ms.HasValue).Select(s => s.Ms!.Value).ToArray();
        var sorted = okValues.OrderBy(v => v).ToArray();

        int? minMs = sorted.Length > 0 ? sorted[0] : null;
        int? maxMs = sorted.Length > 0 ? sorted[^1] : null;
        int? avgMs = sorted.Length > 0 ? (int)Math.Round(sorted.Average()) : null;
        int? p95Ms = sorted.Length > 0
            ? sorted[Math.Min(sorted.Length - 1, (int)Math.Ceiling(sorted.Length * 0.95) - 1)]
            : null;

        int? jitterMs = null;
        if (okValues.Length >= 2)
        {
            var totalDiff = 0;
            for (var i = 1; i < okValues.Length; i++)
            {
                totalDiff += Math.Abs(okValues[i] - okValues[i - 1]);
            }
            jitterMs = (int)Math.Round((double)totalDiff / (okValues.Length - 1));
        }
        else if (okValues.Length == 1)
        {
            jitterMs = 0;
        }

        var lossPct = (int)Math.Round(((double)(count - okValues.Length) / count) * 100);

        return new RttBenchmarkResult(
            host,
            port,
            targetIp.ToString(),
            (int)dnsSw.ElapsedMilliseconds,
            count,
            okValues.Length,
            lossPct,
            minMs,
            avgMs,
            p95Ms,
            maxMs,
            jitterMs,
            samples);
    }
}
