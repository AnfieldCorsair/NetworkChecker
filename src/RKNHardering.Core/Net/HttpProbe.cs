using System.Diagnostics;
using System.Net;
using RKNHardering.Core.Abstractions;

namespace RKNHardering.Core.Net;

/// <summary>Аккуратный HTTP-зонд: без редиректов «в бесконечность», с честным таймаутом и User-Agent.</summary>
public sealed class HttpProbe : IHttpProbe, IDisposable
{
    private readonly HttpClient _direct;
    private readonly HttpClient _system;

    public string UserAgent { get; set; } = "RKNHardering-PC/1.0 (+desktop port of RKNHardering)";

    public HttpProbe()
    {
        _direct = Create(useProxy: false);
        _system = Create(useProxy: true);
    }

    private HttpClient Create(bool useProxy)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = useProxy,
            Proxy = useProxy ? HttpClient.DefaultProxy : null,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 4,
            ConnectTimeout = TimeSpan.FromSeconds(6),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AutomaticDecompression = DecompressionMethods.All,
        };
        var client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json, text/plain, */*");
        return client;
    }

    public async Task<HttpProbeResult> GetAsync(Uri uri, TimeSpan timeout, bool ignoreProxy, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var client = ignoreProxy ? _direct : _system;
        try
        {
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseContentRead, cts.Token)
                .ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return new HttpProbeResult(
                Success: response.IsSuccessStatusCode,
                StatusCode: (int)response.StatusCode,
                Body: body,
                Error: response.IsSuccessStatusCode ? null : $"HTTP {(int)response.StatusCode}",
                Elapsed: sw.Elapsed,
                FinalUri: response.RequestMessage?.RequestUri?.ToString(),
                ServerHeader: response.Headers.TryGetValues("server", out var s) ? string.Join(",", s) : null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new HttpProbeResult(false, 0, null, "таймаут", sw.Elapsed, null, null);
        }
        catch (Exception ex)
        {
            return new HttpProbeResult(false, 0, null, ex.GetBaseException().Message, sw.Elapsed, null, null);
        }
    }

    public void Dispose()
    {
        _direct.Dispose();
        _system.Dispose();
    }
}
