using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetworkChecker.Core.Abstractions;

namespace NetworkChecker.Core.Net;

/// <summary>
/// Реализация <see cref="IExternalProbe"/>: HTTP с произвольными заголовками/User-Agent
/// и DNS-запросы системным резолвером. Те же ограничения, что у <see cref="HttpProbe"/>:
/// честный таймаут, не более четырёх редиректов и потолок тела ответа 1 МиБ.
/// </summary>
public sealed class ExternalHttpProbe : IExternalProbe, IDisposable
{
    public const string DefaultUserAgent = "NetworkChecker/1.6 (+Windows; local reputation diagnostics)";

    private readonly HttpClient _direct;
    private readonly HttpClient _system;

    public ExternalHttpProbe()
    {
        _direct = Create(useProxy: false);
        _system = Create(useProxy: true);
    }

    private static HttpClient Create(bool useProxy)
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
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public async Task<HttpProbeResult> GetAsync(ExternalProbeRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var sw = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(request.Timeout);
        var client = request.IgnoreProxy ? _direct : _system;
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Get, request.Uri);
            if (request.Headers is not null)
            {
                foreach (var pair in request.Headers)
                    message.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
            message.Headers.UserAgent.Clear();
            message.Headers.UserAgent.ParseAdd(request.UserAgent ?? DefaultUserAgent);
            message.Headers.Accept.ParseAdd("application/json, text/plain, text/html, */*");

            using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                .ConfigureAwait(false);
            await response.Content.LoadIntoBufferAsync(1024 * 1024, deadline.Token).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(deadline.Token).ConfigureAwait(false);
            return new HttpProbeResult(
                Success: response.IsSuccessStatusCode,
                StatusCode: (int)response.StatusCode,
                Body: body,
                Error: response.IsSuccessStatusCode ? null : $"HTTP {(int)response.StatusCode}",
                Elapsed: sw.Elapsed,
                FinalUri: response.RequestMessage?.RequestUri?.ToString(),
                ServerHeader: ServerHeaderOf(response));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException)
        {
            return new HttpProbeResult(false, 0, null, "таймаут", sw.Elapsed, null, null);
        }
        catch (Exception ex)
        {
            return new HttpProbeResult(false, 0, null, ex.GetBaseException().Message, sw.Elapsed, null, null);
        }
    }

    public async Task<DnsLookupResult> ResolveAAsync(string name, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(name, ct).ConfigureAwait(false);
            return new DnsLookupResult(true, [.. addresses.Select(a => a.ToString())], null);
        }
        catch (SocketException ex)
        {
            // NXDOMAIN для DNSBL означает «в списке нет», а не ошибку проверки.
            return new DnsLookupResult(false, [],
                ex.SocketErrorCode == SocketError.HostNotFound ? "NXDOMAIN" : ex.Message);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return new DnsLookupResult(false, [], ex.GetBaseException().Message);
        }
    }

    private static string? ServerHeaderOf(HttpResponseMessage response) =>
        response.Headers.TryGetValues("server", out var values) ? string.Join(",", values) : null;

    public void Dispose()
    {
        _direct.Dispose();
        _system.Dispose();
    }
}
