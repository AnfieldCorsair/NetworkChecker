using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace NetworkChecker.Core.VpnAudit;

/// <summary>
/// Живой сборщик среза сети (IP, страна, город, провайдер/ASN, Download/Upload Мбит/с)
/// для 2-шагового отчёта в техподдержку ВПН («Без ВПН — РФ-провайдер» vs «С ВПН — туннель»).
/// </summary>
public static class SupportNetworkProbe
{
    private static readonly Uri IpWhoIsUri = new("https://ipwho.is/");
    private static readonly Uri IpApiCoUri = new("https://ipapi.co/json/");
    private static readonly Uri SpeedDownUri = new("https://speed.cloudflare.com/__down?bytes=2000000");
    private static readonly Uri SpeedUpUri = new("https://speed.cloudflare.com/__up");

    public static async Task<SupportNetworkSnapshot> CaptureAsync(
        HttpClient http,
        string phase,
        bool runSpeedTest = true,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(http);

        var (ip, country, city, isp, asn) = await FetchGeoAsync(http, ct).ConfigureAwait(false);
        SupportSpeedSample? speed = null;
        if (runSpeedTest)
        {
            speed = await MeasureSpeedAsync(http, ct).ConfigureAwait(false);
        }

        return new SupportNetworkSnapshot(
            phase,
            DateTimeOffset.UtcNow,
            ip,
            country,
            city,
            isp,
            asn,
            speed);
    }

    private static async Task<(string? Ip, string? Country, string? City, string? Isp, string? Asn)> FetchGeoAsync(
        HttpClient http,
        CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var json = await http.GetStringAsync(IpWhoIsUri, cts.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True)
            {
                var ip = ReadString(root, "ip");
                var country = ReadString(root, "country");
                var city = ReadString(root, "city");
                string? isp = null;
                string? asn = null;
                if (root.TryGetProperty("connection", out var conn) && conn.ValueKind == JsonValueKind.Object)
                {
                    isp = ReadString(conn, "isp") ?? ReadString(conn, "org");
                    if (conn.TryGetProperty("asn", out var asnEl) && asnEl.TryGetInt64(out var asnNum))
                    {
                        asn = string.Create(CultureInfo.InvariantCulture, $"AS{asnNum}");
                    }
                }
                return (ip, country, city, isp, asn);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            // Fallback to ipapi.co below
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var json = await http.GetStringAsync(IpApiCoUri, cts.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            return (
                ReadString(root, "ip"),
                ReadString(root, "country_name"),
                ReadString(root, "city"),
                ReadString(root, "org"),
                ReadString(root, "asn"));
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            return (null, null, null, null, null);
        }
    }

    private static async Task<SupportSpeedSample> MeasureSpeedAsync(HttpClient http, CancellationToken ct)
    {
        double? downMbps = null;
        double? upMbps = null;
        int? latencyMs = null;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));
            using var req = new HttpRequestMessage(HttpMethod.Get, SpeedDownUri);
            req.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };

            var sw = Stopwatch.StartNew();
            using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            latencyMs = Math.Max(1, (int)sw.ElapsedMilliseconds);
            res.EnsureSuccessStatusCode();

            var bytes = await res.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
            sw.Stop();
            var secs = Math.Max(0.05, sw.Elapsed.TotalSeconds);
            downMbps = Math.Round((bytes.Length * 8.0) / (secs * 1_000_000.0), 1);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException)
        {
            downMbps = null;
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));
            var payload = new byte[512 * 1024];
            using var content = new ByteArrayContent(payload);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

            var sw = Stopwatch.StartNew();
            using var res = await http.PostAsync(SpeedUpUri, content, cts.Token).ConfigureAwait(false);
            sw.Stop();
            if (res.IsSuccessStatusCode)
            {
                var secs = Math.Max(0.05, sw.Elapsed.TotalSeconds);
                upMbps = Math.Round((payload.Length * 8.0) / (secs * 1_000_000.0), 1);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException)
        {
            upMbps = null;
        }

        return new SupportSpeedSample(downMbps, upMbps, latencyMs, "Cloudflare Speed API");
    }

    private static string? ReadString(JsonElement obj, string prop) =>
        obj.TryGetProperty(prop, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;
}
