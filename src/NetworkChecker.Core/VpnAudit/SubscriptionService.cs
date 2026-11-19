using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkChecker.Core.VpnAudit;

public sealed record SubscriptionMetadata(
    string Title,
    long? UploadBytes,
    long? DownloadBytes,
    long? TotalBytes,
    long? ExpireUnix,
    int? UpdateIntervalHours,
    string? RawUserInfo);

public sealed record FetchedSubscription(
    Uri SourceUrl,
    DateTimeOffset FetchedAt,
    string RawBody,
    SubscriptionMetadata Meta,
    IReadOnlyList<SubscriptionNodeAudit> Nodes);

public sealed record BulkPatchOptions(
    bool RemoveAllowInsecure = true,
    bool EnforceUtlsChrome = true,
    bool EnforceVlessTcpVision = true,
    bool FixXhttpModeAuto = true,
    bool DeduplicateNodes = true,
    bool DropLegacyAndNoTls = false);

public sealed record BulkPatchSummary(
    int BeforeCount,
    int AfterCount,
    int FixedAllowInsecure,
    int AddedFpChrome,
    int AddedVisionFlow,
    int FixedXhttpMode,
    int RemovedDuplicates,
    int RemovedLegacyOrUnsafe,
    IReadOnlyList<string> PatchedUris)
{
    public string PatchedText => string.Join('\n', PatchedUris);
    public string PatchedBase64 => Convert.ToBase64String(Encoding.UTF8.GetBytes(PatchedText));
}

/// <summary>
/// Загрузчик ВПН-подписок по HTTPS (с поддержкой subscription-userinfo / profile-title)
/// и массовый «жирный блок-патч» для лечения и очистки узлов перед импортом в клиент.
/// </summary>
public sealed partial class SubscriptionService(HttpClient? httpClient = null)
{
    private static readonly string[] ValidXhttpModes = ["auto", "packet-up", "stream-up", "stream-one"];
    private readonly HttpClient _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

    [GeneratedRegex(@"(?<key>upload|download|total|expire)\s*=\s*(?<val>\d+)", RegexOptions.IgnoreCase)]
    private static partial Regex UserInfoRegex();

    public async Task<FetchedSubscription> FetchAsync(
        Uri subscriptionUrl,
        string userAgent = "v2rayN/7.12.0",
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subscriptionUrl);
        if (subscriptionUrl.Scheme is not ("https" or "http"))
        {
            throw new ArgumentException("Поддерживаются только HTTP/HTTPS ссылки на подписки.", nameof(subscriptionUrl));
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, subscriptionUrl);
        request.Headers.UserAgent.Clear();
        request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var meta = ParseHeaders(response, subscriptionUrl.Host);
        var nodes = VpnConfigAuditor.AuditSubscription(body);

        return new FetchedSubscription(subscriptionUrl, DateTimeOffset.UtcNow, body, meta, nodes);
    }

    public static SubscriptionMetadata ParseHeaders(HttpResponseMessage response, string fallbackTitle)
    {
        ArgumentNullException.ThrowIfNull(response);

        var userInfo = response.Headers.TryGetValues("subscription-userinfo", out var uiValues)
            ? uiValues.FirstOrDefault() ?? string.Empty
            : string.Empty;

        long? upload = null, download = null, total = null, expire = null;
        foreach (Match match in UserInfoRegex().Matches(userInfo))
        {
            if (!long.TryParse(match.Groups["val"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var num))
                continue;
            switch (match.Groups["key"].Value.ToLowerInvariant())
            {
                case "upload": upload = num; break;
                case "download": download = num; break;
                case "total": total = num; break;
                case "expire": expire = num; break;
            }
        }

        var rawTitle = response.Headers.TryGetValues("profile-title", out var titleValues)
            ? titleValues.FirstOrDefault() ?? string.Empty
            : string.Empty;

        var title = fallbackTitle;
        if (!string.IsNullOrWhiteSpace(rawTitle))
        {
            if (rawTitle.StartsWith("base64:", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    title = Encoding.UTF8.GetString(Convert.FromBase64String(rawTitle[7..].Trim()));
                }
                catch (FormatException)
                {
                    title = rawTitle;
                }
            }
            else
            {
                title = rawTitle.Trim();
            }
        }

        int? interval = null;
        if (response.Headers.TryGetValues("profile-update-interval", out var intervalValues) &&
            int.TryParse(intervalValues.FirstOrDefault(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedInt))
        {
            interval = parsedInt;
        }

        return new SubscriptionMetadata(
            title, upload, download, total, expire, interval,
            string.IsNullOrWhiteSpace(userInfo) ? null : userInfo);
    }

    public static BulkPatchSummary ApplyBulkPatch(string rawInput, BulkPatchOptions? options = null)
    {
        var opt = options ?? new BulkPatchOptions();
        var nodes = VpnConfigAuditor.AuditSubscription(rawInput);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var patched = new List<string>(nodes.Count);

        int fixedInsecure = 0, addedFp = 0, addedVision = 0, fixedXhttp = 0, removedDups = 0, removedLegacy = 0;

        foreach (var node in nodes)
        {
            var p = node.Report.Profile;
            if (opt.DropLegacyAndNoTls)
            {
                var isLegacy = p.Protocol is VpnProtocol.LegacyShadowsocks or VpnProtocol.LegacyOpenVpn or VpnProtocol.LegacyWireGuard or VpnProtocol.Unknown;
                var isNoTls = p.Protocol == VpnProtocol.Vless && p.Tls.Mode == "none";
                if (isLegacy || isNoTls)
                {
                    removedLegacy++;
                    continue;
                }
            }

            var currentUri = node.RawUri.Trim();
            if (Uri.TryCreate(currentUri, UriKind.Absolute, out var uri) &&
                uri.Scheme.ToLowerInvariant() is "vless" or "hy2" or "hysteria2" or "trojan")
            {
                var queryPairs = ParseMutableQuery(uri.Query);
                var modified = false;

                if (opt.RemoveAllowInsecure)
                {
                    if (queryPairs.TryGetValue("allowInsecure", out var ai) && ai is "1" or "true")
                    {
                        queryPairs.Remove("allowInsecure");
                        fixedInsecure++;
                        modified = true;
                    }
                    if (queryPairs.TryGetValue("insecure", out var ins) && ins is "1" or "true")
                    {
                        queryPairs.Remove("insecure");
                        fixedInsecure++;
                        modified = true;
                    }
                }

                if (uri.Scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
                {
                    var type = queryPairs.GetValueOrDefault("type", "tcp").ToLowerInvariant();
                    var sec = queryPairs.GetValueOrDefault("security", "none").ToLowerInvariant();

                    if (opt.EnforceUtlsChrome && sec is "reality" or "tls" && !queryPairs.ContainsKey("fp"))
                    {
                        queryPairs["fp"] = "chrome";
                        addedFp++;
                        modified = true;
                    }

                    if (opt.EnforceVlessTcpVision && type is "tcp" or "raw" && sec == "reality" &&
                        !string.Equals(queryPairs.GetValueOrDefault("flow"), "xtls-rprx-vision", StringComparison.OrdinalIgnoreCase))
                    {
                        queryPairs["flow"] = "xtls-rprx-vision";
                        addedVision++;
                        modified = true;
                    }

                    if (opt.FixXhttpModeAuto && type is "xhttp" or "splithttp")
                    {
                        var mode = queryPairs.GetValueOrDefault("mode", string.Empty);
                        if (!ValidXhttpModes.Contains(mode, StringComparer.OrdinalIgnoreCase))
                        {
                            queryPairs["mode"] = "auto";
                            fixedXhttp++;
                            modified = true;
                        }
                    }
                }

                if (modified)
                {
                    var builder = new UriBuilder(uri)
                    {
                        Query = string.Join('&', queryPairs.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}")),
                    };
                    currentUri = builder.Uri.AbsoluteUri;
                }
            }

            if (opt.DeduplicateNodes)
            {
                var dedupKey = $"{p.Protocol}|{p.ServerHost}|{p.ServerPort}|{p.Transport}|{p.Tls.Sni}|{p.Xhttp?.Path ?? p.WsPath}";
                if (!seen.Add(dedupKey))
                {
                    removedDups++;
                    continue;
                }
            }

            patched.Add(currentUri);
        }

        return new BulkPatchSummary(
            nodes.Count, patched.Count, fixedInsecure, addedFp, addedVision, fixedXhttp, removedDups, removedLegacy, patched);
    }

    private static Dictionary<string, string> ParseMutableQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query)) return dict;
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            dict[Uri.UnescapeDataString(pair[..eq])] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return dict;
    }
}
