using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace VpnChecker.Core.VpnAudit;

public sealed record SubscriptionMetadata(
    string Title,
    long? UploadBytes,
    long? DownloadBytes,
    long? TotalBytes,
    long? ExpireUnix,
    int? UpdateIntervalHours,
    string? SupportUrl,
    string? WebPageUrl,
    string? RawUserInfo)
{
    public string TrafficSummaryRu
    {
        get
        {
            var used = (UploadBytes ?? 0) + (DownloadBytes ?? 0);
            if (!TotalBytes.HasValue || TotalBytes.Value <= 0)
            {
                return used > 0
                    ? $"Использовано: {FormatBytes(used)} (безлимит)"
                    : "Трафик: безлимитный или не передан";
            }

            var left = Math.Max(0, TotalBytes.Value - used);
            return $"Потрачено {FormatBytes(used)} из {FormatBytes(TotalBytes.Value)} (осталось {FormatBytes(left)})";
        }
    }

    public string ExpireSummaryRu
    {
        get
        {
            if (!ExpireUnix.HasValue || ExpireUnix.Value <= 0)
            {
                return "Срок действия: бессрочно";
            }

            var exp = DateTimeOffset.FromUnixTimeSeconds(ExpireUnix.Value).ToLocalTime();
            var days = (int)Math.Floor((exp - DateTimeOffset.Now).TotalDays);
            return days < 0
                ? string.Create(CultureInfo.InvariantCulture, $"Истекла {exp:dd.MM.yyyy}")
                : string.Create(CultureInfo.InvariantCulture, $"Активна до {exp:dd.MM.yyyy} (осталось {days} дн.)");
        }
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 Б";
        string[] units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
        var val = (double)bytes;
        var idx = 0;
        while (val >= 1024 && idx < units.Length - 1)
        {
            val /= 1024;
            idx++;
        }

        return string.Create(CultureInfo.InvariantCulture, $"{val:F1} {units[idx]}");
    }
}

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
/// Загрузчик ВПН-подписок по HTTPS (с поддержкой subscription-userinfo, profile-title, support-url и JSON-массивов Happ/Xray),
/// точечный патчер DNS/SNI, извлечение отдельных узлов и локальный HTTP-сервер раздачи исправленной подписки по ссылке.
/// </summary>
public sealed partial class SubscriptionService(HttpClient? httpClient = null)
{
    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly string[] ValidXhttpModes = ["auto", "packet-up", "stream-up", "stream-one"];
    private static readonly char[] LineSeparators = ['\r', '\n'];
    private static readonly object HostLock = new();
    private static TcpListener? s_localListener;
    private static int s_localPort;
    private static string s_hostedBody = "[]";
    private static string s_hostedTitle = "VPN_Checker-Patched";

    private readonly HttpClient _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

    [GeneratedRegex(@"(?<key>upload|download|total|expire)\s*=\s*(?<val>\d+)", RegexOptions.IgnoreCase)]
    private static partial Regex UserInfoRegex();

    public async Task<FetchedSubscription> FetchAsync(
        Uri subscriptionUrl,
        string userAgent = "Happ/2.0.0",
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

        var supportUrl = response.Headers.TryGetValues("support-url", out var supValues)
            ? supValues.FirstOrDefault()?.Trim()
            : null;

        var webPageUrl = response.Headers.TryGetValues("profile-web-page-url", out var webValues)
            ? webValues.FirstOrDefault()?.Trim()
            : null;

        return new SubscriptionMetadata(
            title,
            upload,
            download,
            total,
            expire,
            interval,
            string.IsNullOrWhiteSpace(supportUrl) ? null : supportUrl,
            string.IsNullOrWhiteSpace(webPageUrl) ? null : webPageUrl,
            string.IsNullOrWhiteSpace(userInfo) ? null : userInfo);
    }

    /// <summary>
    /// Извлекает чистый текст одного выбранного узла из мульти-подписки (JSON-объект из массива [...] или строку vless://)
    /// для копирования в буфер обмена и ручной вставки в Happ / v2rayN / Hiddify.
    /// </summary>
    public static bool TryExtractSingleNodeText(
        string rawSubscription,
        int nodeIndex,
        out string singleNodeText,
        out string nodeName)
    {
        singleNodeText = string.Empty;
        nodeName = string.Empty;

        if (string.IsNullOrWhiteSpace(rawSubscription))
        {
            return false;
        }

        var lines = VpnConfigParser.ExtractSubscriptionLines(rawSubscription);
        if (lines.Count == 0)
        {
            singleNodeText = rawSubscription.Trim();
            var profile = VpnConfigParser.Parse(singleNodeText);
            nodeName = profile.Name;
            return true;
        }

        var zeroBased = nodeIndex > 0 ? nodeIndex - 1 : 0;
        var idx = Math.Clamp(zeroBased, 0, lines.Count - 1);
        var item = lines[idx];
        if (item.TrimStart().StartsWith('{'))
        {
            try
            {
                var node = JsonNode.Parse(item);
                if (node is not null)
                {
                    singleNodeText = node.ToJsonString(PrettyJson);
                    nodeName = node["remarks"]?.GetValue<string>() ?? string.Create(CultureInfo.InvariantCulture, $"Узел #{idx + 1}");
                    return true;
                }
            }
            catch (JsonException)
            {
                // fallback to raw item
            }
        }

        singleNodeText = item;
        nodeName = VpnConfigParser.Parse(item).Name;
        return true;
    }

    private static readonly JsonDocumentOptions TolerantJsonDoc = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    private static readonly string[] NonProxyOutboundTypes = ["freedom", "direct", "blackhole", "block", "dns"];

    /// <summary>
    /// Точечно заменяет SNI (serverName / sni) в одиночном конфиге, выбранном узле подписки или во всех узлах подписки.
    /// Поддерживает JSON (Xray/Sing-box/Happ), списки URI (vless/trojan/hy2 с сохранением кириллицы/эмодзи в #fragment) и Base64-подписки.
    /// </summary>
    public static bool TryPatchSniInConfig(
        string rawConfigOrSubscription,
        string newSni,
        out string patchedText,
        out string summaryMessage,
        int? targetNodeIndex = null,
        bool extractSingleNodeOnly = false)
    {
        patchedText = rawConfigOrSubscription;
        summaryMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(rawConfigOrSubscription) || string.IsNullOrWhiteSpace(newSni))
        {
            summaryMessage = "Укажите новый домен SNI.";
            return false;
        }

        var cleanSni = newSni.Trim().ToLowerInvariant();
        var workingText = rawConfigOrSubscription.Trim();

        // Если подписка закодирована в Base64 — декодируем перед патчингом
        if (!workingText.StartsWith('{') &&
            !workingText.StartsWith('[') &&
            !workingText.Contains("://", StringComparison.Ordinal) &&
            TryDecodeBase64Payload(workingText, out var decodedPayload))
        {
            workingText = decodedPayload;
        }

        // 1. Проверяем JSON (одиночный объект или массив [...])
        if (workingText.StartsWith('{') || workingText.StartsWith('['))
        {
            try
            {
                var root = JsonNode.Parse(workingText, nodeOptions: null, TolerantJsonDoc);
                if (root is JsonObject singleObj)
                {
                    var changed = PatchSniInJsonObject(singleObj, cleanSni);
                    if (!changed)
                    {
                        summaryMessage = "В данном JSON-профиле не найдены секции realitySettings / tlsSettings / tls для замены SNI.";
                        return false;
                    }

                    var candidate = singleObj.ToJsonString(PrettyJson);
                    if (!DnsConfigArchitect.ValidateStrictJson(candidate, out var jsonError))
                    {
                        summaryMessage = $"Замена SNI отменена: {jsonError}";
                        return false;
                    }

                    patchedText = candidate;
                    summaryMessage = $"SNI точечно заменён на «{cleanSni}» в JSON-конфиге (JSON проверен).";
                    return true;
                }

                if (root is JsonArray arr && arr.Count > 0)
                {
                    var targetZeroIdx = targetNodeIndex.HasValue
                        ? Math.Clamp(targetNodeIndex.Value > 0 ? targetNodeIndex.Value - 1 : 0, 0, arr.Count - 1)
                        : (int?)null;

                    if (extractSingleNodeOnly)
                    {
                        var idx = targetZeroIdx ?? 0;
                        if (arr[idx] is JsonObject selectedObj)
                        {
                            var clone = selectedObj.DeepClone().AsObject();
                            if (!PatchSniInJsonObject(clone, cleanSni))
                            {
                                summaryMessage = "В выбранном узле JSON-подписки не найдено полей serverName / server_name.";
                                return false;
                            }

                            var candidate = clone.ToJsonString(PrettyJson);
                            if (!DnsConfigArchitect.ValidateStrictJson(candidate, out var jsonError))
                            {
                                summaryMessage = $"Замена SNI отменена: {jsonError}";
                                return false;
                            }

                            patchedText = candidate;
                            var remarks = clone["remarks"]?.GetValue<string>() ?? string.Create(CultureInfo.InvariantCulture, $"Узел #{idx + 1}");
                            summaryMessage = $"Готов исправленный профиль «{remarks}» с новым SNI «{cleanSni}» (JSON проверен).";
                            return true;
                        }
                    }

                    var updatedNodes = 0;
                    for (var i = 0; i < arr.Count; i++)
                    {
                        if (targetZeroIdx.HasValue && targetZeroIdx.Value != i)
                        {
                            continue;
                        }

                        if (arr[i] is JsonObject itemObj && PatchSniInJsonObject(itemObj, cleanSni))
                        {
                            updatedNodes++;
                        }
                    }

                    if (updatedNodes == 0)
                    {
                        summaryMessage = "В выбранных узлах JSON-подписки не найдено полей serverName / server_name.";
                        return false;
                    }

                    var candidateArray = arr.ToJsonString(PrettyJson);
                    if (!DnsConfigArchitect.ValidateStrictJson(candidateArray, out var arrJsonError))
                    {
                        summaryMessage = $"Замена SNI отменена: {arrJsonError}";
                        return false;
                    }

                    patchedText = candidateArray;
                    summaryMessage = targetZeroIdx.HasValue
                        ? string.Create(CultureInfo.InvariantCulture, $"SNI в локации #{targetZeroIdx.Value + 1} обновлён на «{cleanSni}» (JSON проверен).")
                        : string.Create(CultureInfo.InvariantCulture, $"SNI обновлён на «{cleanSni}» во всех подходящих локациях подписки ({updatedNodes} шт., JSON проверен).");
                    return true;
                }
            }
            catch (JsonException)
            {
                // Переходим к обработке URI-ссылок ниже
            }
        }

        // 2. Список URI-ссылок (vless://, trojan://, hy2://)
        var lines = workingText.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);
        var updatedLines = new List<string>(lines.Length);
        var uriIndex = 0;
        var changedCount = 0;

        foreach (var line in lines)
        {
            var current = line.Trim();
            if (Uri.TryCreate(current, UriKind.Absolute, out var uri) &&
                uri.Scheme.ToLowerInvariant() is "vless" or "trojan" or "hy2" or "hysteria2")
            {
                var targetZero = targetNodeIndex.HasValue ? Math.Max(0, targetNodeIndex.Value - 1) : (int?)null;
                var shouldPatch = !targetZero.HasValue || targetZero.Value == uriIndex;
                uriIndex++;

                if (shouldPatch)
                {
                    var query = ParseMutableQuery(uri.Query);
                    var oldSni = query.GetValueOrDefault("sni");
                    query["sni"] = cleanSni;
                    if (query.TryGetValue("host", out var currHost) &&
                        !string.IsNullOrWhiteSpace(oldSni) &&
                        string.Equals(currHost, oldSni, StringComparison.OrdinalIgnoreCase))
                    {
                        query["host"] = cleanSni;
                    }

                    current = RebuildUriPreservingFragment(current, query);
                    changedCount++;

                    if (extractSingleNodeOnly)
                    {
                        patchedText = current;
                        summaryMessage = $"Готова исправленная ссылка с новым SNI «{cleanSni}».";
                        return true;
                    }
                }
            }

            updatedLines.Add(current);
        }

        if (changedCount > 0)
        {
            patchedText = string.Join('\n', updatedLines);
            summaryMessage = string.Create(CultureInfo.InvariantCulture, $"SNI обновлён на «{cleanSni}» (затронуто ссылок: {changedCount}).");
            return true;
        }

        summaryMessage = "Текущий формат не поддерживает замену SNI (поддерживаются JSON Xray/Sing-box, подписки Happ и ссылки vless/trojan/hy2).";
        return false;
    }

    private static bool TryDecodeBase64Payload(string input, out string decoded)
    {
        decoded = string.Empty;
        try
        {
            var clean = input.Replace('-', '+').Replace('_', '/').Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal).Trim();
            switch (clean.Length % 4)
            {
                case 2: clean += "=="; break;
                case 3: clean += "="; break;
            }
            var bytes = Convert.FromBase64String(clean);
            var text = Encoding.UTF8.GetString(bytes).Trim();
            if (text.StartsWith('{') || text.StartsWith('[') || text.Contains("://", StringComparison.Ordinal))
            {
                decoded = text;
                return true;
            }
        }
        catch (FormatException)
        {
            // не Base64
        }
        return false;
    }

    private static string RebuildUriPreservingFragment(string rawUri, Dictionary<string, string> query)
    {
        var hashIdx = rawUri.IndexOf('#', StringComparison.Ordinal);
        var fragment = hashIdx >= 0 ? rawUri[hashIdx..] : string.Empty;
        var beforeHash = hashIdx >= 0 ? rawUri[..hashIdx] : rawUri;
        var qIdx = beforeHash.IndexOf('?', StringComparison.Ordinal);
        var basePart = qIdx >= 0 ? beforeHash[..qIdx] : beforeHash;
        var queryStr = string.Join('&', query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return string.IsNullOrEmpty(queryStr) ? $"{basePart}{fragment}" : $"{basePart}?{queryStr}{fragment}";
    }

    private static bool PatchSniInJsonObject(JsonObject obj, string newSni)
    {
        var changed = false;
        if (obj["outbounds"] is JsonArray outbounds)
        {
            foreach (var item in outbounds)
            {
                if (item is not JsonObject ob) continue;

                var proto = ob["protocol"]?.GetValue<string>() ?? ob["type"]?.GetValue<string>() ?? string.Empty;
                if (NonProxyOutboundTypes.Contains(proto, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Sing-box dialect: ob["tls"]["server_name"]
                if (ob["tls"] is JsonObject sbTls &&
                    (sbTls.ContainsKey("server_name") ||
                     (sbTls["enabled"] is JsonValue enVal && enVal.TryGetValue<bool>(out var enabled) && enabled)))
                {
                    sbTls["server_name"] = newSni;
                    changed = true;
                }

                // Xray dialect: ob["streamSettings"]["realitySettings" | "tlsSettings"]["serverName"]
                if (ob["streamSettings"] is JsonObject stream)
                {
                    string? oldSni = null;
                    if (stream["realitySettings"] is JsonObject reality)
                    {
                        oldSni = reality["serverName"]?.GetValue<string>();
                        reality["serverName"] = newSni;
                        changed = true;
                    }

                    if (stream["tlsSettings"] is JsonObject tls)
                    {
                        oldSni ??= tls["serverName"]?.GetValue<string>();
                        tls["serverName"] = newSni;
                        changed = true;
                    }

                    // Если в xhttpSettings.host стоял тот же домен, что и в старом SNI — синхронно обновляем его
                    if (stream["xhttpSettings"] is JsonObject xhttp &&
                        xhttp["host"] is JsonValue hostVal &&
                        hostVal.TryGetValue<string>(out var oldHost) &&
                        !string.IsNullOrWhiteSpace(oldHost) &&
                        !string.IsNullOrWhiteSpace(oldSni) &&
                        string.Equals(oldHost, oldSni, StringComparison.OrdinalIgnoreCase))
                    {
                        xhttp["host"] = newSni;
                    }
                }
            }
        }
        return changed;
    }

    /// <summary>
    /// Запускает (или обновляет) встроенный локальный HTTP-сервер на 127.0.0.1,
    /// раздающий исправленную подписку по ссылке http://127.0.0.1:17890/sub/patched.json
    /// для прямого добавления по URL в Happ, v2rayN или Hiddify.
    /// </summary>
    public static string StartOrUpdateLocalSubscriptionServer(string patchedContent, string title = "VPN_Checker-Patched")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(patchedContent);

        lock (HostLock)
        {
            s_hostedBody = patchedContent;
            s_hostedTitle = string.IsNullOrWhiteSpace(title) ? "VPN_Checker-Patched" : title.Trim();

            if (s_localListener is null)
            {
                // Пробуем стандартный порт 17890, если занят — берём любой свободный порт loopback
                try
                {
                    s_localListener = StartLoopbackListener(17890);
                    s_localPort = 17890;
                }
                catch (SocketException)
                {
                    var fallback = StartLoopbackListener(0);
                    s_localListener = fallback;
                    s_localPort = ((IPEndPoint)fallback.LocalEndpoint).Port;
                }

                _ = Task.Run(() => AcceptLocalSubscriptionClientsAsync(s_localListener));
            }

            return string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{s_localPort}/sub/patched.json");
        }
    }

    /// <summary>
    /// Корректно останавливает встроенный локальный HTTP-сервер при закрытии приложения.
    /// </summary>
    public static void StopLocalSubscriptionServer()
    {
        lock (HostLock)
        {
            if (s_localListener is null)
            {
                return;
            }

            try
            {
                s_localListener.Stop();
                s_localListener.Dispose();
            }
            catch (SocketException)
            {
                // Игнорируем ошибку сокета при завершении приложения
            }
            catch (ObjectDisposedException)
            {
                // Уже остановлен
            }
            finally
            {
                s_localListener = null;
                s_localPort = 0;
            }
        }
    }

    private static TcpListener StartLoopbackListener(int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        try
        {
            listener.Start();
            return listener;
        }
        catch
        {
            listener.Dispose();
            throw;
        }
    }

    private static async Task AcceptLocalSubscriptionClientsAsync(TcpListener listener)
    {
        while (true)
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                await using var stream = client.GetStream();

                // Читаем первую строку HTTP-запроса клиента (Happ / v2rayN / Hiddify / браузер) без риска CA2022
                using var reader = new StreamReader(
                    stream,
                    Encoding.ASCII,
                    detectEncodingFromByteOrderMarks: false,
                    bufferSize: 1024,
                    leaveOpen: true);
                _ = await reader.ReadLineAsync().ConfigureAwait(false);

                string bodySnapshot;
                string titleSnapshot;
                lock (HostLock)
                {
                    bodySnapshot = s_hostedBody;
                    titleSnapshot = s_hostedTitle;
                }

                var bodyBytes = Encoding.UTF8.GetBytes(bodySnapshot);
                var titleBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(titleSnapshot));
                var isJson = bodySnapshot.TrimStart().StartsWith('[') || bodySnapshot.TrimStart().StartsWith('{');
                var contentType = isJson ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";

                var header = string.Create(
                    CultureInfo.InvariantCulture,
                    $"HTTP/1.1 200 OK\r\nContent-Type: {contentType}\r\nContent-Length: {bodyBytes.Length}\r\nprofile-title: base64:{titleBase64}\r\nsubscription-userinfo: upload=0; download=0; total=1099511627776; expire=1893456000\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n");

                var headerBytes = Encoding.UTF8.GetBytes(header);
                await stream.WriteAsync(headerBytes).ConfigureAwait(false);
                await stream.WriteAsync(bodyBytes).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                // Локальный сервер остановлен при закрытии приложения
                break;
            }
            catch (Exception ex) when (ex is IOException or SocketException or InvalidOperationException)
            {
                if (ReferenceEquals(s_localListener, null))
                {
                    break;
                }
                // Игнорируем единичные обрывы клиента и продолжаем раздавать подписку
            }
        }
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
                    currentUri = RebuildUriPreservingFragment(currentUri, queryPairs);
                }
            }

            if (opt.DeduplicateNodes)
            {
                var dedupKey = string.Create(CultureInfo.InvariantCulture, $"{p.Protocol}|{p.Name}|{p.ServerHost}|{p.ServerPort}|{p.Transport}|{p.Tls.Sni}|{p.Xhttp?.Path ?? p.WsPath}");
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
            var eq = pair.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0) continue;
            dict[Uri.UnescapeDataString(pair[..eq])] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return dict;
    }
}
