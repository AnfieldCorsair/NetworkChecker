using System.Globalization;
using System.Text;
using System.Text.Json;

namespace NetworkChecker.Core.VpnAudit;

/// <summary>
/// Отказоустойчивый парсер и нормализатор ВПН-конфигураций с приоритетом под реалии РФ:
/// VLESS (TCP/Vision, XHTTP/SplitHTTP, WS), AmneziaWG, Hysteria2, Trojan, VMess, Shadowsocks,
/// Sing-box/Xray JSON (включая JSON-массивы подписок Happ/Xray, строковые dns.servers, Xray vnext и Xray Hysteria2) и Base64-подписки.
/// </summary>
public static class VpnConfigParser
{
    private static readonly string[] UriSchemes =
    [
        "vless://",
        "hy2://",
        "hysteria2://",
        "trojan://",
        "vmess://",
        "ss://",
    ];

    private static readonly char[] LineSeparators = ['\r', '\n'];

    /// <summary>
    /// Проверяет, является ли введённый текст прямой HTTP/HTTPS-ссылкой на подписку (например https://sub.example.com/profile).
    /// </summary>
    public static bool TryExtractHttpSubscriptionUrl(string? rawInput, out Uri? subscriptionUri)
    {
        subscriptionUri = null;
        if (string.IsNullOrWhiteSpace(rawInput)) return false;

        var trimmed = rawInput.Trim();
        if (trimmed.Contains('\n', StringComparison.Ordinal) ||
            trimmed.Contains('\r', StringComparison.Ordinal) ||
            trimmed.Contains(' ', StringComparison.Ordinal))
        {
            return false;
        }

        if ((trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
             trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) &&
            Uri.TryCreate(trimmed, UriKind.Absolute, out var parsed) &&
            !string.IsNullOrWhiteSpace(parsed.Host) &&
            parsed.Host.Contains('.', StringComparison.Ordinal))
        {
            subscriptionUri = parsed;
            return true;
        }

        return false;
    }

    public static IReadOnlyList<string> ExtractSubscriptionLines(string rawInput)
    {
        if (string.IsNullOrWhiteSpace(rawInput)) return [];

        var trimmed = rawInput.Trim();
        var directLines = SplitUriLines(trimmed);
        if (directLines.Count > 0) return directLines;

        // Поддержка JSON-массивов подписок (формат Happ / Xray / Remnawave / v2rayN)
        if (trimmed.StartsWith('[') && TryExtractJsonArrayItems(trimmed, out var jsonItems) && jsonItems.Count > 0)
        {
            return jsonItems;
        }

        // Попытка декодировать Base64-подписку (список URI или Base64-кодированный JSON-массив)
        if (!trimmed.Contains(' ', StringComparison.Ordinal) &&
            !trimmed.StartsWith('{') &&
            !trimmed.StartsWith('[') &&
            trimmed.Length >= 24)
        {
            if (TryDecodeBase64Utf8(trimmed, out var decoded))
            {
                var decodedTrim = decoded.Trim();
                var decodedLines = SplitUriLines(decodedTrim);
                if (decodedLines.Count > 0) return decodedLines;

                if (decodedTrim.StartsWith('[') && TryExtractJsonArrayItems(decodedTrim, out var decodedJsonItems) && decodedJsonItems.Count > 0)
                {
                    return decodedJsonItems;
                }
            }
        }

        return [];
    }

    public static IReadOnlyList<NormalizedVpnProfile> ParseSubscription(string rawInput)
    {
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            return [];
        }

        var lines = ExtractSubscriptionLines(rawInput);
        if (lines.Count > 0)
        {
            var list = new List<NormalizedVpnProfile>(lines.Count);
            foreach (var line in lines)
            {
                var item = line.Trim();
                var parsed = item.StartsWith('{') || item.StartsWith('[')
                    ? ParseJsonConfig(item)
                    : ParseUri(item);
                if (parsed.Protocol != VpnProtocol.Unknown)
                {
                    list.Add(parsed);
                }
            }

            if (list.Count > 0)
            {
                return list;
            }
        }

        var single = Parse(rawInput);
        return single.Protocol != VpnProtocol.Unknown ? [single] : [];
    }

    public static NormalizedVpnProfile Parse(string rawInput)
    {
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            return Empty(VpnProtocol.Unknown, "Пустой ввод", "Нет данных");
        }

        var trimmed = rawInput.Trim();

        var subLines = ExtractSubscriptionLines(trimmed);
        if (subLines.Count > 0)
        {
            var firstItem = subLines[0].Trim();
            return firstItem.StartsWith('{') || firstItem.StartsWith('[')
                ? ParseJsonConfig(firstItem)
                : ParseUri(firstItem);
        }

        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            return ParseJsonConfig(trimmed);
        }

        if (TryExtractHttpSubscriptionUrl(trimmed, out var subUri) && subUri is not null)
        {
            return new NormalizedVpnProfile
            {
                Protocol = VpnProtocol.Unknown,
                ProtocolLabel = "Ссылка на подписку (HTTPS)",
                Name = $"Подписка {subUri.Host}",
                ServerHost = subUri.Host,
                ServerPort = subUri.Port > 0 ? subUri.Port : 443,
                Transport = "HTTPS",
                Tls = new TlsSettings("tls", subUri.Host, null, null, null, null, false, []),
                ParseWarnings = [$"Обнаружена ссылка на подписку {subUri}. Нажмите «Загрузить подписку», чтобы скачать и проверить все локации."],
            };
        }

        if (trimmed.Contains("[Interface]", StringComparison.OrdinalIgnoreCase))
        {
            return ParseWireGuardOrAmnezia(trimmed);
        }

        if (trimmed.Contains("remote ", StringComparison.OrdinalIgnoreCase) &&
            (trimmed.Contains("dev tun", StringComparison.OrdinalIgnoreCase) ||
             trimmed.Contains("proto ", StringComparison.OrdinalIgnoreCase)))
        {
            return ParseLegacyOpenVpn(trimmed);
        }

        return Empty(VpnProtocol.Unknown, "Формат не распознан", "Неизвестный профиль") with
        {
            ParseWarnings = ["Поддерживаются ссылки на подписки (https://...), VLESS (TCP/XHTTP/WS), AmneziaWG, Hysteria2, Trojan, VMess, Shadowsocks, Xray/Sing-box JSON (включая массивы Happ) и Base64-подписки."],
        };
    }

    private static bool TryExtractJsonArrayItems(string jsonText, out List<string> items)
    {
        items = [];
        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.ValueKind == JsonValueKind.Object)
                {
                    items.Add(el.GetRawText());
                }
                else if (el.ValueKind == JsonValueKind.String)
                {
                    var str = el.GetString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(str) && UriSchemes.Any(s => str.StartsWith(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        items.Add(str);
                    }
                }
            }

            return items.Count > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static NormalizedVpnProfile ParseUri(string uriText)
    {
        var trimmed = uriText.Trim();
        if (trimmed.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseVmessUri(trimmed);
        }

        if (trimmed.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseShadowsocksUri(trimmed);
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            return Empty(VpnProtocol.Unknown, "Битая URI-ссылка", "Ошибка синтаксиса") with
            {
                ParseWarnings = ["Не удалось разобрать URI-ссылку."],
            };
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        var name = string.IsNullOrWhiteSpace(uri.Fragment)
            ? $"Узел {scheme.ToUpperInvariant()}"
            : SafeUnescape(uri.Fragment.TrimStart('#'));
        var query = ParseQueryString(uri.Query);
        var secrets = new List<string>();
        var userInfo = SafeUnescape(uri.UserInfo);
        if (!string.IsNullOrWhiteSpace(userInfo)) secrets.Add(userInfo);

        if (scheme == "vless")
        {
            var rawType = query.GetValueOrDefault("type", "tcp").ToLowerInvariant();
            var normalizedType = rawType is "splithttp" or "xhttp" ? "xhttp" : rawType;
            var security = query.GetValueOrDefault("security", "none").ToLowerInvariant();
            var sni = query.GetValueOrDefault("sni") ?? query.GetValueOrDefault("peer");
            var fp = query.GetValueOrDefault("fp");
            var flow = query.GetValueOrDefault("flow");
            var pbk = query.GetValueOrDefault("pbk");
            var sid = query.GetValueOrDefault("sid");
            var allowInsecure = query.GetValueOrDefault("allowInsecure") is "1" or "true"
                || query.GetValueOrDefault("insecure") is "1" or "true";
            var alpn = query.GetValueOrDefault("alpn", string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            XhttpSettings? xhttp = null;
            if (normalizedType == "xhttp")
            {
                var mode = query.GetValueOrDefault("mode", "auto");
                var path = query.GetValueOrDefault("path", "/");
                var host = query.GetValueOrDefault("host");
                var extraRaw = query.GetValueOrDefault("extra");
                var hasPadding = extraRaw?.Contains("xPaddingBytes", StringComparison.OrdinalIgnoreCase) == true;
                var hasXmux = extraRaw?.Contains("xmux", StringComparison.OrdinalIgnoreCase) == true;
                var hasDownload = extraRaw?.Contains("downloadSettings", StringComparison.OrdinalIgnoreCase) == true;
                xhttp = new XhttpSettings(mode, path, host, extraRaw, hasPadding, hasXmux, hasDownload);
            }

            string? wsPath = null;
            string? wsHost = null;
            int? wsEd = null;
            if (normalizedType == "ws")
            {
                wsPath = query.GetValueOrDefault("path", "/");
                wsHost = query.GetValueOrDefault("host");
                if (wsPath.Contains("ed=", StringComparison.OrdinalIgnoreCase))
                {
                    var edIdx = wsPath.IndexOf("ed=", StringComparison.OrdinalIgnoreCase);
                    var edPart = new string(wsPath[(edIdx + 3)..].TakeWhile(char.IsDigit).ToArray());
                    if (int.TryParse(edPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedEd))
                    {
                        wsEd = parsedEd;
                    }
                }
            }

            var label = normalizedType switch
            {
                "xhttp" => "VLESS + XHTTP",
                "ws" => "VLESS + WebSocket",
                "grpc" => "VLESS + gRPC",
                _ => "VLESS + TCP",
            };

            return new NormalizedVpnProfile
            {
                Protocol = VpnProtocol.Vless,
                ProtocolLabel = security == "reality" ? $"{label} + Reality" : label,
                Name = name,
                ServerHost = uri.Host,
                ServerPort = uri.Port > 0 ? uri.Port : 443,
                Transport = normalizedType.ToUpperInvariant(),
                Tls = new TlsSettings(security, sni, fp, flow, pbk, sid, allowInsecure, alpn),
                Xhttp = xhttp,
                WsPath = wsPath,
                WsHost = wsHost,
                WsEarlyData = wsEd,
                RawSecrets = secrets,
            };
        }

        if (scheme is "hy2" or "hysteria2")
        {
            var sni = query.GetValueOrDefault("sni");
            var obfs = query.GetValueOrDefault("obfs");
            var obfsPass = query.GetValueOrDefault("obfs-password");
            if (!string.IsNullOrWhiteSpace(obfsPass)) secrets.Add(obfsPass);
            var insecure = query.GetValueOrDefault("insecure") is "1" or "true";
            var mport = query.GetValueOrDefault("mport");

            return new NormalizedVpnProfile
            {
                Protocol = VpnProtocol.Hysteria2,
                ProtocolLabel = "Hysteria2 (QUIC/UDP)",
                Name = name,
                ServerHost = uri.Host,
                ServerPort = uri.Port > 0 ? uri.Port : 443,
                Transport = "QUIC (UDP)",
                Tls = new TlsSettings("tls", sni, null, null, null, null, insecure, ["h3"]),
                Obfs = obfs,
                HasObfsPassword = !string.IsNullOrWhiteSpace(obfsPass),
                PortHopping = mport,
                RawSecrets = secrets,
            };
        }

        if (scheme == "trojan")
        {
            var rawType = query.GetValueOrDefault("type", "tcp").ToLowerInvariant();
            var security = query.GetValueOrDefault("security", "tls").ToLowerInvariant();
            var sni = query.GetValueOrDefault("sni") ?? query.GetValueOrDefault("peer") ?? uri.Host;
            var fp = query.GetValueOrDefault("fp");
            var allowInsecure = query.GetValueOrDefault("allowInsecure") is "1" or "true"
                || query.GetValueOrDefault("insecure") is "1" or "true";
            var alpn = query.GetValueOrDefault("alpn", string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            return new NormalizedVpnProfile
            {
                Protocol = VpnProtocol.Trojan,
                ProtocolLabel = rawType == "ws" ? "Trojan + WebSocket" : "Trojan (TLS)",
                Name = name,
                ServerHost = uri.Host,
                ServerPort = uri.Port > 0 ? uri.Port : 443,
                Transport = rawType.ToUpperInvariant(),
                Tls = new TlsSettings(security, sni, fp, null, null, null, allowInsecure, alpn),
                WsPath = rawType == "ws" ? query.GetValueOrDefault("path", "/") : null,
                WsHost = rawType == "ws" ? query.GetValueOrDefault("host") : null,
                RawSecrets = secrets,
            };
        }

        return Empty(VpnProtocol.LegacyShadowsocks, $"Протокол {scheme.ToUpperInvariant()}", name) with
        {
            ServerHost = uri.Host,
            ServerPort = uri.Port > 0 ? uri.Port : 443,
            RawSecrets = secrets,
        };
    }

    private static NormalizedVpnProfile ParseVmessUri(string vmessUri)
    {
        var payload = vmessUri["vmess://".Length..].Trim();
        var hashIdx = payload.IndexOf('#');
        if (hashIdx >= 0) payload = payload[..hashIdx];

        if (!TryDecodeBase64Utf8(payload, out var json))
        {
            return Empty(VpnProtocol.Vmess, "VMess (ошибка Base64)", "Битая ссылка VMess") with
            {
                ParseWarnings = ["Не удалось декодировать Base64-блок vmess://."],
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Empty(VpnProtocol.Vmess, "VMess (неверный JSON)", "Битый профиль VMess") with
                {
                    ParseWarnings = ["Содержимое vmess:// не является JSON-объектом."],
                };
            }

            var name = TryGetString(root, "ps") ?? "Узел VMess";
            var host = TryGetString(root, "add");
            var port = TryGetInt(root, "port") ?? 443;
            var id = TryGetString(root, "id");
            var net = (TryGetString(root, "net") ?? "tcp").ToLowerInvariant();
            var tls = (TryGetString(root, "tls") ?? "none").ToLowerInvariant();
            var sni = TryGetString(root, "sni") ?? TryGetString(root, "host");
            var fp = TryGetString(root, "fp");
            var path = TryGetString(root, "path");
            var wsHost = TryGetString(root, "host");
            var secrets = string.IsNullOrWhiteSpace(id) ? new List<string>() : new List<string> { id };

            return new NormalizedVpnProfile
            {
                Protocol = VpnProtocol.Vmess,
                ProtocolLabel = tls == "tls" ? $"VMess + {net.ToUpperInvariant()} + TLS" : $"VMess + {net.ToUpperInvariant()}",
                Name = name,
                ServerHost = host,
                ServerPort = port,
                Transport = net.ToUpperInvariant(),
                Tls = new TlsSettings(string.IsNullOrWhiteSpace(tls) ? "none" : tls, sni, fp, null, null, null, false, []),
                WsPath = net == "ws" ? path ?? "/" : null,
                WsHost = net == "ws" ? wsHost : null,
                RawSecrets = secrets,
            };
        }
        catch (JsonException ex)
        {
            return Empty(VpnProtocol.Vmess, "VMess (ошибка JSON)", "Битый профиль VMess") with
            {
                ParseWarnings = [$"Ошибка разбора JSON внутри vmess://: {ex.Message}"],
            };
        }
    }

    private static NormalizedVpnProfile ParseShadowsocksUri(string ssUri)
    {
        var raw = ssUri["ss://".Length..].Trim();
        var name = "Узел Shadowsocks";
        var hashIdx = raw.IndexOf('#');
        if (hashIdx >= 0)
        {
            name = SafeUnescape(raw[(hashIdx + 1)..]);
            raw = raw[..hashIdx];
        }

        var qIdx = raw.IndexOf('?');
        if (qIdx >= 0)
        {
            raw = raw[..qIdx];
        }

        string? method = null;
        string? password = null;
        string? host = null;
        int? port = null;

        var atIdx = raw.LastIndexOf('@');
        if (atIdx > 0)
        {
            var userPart = raw[..atIdx];
            var hostPort = raw[(atIdx + 1)..];
            var decodedUser = TryDecodeBase64Utf8(userPart, out var uDec) && uDec.Contains(':', StringComparison.Ordinal)
                ? uDec
                : SafeUnescape(userPart);
            var colon = decodedUser.IndexOf(':');
            if (colon > 0)
            {
                method = decodedUser[..colon];
                password = decodedUser[(colon + 1)..];
            }
            ParseHostPort(hostPort, out host, out port);
        }
        else if (TryDecodeBase64Utf8(raw, out var legacy) && legacy.Contains('@', StringComparison.Ordinal))
        {
            var legAt = legacy.LastIndexOf('@');
            var userPart = legacy[..legAt];
            var hostPort = legacy[(legAt + 1)..];
            var colon = userPart.IndexOf(':');
            if (colon > 0)
            {
                method = userPart[..colon];
                password = userPart[(colon + 1)..];
            }
            ParseHostPort(hostPort, out host, out port);
        }

        var secrets = string.IsNullOrWhiteSpace(password) ? new List<string>() : new List<string> { password };
        var label = string.IsNullOrWhiteSpace(method) ? "Shadowsocks" : $"Shadowsocks ({method})";

        return new NormalizedVpnProfile
        {
            Protocol = VpnProtocol.LegacyShadowsocks,
            ProtocolLabel = label,
            Name = name,
            ServerHost = host,
            ServerPort = port,
            Transport = "TCP/UDP",
            CipherMethod = method,
            Tls = new TlsSettings("none", null, null, null, null, null, false, []),
            RawSecrets = secrets,
        };
    }

    private static NormalizedVpnProfile ParseWireGuardOrAmnezia(string raw)
    {
        var iface = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var peer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var section = string.Empty;

        foreach (var rawLine in raw.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries))
        {
            var commentIdx = rawLine.IndexOf('#');
            var line = (commentIdx >= 0 ? rawLine[..commentIdx] : rawLine).Trim();
            if (line.Length == 0) continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim().ToLowerInvariant();
                continue;
            }

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            var target = section == "peer" ? peer : iface;
            target[key] = value;
        }

        int? TryIntKey(string key) =>
            iface.TryGetValue(key, out var s) && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        long? TryLongKey(string key) =>
            iface.TryGetValue(key, out var s) && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

        var awg = new AmneziaWgSettings(
            TryIntKey("Jc"), TryIntKey("Jmin"), TryIntKey("Jmax"),
            TryIntKey("S1"), TryIntKey("S2"),
            TryLongKey("H1"), TryLongKey("H2"), TryLongKey("H3"), TryLongKey("H4"));

        var isAmnezia = awg.Jc.HasValue || awg.S1.HasValue || awg.S2.HasValue || awg.H1.HasValue;

        string? host = null;
        int? port = null;
        if (peer.TryGetValue("Endpoint", out var endpoint))
        {
            ParseHostPort(endpoint, out host, out port);
        }

        var dns = iface.TryGetValue("DNS", out var dnsRaw)
            ? dnsRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        var allowedIps = peer.TryGetValue("AllowedIPs", out var aipRaw)
            ? aipRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];

        var secrets = new List<string>();
        if (iface.TryGetValue("PrivateKey", out var priv)) secrets.Add(priv);
        if (peer.TryGetValue("PresharedKey", out var psk)) secrets.Add(psk);

        int? mtu = iface.TryGetValue("MTU", out var mtuRaw) && int.TryParse(mtuRaw, CultureInfo.InvariantCulture, out var m) ? m : null;
        int? keepalive = peer.TryGetValue("PersistentKeepalive", out var kaRaw) && int.TryParse(kaRaw, CultureInfo.InvariantCulture, out var ka) ? ka : null;

        return new NormalizedVpnProfile
        {
            Protocol = isAmnezia ? VpnProtocol.AmneziaWg : VpnProtocol.LegacyWireGuard,
            ProtocolLabel = isAmnezia ? "AmneziaWG (обфускация)" : "WireGuard (классический)",
            Name = isAmnezia ? "Профиль AmneziaWG" : "Профиль WireGuard",
            ServerHost = host,
            ServerPort = port,
            Transport = "UDP",
            Tls = new TlsSettings("noise", null, null, null, null, null, false, []),
            AmneziaWg = isAmnezia ? awg : null,
            DnsServers = dns,
            AllowedIps = allowedIps,
            RoutesAllIpv4 = allowedIps.Contains("0.0.0.0/0", StringComparer.Ordinal),
            RoutesAllIpv6 = allowedIps.Contains("::/0", StringComparer.Ordinal),
            Mtu = mtu,
            PersistentKeepalive = keepalive,
            HasPresharedKey = peer.ContainsKey("PresharedKey"),
            RawSecrets = secrets,
        };
    }

    private static NormalizedVpnProfile ParseJsonConfig(string raw)
    {
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array)
            {
                var firstObj = root.EnumerateArray().FirstOrDefault(e => e.ValueKind == JsonValueKind.Object);
                if (firstObj.ValueKind != JsonValueKind.Object)
                {
                    return Empty(VpnProtocol.Unknown, "Пустой JSON-массив", "Нет профилей в массиве") with
                    {
                        ParseWarnings = ["JSON-массив подписки не содержит ни одного объекта конфигурации."],
                    };
                }
                root = firstObj;
            }
            else if (root.ValueKind != JsonValueKind.Object)
            {
                return Empty(VpnProtocol.Unknown, "JSON не является объектом", "Неверный корень JSON") with
                {
                    ParseWarnings = ["Конфиг Sing-box/Xray должен быть JSON-объектом { ... } или массивом профилей [ ... ]."],
                };
            }

            var isSingBox = TryGetArray(root, "outbounds", out var outsForDetect) &&
                            outsForDetect.EnumerateArray().Any(e =>
                                e.ValueKind == JsonValueKind.Object &&
                                TryGetPropertySafe(e, "type", out _));

            if (!isSingBox && TryGetObject(root, "route", out _) && !TryGetObject(root, "routing", out _))
            {
                isSingBox = true;
            }

            var customRemarks = TryGetString(root, "remarks")
                                ?? TryGetString(root, "name")
                                ?? TryGetString(root, "ps");

            var rawLower = root.GetRawText().ToLowerInvariant();
            string? host = null;
            int? port = null;
            var transport = "TCP";
            var tlsMode = rawLower.Contains("\"reality\"", StringComparison.Ordinal) ? "reality" : "tls";
            string? sni = null;
            string? fp = null;
            string? flow = null;
            string? pbk = null;
            string? sid = null;
            string? outboundProto = null;
            XhttpSettings? xhttp = null;
            string? wsPath = null;
            string? wsHost = null;
            var alpnList = new List<string>();
            var allowInsecure = rawLower.Contains("\"insecure\": true", StringComparison.Ordinal)
                             || rawLower.Contains("\"allowinsecure\": true", StringComparison.Ordinal)
                             || rawLower.Contains("\"insecure\":true", StringComparison.Ordinal)
                             || rawLower.Contains("\"allowinsecure\":true", StringComparison.Ordinal);
            var secrets = new List<string>();
            var proxyOutboundCount = 0;

            if (TryGetArray(root, "outbounds", out var outbounds))
            {
                foreach (var item in outbounds.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object) continue;

                    var itemProto = (TryGetString(item, "protocol") ?? TryGetString(item, "type") ?? string.Empty).ToLowerInvariant();
                    if (itemProto is "freedom" or "blackhole" or "direct" or "block" or "dns" or "selector" or "urltest")
                    {
                        continue;
                    }

                    // Вариант 1: Sing-box outbound
                    var sbServer = TryGetString(item, "server");
                    if (!string.IsNullOrWhiteSpace(sbServer))
                    {
                        proxyOutboundCount++;
                        if (!string.IsNullOrWhiteSpace(host)) continue;

                        outboundProto = itemProto;
                        host = sbServer;
                        port = TryGetInt(item, "server_port") ?? 443;
                        var uuid = TryGetString(item, "uuid") ?? TryGetString(item, "password");
                        if (!string.IsNullOrWhiteSpace(uuid)) secrets.Add(uuid);
                        flow = TryGetString(item, "flow");

                        if (TryGetObject(item, "transport", out var tr))
                        {
                            var trType = (TryGetString(tr, "type") ?? "tcp").ToLowerInvariant();
                            transport = trType is "xhttp" or "splithttp" ? "XHTTP" : trType.ToUpperInvariant();
                            if (transport == "XHTTP")
                            {
                                var mode = TryGetString(tr, "mode") ?? "auto";
                                var path = TryGetString(tr, "path") ?? "/";
                                var xHost = TryGetString(tr, "host");
                                xhttp = new XhttpSettings(mode, path, xHost, null, false, false, false);
                            }
                            else if (transport == "WS")
                            {
                                wsPath = TryGetString(tr, "path") ?? "/";
                            }
                        }

                        if (TryGetObject(item, "tls", out var tlsObj))
                        {
                            sni = TryGetString(tlsObj, "server_name");
                            if (TryGetBool(tlsObj, "insecure") == true) allowInsecure = true;
                            if (TryGetArray(tlsObj, "alpn", out var sbAlpn))
                            {
                                foreach (var a in sbAlpn.EnumerateArray())
                                {
                                    if (a.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(a.GetString()))
                                    {
                                        alpnList.Add(a.GetString()!);
                                    }
                                }
                            }
                            if (TryGetObject(tlsObj, "utls", out var utlsObj))
                            {
                                fp = TryGetString(utlsObj, "fingerprint");
                            }
                            if (TryGetObject(tlsObj, "reality", out var realObj) && TryGetBool(realObj, "enabled") == true)
                            {
                                tlsMode = "reality";
                                pbk = TryGetString(realObj, "public_key");
                                sid = TryGetString(realObj, "short_id");
                            }
                        }
                        continue;
                    }

                    // Вариант 2: Xray-core outbound (vnext / servers / hysteria settings + streamSettings)
                    if (TryGetObject(item, "settings", out var settingsObj))
                    {
                        string? candidateHost = null;
                        int? candidatePort = null;
                        string? candidateFlow = null;

                        if (TryGetArray(settingsObj, "vnext", out var vnextArr))
                        {
                            foreach (var vn in vnextArr.EnumerateArray())
                            {
                                if (vn.ValueKind != JsonValueKind.Object) continue;
                                var addr = TryGetString(vn, "address");
                                if (string.IsNullOrWhiteSpace(addr)) continue;
                                candidateHost = addr;
                                candidatePort = TryGetInt(vn, "port") ?? 443;

                                if (TryGetArray(vn, "users", out var usersArr))
                                {
                                    foreach (var u in usersArr.EnumerateArray())
                                    {
                                        if (u.ValueKind != JsonValueKind.Object) continue;
                                        var uid = TryGetString(u, "id");
                                        if (!string.IsNullOrWhiteSpace(uid)) secrets.Add(uid);
                                        candidateFlow = TryGetString(u, "flow");
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                        else if (TryGetArray(settingsObj, "servers", out var srvArr))
                        {
                            foreach (var sv in srvArr.EnumerateArray())
                            {
                                if (sv.ValueKind != JsonValueKind.Object) continue;
                                var addr = TryGetString(sv, "address");
                                if (string.IsNullOrWhiteSpace(addr)) continue;
                                candidateHost = addr;
                                candidatePort = TryGetInt(sv, "port") ?? 443;
                                var pass = TryGetString(sv, "password");
                                if (!string.IsNullOrWhiteSpace(pass)) secrets.Add(pass);
                                break;
                            }
                        }
                        else
                        {
                            // Формат Xray Hysteria2: "settings": { "address": "203.0.113.10", "port": 443, "version": 2 }
                            var directAddr = TryGetString(settingsObj, "address");
                            if (!string.IsNullOrWhiteSpace(directAddr))
                            {
                                candidateHost = directAddr;
                                candidatePort = TryGetInt(settingsObj, "port") ?? 443;
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(candidateHost))
                        {
                            proxyOutboundCount++;
                            if (!string.IsNullOrWhiteSpace(host)) continue;

                            outboundProto = itemProto;
                            host = candidateHost;
                            port = candidatePort;
                            flow = candidateFlow;

                            if (TryGetObject(item, "streamSettings", out var ssObj))
                            {
                                var net = TryGetString(ssObj, "network");
                                if (!string.IsNullOrWhiteSpace(net))
                                {
                                    var netLower = net.ToLowerInvariant();
                                    transport = netLower switch
                                    {
                                        "splithttp" or "xhttp" => "XHTTP",
                                        "hysteria" or "hysteria2" or "quic" => "QUIC (UDP)",
                                        _ => net.ToUpperInvariant(),
                                    };
                                }

                                var sec = TryGetString(ssObj, "security");
                                if (!string.IsNullOrWhiteSpace(sec)) tlsMode = sec.ToLowerInvariant();

                                if (TryGetObject(ssObj, "realitySettings", out var rObj))
                                {
                                    tlsMode = "reality";
                                    sni = TryGetString(rObj, "serverName") ?? sni;
                                    fp = TryGetString(rObj, "fingerprint") ?? fp;
                                    pbk = TryGetString(rObj, "publicKey") ?? pbk;
                                    sid = TryGetString(rObj, "shortId") ?? sid;
                                }

                                if (TryGetObject(ssObj, "tlsSettings", out var tObj))
                                {
                                    sni = TryGetString(tObj, "serverName") ?? sni;
                                    fp = TryGetString(tObj, "fingerprint") ?? fp;
                                    if (TryGetBool(tObj, "allowInsecure") == true) allowInsecure = true;
                                    if (TryGetArray(tObj, "alpn", out var alpnArr))
                                    {
                                        foreach (var a in alpnArr.EnumerateArray())
                                        {
                                            if (a.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(a.GetString()))
                                            {
                                                alpnList.Add(a.GetString()!);
                                            }
                                        }
                                    }
                                }

                                if (TryGetObject(ssObj, "xhttpSettings", out var xhObj) ||
                                    TryGetObject(ssObj, "splithttpSettings", out xhObj))
                                {
                                    transport = "XHTTP";
                                    var mode = TryGetString(xhObj, "mode") ?? "auto";
                                    var path = TryGetString(xhObj, "path") ?? "/";
                                    var xHost = TryGetString(xhObj, "host");
                                    var xhRaw = xhObj.GetRawText();
                                    var hasPadding = xhRaw.Contains("xPaddingBytes", StringComparison.OrdinalIgnoreCase);
                                    var hasXmux = xhRaw.Contains("xmux", StringComparison.OrdinalIgnoreCase);
                                    var hasDownload = xhRaw.Contains("downloadSettings", StringComparison.OrdinalIgnoreCase);
                                    xhttp = new XhttpSettings(mode, path, xHost, xhRaw, hasPadding, hasXmux, hasDownload);
                                }

                                if (TryGetObject(ssObj, "hysteriaSettings", out var hyObj))
                                {
                                    var hyAuth = TryGetString(hyObj, "auth");
                                    if (!string.IsNullOrWhiteSpace(hyAuth)) secrets.Add(hyAuth);
                                }

                                if (TryGetObject(ssObj, "wsSettings", out var wsObj))
                                {
                                    wsPath = TryGetString(wsObj, "path") ?? "/";
                                    if (TryGetObject(wsObj, "headers", out var hdrObj))
                                    {
                                        wsHost = TryGetString(hdrObj, "Host") ?? TryGetString(hdrObj, "host");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            var dnsServers = new List<string>();
            string? defaultResolver = null;
            if (TryGetObject(root, "route", out var routeEl))
            {
                defaultResolver = TryGetString(routeEl, "default_domain_resolver");
            }

            if (TryGetObject(root, "dns", out var dnsEl) && TryGetArray(dnsEl, "servers", out var serversEl))
            {
                foreach (var s in serversEl.EnumerateArray())
                {
                    if (s.ValueKind == JsonValueKind.String)
                    {
                        var strVal = s.GetString();
                        if (!string.IsNullOrWhiteSpace(strVal))
                        {
                            dnsServers.Add(NormalizeDnsEntry(strVal));
                        }
                        continue;
                    }

                    if (s.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var tag = TryGetString(s, "tag") ?? string.Empty;
                    var type = (TryGetString(s, "type") ?? string.Empty).ToLowerInvariant();
                    var addr = TryGetString(s, "address") ?? TryGetString(s, "server") ?? string.Empty;
                    var hasScopedDomains = TryGetArray(s, "domains", out var domArr) && domArr.GetArrayLength() > 0;

                    if (type == "https" && !string.IsNullOrWhiteSpace(addr))
                    {
                        dnsServers.Add(addr.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? addr : $"https://{addr}/dns-query");
                    }
                    else if (type == "tls" && !string.IsNullOrWhiteSpace(addr))
                    {
                        dnsServers.Add(addr.StartsWith("tls://", StringComparison.OrdinalIgnoreCase) ? addr : $"tls://{addr}");
                    }
                    else if (type is "fakeip" or "local")
                    {
                        dnsServers.Add(type);
                    }
                    else if (!string.IsNullOrWhiteSpace(addr))
                    {
                        var isBootstrapOrRuScoped =
                            (!string.IsNullOrWhiteSpace(defaultResolver) && string.Equals(tag, defaultResolver, StringComparison.Ordinal)) ||
                            tag.Contains("bootstrap", StringComparison.OrdinalIgnoreCase) ||
                            hasScopedDomains;
                        var normalizedAddr = NormalizeDnsEntry(addr);
                        if (normalizedAddr.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                            normalizedAddr.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
                        {
                            dnsServers.Add(normalizedAddr);
                        }
                        else
                        {
                            dnsServers.Add(isBootstrapOrRuScoped ? $"bootstrap:{normalizedAddr}" : normalizedAddr);
                        }
                    }
                }
            }

            var hasSniff = rawLower.Contains("\"sniff\": true", StringComparison.Ordinal) ||
                           rawLower.Contains("\"sniff\":true", StringComparison.Ordinal) ||
                           rawLower.Contains("\"sniffing\"", StringComparison.Ordinal) ||
                           (rawLower.Contains("\"action\"", StringComparison.Ordinal) &&
                            rawLower.Contains("\"sniff\"", StringComparison.Ordinal));

            var hasDnsHijack = rawLower.Contains("hijack-dns", StringComparison.Ordinal) ||
                               rawLower.Contains("dns-hijack", StringComparison.Ordinal) ||
                               rawLower.Contains("\"fakedns\"", StringComparison.Ordinal) ||
                               rawLower.Contains("\"dokodemo-door\"", StringComparison.Ordinal);

            var hasPrivateBypass = rawLower.Contains("ip_is_private", StringComparison.Ordinal) ||
                                   rawLower.Contains("geoip:private", StringComparison.Ordinal);

            var hasRuSplit = rawLower.Contains("geosite:category-ru", StringComparison.Ordinal) ||
                             rawLower.Contains("geoip:ru", StringComparison.Ordinal) ||
                             rawLower.Contains("domain:ru", StringComparison.Ordinal) ||
                             rawLower.Contains("\".ru\"", StringComparison.Ordinal) ||
                             rawLower.Contains("xn--p1ai", StringComparison.Ordinal);

            string protocolLabel;
            if (isSingBox)
            {
                protocolLabel = $"Sing-box ({transport}{(tlsMode == "reality" ? " · Reality" : string.Empty)})";
            }
            else if (proxyOutboundCount > 1)
            {
                protocolLabel = $"Xray Автовыбор ({proxyOutboundCount} узлов · {transport})";
            }
            else if (outboundProto is "hysteria" or "hysteria2")
            {
                protocolLabel = "Xray · Hysteria2 (QUIC/TLS)";
            }
            else if (outboundProto == "vless")
            {
                protocolLabel = tlsMode == "reality"
                    ? $"Xray · VLESS + {transport} + Reality"
                    : $"Xray · VLESS + {transport}";
            }
            else
            {
                protocolLabel = "Xray-core (JSON)";
            }

            return new NormalizedVpnProfile
            {
                Protocol = isSingBox ? VpnProtocol.SingBoxJson : VpnProtocol.XrayJson,
                ProtocolLabel = protocolLabel,
                Name = !string.IsNullOrWhiteSpace(customRemarks)
                    ? customRemarks.Trim()
                    : (isSingBox ? "Конфиг Sing-box" : "Конфиг Xray"),
                ServerHost = host,
                ServerPort = port,
                Transport = transport,
                DnsServers = dnsServers,
                Tls = new TlsSettings(tlsMode, sni, fp, flow, pbk, sid, allowInsecure, alpnList),
                Xhttp = xhttp,
                WsPath = wsPath,
                WsHost = wsHost,
                HasSniffing = hasSniff,
                HasDnsHijack = hasDnsHijack,
                HasPrivateBypass = hasPrivateBypass,
                HasRuSplitRules = hasRuSplit,
                BalancerOutboundCount = proxyOutboundCount,
                RawSecrets = secrets,
            };
        }
        catch (JsonException ex)
        {
            return Empty(VpnProtocol.Unknown, "Невалидный JSON", "Ошибка JSON") with
            {
                ParseWarnings = [$"Ошибка синтаксиса JSON: {ex.Message}"],
            };
        }
    }

    private static string NormalizeDnsEntry(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("https+local://", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://{trimmed["https+local://".Length..]}";
        }
        if (trimmed.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("fakedns", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed.ToLowerInvariant();
        }
        return trimmed;
    }

    private static bool TryGetPropertySafe(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out value))
        {
            return true;
        }
        value = default;
        return false;
    }

    private static bool TryGetObject(JsonElement element, string name, out JsonElement obj)
    {
        if (TryGetPropertySafe(element, name, out obj) && obj.ValueKind == JsonValueKind.Object)
        {
            return true;
        }
        obj = default;
        return false;
    }

    private static bool TryGetArray(JsonElement element, string name, out JsonElement arr)
    {
        if (TryGetPropertySafe(element, name, out arr) && arr.ValueKind == JsonValueKind.Array)
        {
            return true;
        }
        arr = default;
        return false;
    }

    private static string? TryGetString(JsonElement element, string name)
    {
        if (!TryGetPropertySafe(element, name, out var el)) return null;
        return el.ValueKind == JsonValueKind.String ? el.GetString() : null;
    }

    private static int? TryGetInt(JsonElement element, string name)
    {
        if (!TryGetPropertySafe(element, name, out var el)) return null;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var num)) return num;
        if (el.ValueKind == JsonValueKind.String && int.TryParse(el.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }
        return null;
    }

    private static bool? TryGetBool(JsonElement element, string name)
    {
        if (!TryGetPropertySafe(element, name, out var el)) return null;
        return el.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null,
        };
    }

    private static void ParseHostPort(string input, out string? host, out int? port)
    {
        host = null;
        port = null;
        var trimmed = input.Trim();
        var lastColon = trimmed.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(trimmed[(lastColon + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedPort))
        {
            host = trimmed[..lastColon].Trim('[', ']');
            port = parsedPort;
        }
        else if (!string.IsNullOrWhiteSpace(trimmed))
        {
            host = trimmed.Trim('[', ']');
        }
    }

    private static string SafeUnescape(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }

    private static NormalizedVpnProfile ParseLegacyOpenVpn(string raw)
    {
        return Empty(VpnProtocol.LegacyOpenVpn, "OpenVPN (устаревший для РФ)", "Профиль OpenVPN");
    }

    private static List<string> SplitUriLines(string text)
    {
        return text
            .Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => UriSchemes.Any(s => line.StartsWith(s, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query)) return result;

        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            var key = SafeUnescape(pair[..eq]);
            var val = SafeUnescape(pair[(eq + 1)..]);
            result[key] = val;
        }
        return result;
    }

    private static bool TryDecodeBase64Utf8(string input, out string decoded)
    {
        decoded = string.Empty;
        try
        {
            var normalized = input.Replace('-', '+').Replace('_', '/');
            var pad = normalized.Length % 4;
            if (pad > 0) normalized += new string('=', 4 - pad);
            var bytes = Convert.FromBase64String(normalized);
            decoded = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static NormalizedVpnProfile Empty(VpnProtocol proto, string label, string name) => new()
    {
        Protocol = proto,
        ProtocolLabel = label,
        Name = name,
        Transport = "—",
        Tls = new TlsSettings("none", null, null, null, null, null, false, []),
    };
}
