using System.Globalization;
using System.Text;
using System.Text.Json;

namespace NetworkChecker.Core.VpnAudit;

/// <summary>
/// Парсер и нормализатор ВПН-конфигураций с приоритетом под реалии РФ:
/// VLESS (TCP/Vision, XHTTP/SplitHTTP, WS), AmneziaWG, Hysteria2, Sing-box/Xray JSON и подписки.
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

    public static IReadOnlyList<string> ExtractSubscriptionLines(string rawInput)
    {
        if (string.IsNullOrWhiteSpace(rawInput)) return [];

        var trimmed = rawInput.Trim();
        var directLines = SplitUriLines(trimmed);
        if (directLines.Count > 0) return directLines;

        // Попытка декодировать Base64-подписку (типичный формат раздачи от панелей 3x-ui / Marzban / Remnawave)
        if (!trimmed.Contains(' ', StringComparison.Ordinal) &&
            !trimmed.Contains('[', StringComparison.Ordinal) &&
            !trimmed.StartsWith('{') &&
            trimmed.Length >= 24)
        {
            if (TryDecodeBase64Utf8(trimmed, out var decoded))
            {
                var decodedLines = SplitUriLines(decoded);
                if (decodedLines.Count > 0) return decodedLines;
            }
        }

        return [];
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
            return ParseUri(subLines[0]);
        }

        if (trimmed.StartsWith('{'))
        {
            return ParseJsonConfig(trimmed);
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
            ParseWarnings = ["Поддерживаются VLESS (TCP/XHTTP/WS), AmneziaWG, Hysteria2, Xray/Sing-box JSON и подписки (список или Base64)."],
        };
    }

    private static NormalizedVpnProfile ParseUri(string uriText)
    {
        if (!Uri.TryCreate(uriText.Trim(), UriKind.Absolute, out var uri))
        {
            return Empty(VpnProtocol.Unknown, "Битая URI-ссылка", "Ошибка синтаксиса") with
            {
                ParseWarnings = ["Не удалось разобрать URI-ссылку."],
            };
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        var name = string.IsNullOrWhiteSpace(uri.Fragment)
            ? $"Узел {scheme.ToUpperInvariant()}"
            : Uri.UnescapeDataString(uri.Fragment.TrimStart('#'));
        var query = ParseQueryString(uri.Query);
        var secrets = new List<string>();
        var userInfo = Uri.UnescapeDataString(uri.UserInfo);
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

        return Empty(VpnProtocol.LegacyShadowsocks, $"Протокол {scheme.ToUpperInvariant()}", name) with
        {
            ServerHost = uri.Host,
            ServerPort = uri.Port > 0 ? uri.Port : 443,
            RawSecrets = secrets,
        };
    }

    private static NormalizedVpnProfile ParseWireGuardOrAmnezia(string raw)
    {
        var iface = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var peer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var section = string.Empty;

        foreach (var rawLine in raw.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
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

        int? TryInt(string key) =>
            iface.TryGetValue(key, out var s) && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        long? TryLong(string key) =>
            iface.TryGetValue(key, out var s) && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

        var awg = new AmneziaWgSettings(
            TryInt("Jc"), TryInt("Jmin"), TryInt("Jmax"),
            TryInt("S1"), TryInt("S2"),
            TryLong("H1"), TryLong("H2"), TryLong("H3"), TryLong("H4"));

        var isAmnezia = awg.Jc.HasValue || awg.S1.HasValue || awg.S2.HasValue || awg.H1.HasValue;

        string? host = null;
        int? port = null;
        if (peer.TryGetValue("Endpoint", out var endpoint))
        {
            var lastColon = endpoint.LastIndexOf(':');
            if (lastColon > 0 && int.TryParse(endpoint[(lastColon + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var p))
            {
                host = endpoint[..lastColon].Trim('[', ']');
                port = p;
            }
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
            var isSingBox = root.TryGetProperty("outbounds", out var outs) &&
                            outs.ValueKind == JsonValueKind.Array &&
                            outs.EnumerateArray().Any(e => e.TryGetProperty("type", out _));

            var rawLower = raw.ToLowerInvariant();
            string? host = null;
            int? port = null;
            var transport = "TCP";

            if (root.TryGetProperty("outbounds", out var outbounds) && outbounds.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in outbounds.EnumerateArray())
                {
                    if (item.TryGetProperty("server", out var srv) && srv.ValueKind == JsonValueKind.String)
                    {
                        host = srv.GetString();
                        if (item.TryGetProperty("server_port", out var sp) && sp.TryGetInt32(out var spVal))
                        {
                            port = spVal;
                        }
                        if (item.TryGetProperty("transport", out var tr) && tr.TryGetProperty("type", out var trType))
                        {
                            transport = (trType.GetString() ?? "TCP").ToUpperInvariant();
                        }
                        break;
                    }
                }
            }

            var dnsServers = new List<string>();
            string? defaultResolver = null;
            if (root.TryGetProperty("route", out var routeEl) &&
                routeEl.TryGetProperty("default_domain_resolver", out var ddrEl) &&
                ddrEl.ValueKind == JsonValueKind.String)
            {
                defaultResolver = ddrEl.GetString();
            }

            if (root.TryGetProperty("dns", out var dnsEl) &&
                dnsEl.TryGetProperty("servers", out var serversEl) &&
                serversEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var s in serversEl.EnumerateArray())
                {
                    var tag = s.TryGetProperty("tag", out var tEl) && tEl.ValueKind == JsonValueKind.String
                        ? tEl.GetString() ?? string.Empty
                        : string.Empty;
                    var type = s.TryGetProperty("type", out var tyEl) && tyEl.ValueKind == JsonValueKind.String
                        ? (tyEl.GetString() ?? string.Empty).ToLowerInvariant()
                        : string.Empty;
                    var addr = s.TryGetProperty("address", out var aEl) && aEl.ValueKind == JsonValueKind.String
                        ? aEl.GetString() ?? string.Empty
                        : s.TryGetProperty("server", out var svEl) && svEl.ValueKind == JsonValueKind.String
                            ? svEl.GetString() ?? string.Empty
                            : string.Empty;

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
                        var isBootstrap =
                            (!string.IsNullOrWhiteSpace(defaultResolver) && string.Equals(tag, defaultResolver, StringComparison.Ordinal)) ||
                            tag.Contains("bootstrap", StringComparison.OrdinalIgnoreCase);
                        dnsServers.Add(isBootstrap ? $"bootstrap:{addr}" : addr);
                    }
                }
            }

            var hasSniff = rawLower.Contains("\"sniff\": true", StringComparison.Ordinal) ||
                           (rawLower.Contains("\"action\"", StringComparison.Ordinal) &&
                            rawLower.Contains("\"sniff\"", StringComparison.Ordinal));

            return new NormalizedVpnProfile
            {
                Protocol = isSingBox ? VpnProtocol.SingBoxJson : VpnProtocol.XrayJson,
                ProtocolLabel = isSingBox ? "Sing-box (JSON)" : "Xray-core (JSON)",
                Name = isSingBox ? "Конфиг Sing-box" : "Конфиг Xray",
                ServerHost = host,
                ServerPort = port,
                Transport = transport,
                DnsServers = dnsServers,
                Tls = new TlsSettings(
                    rawLower.Contains("\"reality\"", StringComparison.Ordinal) ? "reality" : "tls",
                    null, null, null, null, null,
                    rawLower.Contains("\"insecure\": true", StringComparison.Ordinal) || rawLower.Contains("\"allowinsecure\": true", StringComparison.Ordinal),
                    []),
                HasSniffing = hasSniff,
                HasDnsHijack = rawLower.Contains("hijack-dns", StringComparison.Ordinal),
                HasPrivateBypass = rawLower.Contains("ip_is_private", StringComparison.Ordinal) || rawLower.Contains("geoip:private", StringComparison.Ordinal),
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

    private static NormalizedVpnProfile ParseLegacyOpenVpn(string raw)
    {
        return Empty(VpnProtocol.LegacyOpenVpn, "OpenVPN (устаревший для РФ)", "Профиль OpenVPN");
    }

    private static List<string> SplitUriLines(string text)
    {
        return text
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
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
            var key = Uri.UnescapeDataString(pair[..eq]);
            var val = Uri.UnescapeDataString(pair[(eq + 1)..]);
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
