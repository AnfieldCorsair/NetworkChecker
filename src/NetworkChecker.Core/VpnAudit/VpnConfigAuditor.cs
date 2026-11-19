using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace NetworkChecker.Core.VpnAudit;

/// <summary>
/// Детерминированный аудитор ВПН-конфигураций без условного балла 0–100.
/// Фокус: VLESS (TCP Vision / XHTTP / WS), AmneziaWG, Hysteria2 и защита от DPI/ТСПУ в РФ.
/// </summary>
public static partial class VpnConfigAuditor
{
    private static readonly string[] ValidXhttpModes = ["auto", "packet-up", "stream-up", "stream-one"];

    [GeneratedRegex("^[0-9a-fA-F]{1,16}$")]
    private static partial Regex HexShortIdRegex();

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")]
    private static partial Regex UuidRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9+/]{42,43}=\b")]
    private static partial Regex WgKeyRegex();

    public static VpnAuditReport Audit(string rawConfig)
    {
        var profile = VpnConfigParser.Parse(rawConfig);
        var findings = new List<VpnAuditFinding>();

        if (profile.Protocol == VpnProtocol.Unknown)
        {
            findings.Add(new VpnAuditFinding(
                "parse-unknown",
                AuditCategory.Routing,
                AuditSeverity.Critical,
                "Формат конфигурации не распознан",
                "Вставьте ссылку vless://, hy2://, конфиг AmneziaWG (.conf), Xray/Sing-box JSON или подписку.",
                string.Join(" ", profile.ParseWarnings),
                rawConfig.Trim().Length > 80 ? rawConfig.Trim()[..80] : rawConfig.Trim(),
                "Проверьте синтаксис конфигурации или загрузите готовый профиль."));
            return new VpnAuditReport(DateTimeOffset.UtcNow, rawConfig, profile, findings);
        }

        if (profile.Protocol == VpnProtocol.LegacyOpenVpn)
        {
            findings.Add(new VpnAuditFinding(
                "legacy-openvpn-rf",
                AuditCategory.TransportDpi,
                AuditSeverity.Critical,
                "OpenVPN стабильно блокируется ТСПУ/DPI в РФ",
                "Классический OpenVPN (даже с tls-crypt) детектируется по сигнатурам и размерам пакетов рукопожатия.",
                "В текущих сетевых условиях РФ OpenVPN пригоден только внутри корпоративных белых списков.",
                "Формат OpenVPN (.ovpn)",
                "Перейдите на VLESS + XHTTP (или TCP Vision) с Reality либо AmneziaWG."));
            return new VpnAuditReport(DateTimeOffset.UtcNow, rawConfig, profile, findings);
        }

        if (profile.Protocol == VpnProtocol.LegacyWireGuard)
        {
            findings.Add(new VpnAuditFinding(
                "legacy-wg-rf",
                AuditCategory.TransportDpi,
                AuditSeverity.Critical,
                "Чистый WireGuard без модификации AmneziaWG не работает под DPI в РФ",
                "Немодифицированный заголовок инициации WireGuard (148 байт) блокируется магистральными и мобильными операторами.",
                "В секции [Interface] отсутствуют параметры обфускации AmneziaWG (Jc, Jmin, Jmax, S1, S2, H1–H4).",
                "WireGuard без Jc/S1/S2/H1-H4",
                "Переведите сервер и клиент на AmneziaWG либо используйте VLESS + XHTTP / TCP Vision."));
        }

        if (profile.Tls.AllowInsecure)
        {
            findings.Add(new VpnAuditFinding(
                "sec-allow-insecure",
                AuditCategory.Security,
                AuditSeverity.Critical,
                "Отключена проверка TLS-сертификата (allowInsecure / insecure=1)",
                "Клиент принимает любой поддельный сертификат — соединение уязвимо к перехвату (MITM).",
                "Флаг allowInsecure=1 / insecure=1 отключает проверку цепочки доверия TLS.",
                "allowInsecure=1 / insecure=1",
                "Удалите allowInsecure=1 и используйте валидный TLS-сертификат или Reality.",
                "allowInsecure=0"));
        }

        switch (profile.Protocol)
        {
            case VpnProtocol.Vless:
                AuditVless(profile, findings);
                break;
            case VpnProtocol.AmneziaWg:
            case VpnProtocol.LegacyWireGuard:
                AuditAmneziaOrWg(profile, findings);
                break;
            case VpnProtocol.Hysteria2:
                AuditHysteria2(profile, findings);
                break;
            case VpnProtocol.SingBoxJson:
            case VpnProtocol.XrayJson:
                AuditCoreJson(profile, findings);
                break;
        }

        return new VpnAuditReport(DateTimeOffset.UtcNow, rawConfig, profile, findings);
    }

    public static IReadOnlyList<SubscriptionNodeAudit> AuditSubscription(string rawInput)
    {
        var lines = VpnConfigParser.ExtractSubscriptionLines(rawInput);
        var list = new List<SubscriptionNodeAudit>(lines.Count);
        for (var i = 0; i < lines.Count; i++)
        {
            list.Add(new SubscriptionNodeAudit(i + 1, lines[i], Audit(lines[i])));
        }
        return list;
    }

    public static string MaskSensitiveText(string input, IEnumerable<string>? extraSecrets = null)
    {
        if (string.IsNullOrEmpty(input)) return input;
        var text = input;
        if (extraSecrets is not null)
        {
            foreach (var secret in extraSecrets)
            {
                if (!string.IsNullOrEmpty(secret) && secret.Length >= 6)
                {
                    text = text.Replace(secret, MaskToken(secret), StringComparison.Ordinal);
                }
            }
        }
        text = UuidRegex().Replace(text, m => MaskToken(m.Value));
        text = WgKeyRegex().Replace(text, m => MaskToken(m.Value));
        return text;
    }

    private static string MaskToken(string value) =>
        value.Length <= 8 ? "••••••••" : $"{value[..4]}••••{value[^4..]}";

    /// <summary>
    /// Генерирует JSON-фрагмент outbound (Xray v25+ или Sing-box 1.12+) для разобранного узла.
    /// </summary>
    public static string BuildNodeOutboundJson(NormalizedVpnProfile p, bool singBoxFormat = false)
    {
        var server = p.ServerHost ?? "example.com";
        var port = p.ServerPort ?? 443;
        var secret = p.RawSecrets.Count > 0 ? p.RawSecrets[0] : "<UUID_OR_SECRET>";

        if (singBoxFormat)
        {
            return $$"""
            {
              "type": "{{p.Protocol.ToString().ToLowerInvariant()}}",
              "tag": "proxy",
              "server": "{{server}}",
              "server_port": {{port}},
              "uuid": "{{secret}}",
              "tls": {
                "enabled": {{(p.Tls.Mode != "none" ? "true" : "false")}},
                "server_name": "{{p.Tls.Sni ?? server}}",
                "utls": {
                  "enabled": true,
                  "fingerprint": "{{p.Tls.Fingerprint ?? "chrome"}}"
                }
              }
            }
            """;
        }

        var network = p.Xhttp is not null ? "xhttp" : p.Transport.ToLowerInvariant();
        return $$"""
        {
          "tag": "proxy",
          "protocol": "vless",
          "settings": {
            "vnext": [
              {
                "address": "{{server}}",
                "port": {{port}},
                "users": [
                  {
                    "id": "{{secret}}",
                    "encryption": "none",
                    "flow": "{{p.Tls.Flow ?? ""}}"
                  }
                ]
              }
            ]
          },
          "streamSettings": {
            "network": "{{network}}",
            "security": "{{p.Tls.Mode}}"
          }
        }
        """;
    }

    private static void AuditVless(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        if (p.Tls.Mode == "none")
        {
            findings.Add(new VpnAuditFinding(
                "vless-no-tls",
                AuditCategory.Security,
                AuditSeverity.Critical,
                "VLESS без Reality или TLS (security=none)",
                "VLESS сам не шифрует трафик — без внешней обёртки он открыт для анализа и мгновенной блокировки.",
                $"Обнаружен security=none на транспорте {p.Transport}.",
                "security=none",
                "Включите security=reality (для TCP/XHTTP) или полноценный TLS 1.3.",
                "&security=reality&fp=chrome"));
        }

        // XHTTP (SplitHTTP) — приоритетный транспорт
        if (p.Xhttp is not null)
        {
            if (!ValidXhttpModes.Contains(p.Xhttp.Mode, StringComparer.OrdinalIgnoreCase))
            {
                findings.Add(new VpnAuditFinding(
                    "vless-xhttp-mode",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Warning,
                    $"Нестандартный режим XHTTP (mode={p.Xhttp.Mode})",
                    "Для XHTTP рекомендуются режимы auto, packet-up или stream-up в зависимости от наличия CDN.",
                    $"Задано mode={p.Xhttp.Mode}, path={p.Xhttp.Path}.",
                    $"mode={p.Xhttp.Mode}",
                    "Используйте mode=auto (для прямого Reality) или mode=packet-up (через CDN/обратный прокси).",
                    "&mode=auto"));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "vless-xhttp-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    $"Актуальный транспорт VLESS XHTTP (mode={p.Xhttp.Mode})",
                    "XHTTP (SplitHTTP) хорошо проходит через современные фильтры и поддерживает разделение upload/download.",
                    $"path={p.Xhttp.Path}, host={p.Xhttp.Host ?? "авто"}, padding={(p.Xhttp.HasPadding ? "да" : "по умолчанию")}, xmux={(p.Xhttp.HasXmux ? "настроен" : "авто")}.",
                    $"type=xhttp&mode={p.Xhttp.Mode}",
                    "Убедитесь, что клиент обновлён до Xray-core v24.11+ / v25+."));
            }

            if (p.Xhttp.Path == "/" && p.Tls.Mode == "tls")
            {
                findings.Add(new VpnAuditFinding(
                    "vless-xhttp-root-path",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Warning,
                    "Корневой path=/ для XHTTP поверх TLS",
                    "При использовании обратного прокси (Nginx/Caddy/CDN) случайный длинный путь лучше скрывает эндпоинт от активного сканирования.",
                    "path=/ легко нащупать простым GET-запросом на корень домена.",
                    "path=/",
                    "Задайте неочевидный путь, например path=/assets/v2/stream-8f4a."));
            }
        }

        // WebSocket (WS) — честное предупреждение по РФ
        if (p.Transport == "WS")
        {
            findings.Add(new VpnAuditFinding(
                "vless-ws-rf-stability",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "WebSocket (WS) в РФ работает с переменной стабильностью",
                "Часть операторов режет долгие WS-сессии или CDN-диапазоны; WS стоит держать как запасной вариант.",
                $"path={p.WsPath ?? "/"}, host={p.WsHost ?? "не задан"}, earlyData={p.WsEarlyData?.ToString(CultureInfo.InvariantCulture) ?? "нет"}.",
                "type=ws",
                "Для основного канала рекомендуется VLESS + XHTTP (Reality) или VLESS + TCP + Vision (Reality)."));

            if (string.IsNullOrWhiteSpace(p.WsHost) && string.IsNullOrWhiteSpace(p.Tls.Sni))
            {
                findings.Add(new VpnAuditFinding(
                    "vless-ws-no-host",
                    AuditCategory.Routing,
                    AuditSeverity.Critical,
                    "Для VLESS WS не заданы ни host, ни sni",
                    "Обратный прокси или CDN отклонит WebSocket Upgrade без заголовка Host.",
                    "Отсутствуют параметры host и sni в URI.",
                    "host=пусто, sni=пусто",
                    "Укажите рабочий домен в параметрах host и sni."));
            }
        }

        // TCP (RAW) + Reality
        if (p.Transport is "TCP" or "RAW" && p.Tls.Mode == "reality")
        {
            if (!string.Equals(p.Tls.Flow, "xtls-rprx-vision", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new VpnAuditFinding(
                    "vless-tcp-no-vision",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    "VLESS TCP + Reality без flow=xtls-rprx-vision",
                    "Без XTLS-Vision вложенный TLS-трафик имеет характерную сигнатуру длины пакетов и легче детектируется.",
                    $"Текущий flow: {p.Tls.Flow ?? "не указан"}.",
                    $"flow={p.Tls.Flow ?? "отсутствует"}",
                    "Добавьте параметр flow=xtls-rprx-vision в клиентскую ссылку и серверный inbound.",
                    "&flow=xtls-rprx-vision"));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "vless-tcp-vision-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    "VLESS TCP + XTLS-Vision настроен корректно",
                    "XTLS-Vision устраняет паттерн «TLS внутри TLS».",
                    "flow=xtls-rprx-vision активен.",
                    "flow=xtls-rprx-vision",
                    "Дополнительных изменений по flow не требуется."));
            }
        }

        // Общие проверки Reality
        if (p.Tls.Mode == "reality")
        {
            if (string.IsNullOrWhiteSpace(p.Tls.PublicKey) || p.Tls.PublicKey.Length < 40)
            {
                findings.Add(new VpnAuditFinding(
                    "reality-bad-pbk",
                    AuditCategory.Security,
                    AuditSeverity.Critical,
                    "Отсутствует или некорректен Reality PublicKey (pbk)",
                    "Ключ X25519 должен иметь длину ~43 символа (Base64URL), иначе рукопожатие Reality не пройдёт.",
                    $"pbk={p.Tls.PublicKey ?? "отсутствует"}.",
                    $"pbk={p.Tls.PublicKey ?? "пусто"}",
                    "Скопируйте корректный публичный ключ из серверного конфига Xray/Sing-box."));
            }

            if (!string.IsNullOrWhiteSpace(p.Tls.ShortId) && !HexShortIdRegex().IsMatch(p.Tls.ShortId))
            {
                findings.Add(new VpnAuditFinding(
                    "reality-bad-sid",
                    AuditCategory.Security,
                    AuditSeverity.Warning,
                    $"Некорректный формат ShortId (sid={p.Tls.ShortId})",
                    "ShortId в Reality должен быть шестнадцатеричной строкой (hex) длиной от 1 до 16 символов.",
                    $"Найдено sid={p.Tls.ShortId}.",
                    $"sid={p.Tls.ShortId}",
                    "Задайте корректный hex shortId (например a1b2c3d4) совпадающий с сервером."));
            }

            if (string.IsNullOrWhiteSpace(p.Tls.Sni) ||
                IPAddress.TryParse(p.Tls.Sni, out _) ||
                string.Equals(p.Tls.Sni, p.ServerHost, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new VpnAuditFinding(
                    "reality-bad-sni",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    $"Неподходящий SNI для Reality ({p.Tls.Sni ?? "не указан"})",
                    "SNI должен указывать на реальный крупный внешний домен с TLS 1.3 + HTTP/2, а не на IP или сам сервер.",
                    $"sni={p.Tls.Sni ?? "отсутствует"}, server={p.ServerHost ?? "—"}.",
                    $"sni={p.Tls.Sni ?? "пусто"}",
                    "Подберите стабильный зарубежный/нейтральный домен с TLS 1.3 + ALPN h2 и проверьте его кнопкой «Проверить SNI»."));
            }
        }

        if (p.Tls.Mode is "reality" or "tls" && string.IsNullOrWhiteSpace(p.Tls.Fingerprint))
        {
            findings.Add(new VpnAuditFinding(
                "vless-no-fp",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не задан uTLS-отпечаток браузера (fp)",
                "Без fp клиент использует стандартный отпечаток Go TLS, который легко отличить от реального браузера.",
                "Параметр fp отсутствует в URI.",
                "fp=отсутствует",
                "Добавьте fp=chrome или fp=firefox (или randomized).",
                "&fp=chrome"));
        }

        if (p.ServerPort.HasValue && p.ServerPort.Value != 443)
        {
            findings.Add(new VpnAuditFinding(
                "vless-non-443",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                $"Нестандартный порт для маскировки под HTTPS ({p.ServerPort.Value})",
                "Порт 443 максимально сливается с обычным веб-трафиком и реже режется корпоративными/мобильными фильтрами.",
                $"Порт: {p.ServerPort.Value}.",
                $"port={p.ServerPort.Value}",
                "При возможности переведите сервер на порт 443."));
        }
    }

    private static void AuditAmneziaOrWg(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        if (p.AmneziaWg is { } awg)
        {
            if (awg.S1.HasValue && awg.S2.HasValue && awg.S1.Value + 56 == awg.S2.Value)
            {
                findings.Add(new VpnAuditFinding(
                    "awg-s1-s2-collision",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    $"Конфликт параметров AmneziaWG: S1 + 56 == S2 ({awg.S1} + 56 = {awg.S2})",
                    "При равенстве S1 + 56 == S2 клиент и сервер не отличают пакет инициации от ответа — туннель не поднимется.",
                    $"Текущие значения: S1={awg.S1}, S2={awg.S2}.",
                    $"S1 = {awg.S1}, S2 = {awg.S2}",
                    "Измените S1 или S2 на сервере и клиенте так, чтобы S1 + 56 != S2."));
            }

            if (awg.Jmin.HasValue && awg.Jmax.HasValue && (awg.Jmin.Value > awg.Jmax.Value || awg.Jmax.Value > 1280))
            {
                findings.Add(new VpnAuditFinding(
                    "awg-junk-range",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    $"Некорректный диапазон мусорных пакетов (Jmin={awg.Jmin}, Jmax={awg.Jmax})",
                    "Должно выполняться Jmin <= Jmax <= 1280, иначе пакеты фрагментируются или отбрасываются.",
                    $"Jmin={awg.Jmin}, Jmax={awg.Jmax}.",
                    $"Jmin = {awg.Jmin}, Jmax = {awg.Jmax}",
                    "Установите, например, Jmin = 50, Jmax = 1000 (синхронно с сервером)."));
            }

            var headers = new[] { awg.H1, awg.H2, awg.H3, awg.H4 }.Where(h => h.HasValue).Select(h => h!.Value).ToArray();
            if (headers.Length == 4 && headers.Distinct().Count() < 4)
            {
                findings.Add(new VpnAuditFinding(
                    "awg-duplicate-headers",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    "Совпадающие магические заголовки H1–H4 в AmneziaWG",
                    "Все четыре идентификатора H1, H2, H3, H4 должны быть уникальными числами.",
                    $"Значения: H1={awg.H1}, H2={awg.H2}, H3={awg.H3}, H4={awg.H4}.",
                    $"H1..H4 дублируются",
                    "Задайте 4 разных случайных числа в диапазоне uint32 на сервере и клиенте."));
            }
            else if (awg.S1.HasValue && awg.S2.HasValue && awg.S1.Value + 56 != awg.S2.Value)
            {
                findings.Add(new VpnAuditFinding(
                    "awg-params-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    "Параметры обфускации AmneziaWG согласованы",
                    "S1 + 56 != S2, диапазон мусорных пакетов и заголовки H1–H4 корректны.",
                    $"Jc={awg.Jc}, Jmin={awg.Jmin}, Jmax={awg.Jmax}, S1={awg.S1}, S2={awg.S2}.",
                    "Параметры AWG валидны",
                    "Убедитесь, что значения полностью совпадают с серверной стороной."));
            }
        }

        if (p.DnsServers.Count == 0)
        {
            findings.Add(new VpnAuditFinding(
                "wg-no-dns",
                AuditCategory.Leaks,
                AuditSeverity.Critical,
                "Не задан DNS в [Interface] — утечка DNS-запросов",
                "Без явного DNS система отправит все запросы резолверу провайдера в обход туннеля.",
                "Директива DNS отсутствует.",
                "DNS не указан",
                "Добавьте DNS = 1.1.1.1, 9.9.9.9 в секцию [Interface].",
                "DNS = 1.1.1.1, 9.9.9.9"));
        }

        if (p.RoutesAllIpv4 && !p.RoutesAllIpv6)
        {
            findings.Add(new VpnAuditFinding(
                "wg-ipv6-leak",
                AuditCategory.Leaks,
                AuditSeverity.Critical,
                "Утечка IPv6 мимо туннеля (нет ::/0 в AllowedIPs)",
                "На провайдерах с IPv6 браузер пойдёт напрямую в обход ВПН.",
                $"AllowedIPs = {string.Join(", ", p.AllowedIps)}.",
                $"AllowedIPs = {string.Join(", ", p.AllowedIps)}",
                "Добавьте ::/0 в AllowedIPs либо отключите IPv6 на локальном адаптере.",
                "AllowedIPs = 0.0.0.0/0, ::/0"));
        }

        if (!p.Mtu.HasValue || p.Mtu.Value > 1380)
        {
            findings.Add(new VpnAuditFinding(
                "wg-high-mtu",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                $"Завышенный или не заданный MTU ({p.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "по умолчанию"})",
                "Для AmneziaWG с добавленными заголовками S1/S2 высокий MTU часто приводит к «зависанию» сайтов на мобильной сети и PPPoE.",
                $"Текущий MTU: {p.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "не задан (1420)"}.",
                $"MTU = {p.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "авто"}",
                "Задайте MTU = 1280 или 1340 в секции [Interface].",
                "MTU = 1280"));
        }

        if (!p.PersistentKeepalive.HasValue || p.PersistentKeepalive.Value == 0)
        {
            findings.Add(new VpnAuditFinding(
                "wg-no-keepalive",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Отключён PersistentKeepalive",
                "За NAT провайдера UDP-сессия будет обрываться при простое.",
                "PersistentKeepalive не задан в [Peer].",
                "PersistentKeepalive отсутствует",
                "Добавьте PersistentKeepalive = 25 в секцию [Peer].",
                "PersistentKeepalive = 25"));
        }
    }

    private static void AuditHysteria2(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        findings.Add(new VpnAuditFinding(
            "hy2-udp-rf-warning",
            AuditCategory.TransportDpi,
            AuditSeverity.Warning,
            "Hysteria2 работает по UDP/QUIC — возможен троттлинг в сетях РФ",
            "На части мобильных и региональных провайдеров в РФ UDP-трафик искусственно режется или блокируется.",
            "Рекомендуется использовать Hysteria2 вместе с port hopping (mport) и держать резервный узел на VLESS TCP/XHTTP.",
            $"QUIC/UDP :{p.ServerPort}",
            "Настройте mport (прыжки по портам) и держите VLESS XHTTP/Vision как основной канал."));

        if (!string.Equals(p.Obfs, "salamander", StringComparison.OrdinalIgnoreCase) || !p.HasObfsPassword)
        {
            findings.Add(new VpnAuditFinding(
                "hy2-no-salamander",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не включена обфускация Salamander (obfs=salamander)",
                "Без Salamander QUIC-рукопожатие Hysteria2 легче классифицируется фильтрами операторов.",
                $"obfs={p.Obfs ?? "нет"}, obfs-password={(p.HasObfsPassword ? "задан" : "нет")}.",
                "obfs не настроен",
                "Включите obfs=salamander и задайте стойкий obfs-password на сервере и клиенте.",
                "&obfs=salamander&obfs-password=<пароль>"));
        }

        if (string.IsNullOrWhiteSpace(p.PortHopping))
        {
            findings.Add(new VpnAuditFinding(
                "hy2-no-mport",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не настроен Port Hopping (mport)",
                "Прыжки по диапазону UDP-портов помогают обходить пороговое ограничение скорости на один UDP-поток.",
                "Параметр mport отсутствует.",
                "mport не задан",
                "Настройте iptables DNAT на сервере и добавьте &mport=20000-40000 в ссылку."));
        }
    }

    private static void AuditCoreJson(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        var plainDns = p.DnsServers
            .Where(d =>
                !d.StartsWith("bootstrap:", StringComparison.OrdinalIgnoreCase) &&
                !d.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                !d.StartsWith("tls://", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(d, "fakeip", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(d, "local", StringComparison.OrdinalIgnoreCase) &&
                (IPAddress.TryParse(d, out _) || d.StartsWith("udp://", StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        var encryptedDns = p.DnsServers
            .Where(d =>
                d.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                d.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (plainDns.Length > 0)
        {
            findings.Add(new VpnAuditFinding(
                "json-plain-dns",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Используется открытый UDP DNS",
                "Незашифрованный UDP DNS (порт 53) легко подменяется провайдером.",
                $"Открытые серверы: {string.Join(", ", plainDns)}.",
                string.Join(", ", plainDns),
                "Переведите основной DNS на DoH (https://1.1.1.1/dns-query) через прокси-outbound."));
        }
        else if (encryptedDns.Length > 0)
        {
            findings.Add(new VpnAuditFinding(
                "json-encrypted-dns-ok",
                AuditCategory.Leaks,
                AuditSeverity.Ok,
                "Настроен зашифрованный DNS (DoH / DoT)",
                "Запросы доменов защищены от перехвата и подмены со стороны провайдера.",
                $"Серверы: {string.Join(", ", encryptedDns)}.",
                string.Join(", ", encryptedDns),
                "Изменения по транспорту DNS не требуются."));
        }

        if (!p.HasSniffing)
        {
            findings.Add(new VpnAuditFinding(
                "json-no-sniff",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Не включён sniffing входящих соединений",
                "Без восстановления домена по TLS SNI доменные правила split-tunneling срабатывают не полностью.",
                "Правило { \"action\": \"sniff\" } не найдено.",
                "sniff отключён",
                "Включите { \"action\": \"sniff\" } в route.rules (Sing-box 1.11+ / 1.12+)."));
        }

        if (!p.HasDnsHijack)
        {
            findings.Add(new VpnAuditFinding(
                "json-no-hijack-dns",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Не найден перехват DNS (hijack-dns)",
                "Приложения со вшитым 8.8.8.8 могут обходить DNS-правила конфига.",
                "Правило hijack-dns не обнаружено.",
                "hijack-dns отсутствует",
                "Добавьте правило перехвата протокола dns в route.rules."));
        }

        if (!p.HasPrivateBypass)
        {
            findings.Add(new VpnAuditFinding(
                "json-no-private-bypass",
                AuditCategory.Routing,
                AuditSeverity.Warning,
                "Не найдено правило обхода локальной сети (ip_is_private / geoip:private)",
                "При полном туннелировании может пропасть доступ к роутеру и локальным сервисам.",
                "Исключение приватных подсетей не обнаружено.",
                "ip_is_private не найден",
                "Добавьте { \"ip_is_private\": true, \"outbound\": \"direct\" } в начало route.rules."));
        }
    }
}
