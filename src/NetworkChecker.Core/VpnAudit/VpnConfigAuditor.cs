using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace NetworkChecker.Core.VpnAudit;

/// <summary>
/// Детерминированный аудитор ВПН-конфигураций с понятными объяснениями для обычного пользователя
/// и глубокими инженерными деталями (VLESS TCP Vision / XHTTP / WS, AmneziaWG, Hysteria2, Xray/Sing-box JSON и подписки Happ).
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

        if (VpnConfigParser.TryExtractHttpSubscriptionUrl(rawConfig, out var subUri) && subUri is not null)
        {
            findings.Add(new VpnAuditFinding(
                "sub-url-detected",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                $"Распознана ссылка на подписку ({subUri.Host})",
                "Вы вставили ссылку на подписку. Программа автоматически скачивает список всех локаций и проверяет каждую из них.",
                $"URL подписки: {subUri}",
                subUri.ToString(),
                "Если автозагрузка ещё не началась, нажмите кнопку «Загрузить подписку по ссылке»."));
            return new VpnAuditReport(DateTimeOffset.UtcNow, rawConfig, profile, findings);
        }

        if (profile.Protocol == VpnProtocol.Unknown)
        {
            findings.Add(new VpnAuditFinding(
                "parse-unknown",
                AuditCategory.Routing,
                AuditSeverity.Critical,
                "Формат конфигурации не распознан",
                "Вставьте ссылку на подписку (https://...), ключ vless://, hy2://, конфиг AmneziaWG (.conf) или JSON-профиль Happ/Xray/Sing-box.",
                string.Join(" ", profile.ParseWarnings),
                rawConfig.Trim().Length > 80 ? rawConfig.Trim()[..80] : rawConfig.Trim(),
                "Проверьте, что ссылка скопирована полностью, или выберите один из тестовых примеров."));
            return new VpnAuditReport(DateTimeOffset.UtcNow, rawConfig, profile, findings);
        }

        if (profile.Protocol == VpnProtocol.LegacyOpenVpn)
        {
            findings.Add(new VpnAuditFinding(
                "legacy-openvpn-rf",
                AuditCategory.TransportDpi,
                AuditSeverity.Critical,
                "OpenVPN стабильно блокируется ТСПУ/DPI в РФ",
                "Оборудование провайдеров легко узнаёт классический OpenVPN по первым пакетам подключения и обрывает связь.",
                "Даже с tls-crypt OpenVPN детектируется по сигнатурам P_CONTROL_HARD_RESET_CLIENT_V2 и размерам пакетов рукопожатия.",
                "Формат OpenVPN (.ovpn)",
                "Попросите у провайдера ВПН ключ формата VLESS + XHTTP / Reality либо AmneziaWG."));
            return new VpnAuditReport(DateTimeOffset.UtcNow, rawConfig, profile, findings);
        }

        if (profile.Protocol == VpnProtocol.LegacyWireGuard)
        {
            findings.Add(new VpnAuditFinding(
                "legacy-wg-rf",
                AuditCategory.TransportDpi,
                AuditSeverity.Critical,
                "Обычный WireGuard без защиты AmneziaWG блокируется в РФ",
                "Чистый WireGuard без маскировки пакетов блокируется на мобильном интернете и большинстве домашних провайдеров.",
                "В секции [Interface] отсутствуют параметры обфускации AmneziaWG (Jc, Jmin, Jmax, S1, S2, H1–H4), поэтому пакет инициации (148 байт) сразу виден ТСПУ.",
                "WireGuard без Jc/S1/S2/H1-H4",
                "Откройте конфиг в AmneziaWG (с параметрами Jc/S1/S2) или перейдите на VLESS + XHTTP / Reality."));
        }

        if (profile.Tls.AllowInsecure)
        {
            findings.Add(new VpnAuditFinding(
                "sec-allow-insecure",
                AuditCategory.Security,
                AuditSeverity.Critical,
                "Отключена проверка подлинности сервера (allowInsecure=1)",
                "С этой настройкой любой узел по пути может притвориться вашим ВПН-сервером и перехватить трафик.",
                "Флаг allowInsecure=1 / insecure=1 отключает верификацию цепочки TLS X.509 сертификата.",
                "allowInsecure=1 / insecure=1",
                "Нажмите «Автолечение подписки (Блок-патч)», чтобы автоматически убрать небезопасный флаг allowInsecure.",
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
            case VpnProtocol.Trojan:
                AuditTrojan(profile, findings);
                break;
            case VpnProtocol.Vmess:
                AuditVmess(profile, findings);
                break;
            case VpnProtocol.LegacyShadowsocks:
                AuditShadowsocks(profile, findings);
                break;
            case VpnProtocol.SingBoxJson:
            case VpnProtocol.XrayJson:
                AuditCoreJson(profile, rawConfig, findings);
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
                "Узел VLESS не защищён шифрованием (security=none)",
                "Без защиты Reality или TLS ваш трафик виден провайдеру в открытом виде и сразу блокируется.",
                $"Обнаружен security=none на транспорте {p.Transport}.",
                "security=none",
                "Используйте узел с включённым security=reality (XHTTP или TCP Vision) либо TLS 1.3.",
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
                    "В параметрах транспорта указан редкий режим, из-за которого клиент может не подключиться.",
                    $"Задано mode={p.Xhttp.Mode}, path={p.Xhttp.Path}. Поддерживаемые режимы: auto, packet-up, stream-up, stream-one.",
                    $"mode={p.Xhttp.Mode}",
                    "Нажмите «Автолечение подписки (Блок-патч)», чтобы исправить режим на mode=auto.",
                    "&mode=auto"));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "vless-xhttp-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    $"Современная защита от блокировок: VLESS XHTTP (mode={p.Xhttp.Mode})",
                    "Протокол XHTTP (SplitHTTP) дробит и маскирует поток под обычные веб-запросы, отлично обходя лимит 16 КБ и фильтры ТСПУ.",
                    $"path={p.Xhttp.Path}, host={p.Xhttp.Host ?? "авто"}, xPaddingBytes={(p.Xhttp.HasPadding ? "настроен" : "по умолчанию")}, xmux={(p.Xhttp.HasXmux ? "включён" : "авто")}.",
                    $"type=xhttp&mode={p.Xhttp.Mode}&path={p.Xhttp.Path}",
                    "Отличный выбор для РФ. Работает в Happ, v2rayN, Hiddify и NekoBox."));
            }

            if (p.Xhttp.Path == "/" && p.Tls.Mode == "tls")
            {
                findings.Add(new VpnAuditFinding(
                    "vless-xhttp-root-path",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Warning,
                    "Простой корневой путь path=/ для XHTTP поверх TLS",
                    "Длинный случайный путь лучше прячет сервер от автоматических проверок.",
                    "path=/ легко проверить обычным GET-запросом к корню домена.",
                    "path=/",
                    "При настройке своего сервера задайте путь вроде /api/v2/stream."));
            }
        }

        // WebSocket (WS)
        if (p.Transport == "WS")
        {
            findings.Add(new VpnAuditFinding(
                "vless-ws-rf-stability",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Транспорт WebSocket (WS) — лучше держать как запасной",
                "На части российских провайдеров долгие соединения WebSocket могут замедляться или обрываться.",
                $"path={p.WsPath ?? "/"}, host={p.WsHost ?? "не задан"}, earlyData={p.WsEarlyData?.ToString(CultureInfo.InvariantCulture) ?? "нет"}.",
                "type=ws",
                "Для основной работы выбирайте узлы с VLESS + XHTTP или VLESS + TCP Vision (Reality)."));

            if (string.IsNullOrWhiteSpace(p.WsHost) && string.IsNullOrWhiteSpace(p.Tls.Sni))
            {
                findings.Add(new VpnAuditFinding(
                    "vless-ws-no-host",
                    AuditCategory.Routing,
                    AuditSeverity.Critical,
                    "Не указан домен (host / sni) для WebSocket",
                    "Без имени сайта сервер не поймёт, куда направить подключение, и выдаст ошибку.",
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
                    "Отсутствует защита XTLS-Vision (flow=xtls-rprx-vision)",
                    "Без этого параметра фильтр провайдера быстро замечает «шифрование внутри шифрования» и блокирует узел.",
                    $"Текущий flow: {p.Tls.Flow ?? "не указан"}. Для VLESS TCP + Reality параметр xtls-rprx-vision обязателен.",
                    $"flow={p.Tls.Flow ?? "отсутствует"}",
                    "Нажмите «Автолечение подписки (Блок-патч)», чтобы автоматически добавить flow=xtls-rprx-vision.",
                    "&flow=xtls-rprx-vision"));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "vless-tcp-vision-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    "Защита VLESS TCP + XTLS-Vision включена",
                    "Трафик полностью маскируется под обычное HTTPS-соединение с сайтом.",
                    "flow=xtls-rprx-vision активен.",
                    "flow=xtls-rprx-vision",
                    "Настройка оптимальна, ничего менять не нужно."));
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
                    "Повреждён или отсутствует публичный ключ Reality (pbk)",
                    "Ключ сервера обрезан или пуст — ВПН-клиент не сможет установить защищённое соединение.",
                    $"pbk={p.Tls.PublicKey ?? "отсутствует"} (ожидается ~43 символа Base64URL X25519).",
                    $"pbk={p.Tls.PublicKey ?? "пусто"}",
                    "Обновите подписку или скопируйте ссылку заново из личного кабинета."));
            }

            if (!string.IsNullOrWhiteSpace(p.Tls.ShortId) && !HexShortIdRegex().IsMatch(p.Tls.ShortId))
            {
                findings.Add(new VpnAuditFinding(
                    "reality-bad-sid",
                    AuditCategory.Security,
                    AuditSeverity.Warning,
                    $"Некорректный идентификатор ShortId (sid={p.Tls.ShortId})",
                    "В параметре sid содержатся лишние символы (допускаются только цифры 0–9 и буквы a–f).",
                    $"Найдено sid={p.Tls.ShortId}.",
                    $"sid={p.Tls.ShortId}",
                    "Проверьте правильность ссылки или обновите подписку."));
            }

            if (string.IsNullOrWhiteSpace(p.Tls.Sni) ||
                IPAddress.TryParse(p.Tls.Sni, out _) ||
                string.Equals(p.Tls.Sni, p.ServerHost, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new VpnAuditFinding(
                    "reality-bad-sni",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    $"Неправильный маскировочный домен SNI ({p.Tls.Sni ?? "не указан"})",
                    "Для маскировки Reality нужен реальный популярный сайт (а не IP-адрес), иначе блокировка сразу вычислит ВПН.",
                    $"sni={p.Tls.Sni ?? "отсутствует"}, server={p.ServerHost ?? "—"}.",
                    $"sni={p.Tls.Sni ?? "пусто"}",
                    "Подберите рабочий маскировочный домен на вкладке «4. Сетевой стек и подбор SNI»."));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "reality-sni-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    $"Маскировка Reality под сайт «{p.Tls.Sni}» настроена",
                    "Для оборудования провайдера подключение к ВПН выглядит как обычный вход на этот сайт.",
                    $"sni={p.Tls.Sni}, fp={p.Tls.Fingerprint ?? "по умолчанию"}.",
                    $"sni={p.Tls.Sni}",
                    "Нажмите «Проверить этот узел» или «Проверить все узлы подписки», чтобы убедиться, что сервер отвечает."));
            }
        }

        if (p.Tls.Mode is "reality" or "tls" && string.IsNullOrWhiteSpace(p.Tls.Fingerprint))
        {
            findings.Add(new VpnAuditFinding(
                "vless-no-fp",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не указана маскировка под браузер (параметр fp)",
                "Без этого параметра соединение выглядит как программа, а не как живой браузер Chrome или Firefox.",
                "Параметр fp (uTLS fingerprint) отсутствует в конфигурации.",
                "fp=отсутствует",
                "Нажмите «Автолечение подписки (Блок-патч)», чтобы автоматически прописать fp=chrome.",
                "&fp=chrome"));
        }

        if (p.ServerPort.HasValue && p.ServerPort.Value != 443)
        {
            findings.Add(new VpnAuditFinding(
                "vless-non-443",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                $"Используется нестандартный порт {p.ServerPort.Value} вместо 443",
                "Обычные сайты работают на порту 443. Другие порты чаще блокируются в мобильных сетях и офисах.",
                $"Порт сервера: {p.ServerPort.Value}.",
                $"port={p.ServerPort.Value}",
                "Если связь работает стабильно — можно оставить, но порт 443 надёжнее."));
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
                    $"Ошибка параметров AmneziaWG: S1 + 56 равно S2 ({awg.S1} + 56 = {awg.S2})",
                    "Из-за совпадения размеров пакетов клиент и сервер не поймут друг друга, и ВПН не подключится.",
                    $"Текущие значения: S1={awg.S1}, S2={awg.S2}. По протоколу S1 + 56 не должно равняться S2.",
                    $"S1 = {awg.S1}, S2 = {awg.S2}",
                    "Измените параметр S1 или S2 в настройках сервера Amnezia и скачайте конфиг заново."));
            }

            if (awg.Jmin.HasValue && awg.Jmax.HasValue && (awg.Jmin.Value > awg.Jmax.Value || awg.Jmax.Value > 1280))
            {
                findings.Add(new VpnAuditFinding(
                    "awg-junk-range",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    $"Неправильный размер шумовых пакетов (Jmin={awg.Jmin}, Jmax={awg.Jmax})",
                    "Размер шумовых пакетов превышает допустимый предел (1280 байт), из-за чего пакеты будут теряться.",
                    $"Jmin={awg.Jmin}, Jmax={awg.Jmax}. Требуется Jmin <= Jmax <= 1280.",
                    $"Jmin = {awg.Jmin}, Jmax = {awg.Jmax}",
                    "Установите Jmin = 50 и Jmax = 1000."));
            }

            var headers = new[] { awg.H1, awg.H2, awg.H3, awg.H4 }.Where(h => h.HasValue).Select(h => h!.Value).ToArray();
            if (headers.Length == 4 && headers.Distinct().Count() < 4)
            {
                findings.Add(new VpnAuditFinding(
                    "awg-duplicate-headers",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Critical,
                    "Одинаковые заголовки H1–H4 в AmneziaWG",
                    "Четыре защитных кода H1, H2, H3 и H4 должны быть разными числами.",
                    $"Значения: H1={awg.H1}, H2={awg.H2}, H3={awg.H3}, H4={awg.H4}.",
                    "H1..H4 дублируются",
                    "Задайте 4 разных числа для H1, H2, H3, H4 на сервере и в клиенте."));
            }
            else if (awg.S1.HasValue && awg.S2.HasValue && awg.S1.Value + 56 != awg.S2.Value)
            {
                findings.Add(new VpnAuditFinding(
                    "awg-params-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    "Защита AmneziaWG от блокировок настроена правильно",
                    "Шумовые пакеты и изменённые заголовки скрывают работу WireGuard от оборудования провайдера.",
                    $"Jc={awg.Jc}, Jmin={awg.Jmin}, Jmax={awg.Jmax}, S1={awg.S1}, S2={awg.S2}.",
                    "Параметры AWG валидны",
                    "Никаких изменений в параметрах обфускации не требуется."));
            }
        }

        if (p.DnsServers.Count == 0)
        {
            findings.Add(new VpnAuditFinding(
                "wg-no-dns",
                AuditCategory.Leaks,
                AuditSeverity.Critical,
                "В конфиге не указан DNS-сервер — сайты могут не открываться",
                "Без строки DNS ваш компьютер продолжит спрашивать адреса сайтов у российского провайдера и получать отказ.",
                "Директива DNS отсутствует в секции [Interface].",
                "DNS не указан",
                "Добавьте строку DNS = 1.1.1.1, 9.9.9.9 в блок [Interface].",
                "DNS = 1.1.1.1, 9.9.9.9"));
        }

        if (p.RoutesAllIpv4 && !p.RoutesAllIpv6)
        {
            findings.Add(new VpnAuditFinding(
                "wg-ipv6-leak",
                AuditCategory.Leaks,
                AuditSeverity.Critical,
                "Возможна утечка трафика через IPv6 мимо ВПН",
                "Если ваш провайдер раздаёт IPv6, браузер может пойти напрямую без ВПН.",
                $"AllowedIPs = {string.Join(", ", p.AllowedIps)} (отсутствует ::/0).",
                $"AllowedIPs = {string.Join(", ", p.AllowedIps)}",
                "Добавьте , ::/0 в конец строки AllowedIPs.",
                "AllowedIPs = 0.0.0.0/0, ::/0"));
        }

        if (!p.Mtu.HasValue || p.Mtu.Value > 1380)
        {
            findings.Add(new VpnAuditFinding(
                "wg-high-mtu",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                $"Слишком большой размер пакета MTU ({p.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "по умолчанию 1420"})",
                "На мобильном интернете и домашних роутерах высокий MTU часто приводит к тому, что ВПН подключён, а страницы бесконечно грузятся.",
                $"Текущий MTU: {p.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "не задан"}.",
                $"MTU = {p.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "авто"}",
                "Добавьте строку MTU = 1280 в секцию [Interface].",
                "MTU = 1280"));
        }

        if (!p.PersistentKeepalive.HasValue || p.PersistentKeepalive.Value == 0)
        {
            findings.Add(new VpnAuditFinding(
                "wg-no-keepalive",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не включено поддержание связи (PersistentKeepalive)",
                "После 1–2 минут бездействия соединение может «засыпать».",
                "PersistentKeepalive не задан в секции [Peer].",
                "PersistentKeepalive отсутствует",
                "Добавьте PersistentKeepalive = 25 в конец конфига.",
                "PersistentKeepalive = 25"));
        }
    }

    private static void AuditHysteria2(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        findings.Add(new VpnAuditFinding(
            "hy2-udp-rf-warning",
            AuditCategory.TransportDpi,
            AuditSeverity.Warning,
            "Протокол Hysteria2 работает по UDP — отличный запасной вариант",
            "Hysteria2 даёт высокую скорость на плохих линиях, но некоторые мобильные операторы режут UDP. Хорошо подходит как резервный профиль.",
            $"QUIC/UDP на порту {p.ServerPort ?? 443}.",
            $"QUIC/UDP :{p.ServerPort ?? 443}",
            "Используйте Hysteria2 вместе с основными узлами VLESS + XHTTP / Reality."));

        if (!string.Equals(p.Obfs, "salamander", StringComparison.OrdinalIgnoreCase) || !p.HasObfsPassword)
        {
            findings.Add(new VpnAuditFinding(
                "hy2-no-salamander",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не включена маскировка Salamander (obfs=salamander)",
                "Дополнительная обфускация Salamander помогает скрыть протокол QUIC от фильтров провайдера.",
                $"obfs={p.Obfs ?? "нет"}, obfs-password={(p.HasObfsPassword ? "задан" : "нет")}.",
                "obfs не настроен",
                "Если настраиваете свой сервер — включите obfs=salamander.",
                "&obfs=salamander&obfs-password=<пароль>"));
        }

        if (string.IsNullOrWhiteSpace(p.PortHopping))
        {
            findings.Add(new VpnAuditFinding(
                "hy2-no-mport",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Не настроена смена портов (Port Hopping / mport)",
                "Прыжки по портам помогают обходить ограничение скорости на один UDP-поток.",
                "Параметр mport отсутствует.",
                "mport не задан",
                "При замедлении скорости можно добавить диапазон портов &mport=20000-40000."));
        }
    }

    private static void AuditCoreJson(NormalizedVpnProfile p, string rawConfig, List<VpnAuditFinding> findings)
    {
        if (p.BalancerOutboundCount > 1)
        {
            findings.Add(new VpnAuditFinding(
                "json-auto-balancer-ok",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                $"Включён умный автовыбор сервера ({p.BalancerOutboundCount} узлов в пуле)",
                "Этот профиль сам измеряет задержку до всех серверов подписки и автоматически переключает вас на самый быстрый рабочий узел.",
                $"Обнаружено {p.BalancerOutboundCount} прокси-аутбаундов с балансировщиком leastPing / AUTO.",
                $"outbounds: {p.BalancerOutboundCount} шт.",
                "Удобный режим «включи и забудь» для Happ и v2rayN."));
        }

        if (p.Xhttp is not null)
        {
            findings.Add(new VpnAuditFinding(
                "json-xhttp-ok",
                AuditCategory.TransportDpi,
                AuditSeverity.Ok,
                $"Современный транспорт XHTTP / SplitHTTP (mode={p.Xhttp.Mode})",
                "Узел использует продвинутую маскировку XHTTP с рандомизацией размера пакетов и мультиплексированием (XMUX) против блокировок 16 КБ.",
                $"path={p.Xhttp.Path}, host={p.Xhttp.Host ?? "авто"}, xPaddingBytes={(p.Xhttp.HasPadding ? "настроен" : "по умолчанию")}, xmux={(p.Xhttp.HasXmux ? "активен" : "авто")}.",
                $"network=xhttp · mode={p.Xhttp.Mode} · path={p.Xhttp.Path}",
                "Конфигурация транспорта полностью готова к работе в сетях РФ."));
        }

        if (p.HasRuSplitRules)
        {
            findings.Add(new VpnAuditFinding(
                "json-ru-split-ok",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                "Российские сайты, банки и Госуслуги открываются напрямую без ВПН",
                "В профиль уже встроены правила раздельного туннелирования: российские сервисы (.ru, .рф, банки, маркетплейсы) работают напрямую на полной скорости, а заблокированные — через ВПН.",
                "Найдены правила маршрутизации geosite:category-ru / domain:ru / geoip:ru → DIRECT.",
                "RU Split-Tunneling → DIRECT",
                "Отключать ВПН для входа в российские банки и сервисы не придётся."));
        }

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

        if (encryptedDns.Length > 0)
        {
            findings.Add(new VpnAuditFinding(
                "json-encrypted-dns-ok",
                AuditCategory.Leaks,
                AuditSeverity.Ok,
                "Зашифрованный DNS (DoH / DoT) защищает от подмены сайтов",
                "Адреса сайтов запрашиваются по зашифрованному каналу, поэтому провайдер не сможет подменить страницу на заглушку.",
                $"Серверы: {string.Join(", ", encryptedDns)}.",
                string.Join(", ", encryptedDns),
                "Защита DNS настроена правильно."));
        }
        else if (plainDns.Length > 0)
        {
            findings.Add(new VpnAuditFinding(
                "json-plain-dns",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Используется незашифрованный DNS",
                "Обычный DNS без шифрования может перехватываться интернет-провайдером.",
                $"Открытые серверы: {string.Join(", ", plainDns)}.",
                string.Join(", ", plainDns),
                "Рекомендуется добавить DoH (например https://8.8.8.8/dns-query или https://1.1.1.1/dns-query) на вкладке «2. Настройка DNS»."));
        }

        var hasInboundsDefined = rawConfig.Contains("\"inbounds\"", StringComparison.OrdinalIgnoreCase);

        if (!p.HasSniffing && hasInboundsDefined)
        {
            findings.Add(new VpnAuditFinding(
                "json-no-sniff",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Не включено распознавание доменов (sniffing)",
                "Без этой функции умное разделение трафика (РФ напрямую / зарубежье через ВПН) может срабатывать не для всех программ.",
                "В секции inbounds / route.rules не найдено правило sniffing.",
                "sniff отключён",
                "Включите sniffing в настройках клиента или добавьте { \"action\": \"sniff\" }."));
        }

        if (!p.HasDnsHijack && p.Protocol == VpnProtocol.SingBoxJson && hasInboundsDefined)
        {
            findings.Add(new VpnAuditFinding(
                "json-no-hijack-dns",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "Не найден принудительный перехват DNS (hijack-dns)",
                "Некоторые программы и браузеры могут пытаться отправлять DNS-запросы в обход правил.",
                "Правило hijack-dns не обнаружено в route.rules.",
                "hijack-dns отсутствует",
                "Добавьте правило перехвата протокола dns на вкладке «2. Настройка DNS»."));
        }

        if (!p.HasPrivateBypass)
        {
            findings.Add(new VpnAuditFinding(
                "json-no-private-bypass",
                AuditCategory.Routing,
                AuditSeverity.Warning,
                "Не найдено правило для домашней локальной сети (geoip:private)",
                "При включённом ВПН может не открываться страница настроек домашнего роутера (192.168.1.1) или сетевой принтер.",
                "Исключение приватных подсетей (geoip:private / ip_is_private) не обнаружено.",
                "ip_is_private не найден",
                "Добавьте правило пропуска приватных IP напрямую (direct)."));
        }

        if (p.Tls.Mode == "reality" && !string.IsNullOrWhiteSpace(p.ServerHost))
        {
            if (string.IsNullOrWhiteSpace(p.Tls.Sni) || IPAddress.TryParse(p.Tls.Sni, out _))
            {
                findings.Add(new VpnAuditFinding(
                    "json-reality-bad-sni",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Warning,
                    "Не указан маскировочный домен (SNI) для Reality",
                    "Проверьте поле serverName в настройках Reality.",
                    $"sni={p.Tls.Sni ?? "не указан"}.",
                    $"sni={p.Tls.Sni ?? "пусто"}",
                    "Укажите реальный домен с TLS 1.3 + ALPN h2."));
            }
            else
            {
                findings.Add(new VpnAuditFinding(
                    "json-reality-ok",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Ok,
                    $"Маскировка Reality активна (сайт прикрытия: {p.Tls.Sni})",
                    "Трафик маскируется под посещение реального сайта с отпечатком браузера.",
                    $"Сервер: {p.ServerHost}:{p.ServerPort ?? 443}, транспорт: {p.Transport}, отпечаток uTLS: {p.Tls.Fingerprint ?? "авто"}.",
                    $"SNI={p.Tls.Sni} · fp={p.Tls.Fingerprint ?? "auto"}",
                    "Нажмите «Проверить все узлы подписки» или «Проверить этот узел» для проверки связи."));
            }
        }
        else if (p.Transport == "QUIC (UDP)" && !string.IsNullOrWhiteSpace(p.ServerHost))
        {
            findings.Add(new VpnAuditFinding(
                "json-hysteria-ok",
                AuditCategory.TransportDpi,
                AuditSeverity.Ok,
                $"Запасной протокол Hysteria2 / QUIC ({p.ServerHost}:{p.ServerPort ?? 443})",
                "Этот профиль использует скоростной UDP-протокол Hysteria2 на случай сбоев обычного TCP.",
                $"Сервер: {p.ServerHost}:{p.ServerPort ?? 443}, SNI: {p.Tls.Sni ?? "—"}, ALPN: {string.Join(", ", p.Tls.Alpn)}.",
                $"Hysteria2 QUIC · SNI={p.Tls.Sni ?? "—"}",
                "Хорошо подходит как резервный канал связи."));
        }
    }

    private static void AuditTrojan(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        if (string.IsNullOrWhiteSpace(p.Tls.Fingerprint))
        {
            findings.Add(new VpnAuditFinding(
                "trojan-no-fp",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                "Для Trojan не задана маскировка под браузер (fp)",
                "Добавление параметра fp=chrome делает подключение похожим на обычный браузер.",
                "Параметр fp отсутствует в URI.",
                "fp=отсутствует",
                "Добавьте &fp=chrome или нажмите «Автолечение подписки».",
                "&fp=chrome"));
        }

        if (string.IsNullOrWhiteSpace(p.Tls.Sni) || IPAddress.TryParse(p.Tls.Sni, out _))
        {
            findings.Add(new VpnAuditFinding(
                "trojan-no-sni",
                AuditCategory.Security,
                AuditSeverity.Critical,
                "Для Trojan не задан доменный адрес SNI",
                "Протокол Trojan требует настоящий домен с сертификатом, иначе связь легко блокируется.",
                $"Текущий sni={p.Tls.Sni ?? "не указан"}.",
                $"sni={p.Tls.Sni ?? "пусто"}",
                "Укажите домен с действительным сертификатом в параметре sni."));
        }
        else
        {
            findings.Add(new VpnAuditFinding(
                "trojan-tls-ok",
                AuditCategory.TransportDpi,
                AuditSeverity.Ok,
                $"Протокол Trojan поверх TLS (домен: {p.Tls.Sni})",
                "Базовая маскировка под HTTPS-сайт настроена.",
                $"Хост: {p.ServerHost}:{p.ServerPort ?? 443}, транспорт: {p.Transport}.",
                $"SNI={p.Tls.Sni}",
                "Если провайдер начнёт блокировать домен — переключитесь на узел с VLESS Reality."));
        }
    }

    private static void AuditVmess(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        if (!string.Equals(p.Tls.Mode, "tls", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new VpnAuditFinding(
                "vmess-no-tls",
                AuditCategory.Security,
                AuditSeverity.Critical,
                "Устаревший VMess без TLS-защиты — блокируется в РФ",
                "Незащищённый поток VMess легко распознаётся оборудованием провайдера.",
                $"Текущий режим: transport={p.Transport}, tls={p.Tls.Mode}.",
                "tls=none",
                "Переключитесь на локацию с VLESS + XHTTP / Reality."));
        }
        else
        {
            findings.Add(new VpnAuditFinding(
                "vmess-rf-legacy",
                AuditCategory.TransportDpi,
                AuditSeverity.Warning,
                $"VMess + {p.Transport} + TLS — устаревающий протокол для РФ",
                "VMess работает медленнее и хуже защищён от современных блокировок, чем VLESS Reality.",
                $"SNI={p.Tls.Sni ?? "не указан"}, fp={p.Tls.Fingerprint ?? "не задан"}.",
                $"VMess/{p.Transport}/TLS",
                "По возможности используйте узлы VLESS + Reality."));
        }
    }

    private static void AuditShadowsocks(NormalizedVpnProfile p, List<VpnAuditFinding> findings)
    {
        var method = p.CipherMethod ?? string.Empty;
        var isAead2022 = method.StartsWith("2022-blake3-", StringComparison.OrdinalIgnoreCase);

        findings.Add(new VpnAuditFinding(
            "ss-rf-dpi",
            AuditCategory.TransportDpi,
            isAead2022 ? AuditSeverity.Warning : AuditSeverity.Critical,
            isAead2022
                ? $"Shadowsocks 2022 ({method}) — может блокироваться на мобильных сетях"
                : $"Классический Shadowsocks ({(string.IsNullOrWhiteSpace(method) ? "старый шифр" : method)}) блокируется ТСПУ",
            isAead2022
                ? "Даже обновлённый Shadowsocks-2022 часто режется операторами связи в РФ."
                : "Обычный Shadowsocks без маскировки легко распознаётся и блокируется.",
            $"Хост: {p.ServerHost ?? "—"}:{p.ServerPort?.ToString(CultureInfo.InvariantCulture) ?? "—"}, шифр: {(string.IsNullOrWhiteSpace(method) ? "не указан" : method)}.",
            $"SS ({(string.IsNullOrWhiteSpace(method) ? "legacy" : method)})",
            "Для надёжной работы в РФ выбирайте узлы VLESS + Reality (XHTTP или TCP Vision) либо AmneziaWG."));
    }
}
