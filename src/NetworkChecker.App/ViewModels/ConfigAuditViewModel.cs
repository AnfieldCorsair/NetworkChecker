using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

public sealed partial class AuditFindingDisplayItem : ObservableObject
{
    public AuditFindingDisplayItem(
        string severityLabel,
        IBrush severityBrush,
        string title,
        string simpleSummary,
        string technicalDetail,
        string evidence,
        string remediation,
        bool isExpanded = false)
    {
        SeverityLabel = severityLabel;
        SeverityBrush = severityBrush;
        Title = title;
        SimpleSummary = simpleSummary;
        TechnicalDetail = technicalDetail;
        Evidence = evidence;
        Remediation = remediation;
        IsExpanded = isExpanded;
    }

    public string SeverityLabel { get; }
    public IBrush SeverityBrush { get; }
    public string Title { get; }
    public string SimpleSummary { get; }
    public string TechnicalDetail { get; }
    public string Evidence { get; }
    public string Remediation { get; }

    [ObservableProperty]
    public partial bool IsExpanded { get; set; }

    public string SpoilerButtonText => IsExpanded
        ? "▲ Скрыть технические подробности"
        : "▼ Показать технические подробности (параметры протокола и конфига)";

    partial void OnIsExpandedChanged(bool value)
    {
        OnPropertyChanged(nameof(SpoilerButtonText));
    }

    [RelayCommand]
    private void ToggleExpanded()
    {
        IsExpanded = !IsExpanded;
    }
}

public sealed partial class SubscriptionNodeDisplayItem : ObservableObject
{
    private static readonly IBrush CleanBrush = new SolidColorBrush(Color.Parse("#4ADE80"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
    private static readonly IBrush DangerBrush = new SolidColorBrush(Color.Parse("#F87171"));
    private static readonly IBrush MutedBrush = new SolidColorBrush(Color.Parse("#9BAAC2"));

    public SubscriptionNodeDisplayItem(SubscriptionNodeAudit node)
    {
        ArgumentNullException.ThrowIfNull(node);
        Node = node;
        Index = node.Index;
        Name = node.Report.Profile.Name;
        ProtocolLabel = node.Report.Profile.ProtocolLabel;
        var host = node.Report.Profile.ServerHost ?? "—";
        var port = node.Report.Profile.ServerPort?.ToString(CultureInfo.InvariantCulture) ?? "443";
        EndpointText = $"{host}:{port}";

        (AuditBadgeText, AuditBadgeBrush) = node.Report.OverallVerdict switch
        {
            AuditSeverity.Critical => ("ЕСТЬ ОШИБКИ", DangerBrush),
            AuditSeverity.Warning => ("ЕСТЬ ЗАМЕЧАНИЯ", WarnBrush),
            _ => ("ЗАЩИЩЁН (РФ)", CleanBrush),
        };
    }

    public SubscriptionNodeAudit Node { get; }
    public int Index { get; }
    public string Name { get; }
    public string ProtocolLabel { get; }
    public string EndpointText { get; }
    public string AuditBadgeText { get; }
    public IBrush AuditBadgeBrush { get; }

    [ObservableProperty]
    public partial string LiveStatusText { get; set; } = "Не проверен";

    [ObservableProperty]
    public partial IBrush LiveStatusBrush { get; set; } = MutedBrush;

    public long? LastLatencyMs { get; private set; }

    public void SetProbing()
    {
        LiveStatusText = "Проверка...";
        LiveStatusBrush = WarnBrush;
    }

    public void SetProbeResult(bool ok, long? latencyMs, string label)
    {
        LastLatencyMs = latencyMs;
        LiveStatusText = label;
        LiveStatusBrush = ok ? CleanBrush : DangerBrush;
    }
}

/// <summary>
/// Вкладка 1: Проверка ВПН и подписки (автораспознавание https-ссылок, разбор JSON-массивов Happ/Xray, карточка подписки,
/// точечная замена DNS/SNI и выгрузка в буфер обмена, файл или локальную ссылку подписки).
/// </summary>
public sealed partial class ConfigAuditViewModel : ViewModelBase
{
    private static readonly IBrush DangerBrush = new SolidColorBrush(Color.Parse("#F87171"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
    private static readonly IBrush CleanBrush = new SolidColorBrush(Color.Parse("#4ADE80"));

    private const string PresetVlessXhttp =
        "vless://9f8e7d6c-5b4a-4321-8765-abcdef012345@1.1.1.1:443?encryption=none&security=reality&type=xhttp&mode=auto&path=/api/v2/stream&sni=www.microsoft.com&fp=chrome&pbk=8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA&sid=6ba85179#Москва-XHTTP";

    private const string PresetVlessTcpBroken =
        "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:8443?encryption=none&security=reality&type=tcp&sni=1.1.1.1&pbk=short&allowInsecure=1#Проблемный-TCP";

    private const string PresetAmneziaWg = """
        [Interface]
        PrivateKey = cF9vN2xK8mR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8k=
        Address = 10.8.1.2/32
        DNS = 1.1.1.1, 9.9.9.9
        MTU = 1280
        Jc = 4
        Jmin = 50
        Jmax = 1000
        S1 = 30
        S2 = 95
        H1 = 10112233
        H2 = 20223344
        H3 = 30334455
        H4 = 40445566

        [Peer]
        PublicKey = xK8mR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2c=
        Endpoint = 198.51.100.10:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """;

    private const string PresetHappJsonArray = """
        [
          {
            "remarks": "⚡ Автовыбор — включи и забудь",
            "dns": {
              "servers": [
                { "address": "77.88.8.8", "port": 53, "domains": ["geosite:category-ru", "domain:ru"], "skipFallback": true },
                { "address": "https://dns.njal.la/dns-query", "skipFallback": false }
              ],
              "queryStrategy": "UseIPv4"
            },
            "outbounds": [
              {
                "tag": "proxy",
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "edge-eu.example.com", "port": 443, "users": [{ "id": "00000000-1111-2222-3333-444444444444", "encryption": "none" }] }] },
                "streamSettings": {
                  "network": "xhttp",
                  "security": "reality",
                  "realitySettings": { "serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA", "shortId": "6ba85179" },
                  "xhttpSettings": { "mode": "auto", "path": "/api/v2/stream", "host": "www.microsoft.com", "extra": { "xPaddingBytes": "100-1000", "xmux": { "maxConcurrency": "16-32" } } }
                }
              },
              {
                "tag": "proxy-2",
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "edge-fi.example.com", "port": 443, "users": [{ "id": "00000000-1111-2222-3333-444444444444", "encryption": "none" }] }] },
                "streamSettings": {
                  "network": "xhttp",
                  "security": "reality",
                  "realitySettings": { "serverName": "www.apple.com", "fingerprint": "chrome", "publicKey": "8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA", "shortId": "6ba85179" },
                  "xhttpSettings": { "mode": "auto", "path": "/api/v2/stream" }
                }
              },
              { "tag": "DIRECT", "protocol": "freedom" }
            ],
            "routing": {
              "balancers": [{ "tag": "AUTO", "selector": ["proxy", "proxy-2"], "strategy": { "type": "leastPing" } }],
              "rules": [
                { "type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "DIRECT" },
                { "type": "field", "domain": ["geosite:category-ru", "domain:ru"], "outboundTag": "DIRECT" }
              ]
            }
          },
          {
            "remarks": "📶 Мобильный интернет · TCP Vision",
            "dns": {
              "servers": [
                { "address": "https://dns.njal.la/dns-query", "skipFallback": false }
              ]
            },
            "outbounds": [
              {
                "tag": "proxy",
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "198.51.100.42", "port": 443, "users": [{ "id": "00000000-1111-2222-3333-444444444444", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
                "streamSettings": {
                  "network": "tcp",
                  "security": "reality",
                  "realitySettings": { "serverName": "cdn.jsdelivr.net", "fingerprint": "chrome", "publicKey": "8xR4qT7wY1zB5nL0jH3dG6sA9eU2iO4pM8kF9vN2cAA", "shortId": "6ba85179" }
                }
              }
            ],
            "routing": {
              "rules": [
                { "type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "DIRECT" }
              ]
            }
          },
          {
            "remarks": "🌍 Запасной протокол (Hysteria2)",
            "dns": {
              "servers": [
                { "address": "https://doh.libredns.gr/dns-query", "skipFallback": false }
              ]
            },
            "outbounds": [
              {
                "tag": "proxy",
                "protocol": "hysteria",
                "settings": { "address": "203.0.113.10", "port": 443, "version": 2 },
                "streamSettings": {
                  "network": "hysteria",
                  "hysteriaSettings": { "version": 2, "auth": "demo-auth-token-2026" },
                  "security": "tls",
                  "tlsSettings": { "serverName": "hy2.example.com", "fingerprint": "chrome", "alpn": ["h3"] }
                }
              }
            ],
            "routing": {
              "rules": [
                { "type": "field", "ip": ["geoip:private"], "outboundTag": "DIRECT" }
              ]
            }
          }
        ]
        """;

    private readonly VpnEndpointProbe _probe;
    private readonly SubscriptionService _subscriptions;
    private readonly IDesktopUiService _ui;
    private bool _suppressAutoUrlFetch;

    public ConfigAuditViewModel(
        VpnEndpointProbe probe,
        SubscriptionService subscriptions,
        IDesktopUiService ui)
    {
        _probe = probe;
        _subscriptions = subscriptions;
        _ui = ui;
        SubscriptionUrl = string.Empty;
        RawConfig = PresetVlessXhttp;
        Analyze();
    }

    public override string Title => "Проверка ВПН и подписки";
    public override string Subtitle => "Ссылки · Happ · VLESS · AWG";
    public override string Description => "Вставьте ссылку на подписку (https://...) или ключ (vless://, JSON, AWG). Программа сама скачает подписку, покажет все локации, заменит DNS/SNI и выдаст готовый конфиг.";
    public override string SimpleGuideText =>
        "Вставьте вашу ссылку на подписку (например из Happ / Telegram-бота) прямо в поле ниже или нажмите «Загрузить по ссылке». Вы можете проверить все локации одним кликом, вшить в них приватный Ninja DNS (Njalla + LibreDNS) и скопировать один узел или локальную ссылку подписки.";

    public VpnAuditReport? CurrentReport { get; private set; }
    public RttBenchmarkResult? LastRttResult { get; private set; }

    [ObservableProperty]
    public partial string RawConfig { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SubscriptionUrl { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool MaskSecrets { get; set; } = true;

    [ObservableProperty]
    public partial string ProtocolSummary { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string VerdictHeadline { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int CriticalCount { get; set; }

    [ObservableProperty]
    public partial int WarningCount { get; set; }

    [ObservableProperty]
    public partial int OkCount { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Вставьте ссылку на подписку (https://...) или конфиг в любое поле — программа сама распознает формат.";

    [ObservableProperty]
    public partial SubscriptionNodeDisplayItem? SelectedNode { get; set; }

    // Поля карточки подписки
    [ObservableProperty]
    public partial bool HasSubscriptionCard { get; set; }

    [ObservableProperty]
    public partial string SubscriptionTitle { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SubscriptionTrafficText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SubscriptionExpireText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SubscriptionSupportText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SubscriptionNodesCountText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string HostedSubscriptionUrl { get; set; } = string.Empty;

    public bool HasHostedSubscriptionUrl => !string.IsNullOrWhiteSpace(HostedSubscriptionUrl);

    public ObservableCollection<AuditFindingDisplayItem> Findings { get; } = [];
    public ObservableCollection<SubscriptionNodeDisplayItem> SubscriptionNodes { get; } = [];
    public bool HasMultipleNodes => SubscriptionNodes.Count > 1;

    partial void OnHostedSubscriptionUrlChanged(string value)
    {
        OnPropertyChanged(nameof(HasHostedSubscriptionUrl));
    }

    partial void OnRawConfigChanged(string value)
    {
        if (!_suppressAutoUrlFetch &&
            VpnConfigParser.TryExtractHttpSubscriptionUrl(value, out var pastedUri) &&
            pastedUri is not null)
        {
            SubscriptionUrl = pastedUri.ToString();
            Analyze();
            _ = AutoFetchPastedUrlAsync(pastedUri);
            return;
        }

        Analyze();
    }

    partial void OnSelectedNodeChanged(SubscriptionNodeDisplayItem? value)
    {
        if (value is not null)
        {
            ApplyReport(value.Node.Report);
        }
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName == nameof(ShowTechnicalDetails))
        {
            foreach (var item in Findings)
            {
                item.IsExpanded = ShowTechnicalDetails;
            }
        }
    }

    public void UpdateRawConfigFromPatcher(string patchedText, string statusMessage)
    {
        _suppressAutoUrlFetch = true;
        try
        {
            RawConfig = patchedText;
            StatusText = statusMessage;
        }
        finally
        {
            _suppressAutoUrlFetch = false;
        }
    }

    private async Task AutoFetchPastedUrlAsync(Uri uri)
    {
        await FetchSubscriptionCoreAsync(uri, CancellationToken.None).ConfigureAwait(true);
    }

    [RelayCommand]
    private void LoadPreset(string presetKey)
    {
        _suppressAutoUrlFetch = true;
        try
        {
            if (presetKey == "happ")
            {
                RawConfig = PresetHappJsonArray;
                HasSubscriptionCard = true;
                SubscriptionTitle = "Пример JSON-подписки (Happ / Xray)";
                SubscriptionTrafficText = "Трафик: тестовый синтетический пример";
                SubscriptionExpireText = "Срок действия: тестовый профиль";
                SubscriptionSupportText = "Вставьте вашу реальную ссылку сверху для загрузки своей подписки";
                SubscriptionNodesCountText = string.Create(CultureInfo.InvariantCulture, $"Локаций в подписке: {SubscriptionNodes.Count}");
                StatusText = "Загружен синтетический пример мульти-подписки Happ (JSON-массив из 3 профилей: Автовыбор XHTTP, TCP Vision и Hysteria2).";
                return;
            }

            HasSubscriptionCard = false;
            RawConfig = presetKey switch
            {
                "broken" => PresetVlessTcpBroken,
                "awg" => PresetAmneziaWg,
                _ => PresetVlessXhttp,
            };
            StatusText = "Загружен тестовый профиль для проверки.";
        }
        finally
        {
            _suppressAutoUrlFetch = false;
        }
    }

    [RelayCommand]
    private void Analyze()
    {
        try
        {
            Findings.Clear();
            SubscriptionNodes.Clear();

            var nodes = VpnConfigAuditor.AuditSubscription(RawConfig);
            if (nodes.Count > 1)
            {
                foreach (var node in nodes)
                {
                    SubscriptionNodes.Add(new SubscriptionNodeDisplayItem(node));
                }

                OnPropertyChanged(nameof(HasMultipleNodes));
                SubscriptionNodesCountText = string.Create(CultureInfo.InvariantCulture, $"Локаций в подписке: {SubscriptionNodes.Count}");
                if (!HasSubscriptionCard)
                {
                    HasSubscriptionCard = true;
                    SubscriptionTitle = RawConfig.TrimStart().StartsWith('[')
                        ? "Мульти-подписка Happ / Xray (JSON)"
                        : "Загруженная подписка ВПН";
                    SubscriptionTrafficText = "Трафик: данные из локального списка";
                    SubscriptionExpireText = string.Create(CultureInfo.InvariantCulture, $"Проверено локаций: {SubscriptionNodes.Count}");
                    SubscriptionSupportText = "Выберите любую локацию ниже или нажмите «Проверить все узлы подписки»";
                }

                SelectedNode = SubscriptionNodes[0];
                ApplyReport(nodes[0].Report);
                return;
            }

            OnPropertyChanged(nameof(HasMultipleNodes));
            SelectedNode = null;
            var report = VpnConfigAuditor.Audit(RawConfig);
            ApplyReport(report);
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or ArgumentException)
        {
            CurrentReport = null;
            Findings.Clear();
            Findings.Add(new AuditFindingDisplayItem(
                "КРИТИЧНО",
                DangerBrush,
                "Ошибка разбора конфигурации",
                "Переданный текст содержит нестандартную структуру, но программа продолжила работу.",
                ex.Message,
                ex.GetType().Name,
                "Проверьте полноту вставленного JSON или ссылки на подписку.",
                ShowTechnicalDetails));
            ProtocolSummary = "Ошибка разбора";
            VerdictHeadline = "Ошибка разбора (1)";
            CriticalCount = 1;
            WarningCount = 0;
            OkCount = 0;
        }
    }

    [RelayCommand]
    private async Task FetchSubscriptionAsync(CancellationToken ct)
    {
        var candidateUrl = SubscriptionUrl.Trim();
        if (string.IsNullOrWhiteSpace(candidateUrl) &&
            VpnConfigParser.TryExtractHttpSubscriptionUrl(RawConfig, out var fromRaw) &&
            fromRaw is not null)
        {
            candidateUrl = fromRaw.ToString();
            SubscriptionUrl = candidateUrl;
        }

        if (!Uri.TryCreate(candidateUrl, UriKind.Absolute, out var uri))
        {
            StatusText = "Вставьте корректную https:// ссылку на подписку (в верхнее поле ссылки или прямо в главное окно).";
            return;
        }

        await FetchSubscriptionCoreAsync(uri, ct).ConfigureAwait(true);
    }

    private async Task FetchSubscriptionCoreAsync(Uri uri, CancellationToken ct)
    {
        IsBusy = true;
        StatusText = $"Скачиваем подписку по ссылке {uri.Host}...";
        try
        {
            var fetched = await _subscriptions.FetchAsync(uri, ct: ct).ConfigureAwait(true);
            _suppressAutoUrlFetch = true;
            try
            {
                HasSubscriptionCard = true;
                SubscriptionTitle = fetched.Meta.Title;
                SubscriptionTrafficText = fetched.Meta.TrafficSummaryRu;
                SubscriptionExpireText = fetched.Meta.ExpireSummaryRu;
                SubscriptionSupportText = !string.IsNullOrWhiteSpace(fetched.Meta.SupportUrl)
                    ? $"Поддержка: {fetched.Meta.SupportUrl}"
                    : $"Источник: {uri.Host}";
                RawConfig = fetched.RawBody;
                SubscriptionNodesCountText = string.Create(CultureInfo.InvariantCulture, $"Локаций в подписке: {fetched.Nodes.Count}");
            }
            finally
            {
                _suppressAutoUrlFetch = false;
            }

            StatusText = string.Create(
                CultureInfo.InvariantCulture,
                $"Подписка «{fetched.Meta.Title}» успешно загружена ({fetched.Nodes.Count} локаций). Нажмите «Проверить все узлы подписки», чтобы узнать пинг.");
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or ArgumentException)
        {
            StatusText = $"Не удалось скачать подписку по ссылке: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ProbeAllSubscriptionNodesAsync(CancellationToken ct)
    {
        if (SubscriptionNodes.Count == 0)
        {
            await ProbeCurrentEndpointAsync(ct).ConfigureAwait(true);
            return;
        }

        IsBusy = true;
        StatusText = string.Create(CultureInfo.InvariantCulture, $"Проверяем все локации подписки ({SubscriptionNodes.Count} шт.) на доступность, пинг и TLS...");

        try
        {
            foreach (var item in SubscriptionNodes)
            {
                item.SetProbing();
            }

            using var gate = new SemaphoreSlim(4, 4);
            var tasks = SubscriptionNodes.Select(async item =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(true);
                try
                {
                    var p = item.Node.Report.Profile;
                    var host = p.ServerHost;
                    var port = p.ServerPort ?? 443;
                    if (string.IsNullOrWhiteSpace(host))
                    {
                        item.SetProbeResult(false, null, "Нет адреса");
                        return;
                    }

                    var isUdp = p.Protocol is VpnProtocol.AmneziaWg or VpnProtocol.LegacyWireGuard or VpnProtocol.Hysteria2
                                || p.Transport.Contains("QUIC", StringComparison.OrdinalIgnoreCase);

                    if (isUdp)
                    {
                        var sw = Stopwatch.StartNew();
                        var addrs = await Dns.GetHostAddressesAsync(host.Trim(), ct).ConfigureAwait(true);
                        sw.Stop();
                        if (addrs.Length > 0)
                        {
                            item.SetProbeResult(true, sw.ElapsedMilliseconds, string.Create(CultureInfo.InvariantCulture, $"UDP · DNS {sw.ElapsedMilliseconds} мс"));
                        }
                        else
                        {
                            item.SetProbeResult(false, null, "Сбой DNS");
                        }
                        return;
                    }

                    var res = await _probe.ProbeAsync(host, port, p.Tls.Sni, checkTls: true, timeoutMs: 3800, ct: ct).ConfigureAwait(true);
                    if (!res.DnsOk)
                    {
                        item.SetProbeResult(false, null, "Сбой DNS");
                    }
                    else if (!res.TcpOk)
                    {
                        item.SetProbeResult(false, null, "НЕДОСТУПЕН (TCP)");
                    }
                    else if (res.TlsChecked && !res.TlsOk)
                    {
                        item.SetProbeResult(false, res.TcpMs, "Сбой TLS");
                    }
                    else
                    {
                        var ping = res.TlsMs ?? res.TcpMs ?? res.DnsMs;
                        item.SetProbeResult(true, ping, string.Create(CultureInfo.InvariantCulture, $"РАБОТАЕТ · {ping} мс"));
                    }
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException)
                {
                    item.SetProbeResult(false, null, "Таймаут");
                }
                finally
                {
                    gate.Release();
                }
            }).ToArray();

            await Task.WhenAll(tasks).ConfigureAwait(true);

            var working = SubscriptionNodes.Where(n => n.LastLatencyMs.HasValue).OrderBy(n => n.LastLatencyMs!.Value).ToList();
            var best = working.FirstOrDefault();
            StatusText = best is not null
                ? string.Create(
                    CultureInfo.InvariantCulture,
                    $"Проверка всех узлов завершена: работают {working.Count} из {SubscriptionNodes.Count}. Лучшая локация: «{best.Name}» ({best.LiveStatusText}).")
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Проверка завершена: ни один из {SubscriptionNodes.Count} узлов не ответил по TCP/TLS.");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ApplyBulkPatch()
    {
        var summary = SubscriptionService.ApplyBulkPatch(RawConfig);
        if (summary.BeforeCount == 0)
        {
            StatusText = "Автолечение (Блок-патч) применяется к ссылкам vless://, hy2://, trojan:// и спискам узлов.";
            return;
        }

        UpdateRawConfigFromPatcher(
            summary.PatchedText,
            string.Create(
                CultureInfo.InvariantCulture,
                $"Автолечение выполнено: узлов {summary.BeforeCount} → {summary.AfterCount}, убрано allowInsecure: {summary.FixedAllowInsecure}, добавлен fp=chrome: {summary.AddedFpChrome}, добавлен Vision: {summary.AddedVisionFlow}."));
    }

    [RelayCommand]
    private Task QuickInjectClassicDnsAsync() => QuickInjectDnsByProfileAsync(DnsProviderProfile.CloudflareGoogle);

    [RelayCommand]
    private Task QuickInjectNinjaDnsAsync() => QuickInjectDnsByProfileAsync(DnsProviderProfile.NinjaPrivacy);

    private async Task QuickInjectDnsByProfileAsync(DnsProviderProfile providerProfile)
    {
        var opt = new DnsArchitectOptions(
            DnsCoreTarget.XrayCore,
            RfSplitTunneling: true,
            UseFakeIp: false,
            Ipv4Only: true,
            BlockAds: false,
            ProviderProfile: providerProfile,
            OutputScope: DnsOutputScope.DnsBlockOnly);

        if (!DnsConfigArchitect.TryInjectDnsIntoJsonConfig(RawConfig, opt, out var patchedJson, out var summaryMessage))
        {
            StatusText = summaryMessage;
            return;
        }

        UpdateRawConfigFromPatcher(patchedJson, summaryMessage);
        var copied = await _ui.CopyTextAsync(patchedJson).ConfigureAwait(true);
        if (copied)
        {
            StatusText = $"{summaryMessage} Исправленный JSON скопирован в буфер обмена!";
        }
    }

    [RelayCommand]
    private async Task CopySelectedNodeOnlyAsync()
    {
        var idx = SelectedNode?.Index ?? 1;
        if (!SubscriptionService.TryExtractSingleNodeText(RawConfig, idx, out var singleNodeText, out var nodeName))
        {
            StatusText = "Не удалось извлечь выбранный узел.";
            return;
        }

        var ok = await _ui.CopyTextAsync(singleNodeText).ConfigureAwait(true);
        StatusText = ok
            ? $"Узел «{nodeName}» (#{idx}) скопирован в буфер обмена как отдельный готовый конфиг — можно сразу вставить в Happ или v2rayN (Импорт из буфера)."
            : "Буфер обмена недоступен.";
    }

    [RelayCommand]
    private async Task HostLocalSubscriptionAsync()
    {
        var title = !string.IsNullOrWhiteSpace(SubscriptionTitle) ? SubscriptionTitle : "KonturVPN-Patched";
        var url = SubscriptionService.StartOrUpdateLocalSubscriptionServer(RawConfig, title);
        HostedSubscriptionUrl = url;
        var ok = await _ui.CopyTextAsync(url).ConfigureAwait(true);
        StatusText = ok
            ? $"Локальная ссылка на исправленную подписку создана и скопирована в буфер: {url} (добавьте её в Happ или v2rayN как ссылку подписки)."
            : $"Локальная ссылка на подписку запущена: {url}";
    }

    [RelayCommand]
    private async Task SavePatchedSubscriptionFileAsync()
    {
        var isJson = RawConfig.TrimStart().StartsWith('{') || RawConfig.TrimStart().StartsWith('[');
        var ext = isJson ? ".json" : ".txt";
        var fileName = isJson ? "patched-subscription.json" : "patched-subscription.txt";
        var path = await _ui.SaveTextFileAsync(fileName, RawConfig, ext, "Конфигурация / подписка ВПН").ConfigureAwait(true);
        StatusText = path is not null
            ? $"Исправленная конфигурация сохранена в файл: {path}"
            : "Сохранение в файл отменено.";
    }

    [RelayCommand]
    private async Task ProbeCurrentEndpointAsync(CancellationToken ct)
    {
        var report = CurrentReport ?? VpnConfigAuditor.Audit(RawConfig);
        if (string.IsNullOrWhiteSpace(report.Profile.ServerHost))
        {
            StatusText = "В конфигурации не найден адрес сервера (вставьте ссылку на подписку или выберите локацию).";
            return;
        }

        var isUdpOnly = report.Profile.Protocol is VpnProtocol.AmneziaWg or VpnProtocol.LegacyWireGuard or VpnProtocol.Hysteria2
                        || report.Profile.Transport.Contains("QUIC", StringComparison.OrdinalIgnoreCase);
        var port = report.Profile.ServerPort ?? 443;

        IsBusy = true;
        StatusText = isUdpOnly
            ? $"Проверка DNS для UDP-сервера {report.Profile.ServerHost}:{port}..."
            : string.Create(CultureInfo.InvariantCulture, $"Проверяем связь с сервером {report.Profile.ServerHost}:{port}...");

        try
        {
            if (isUdpOnly)
            {
                var sw = Stopwatch.StartNew();
                var addrs = await Dns.GetHostAddressesAsync(report.Profile.ServerHost.Trim(), ct).ConfigureAwait(true);
                sw.Stop();
                var ips = string.Join(", ", addrs.Select(a => a.ToString()).Distinct(StringComparer.Ordinal).Take(3));
                var sniNote = !string.IsNullOrWhiteSpace(report.Profile.Tls.Sni)
                    ? " · Для проверки сайта прикрытия нажмите «Проверить маскировку SNI»."
                    : " · Протокол работает по UDP.";
                StatusText = string.Create(CultureInfo.InvariantCulture, $"Сервер найден в DNS ({sw.ElapsedMilliseconds} мс) → {ips}{sniNote}");
                SelectedNode?.SetProbeResult(true, sw.ElapsedMilliseconds, string.Create(CultureInfo.InvariantCulture, $"UDP · DNS {sw.ElapsedMilliseconds} мс"));
                return;
            }

            var checkTls = report.Profile.Protocol is VpnProtocol.Vless or VpnProtocol.Trojan or VpnProtocol.Vmess or VpnProtocol.SingBoxJson or VpnProtocol.XrayJson;
            var res = await _probe.ProbeAsync(
                report.Profile.ServerHost,
                port,
                report.Profile.Tls.Sni,
                checkTls,
                ct: ct).ConfigureAwait(true);

            StatusText = FormatProbeStatus("Сервер ВПН", res);
            if (SelectedNode is not null)
            {
                var ok = res.DnsOk && res.TcpOk && (!res.TlsChecked || res.TlsOk);
                var ping = res.TlsMs ?? res.TcpMs ?? res.DnsMs;
                SelectedNode.SetProbeResult(
                    ok,
                    ok ? ping : null,
                    ok ? string.Create(CultureInfo.InvariantCulture, $"РАБОТАЕТ · {ping} мс") : "НЕДОСТУПЕН");
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            StatusText = $"Сервер не ответил: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ProbeSniAsync(CancellationToken ct)
    {
        var report = CurrentReport ?? VpnConfigAuditor.Audit(RawConfig);
        var sni = report.Profile.Tls.Sni;
        if (string.IsNullOrWhiteSpace(sni) || IPAddress.TryParse(sni, out _))
        {
            StatusText = "В выбранном профиле не указан сайт прикрытия (SNI).";
            return;
        }

        IsBusy = true;
        StatusText = $"Проверяем сайт прикрытия (SNI) {sni}:443 на поддержку TLS 1.3 и HTTP/2...";
        try
        {
            var res = await _probe.ProbeAsync(sni, 443, sni, checkTls: true, ct: ct).ConfigureAwait(true);
            StatusText = FormatProbeStatus($"Сайт прикрытия SNI ({sni})", res);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            StatusText = $"Сбой проверки сайта прикрытия SNI: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RunRttBenchmarkAsync(CancellationToken ct)
    {
        var report = CurrentReport ?? VpnConfigAuditor.Audit(RawConfig);
        if (string.IsNullOrWhiteSpace(report.Profile.ServerHost))
        {
            StatusText = "Выберите локацию с адресом сервера для проверки стабильности пинга.";
            return;
        }

        if (report.Profile.Protocol is VpnProtocol.AmneziaWg or VpnProtocol.LegacyWireGuard)
        {
            StatusText = "AmneziaWG/WireGuard работает по UDP — замер TCP-пинга не требуется.";
            return;
        }

        IsBusy = true;
        var port = report.Profile.ServerPort ?? 443;
        StatusText = string.Create(CultureInfo.InvariantCulture, $"Замеряем стабильность пинга (6 попыток подряд) до {report.Profile.ServerHost}:{port}...");
        try
        {
            var rtt = await RttBenchmarkProbe.RunAsync(report.Profile.ServerHost, port, attempts: 6, cancellationToken: ct).ConfigureAwait(true);
            LastRttResult = rtt;
            StatusText = rtt.Succeeded == 0
                ? string.Create(CultureInfo.InvariantCulture, $"Пинг до {rtt.Host}:{rtt.Port}: сервер не ответил ни на одну из {rtt.Attempts} попыток (потери 100%).")
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Стабильность пинга ({rtt.TargetIp}:{rtt.Port}) · мин {rtt.MinMs} мс · средн {rtt.AvgMs} мс · скачки (джиттер) {rtt.JitterMs} мс · потери {rtt.LossPct}%");
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            StatusText = $"Ошибка замера пинга: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task CopyOutboundJsonAsync()
    {
        var report = CurrentReport ?? VpnConfigAuditor.Audit(RawConfig);
        var json = VpnConfigAuditor.BuildNodeOutboundJson(report.Profile, singBoxFormat: true);
        if (MaskSecrets)
        {
            json = VpnConfigAuditor.MaskSensitiveText(json, report.Profile.RawSecrets);
        }

        var ok = await _ui.CopyTextAsync(json).ConfigureAwait(true);
        StatusText = ok ? "Технический JSON-блок узла скопирован в буфер обмена." : "Буфер обмена недоступен.";
    }

    [RelayCommand]
    private async Task CopyConfigAsync()
    {
        var report = CurrentReport ?? VpnConfigAuditor.Audit(RawConfig);
        var text = MaskSecrets
            ? VpnConfigAuditor.MaskSensitiveText(RawConfig, report.Profile.RawSecrets)
            : RawConfig;
        var ok = await _ui.CopyTextAsync(text).ConfigureAwait(true);
        StatusText = ok
            ? (MaskSecrets ? "Конфиг скопирован (личные ключи и пароли скрыты звездочками)." : "Конфиг полностью скопирован в буфер обмена (для вставки в Happ / v2rayN).")
            : "Буфер обмена недоступен.";
    }

    private void ApplyReport(VpnAuditReport report)
    {
        CurrentReport = report;
        Findings.Clear();
        foreach (var f in report.Findings.OrderByDescending(x => x.Severity))
        {
            Findings.Add(new AuditFindingDisplayItem(
                f.SeverityLabel,
                SeverityToBrush(f.Severity),
                f.Title,
                f.SimpleSummary,
                f.TechnicalDetail,
                f.Evidence,
                f.Remediation,
                ShowTechnicalDetails));
        }

        var portText = report.Profile.ServerPort?.ToString(CultureInfo.InvariantCulture) ?? "—";
        var sniPart = !string.IsNullOrWhiteSpace(report.Profile.Tls.Sni) ? $" · Сайт прикрытия (SNI): {report.Profile.Tls.Sni}" : string.Empty;
        var dnsPart = report.Profile.DnsServers.Count > 0 ? $" · DNS: {string.Join(", ", report.Profile.DnsServers.Take(2))}" : string.Empty;
        ProtocolSummary = $"Локация: {report.Profile.Name} · {report.Profile.ProtocolLabel} · Сервер: {report.Profile.ServerHost ?? "—"}:{portText}{sniPart}{dnsPart}";
        CriticalCount = report.CriticalCount;
        WarningCount = report.WarningCount;
        OkCount = report.OkCount;

        VerdictHeadline = report.OverallVerdict switch
        {
            AuditSeverity.Critical => string.Create(CultureInfo.InvariantCulture, $"Найдены критические проблемы ({report.CriticalCount}) — узел может не работать"),
            AuditSeverity.Warning => string.Create(CultureInfo.InvariantCulture, $"Узел рабочий, но есть советы по улучшению ({report.WarningCount})"),
            _ => $"Узел «{report.Profile.Name}» полностью защищён и готов к работе в РФ",
        };
    }

    private static string FormatProbeStatus(string prefix, VpnEndpointProbeResult res)
    {
        if (!res.DnsOk)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{prefix} · Ошибка поиска адреса (DNS {res.DnsMs} мс): {res.Error}");
        }
        if (!res.TcpOk)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{prefix} · Адрес найден ({res.DnsMs} мс), но сервер :{res.Port} не отвечает (возможно заблокирован IP): {res.Error}");
        }
        if (res.TlsChecked && !res.TlsOk)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{prefix} · Сервер доступен ({res.TcpMs} мс), но защищённое соединение TLS оборвалось: {res.Error}");
        }
        if (res.TlsChecked)
        {
            var realityHint = res.SuitableForRealitySni
                ? "Отлично подходит для маскировки Reality (TLS 1.3 + HTTP/2)"
                : "Внимание: для Reality желателен TLS 1.3 + h2";
            return string.Create(
                CultureInfo.InvariantCulture,
                $"{prefix}: РАБОТАЕТ ОТЛИЧНО · отклик {res.TlsMs ?? res.TcpMs} мс (DNS {res.DnsMs} мс, TCP {res.TcpMs} мс, {res.TlsProtocol}) · {realityHint}");
        }

        return string.Create(CultureInfo.InvariantCulture, $"{prefix} · РАБОТАЕТ · отклик TCP {res.TcpMs} мс (DNS {res.DnsMs} мс)");
    }

    private static IBrush SeverityToBrush(AuditSeverity severity) => severity switch
    {
        AuditSeverity.Critical => DangerBrush,
        AuditSeverity.Warning => WarnBrush,
        _ => CleanBrush,
    };
}
