using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

/// <summary>
/// Вкладка 1: Аудит ВПН-конфигов и подписок + загрузка по URL + жирный блок-патч + живая проба TLS и RTT-бенчмарк.
/// </summary>
public sealed partial class ConfigAuditViewModel : ViewModelBase
{
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

    private const string PresetHysteria2 =
        "hy2://s3cr3tPass@198.51.100.20:443?sni=www.cloudflare.com&obfs=salamander&obfs-password=obfsKey99&mport=20000-40000#Европа-HY2";

    private readonly VpnEndpointProbe _probe;
    private readonly SubscriptionService _subscriptions;
    private readonly IDesktopUiService _ui;

    public ConfigAuditViewModel(
        VpnEndpointProbe probe,
        SubscriptionService subscriptions,
        IDesktopUiService ui)
    {
        _probe = probe;
        _subscriptions = subscriptions;
        _ui = ui;
        RawConfig = PresetVlessXhttp;
        Analyze();
    }

    public override string Title => "Аудит и подписки";
    public override string Subtitle => "VLESS · AWG · HY2 · RTT";
    public override string Description => "Разбор конфигов и Base64-подписок, массовый блок-патч, живая проба DNS/TCP/TLS 1.3 и замер TCP RTT.";

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
    public partial string StatusText { get; set; } = "Вставьте конфиг или ссылку на подписку, затем нажмите «Проверить TLS» или «Замер RTT».";

    [ObservableProperty]
    public partial SubscriptionNodeAudit? SelectedNode { get; set; }

    public ObservableCollection<VpnAuditFinding> Findings { get; } = [];
    public ObservableCollection<SubscriptionNodeAudit> SubscriptionNodes { get; } = [];
    public bool HasMultipleNodes => SubscriptionNodes.Count > 1;

    partial void OnRawConfigChanged(string value) => Analyze();

    partial void OnSelectedNodeChanged(SubscriptionNodeAudit? value)
    {
        if (value is not null)
        {
            ApplyReport(value.Report);
        }
    }

    [RelayCommand]
    private void LoadPreset(string presetKey)
    {
        RawConfig = presetKey switch
        {
            "broken" => PresetVlessTcpBroken,
            "awg" => PresetAmneziaWg,
            "hy2" => PresetHysteria2,
            _ => PresetVlessXhttp,
        };
        StatusText = "Загружен тестовый профиль для проверки.";
    }

    [RelayCommand]
    private void Analyze()
    {
        Findings.Clear();
        SubscriptionNodes.Clear();

        var nodes = VpnConfigAuditor.AuditSubscription(RawConfig);
        if (nodes.Count > 1)
        {
            foreach (var node in nodes)
            {
                SubscriptionNodes.Add(node);
            }

            OnPropertyChanged(nameof(HasMultipleNodes));
            SelectedNode = SubscriptionNodes[0];
            ApplyReport(nodes[0].Report);
            return;
        }

        OnPropertyChanged(nameof(HasMultipleNodes));
        SelectedNode = null;
        var report = VpnConfigAuditor.Audit(RawConfig);
        ApplyReport(report);
    }

    [RelayCommand]
    private async Task FetchSubscriptionAsync(CancellationToken ct)
    {
        if (!Uri.TryCreate(SubscriptionUrl.Trim(), UriKind.Absolute, out var uri))
        {
            StatusText = "Укажите корректную https:// ссылку на подписку.";
            return;
        }

        IsBusy = true;
        StatusText = $"Загрузка подписки {uri.Host}...";
        try
        {
            var fetched = await _subscriptions.FetchAsync(uri, ct: ct).ConfigureAwait(true);
            RawConfig = fetched.RawBody;
            StatusText = string.Create(
                CultureInfo.InvariantCulture,
                $"Подписка «{fetched.Meta.Title}» загружена: узлов {fetched.Nodes.Count}.");
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or ArgumentException)
        {
            StatusText = $"Ошибка загрузки подписки: {ex.Message}";
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
            StatusText = "Блок-патч работает со ссылками vless://, hy2:// и подписками.";
            return;
        }

        RawConfig = summary.PatchedText;
        StatusText = string.Create(
            CultureInfo.InvariantCulture,
            $"Блок-патч применён: узлов {summary.BeforeCount} → {summary.AfterCount}, allowInsecure: {summary.FixedAllowInsecure}, fp=chrome: {summary.AddedFpChrome}, Vision: {summary.AddedVisionFlow}, XHTTP auto: {summary.FixedXhttpMode}, дубли: {summary.RemovedDuplicates}.");
    }

    [RelayCommand]
    private async Task ProbeCurrentEndpointAsync(CancellationToken ct)
    {
        var report = CurrentReport ?? VpnConfigAuditor.Audit(RawConfig);
        if (string.IsNullOrWhiteSpace(report.Profile.ServerHost))
        {
            StatusText = "В конфигурации не найден адрес сервера.";
            return;
        }

        IsBusy = true;
        var port = report.Profile.ServerPort ?? 443;
        StatusText = string.Create(CultureInfo.InvariantCulture, $"Живая проба {report.Profile.ServerHost}:{port}...");
        try
        {
            var checkTls = report.Profile.Protocol is VpnProtocol.Vless or VpnProtocol.SingBoxJson or VpnProtocol.XrayJson;
            var res = await _probe.ProbeAsync(
                report.Profile.ServerHost,
                port,
                report.Profile.Tls.Sni,
                checkTls,
                ct: ct).ConfigureAwait(true);

            if (!res.DnsOk)
            {
                StatusText = string.Create(CultureInfo.InvariantCulture, $"Сбой DNS ({res.DnsMs} мс): {res.Error}");
            }
            else if (!res.TcpOk)
            {
                StatusText = string.Create(CultureInfo.InvariantCulture, $"DNS OK ({res.DnsMs} мс), но TCP :{res.Port} недоступен: {res.Error}");
            }
            else if (res.TlsChecked && !res.TlsOk)
            {
                StatusText = string.Create(CultureInfo.InvariantCulture, $"DNS {res.DnsMs} мс · TCP {res.TcpMs} мс · Сбой TLS: {res.Error}");
            }
            else if (res.TlsChecked)
            {
                var realityHint = res.SuitableForRealitySni
                    ? "Подходит для Reality (TLSv1.3 + h2)"
                    : "Для Reality нужен TLSv1.3 + ALPN h2";
                StatusText = string.Create(
                    CultureInfo.InvariantCulture,
                    $"OK · DNS {res.DnsMs} мс · TCP {res.TcpMs} мс · TLS {res.TlsMs} мс ({res.TlsProtocol} / {res.AlpnProtocol ?? "нет"}) · {realityHint}");
            }
            else
            {
                StatusText = string.Create(CultureInfo.InvariantCulture, $"DNS OK ({res.DnsMs} мс) · TCP OK ({res.TcpMs} мс)");
            }
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
            StatusText = "Укажите конфигурацию с адресом сервера для замера TCP RTT.";
            return;
        }

        IsBusy = true;
        var port = report.Profile.ServerPort ?? 443;
        StatusText = string.Create(CultureInfo.InvariantCulture, $"Серийный замер TCP RTT (6 попыток) до {report.Profile.ServerHost}:{port}...");
        try
        {
            var rtt = await RttBenchmarkProbe.RunAsync(report.Profile.ServerHost, port, attempts: 6, cancellationToken: ct).ConfigureAwait(true);
            LastRttResult = rtt;
            StatusText = string.Create(
                CultureInfo.InvariantCulture,
                $"TCP RTT ({rtt.TargetIp}:{rtt.Port}) · min {rtt.MinMs} мс · avg {rtt.AvgMs} мс · p95 {rtt.P95Ms} мс · jitter {rtt.JitterMs} мс · потери {rtt.LossPct}%");
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or OperationCanceledException)
        {
            StatusText = $"Ошибка замера RTT: {ex.Message}";
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
        StatusText = ok ? "JSON Outbound (Sing-box) скопирован в буфер обмена." : "Буфер обмена недоступен.";
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
            ? (MaskSecrets ? "Конфиг скопирован (ключи и UUID замаскированы)." : "Конфиг скопирован в буфер обмена.")
            : "Буфер обмена недоступен.";
    }

    private void ApplyReport(VpnAuditReport report)
    {
        CurrentReport = report;
        Findings.Clear();
        foreach (var f in report.Findings.OrderByDescending(x => x.Severity))
        {
            Findings.Add(f);
        }

        var portText = report.Profile.ServerPort?.ToString(CultureInfo.InvariantCulture) ?? "—";
        ProtocolSummary = $"{report.Profile.ProtocolLabel} · {report.Profile.ServerHost ?? "—"}:{portText} · {report.Profile.Transport}";
        CriticalCount = report.CriticalCount;
        WarningCount = report.WarningCount;
        OkCount = report.OkCount;

        VerdictHeadline = report.OverallVerdict switch
        {
            AuditSeverity.Critical => string.Create(CultureInfo.InvariantCulture, $"Критические проблемы ({report.CriticalCount})"),
            AuditSeverity.Warning => string.Create(CultureInfo.InvariantCulture, $"Есть замечания ({report.WarningCount})"),
            _ => "Базовый аудит пройден",
        };
    }
}
