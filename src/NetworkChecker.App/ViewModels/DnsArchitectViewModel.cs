using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

/// <summary>
/// Вкладка 2: Генератор, диалектный аудитор и точечный инжектор оптимального DNS-блока под РФ
/// (Sing-box 1.12+, Xray-core v25+ / Happ, Clash/Mihomo) с поддержкой Ninja Privacy (Njalla + LibreDNS)
/// и режимом генерации «Только блок dns (нижнее не трогаем)».
/// </summary>
public sealed partial class DnsArchitectViewModel : ViewModelBase
{
    private static readonly IBrush CleanBrush = new SolidColorBrush(Color.Parse("#4ADE80"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
    private static readonly IBrush DangerBrush = new SolidColorBrush(Color.Parse("#F87171"));

    private readonly ConfigAuditViewModel _configAudit;
    private readonly IDesktopUiService _ui;

    public DnsArchitectViewModel(ConfigAuditViewModel configAudit, IDesktopUiService ui)
    {
        _configAudit = configAudit;
        _ui = ui;
        SelectedCoreIndex = 1; // Xray / Happ по умолчанию для быстрой работы с подписками
        SelectedProviderIndex = 0; // Ninja Privacy (Njalla + LibreDNS)
        SelectedScopeIndex = 0; // Только блок "dns" (без дальнейших правок ниже)
        UseFakeIp = false;
        Regenerate();
    }

    public override string Title => "Настройка DNS";
    public override string Subtitle => "Ninja DNS · Только блок dns · Врезка";
    public override string Description => "Генератор защищённого DNS (включая приватные Njalla и LibreDNS), режим «Только блок dns без нижних секций» и точечная врезка в вашу подписку или выбранный узел.";
    public override string SimpleGuideText =>
        "Выберите «Только блок dns (нижнее не трогаем)» и провайдера «Ninja Privacy (Njalla + LibreDNS)». Вы можете скопировать сам блок [dns], либо одним кликом вшить его в вашу подписку из Шага 1 и забрать готовый узел в буфер или по локальной ссылке.";

    public IReadOnlyList<string> CoreChoices { get; } =
    [
        "Sing-box 1.12+ / Hiddify / NekoBox (JSON)",
        "Xray-core v25+ / v2rayN / Happ (JSON)",
        "Clash / Mihomo / Clash Verge (YAML)",
    ];

    public IReadOnlyList<string> ProviderChoices { get; } =
    [
        "Ninja Privacy: Njalla (dns.njal.la) + LibreDNS (doh.libredns.gr)",
        "Приватный No-Log: Mullvad DoH + Quad9 DoH",
        "Классический: Cloudflare (1.1.1.1) + Google (8.8.8.8)",
        "РФ и антиреклама: Comss.one DoH + AdGuard DoH",
    ];

    public IReadOnlyList<string> ScopeChoices { get; } =
    [
        "Только блок \"dns\" (в фигурных/квадратных скобках, нижнее не трогаем)",
        "Полный блок \"dns\" + \"routing\" (вместе с правилами маршрутов)",
    ];

    [ObservableProperty]
    public partial int SelectedCoreIndex { get; set; }

    [ObservableProperty]
    public partial int SelectedProviderIndex { get; set; }

    [ObservableProperty]
    public partial int SelectedScopeIndex { get; set; }

    [ObservableProperty]
    public partial bool RfSplitTunneling { get; set; } = true;

    [ObservableProperty]
    public partial bool UseFakeIp { get; set; }

    [ObservableProperty]
    public partial bool Ipv4Only { get; set; } = true;

    [ObservableProperty]
    public partial bool BlockAds { get; set; }

    [ObservableProperty]
    public partial string GeneratedConfig { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string AuditSummary { get; set; } = "Готовый блок DNS полностью защищён от подмены и утечек.";

    [ObservableProperty]
    public partial IBrush AuditSummaryBrush { get; set; } = CleanBrush;

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Выберите режим («Только блок dns» или «Полный»), провайдера (например Ninja: Njalla + LibreDNS) и скопируйте либо вшейте в подписку.";

    public ObservableCollection<AuditFindingDisplayItem> AuditFindings { get; } = [];

    partial void OnSelectedCoreIndexChanged(int value) => Regenerate();
    partial void OnSelectedProviderIndexChanged(int value) => Regenerate();
    partial void OnSelectedScopeIndexChanged(int value) => Regenerate();
    partial void OnRfSplitTunnelingChanged(bool value) => Regenerate();
    partial void OnUseFakeIpChanged(bool value) => Regenerate();
    partial void OnIpv4OnlyChanged(bool value) => Regenerate();
    partial void OnBlockAdsChanged(bool value) => Regenerate();
    partial void OnGeneratedConfigChanged(string value) => RunAudit(value);

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName == nameof(ShowTechnicalDetails))
        {
            foreach (var item in AuditFindings)
            {
                item.IsExpanded = ShowTechnicalDetails;
            }
        }
    }

    private DnsArchitectOptions BuildCurrentOptions()
    {
        var target = SelectedCoreIndex switch
        {
            1 => DnsCoreTarget.XrayCore,
            2 => DnsCoreTarget.ClashMihomo,
            _ => DnsCoreTarget.SingBox112,
        };

        var provider = SelectedProviderIndex switch
        {
            1 => DnsProviderProfile.MullvadQuad9,
            2 => DnsProviderProfile.CloudflareGoogle,
            3 => DnsProviderProfile.ComssAdGuard,
            _ => DnsProviderProfile.NinjaPrivacy,
        };

        var scope = SelectedScopeIndex == 0
            ? DnsOutputScope.DnsBlockOnly
            : DnsOutputScope.FullDnsAndRouting;

        return new DnsArchitectOptions(
            target,
            RfSplitTunneling,
            UseFakeIp,
            Ipv4Only,
            BlockAds,
            provider,
            scope);
    }

    [RelayCommand]
    private void Regenerate()
    {
        var opt = BuildCurrentOptions();
        GeneratedConfig = DnsConfigArchitect.GenerateOptimalBlock(opt);
    }

    [RelayCommand]
    private void LoadNinjaSample()
    {
        SelectedCoreIndex = 1;
        SelectedProviderIndex = 0;
        SelectedScopeIndex = 0;
        GeneratedConfig = DnsConfigArchitect.NinjaSampleJson;
        StatusText = "Загружен эталонный блок Ninja DNS (77.88.8.8 для category-ru + Njalla + LibreDNS + резервный localhost).";
    }

    [RelayCommand]
    private async Task CopyGeneratedAsync()
    {
        var ok = await _ui.CopyTextAsync(GeneratedConfig).ConfigureAwait(true);
        StatusText = ok
            ? (SelectedScopeIndex == 0
                ? "Только блок \"dns\" (без нижних секций) скопирован в буфер обмена."
                : "Полный блок DNS + маршрутизации скопирован в буфер обмена.")
            : "Буфер обмена недоступен.";
    }

    [RelayCommand]
    private async Task InjectDnsIntoAllNodesAsync()
    {
        var opt = BuildCurrentOptions();
        if (!DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
                _configAudit.RawConfig,
                opt,
                out var patchedJson,
                out var summaryMessage,
                targetNodeIndex: null,
                extractSingleNodeOnly: false))
        {
            StatusText = summaryMessage;
            return;
        }

        _configAudit.UpdateRawConfigFromPatcher(patchedJson, summaryMessage);
        var copied = await _ui.CopyTextAsync(patchedJson).ConfigureAwait(true);
        StatusText = copied
            ? $"{summaryMessage} Вся исправленная подписка/конфигурация скопирована в буфер обмена!"
            : summaryMessage;
    }

    [RelayCommand]
    private async Task InjectDnsIntoSelectedNodeOnlyAsync()
    {
        var opt = BuildCurrentOptions();
        var selectedIdx = _configAudit.SelectedNode?.Index ?? 1;
        if (!DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
                _configAudit.RawConfig,
                opt,
                out var patchedSingleNodeJson,
                out var summaryMessage,
                targetNodeIndex: selectedIdx,
                extractSingleNodeOnly: true))
        {
            StatusText = summaryMessage;
            return;
        }

        var copied = await _ui.CopyTextAsync(patchedSingleNodeJson).ConfigureAwait(true);
        StatusText = copied
            ? $"{summaryMessage} Готовый одиночный конфиг узла #{selectedIdx} скопирован в буфер обмена (можно сразу вставить в Happ или v2rayN)."
            : summaryMessage;
    }

    [RelayCommand]
    private async Task InjectDnsAndHostLocalUrlAsync()
    {
        var opt = BuildCurrentOptions();
        if (!DnsConfigArchitect.TryInjectDnsIntoJsonConfig(
                _configAudit.RawConfig,
                opt,
                out var patchedJson,
                out var summaryMessage,
                targetNodeIndex: null,
                extractSingleNodeOnly: false))
        {
            StatusText = summaryMessage;
            return;
        }

        _configAudit.UpdateRawConfigFromPatcher(patchedJson, summaryMessage);
        var title = !string.IsNullOrWhiteSpace(_configAudit.SubscriptionTitle)
            ? _configAudit.SubscriptionTitle
            : "KonturVPN-NinjaDNS";
        var url = SubscriptionService.StartOrUpdateLocalSubscriptionServer(patchedJson, title);
        _configAudit.HostedSubscriptionUrl = url;
        var copied = await _ui.CopyTextAsync(url).ConfigureAwait(true);
        StatusText = copied
            ? $"Блок DNS вшит во все узлы подписки! Локальная ссылка скопирована в буфер: {url} (добавьте её в Happ / v2rayN)."
            : $"Локальная ссылка с новым DNS запущена: {url}";
    }

    [RelayCommand]
    private async Task SaveGeneratedAsync()
    {
        var isYaml = SelectedCoreIndex == 2;
        var ext = isYaml ? ".yaml" : ".json";
        var name = isYaml ? "dns-clash-mihomo.yaml" : (SelectedCoreIndex == 1 ? "dns-xray-ninja.json" : "dns-singbox-112.json");
        var desc = isYaml ? "YAML-конфиг" : "JSON-конфиг";
        var path = await _ui.SaveTextFileAsync(name, GeneratedConfig, ext, desc).ConfigureAwait(true);
        StatusText = path is not null ? $"Файл сохранён: {path}" : "Сохранение отменено.";
    }

    private void RunAudit(string raw)
    {
        AuditFindings.Clear();
        var findings = DnsConfigArchitect.AuditDnsBlock(raw);
        foreach (var f in findings)
        {
            var brush = f.Severity switch
            {
                AuditSeverity.Critical => DangerBrush,
                AuditSeverity.Warning => WarnBrush,
                _ => CleanBrush,
            };
            AuditFindings.Add(new AuditFindingDisplayItem(
                f.SeverityLabel,
                brush,
                f.Title,
                f.SimpleSummary,
                f.TechnicalDetail,
                f.Evidence,
                f.Remediation,
                ShowTechnicalDetails));
        }

        var actionableCount = findings.Count(x => x.Severity is AuditSeverity.Critical or AuditSeverity.Warning);
        if (actionableCount == 0)
        {
            AuditSummary = "Всё отлично: зашифрованный DNS (DoH) через туннель и прямой доступ к сайтам РФ настроены правильно.";
            AuditSummaryBrush = CleanBrush;
        }
        else
        {
            var hasCritical = findings.Any(x => x.Severity == AuditSeverity.Critical);
            AuditSummary = string.Create(CultureInfo.InvariantCulture, $"Найдено замечаний в настройках DNS: {actionableCount}");
            AuditSummaryBrush = hasCritical ? DangerBrush : WarnBrush;
        }
    }
}
