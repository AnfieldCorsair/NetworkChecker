using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VpnChecker.App.Startup;
using VpnChecker.Core.VpnAudit;

namespace VpnChecker.App.ViewModels;

/// <summary>
/// Вкладка 2: Генератор, диалектный аудитор и точечный инжектор блока DNS под РФ
/// (Классика DoH Cloudflare + Google по умолчанию и Приватный Ninja: Njalla + LibreDNS)
/// с автоподбором формата (Sing-box / Xray) и строгой проверкой JSON (запятые и скобки).
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
        SelectedProviderIndex = 0; // Классика DoH: Cloudflare (1.1.1.1) + Google (8.8.8.8)
        SelectedScopeIndex = 0; // Только блок "dns" (без дальнейших правок ниже)
        UseFakeIp = false;
        Regenerate();
    }

    public override string Title => "Настройка DNS";
    public override string Subtitle => "Классика DoH · Приватный · Врезка";
    public override string Description => "Генератор и аудитор блока DNS: классический DoH (Cloudflare + Google) по умолчанию и приватный вариант (Njalla + LibreDNS), с автоподбором формата и проверкой JSON при врезке.";
    public override string SimpleGuideText =>
        "По умолчанию выбрана надёжная классика DoH (Cloudflare 1.1.1.1 + Google 8.8.8.8). Рядом доступна кнопка приватного варианта (Njalla + LibreDNS). При врезке в подписку программа сама подбирает формат и проверяет целостность JSON (запятые и скобки).";

    public IReadOnlyList<string> CoreChoices { get; } =
    [
        "Sing-box 1.12+ / Hiddify / NekoBox (JSON)",
        "Xray-core v25+ / v2rayN / Happ (JSON)",
        "Clash / Mihomo / Clash Verge (YAML)",
    ];

    public IReadOnlyList<string> ProviderChoices { get; } =
    [
        "Классика DoH: Cloudflare (1.1.1.1) + Google (8.8.8.8)",
        "Приватный Ninja: Njalla (dns.njal.la) + LibreDNS (doh.libredns.gr)",
        "Приватный No-Log: Mullvad DoH + Quad9 DoH",
        "РФ и антиреклама: Comss.one DoH + AdGuard DoH",
    ];

    public IReadOnlyList<string> ScopeChoices { get; } =
    [
        "Вставка в готовый конфиг (\"dns\": { ... }, без внешних { } и с запятой)",
        "Отдельный валидный JSON-объект ({ \"dns\": { ... } })",
        "Только тело DNS (для поля Custom DNS в v2rayN: { \"servers\": [...] })",
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
    public partial string JsonValidationStatus { get; set; } = "JSON проверен: запятые и скобки валидны.";

    [ObservableProperty]
    public partial IBrush JsonValidationBrush { get; set; } = CleanBrush;

    [ObservableProperty]
    public partial string AuditSummary { get; set; } = "Готовый блок DNS защищён от подмены и утечек.";

    [ObservableProperty]
    public partial IBrush AuditSummaryBrush { get; set; } = CleanBrush;

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Выберите базовый вариант (Классика DoH или Приватный Ninja) и вшейте в подписку — целостность JSON проверяется автоматически.";

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
            1 => DnsProviderProfile.NinjaPrivacy,
            2 => DnsProviderProfile.MullvadQuad9,
            3 => DnsProviderProfile.ComssAdGuard,
            _ => DnsProviderProfile.CloudflareGoogle,
        };

        var scope = SelectedScopeIndex switch
        {
            0 => DnsOutputScope.DnsPropertySnippet,
            1 => DnsOutputScope.DnsBlockOnly,
            2 => DnsOutputScope.DnsInnerBodyOnly,
            _ => DnsOutputScope.FullDnsAndRouting,
        };

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
    private void LoadClassicSample()
    {
        SelectedCoreIndex = 1;
        SelectedProviderIndex = 0;
        SelectedScopeIndex = 0;
        GeneratedConfig = DnsConfigArchitect.FormatAsPropertySnippet(DnsConfigArchitect.ClassicSampleJson, includeTrailingComma: true);
        StatusText = "Выбрана классика DoH (Cloudflare + Google + 77.88.8.8) в формате вставки \"dns\": { ... }, — без лишних внешних { } и с запятой в конце.";
    }

    [RelayCommand]
    private void LoadNinjaSample()
    {
        SelectedCoreIndex = 1;
        SelectedProviderIndex = 1;
        SelectedScopeIndex = 0;
        GeneratedConfig = DnsConfigArchitect.FormatAsPropertySnippet(DnsConfigArchitect.NinjaSampleJson, includeTrailingComma: true);
        StatusText = "Выбран приватный Ninja (Njalla + LibreDNS + 77.88.8.8) в формате вставки \"dns\": { ... }, — без лишних внешних { } и с запятой в конце.";
    }

    [RelayCommand]
    private async Task CopyPropertySnippetAsync()
    {
        if (SelectedCoreIndex == 2)
        {
            await CopyGeneratedAsync().ConfigureAwait(true);
            return;
        }

        var opt = BuildCurrentOptions() with { OutputScope = DnsOutputScope.DnsPropertySnippet };
        var snippet = DnsConfigArchitect.GenerateOptimalBlock(opt);
        if (!DnsConfigArchitect.ValidateDnsJsonOrSnippet(snippet, out var err, out _))
        {
            StatusText = $"Копирование остановлено: {err}";
            return;
        }

        var ok = await _ui.CopyTextAsync(snippet).ConfigureAwait(true);
        StatusText = ok
            ? "Скопирован фрагмент \"dns\": { ... }, (внешние { } сняты, запятая в конце добавлена — можно сразу вставлять в конфиг Happ/Xray/Sing-box!)."
            : "Буфер обмена недоступен.";
    }

    [RelayCommand]
    private async Task CopyGeneratedAsync()
    {
        if (SelectedCoreIndex != 2 && !DnsConfigArchitect.ValidateDnsJsonOrSnippet(GeneratedConfig, out var err, out _))
        {
            StatusText = $"Копирование остановлено: {err}";
            return;
        }

        var ok = await _ui.CopyTextAsync(GeneratedConfig).ConfigureAwait(true);
        StatusText = ok
            ? SelectedScopeIndex switch
            {
                0 => "Фрагмент \"dns\": { ... }, скопирован (без внешних { }, с запятой в конце — готов к вставке в конфиг).",
                1 => "Отдельный JSON-объект { \"dns\": { ... } } скопирован в буфер обмена.",
                2 => "Тело секции DNS { \"servers\": [...] } скопировано (для поля Custom DNS в v2rayN).",
                _ => "Полный блок DNS + маршрутизации скопирован в буфер обмена.",
            }
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
            ? string.Create(CultureInfo.InvariantCulture, $"{summaryMessage} Готовый одиночный конфиг узла #{selectedIdx} скопирован в буфер обмена (можно сразу вставить в Happ или v2rayN).")
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
            : "VPN_Checker-DNS";
        var url = SubscriptionService.StartOrUpdateLocalSubscriptionServer(patchedJson, title);
        _configAudit.HostedSubscriptionUrl = url;
        var copied = await _ui.CopyTextAsync(url).ConfigureAwait(true);
        StatusText = copied
            ? $"Блок DNS вшит во все узлы подписки (JSON проверен)! Локальная ссылка скопирована в буфер: {url}"
            : $"Локальная ссылка с новым DNS запущена: {url}";
    }

    [RelayCommand]
    private async Task SaveGeneratedAsync()
    {
        var isYaml = SelectedCoreIndex == 2;
        var ext = isYaml ? ".yaml" : ".json";
        var name = isYaml ? "dns-clash-mihomo.yaml" : (SelectedCoreIndex == 1 ? "dns-xray.json" : "dns-singbox-112.json");
        var desc = isYaml ? "YAML-конфиг" : "JSON-конфиг";
        var path = await _ui.SaveTextFileAsync(name, GeneratedConfig, ext, desc).ConfigureAwait(true);
        StatusText = path is not null ? $"Файл сохранён: {path}" : "Сохранение отменено.";
    }

    private void RunAudit(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('[') || trimmed.StartsWith('"'))
        {
            var valid = DnsConfigArchitect.ValidateDnsJsonOrSnippet(trimmed, out var msg, out _);
            JsonValidationStatus = msg;
            JsonValidationBrush = valid ? CleanBrush : DangerBrush;
        }
        else
        {
            JsonValidationStatus = "Формат YAML (Clash / Mihomo).";
            JsonValidationBrush = CleanBrush;
        }

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
            AuditSummary = "Блок DNS валиден: зашифрованный DoH и раздельные правила для РФ настроены корректно.";
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
