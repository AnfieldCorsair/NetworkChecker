using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

/// <summary>
/// Вкладка 2: Генератор и аудитор оптимального DNS-блока под РФ (Sing-box 1.12+, Xray-core v25+, Clash/Mihomo).
/// </summary>
public sealed partial class DnsArchitectViewModel : ViewModelBase
{
    private readonly IDesktopUiService _ui;

    public DnsArchitectViewModel(IDesktopUiService ui)
    {
        _ui = ui;
        Regenerate();
    }

    public override string Title => "DNS-архитектор";
    public override string Subtitle => "Sing-box · Xray · Clash";
    public override string Description => "Эталонные DNS-блоки без петли (bootstrap), с DoH через proxy против подмены ТСПУ и split-tunneling для РФ.";

    public IReadOnlyList<string> CoreChoices { get; } =
    [
        "Sing-box 1.12+ (JSON)",
        "Xray-core v25+ (JSON)",
        "Clash / Mihomo (YAML)",
    ];

    [ObservableProperty]
    public partial int SelectedCoreIndex { get; set; }

    [ObservableProperty]
    public partial bool RfSplitTunneling { get; set; } = true;

    [ObservableProperty]
    public partial bool UseFakeIp { get; set; } = true;

    [ObservableProperty]
    public partial bool Ipv4Only { get; set; } = true;

    [ObservableProperty]
    public partial bool BlockAds { get; set; }

    [ObservableProperty]
    public partial string GeneratedConfig { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string AuditSummary { get; set; } = "Эталонный блок прошёл проверку без критических ошибок.";

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Измените параметры слева или отредактируйте блок DNS вручную для мгновенного аудита.";

    public ObservableCollection<VpnAuditFinding> AuditFindings { get; } = [];

    partial void OnSelectedCoreIndexChanged(int value) => Regenerate();
    partial void OnRfSplitTunnelingChanged(bool value) => Regenerate();
    partial void OnUseFakeIpChanged(bool value) => Regenerate();
    partial void OnIpv4OnlyChanged(bool value) => Regenerate();
    partial void OnBlockAdsChanged(bool value) => Regenerate();
    partial void OnGeneratedConfigChanged(string value) => RunAudit(value);

    [RelayCommand]
    private void Regenerate()
    {
        var target = SelectedCoreIndex switch
        {
            1 => DnsCoreTarget.XrayCore,
            2 => DnsCoreTarget.ClashMihomo,
            _ => DnsCoreTarget.SingBox112,
        };

        var opt = new DnsArchitectOptions(target, RfSplitTunneling, UseFakeIp, Ipv4Only, BlockAds);
        GeneratedConfig = DnsConfigArchitect.GenerateOptimalBlock(opt);
    }

    [RelayCommand]
    private async Task CopyGeneratedAsync()
    {
        var ok = await _ui.CopyTextAsync(GeneratedConfig).ConfigureAwait(true);
        StatusText = ok ? "Блок DNS скопирован в буфер обмена." : "Буфер обмена недоступен.";
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
        AuditFindings.Clear();
        var findings = DnsConfigArchitect.AuditDnsBlock(raw);
        foreach (var f in findings)
        {
            AuditFindings.Add(f);
        }

        AuditSummary = findings.Count == 0
            ? "Проблем в DNS-блоке не найдено (DoH через proxy, bootstrap и hijack-dns настроены)."
            : string.Create(CultureInfo.InvariantCulture, $"Найдено замечаний по DNS: {findings.Count}");
    }
}
