using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Reputation;
using NetworkChecker.Data;

namespace NetworkChecker.App.ViewModels;

public sealed partial class SettingsViewModel(
    SettingsStore store,
    RknOptions options,
    UiOptions ui,
    HistoryRepository history,
    UiModeService mode,
    ReputationService? reputation = null) : ViewModelBase
{
    private readonly SettingsStore _store = store;
    private readonly RknOptions _options = options;
    private readonly UiOptions _ui = ui;
    private readonly HistoryRepository _history = history;
    private readonly ReputationService? _reputation = reputation;

    public UiModeService Mode { get; } = mode;

    public override string Title => global::NetworkChecker.App.Localization.Localizer.T("Настройки");
    public override string Icon => global::NetworkChecker.App.Icons.Sliders;
    public override string Description => global::NetworkChecker.App.Localization.Localizer.T("Таймауты, цели проверок, приватность");

    public ObservableCollection<string> Languages { get; } = ["ru-RU", "en-US"];

    [ObservableProperty]
    public partial string Language { get; set; } = ui.Culture == "en-US" ? "en-US" : "ru-RU";

    public ObservableCollection<string> Themes { get; } = ["Dark", "Light", "System"];

    [ObservableProperty]
    public partial int RequestTimeout { get; set; } = options.RequestTimeoutSeconds;

    [ObservableProperty]
    public partial int MaxParallelChecks { get; set; } = options.MaxParallelChecks;

    [ObservableProperty]
    public partial bool PrivacyMode { get; set; } = options.PrivacyMode;

    [ObservableProperty]
    public partial bool OfflineMode { get; set; } = options.OfflineMode;

    [ObservableProperty]
    public partial bool SaveHistory { get; set; } = options.SaveHistory;

    [ObservableProperty]
    public partial int MaxTraceHops { get; set; } = options.MaxTraceHops;

    [ObservableProperty]
    public partial string DefaultTraceTarget { get; set; } = options.DefaultTraceTarget;

    [ObservableProperty]
    public partial string GeoIpProviders { get; set; } = string.Join(Environment.NewLine, options.GeoIpProviders);

    [ObservableProperty]
    public partial string ReachabilityTargets { get; set; } = string.Join(Environment.NewLine, options.ReachabilityTargets);

    [ObservableProperty]
    public partial string RttRussianHosts { get; set; } = string.Join(Environment.NewLine, options.RttRussianHosts);

    [ObservableProperty] private string _rttForeignHosts = string.Join(Environment.NewLine, options.RttForeignHosts);
    [ObservableProperty] private string _stunServers = string.Join(Environment.NewLine, options.StunServers);
    [ObservableProperty] private string _localProxyPorts = string.Join(", ", options.LocalProxyPorts);

    // ---- Репутация IP и метка Google -------------------------------------------
    [ObservableProperty] private bool _reputationEnabled = options.ReputationEnabled;
    [ObservableProperty] private bool _googleRegionEnabled = options.GoogleRegionEnabled;
    [ObservableProperty] private string _dnsblZones = string.Join(Environment.NewLine, options.DnsblZones);
    [ObservableProperty] private string _abuseIpDbKey = options.AbuseIpDbKey ?? string.Empty;
    [ObservableProperty] private string _ipQualityScoreKey = options.IpQualityScoreKey ?? string.Empty;
    [ObservableProperty] private string _proxyCheckKey = options.ProxyCheckKey ?? string.Empty;
    [ObservableProperty] private string _ipApiIsKey = options.IpApiIsKey ?? string.Empty;
    [ObservableProperty] private string _scamalyticsUser = options.ScamalyticsUser ?? string.Empty;
    [ObservableProperty] private string _scamalyticsKey = options.ScamalyticsKey ?? string.Empty;
    [ObservableProperty] private string _spamhausDqsKey = options.SpamhausDqsKey ?? string.Empty;

    [ObservableProperty] private string _theme = "Dark";
    [ObservableProperty] private string _saveStatus = Localizer.T("Изменения применяются по кнопке «Сохранить».");
    [ObservableProperty] private string _dbStatus = string.Empty;

    public string DataDirectory { get; } = store.DataDirectory;
    public string DatabasePath { get; } = store.DatabasePath;

    partial void OnThemeChanged(string value)
    {
        _ui.Theme = value;
        App.ApplyTheme(value);
        _store.Save();
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        _options.RequestTimeoutSeconds = Math.Clamp(RequestTimeout, 2, 60);
        _options.MaxParallelChecks = Math.Clamp(MaxParallelChecks, 1, 12);
        _options.PrivacyMode = PrivacyMode;
        _options.OfflineMode = OfflineMode;
        _options.SaveHistory = SaveHistory;
        _options.MaxTraceHops = Math.Clamp(MaxTraceHops, 1, 64);
        _options.DefaultTraceTarget = string.IsNullOrWhiteSpace(DefaultTraceTarget) ? "1.1.1.1" : DefaultTraceTarget.Trim();

        _options.GeoIpProviders = SplitLines(GeoIpProviders);
        _options.ReachabilityTargets = SplitLines(ReachabilityTargets);
        _options.RttRussianHosts = SplitLines(RttRussianHosts);
        _options.RttForeignHosts = SplitLines(RttForeignHosts);
        _options.StunServers = SplitLines(StunServers);
        _options.LocalProxyPorts = [.. LocalProxyPorts
            .Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p.Trim(), out var port) ? port : 0)
            .Where(p => p is > 0 and < 65536)
            .Distinct()];

        _options.ReputationEnabled = ReputationEnabled;
        _options.GoogleRegionEnabled = GoogleRegionEnabled;
        _options.DnsblZones = SplitLines(DnsblZones);
        _options.AbuseIpDbKey = TrimOrNull(AbuseIpDbKey);
        _options.IpQualityScoreKey = TrimOrNull(IpQualityScoreKey);
        _options.ProxyCheckKey = TrimOrNull(ProxyCheckKey);
        _options.IpApiIsKey = TrimOrNull(IpApiIsKey);
        _options.ScamalyticsUser = TrimOrNull(ScamalyticsUser);
        _options.ScamalyticsKey = TrimOrNull(ScamalyticsKey);
        _options.SpamhausDqsKey = TrimOrNull(SpamhausDqsKey);
        // Ключи и список зон изменились: закэшированный отчёт больше не актуален.
        _reputation?.Invalidate();

        _ui.Culture = Language == "en-US" ? "en-US" : "ru-RU";
        Masking.Enabled = PrivacyMode;
        SaveStatus = _store.Save(_options, _ui)
            ? Localizer.Culture == "en-US"
                ? $"Language changes apply after restart. Saved to {Path.Combine(DataDirectory, "settings.json")} — {DateTime.Now:HH:mm:ss}"
                : $"Язык применяется после перезапуска. Сохранено в {Path.Combine(DataDirectory, "settings.json")} — {DateTime.Now:HH:mm:ss}"
            : Localizer.Culture == "en-US"
                ? "Could not save settings to disk. Changes apply only in this session."
                : "Не удалось сохранить настройки на диск. Изменения действуют только в текущем сеансе.";
        await Task.CompletedTask.ConfigureAwait(true);
    }

    [RelayCommand]
    private void ResetToDefaults()
    {
        var defaults = new RknOptions();
        RequestTimeout = defaults.RequestTimeoutSeconds;
        MaxParallelChecks = defaults.MaxParallelChecks;
        PrivacyMode = defaults.PrivacyMode;
        OfflineMode = defaults.OfflineMode;
        SaveHistory = defaults.SaveHistory;
        MaxTraceHops = defaults.MaxTraceHops;
        DefaultTraceTarget = defaults.DefaultTraceTarget;
        GeoIpProviders = string.Join(Environment.NewLine, defaults.GeoIpProviders);
        ReachabilityTargets = string.Join(Environment.NewLine, defaults.ReachabilityTargets);
        RttRussianHosts = string.Join(Environment.NewLine, defaults.RttRussianHosts);
        RttForeignHosts = string.Join(Environment.NewLine, defaults.RttForeignHosts);
        StunServers = string.Join(Environment.NewLine, defaults.StunServers);
        LocalProxyPorts = string.Join(", ", defaults.LocalProxyPorts);
        ReputationEnabled = defaults.ReputationEnabled;
        GoogleRegionEnabled = defaults.GoogleRegionEnabled;
        DnsblZones = string.Join(Environment.NewLine, defaults.DnsblZones);
        AbuseIpDbKey = string.Empty;
        IpQualityScoreKey = string.Empty;
        ProxyCheckKey = string.Empty;
        IpApiIsKey = string.Empty;
        ScamalyticsUser = string.Empty;
        ScamalyticsKey = string.Empty;
        SpamhausDqsKey = string.Empty;
        SaveStatus = Localizer.Culture == "en-US" ? "Defaults restored. Select Save." : "Значения сброшены к дефолтным. Нажмите «Сохранить».";
    }

    [RelayCommand]
    private async Task ClearHistoryAsync()
    {
        await _history.ClearAsync().ConfigureAwait(true);
        DbStatus = Localizer.T("История очищена.");
    }

    [RelayCommand]
    private void OpenDataFolder()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = DataDirectory,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            DbStatus = Localizer.T("Не удалось открыть папку: ") + ex.Message;
        }
    }

    private static List<string> SplitLines(string text) =>
        [.. text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => line.Length > 0)
            .Distinct()];

    private static string? TrimOrNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
