using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RKNHardering.Core.Net;
using RKNHardering.Core.Options;
using RKNHardering.Data;

namespace RKNHardering.App.ViewModels;

public sealed partial class SettingsViewModel : ViewModelBase
{
    private readonly SettingsStore _store;
    private readonly RknOptions _options;
    private readonly UiOptions _ui;
    private readonly HistoryRepository _history;

    public SettingsViewModel(SettingsStore store, RknOptions options, UiOptions ui, HistoryRepository history, UiModeService mode)
    {
        Mode = mode;
        _store = store;
        _options = options;
        _ui = ui;
        _history = history;

        _requestTimeout = options.RequestTimeoutSeconds;
        _maxParallelChecks = options.MaxParallelChecks;
        _privacyMode = options.PrivacyMode;
        _offlineMode = options.OfflineMode;
        _saveHistory = options.SaveHistory;
        _maxTraceHops = options.MaxTraceHops;
        _defaultTraceTarget = options.DefaultTraceTarget;

        _geoIpProviders = string.Join(Environment.NewLine, options.GeoIpProviders);
        _reachabilityTargets = string.Join(Environment.NewLine, options.ReachabilityTargets);
        _rttRussianHosts = string.Join(Environment.NewLine, options.RttRussianHosts);
        _rttForeignHosts = string.Join(Environment.NewLine, options.RttForeignHosts);
        _stunServers = string.Join(Environment.NewLine, options.StunServers);
        _localProxyPorts = string.Join(", ", options.LocalProxyPorts);

        DataDirectory = store.DataDirectory;
        DatabasePath = store.DatabasePath;
    }

    public UiModeService Mode { get; }

    public override string Title => "Настройки";
    public override string Icon => global::RKNHardering.App.Icons.Sliders;
    public override string Description => "Таймауты, цели проверок, приватность";

    public ObservableCollection<string> Themes { get; } = new() { "Dark", "Light", "System" };

    [ObservableProperty] private int _requestTimeout = 8;
    [ObservableProperty] private int _maxParallelChecks = 6;
    [ObservableProperty] private bool _privacyMode;
    [ObservableProperty] private bool _offlineMode;
    [ObservableProperty] private bool _saveHistory = true;
    [ObservableProperty] private int _maxTraceHops = 20;
    [ObservableProperty] private string _defaultTraceTarget = "1.1.1.1";
    [ObservableProperty] private string _geoIpProviders = string.Empty;
    [ObservableProperty] private string _reachabilityTargets = string.Empty;
    [ObservableProperty] private string _rttRussianHosts = string.Empty;
    [ObservableProperty] private string _rttForeignHosts = string.Empty;
    [ObservableProperty] private string _stunServers = string.Empty;
    [ObservableProperty] private string _localProxyPorts = string.Empty;
    [ObservableProperty] private string _theme = "Dark";
    [ObservableProperty] private string _saveStatus = "Изменения применяются по кнопке «Сохранить».";
    [ObservableProperty] private string _dbStatus = string.Empty;

    public string DataDirectory { get; }
    public string DatabasePath { get; }

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
        _options.LocalProxyPorts = LocalProxyPorts
            .Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p.Trim(), out var port) ? port : 0)
            .Where(p => p is > 0 and < 65536)
            .Distinct()
            .ToList();

        Masking.Enabled = PrivacyMode;
        _store.Save(_options, _ui);
        SaveStatus = $"Сохранено в {Path.Combine(DataDirectory, "settings.json")} — {DateTime.Now:HH:mm:ss}";
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
        SaveStatus = "Значения сброшены к дефолтным. Нажмите «Сохранить».";
    }

    [RelayCommand]
    private async Task ClearHistoryAsync()
    {
        await _history.ClearAsync().ConfigureAwait(true);
        DbStatus = "История очищена.";
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
            DbStatus = "Не удалось открыть папку: " + ex.Message;
        }
    }

    private static List<string> SplitLines(string text) =>
        text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => line.Length > 0)
            .Distinct()
            .ToList();
}
