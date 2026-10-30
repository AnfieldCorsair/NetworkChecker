using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.Data;

namespace NetworkChecker.App.ViewModels;

public sealed partial class SettingsViewModel(SettingsStore store, RknOptions options, UiOptions ui, HistoryRepository history, UiModeService mode) : ViewModelBase
{
    private readonly SettingsStore _store = store;
    private readonly RknOptions _options = options;
    private readonly UiOptions _ui = ui;
    private readonly HistoryRepository _history = history;

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
}
