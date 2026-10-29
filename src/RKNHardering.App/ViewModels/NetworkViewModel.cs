using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Core.NetInfo;
using RKNHardering.Core.Options;
using RKNHardering.Core.Platform;

namespace RKNHardering.App.ViewModels;

public sealed class AdapterRowViewModel(AdapterInfo adapter)
{
    public string Name { get; } = adapter.Name;
    public string KindText { get; } = adapter.KindText;
    public string AddressText { get; } = adapter.AddressText;
    public string GatewayText { get; } = adapter.Gateways.Count == 0 ? "—" : string.Join(", ", adapter.Gateways);
    public string MtuText { get; } = adapter.Mtu.ToString();
    public string MacText { get; } = Masking.Mac(adapter.MacAddress);
    public string DnsText { get; } = adapter.DnsServers.Count == 0 ? "—" : string.Join(", ", adapter.DnsServers);
    public string Description { get; } = adapter.Description;
    public bool IsUp { get; } = adapter.IsUp;
    public string StatusText => IsUp ? "Up" : "Down";
    public Avalonia.Media.IBrush KindBrush => Ui.Brush(KindColor);

    public string KindColor => adapter.Kind switch
    {
        AdapterKind.Tunnel => "#F0524C",
        AdapterKind.Wifi => "#4EA1FF",
        AdapterKind.Ethernet => "#35C48A",
        AdapterKind.Virtual => "#B061D6",
        AdapterKind.Cellular => "#F2913D",
        _ => "#5C7A99",
    };
}

public sealed class RouteRowViewModel(RouteInfo route)
{
    public string Destination { get; } = route.Destination;
    public string GatewayText { get; } = Masking.Ip(route.Gateway ?? "—");
    public string InterfaceName { get; } = route.InterfaceName ?? "—";
    public string MetricText { get; } = route.Metric.ToString();
    public bool IsDefault { get; } = route.IsDefault;
}

public sealed record KeyValueRow(string Key, string Value, string? Hint = null);

/// <summary>Понятный факт о сети для простого режима.</summary>
public sealed class SimpleNetFact(string label, string value, string hint, string tone)
{
    public string Tone { get; } = tone;
    public bool IsGood => Tone == "good";
    public bool IsBad => Tone == "bad";
    public string Label { get; } = label;
    public string Value { get; } = value;
    public string Hint { get; } = hint;
    public Avalonia.Media.IBrush DotBrush { get; } = Ui.Brush(tone switch
    {
        "good" => "#35C48A",
        "bad" => "#F0524C",
        _ => "#F5C542",
    });
}

public sealed partial class NetworkViewModel : ViewModelBase
{
    private readonly NetworkInfoService _service;
    private readonly RknOptions _options;
    private readonly ILogger<NetworkViewModel> _logger;
    private CancellationTokenSource? _cts;

    public NetworkViewModel(NetworkInfoService service, RknOptions options, UiModeService mode, ILogger<NetworkViewModel> logger)
    {
        Mode = mode;
        _service = service;
        _options = options;
        _logger = logger;
        TraceTarget = options.DefaultTraceTarget;
        Mode.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName is nameof(UiModeService.IsSimple) or nameof(UiModeService.IsPro))
            {
                OnPropertyChanged(nameof(ShowTabs));
                OnPropertyChanged(nameof(ShowTechnicalOverview));
                OnPropertyChanged(nameof(ShowSimpleOverview));
                OnPropertyChanged(nameof(ShowOverview));
                if (Mode.IsSimple) ActiveTab = "Овервью";
            }
        };
    }

    public UiModeService Mode { get; }

    public override string Title => "Сеть";
    public override string Icon => global::RKNHardering.App.Icons.Globe;
    public override string Description => "База, диагностика и трассировка";

    public ObservableCollection<AdapterRowViewModel> Adapters { get; } = new();
    public ObservableCollection<RouteRowViewModel> DefaultRoutes { get; } = new();
    public ObservableCollection<KeyValueRow> Overview { get; } = new();
    public ObservableCollection<HostLatency> Latency { get; } = new();
    public ObservableCollection<MtuProbe> Mtu { get; } = new();
    public ObservableCollection<DnsProbeResult> Dns { get; } = new();
    public ObservableCollection<TlsProbe> Tls { get; } = new();
    public ObservableCollection<TraceHop> Hops { get; } = new();
    public ObservableCollection<SimpleNetFact> SimpleFacts { get; } = new();

    /// <summary>Технические таблицы показываем только в подробном режиме.</summary>
    public bool ShowTechnicalOverview => ShowOverview && Mode.IsPro;
    public bool ShowSimpleOverview => Mode.IsSimple;

    [ObservableProperty] private string _simpleSummary = "Нажмите «Обновить», чтобы посмотреть состояние сети простыми словами.";
    [ObservableProperty] private string _simpleTone = "#5C7A99";
    [ObservableProperty] private Avalonia.Media.IBrush _simpleToneBrush = Ui.Brush("#5C7A99");

    [ObservableProperty] private string _traceTarget = "1.1.1.1";
    [ObservableProperty] private bool _isLoadingOverview;
    [ObservableProperty] private bool _isRunningDiagnostics;
    [ObservableProperty] private bool _isTracing;
    [ObservableProperty] private string _statusLine = "Нажмите «Обновить обзор», чтобы прочитать сетевую конфигурацию.";
    [ObservableProperty] private string _overviewRefreshed = "—";
    [ObservableProperty] private string _diagnosticsRefreshed = "диагностика ещё не запускалась";
    [ObservableProperty] private string _traceStatus = "трассировка не запускалась";
    [ObservableProperty] private string _externalIp = "—";
    [ObservableProperty] private string _externalDetails = "нет данных";
    [ObservableProperty] private string _stunText = "—";
    [ObservableProperty] private string _proxyText = "—";
    [ObservableProperty] private string _dnsText = "—";
    [ObservableProperty] private string _gatewayText = "—";
    [ObservableProperty] private string _mtuText = "—";
    [ObservableProperty] private string _adaptersCountText = "—";
    [ObservableProperty] private string _activeTab = "Овервью";

    public string[] Tabs { get; } = ["Овервью", "Диагностика", "Трассировка"];

    /// <summary>В простом режиме вкладки диагностики и трассировки скрыты.</summary>
    public bool ShowTabs => Mode.IsPro;

    public bool ShowOverview => ActiveTab == "Овервью";
    public bool ShowDiagnostics => ActiveTab == "Диагностика";
    public bool ShowTrace => ActiveTab == "Трассировка";

    partial void OnActiveTabChanged(string value)
    {
        OnPropertyChanged(nameof(ShowOverview));
        OnPropertyChanged(nameof(ShowDiagnostics));
        OnPropertyChanged(nameof(ShowTrace));
        OnPropertyChanged(nameof(ShowTechnicalOverview));
        OnPropertyChanged(nameof(ShowSimpleOverview));
    }

    [RelayCommand]
    private void SelectTab(string? tab)
    {
        if (!string.IsNullOrWhiteSpace(tab)) ActiveTab = tab;
    }

    [RelayCommand(CanExecute = nameof(CanLoadOverview))]
    private async Task RefreshOverviewAsync()
    {
        IsLoadingOverview = true;
        RefreshOverviewCommand.NotifyCanExecuteChanged();
        StatusLine = "Читаю сетевую конфигурацию...";
        try
        {
            var overview = await _service.GetOverviewAsync(_options, includeExternal: !_options.OfflineMode, CancellationToken.None)
                .ConfigureAwait(true);

            Adapters.Clear();
            foreach (var adapter in overview.ActiveAdapters.Concat(overview.Adapters.Where(a => !a.IsUp)))
                Adapters.Add(new AdapterRowViewModel(adapter));

            DefaultRoutes.Clear();
            foreach (var route in overview.DefaultRoutes.Concat(overview.Routes.Where(r => !r.IsDefault).Take(12)))
                DefaultRoutes.Add(new RouteRowViewModel(route));

            Overview.Clear();
            Overview.Add(new KeyValueRow("Внешний IP", Masking.Ip(overview.ExternalIp), overview.Country is null ? null : GeoCountries.Name(overview.Country)));
            Overview.Add(new KeyValueRow("Город / ISP", $"{overview.City ?? "—"} · {overview.Isp ?? "—"}", overview.Asn));
            Overview.Add(new KeyValueRow("UDP-выход (STUN)", Masking.Ip(overview.StunIp), "адрес, который видит NAT"));
            Overview.Add(new KeyValueRow("Прокси системы", overview.Proxy.HasProxy ? overview.Proxy.Display : "не настроен", overview.Proxy.Source));
            Overview.Add(new KeyValueRow("DNS", overview.Dns.Servers.Count == 0 ? "авто" : string.Join(", ", overview.Dns.Servers.Take(4)),
                overview.Dns.NameResolutionPolicy.Count > 0 ? $"NRPT-политик: {overview.Dns.NameResolutionPolicy.Count}" : null));
            Overview.Add(new KeyValueRow("Шлюз по умолчанию", overview.GatewaysText, overview.PrimaryAdapter?.Name));
            Overview.Add(new KeyValueRow("MTU основного интерфейса", overview.MtuText));
            Overview.Add(new KeyValueRow("Маршрутов по умолчанию", overview.DefaultRoutes.Count.ToString()));

            ExternalIp = Masking.Ip(overview.ExternalIp);
            ExternalDetails = $"{GeoCountries.Name(overview.Country)} · {overview.City ?? "—"} · {overview.Isp ?? "—"}";
            StunText = Masking.Ip(overview.StunIp);
            ProxyText = overview.Proxy.HasProxy ? overview.Proxy.Display : "не настроен";
            DnsText = overview.Dns.Servers.Count == 0 ? "авто" : string.Join(", ", overview.Dns.Servers.Take(3));
            GatewayText = overview.GatewaysText;
            MtuText = overview.MtuText;
            AdaptersCountText = $"{overview.ActiveAdapters.Count} из {overview.Adapters.Count}";
            OverviewRefreshed = $"обновлено {overview.RefreshedAt:HH:mm:ss}";
            UpdateSimpleFacts(overview);
            StatusLine = "Готово. Данные прочитаны из системы.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка чтения сетевой конфигурации");
            StatusLine = "Ошибка: " + ex.GetBaseException().Message;
        }
        finally
        {
            IsLoadingOverview = false;
            RefreshOverviewCommand.NotifyCanExecuteChanged();
        }
    }

    private void UpdateSimpleFacts(NetworkOverview overview)
    {
        SimpleFacts.Clear();

        var primary = overview.PrimaryAdapter;
        SimpleFacts.Add(new SimpleNetFact(
            "Соединение",
            primary is null ? "не найдено" : $"{primary.KindText} · {primary.Name}",
            primary is null ? "Сетевой адаптер не найден — возможно, нет подключения." : $"Адрес {primary.AddressText}",
            primary is null ? "bad" : "good"));

        var tunnels = overview.Adapters.Where(a => a.IsUp && a.Kind == AdapterKind.Tunnel).ToList();
        SimpleFacts.Add(new SimpleNetFact(
            "VPN или туннель",
            tunnels.Count == 0 ? "не найден" : "включён",
            tunnels.Count == 0 ? "Туннельных интерфейсов в системе нет." : string.Join(", ", tunnels.Select(t => t.Name)),
            tunnels.Count == 0 ? "good" : "bad"));

        SimpleFacts.Add(new SimpleNetFact(
            "Прокси",
            overview.Proxy.HasProxy ? "настроен" : "не настроен",
            overview.Proxy.HasProxy ? overview.Proxy.Display : "Системный прокси выключен.",
            overview.Proxy.HasProxy ? "bad" : "good"));

        SimpleFacts.Add(new SimpleNetFact(
            "Адрес выхода",
            overview.ExternalIp is null ? "неизвестен" : Masking.Ip(overview.ExternalIp),
            overview.Country is null
                ? "Внешний сервис не ответил — проверьте интернет или офлайн-режим."
                : $"{GeoCountries.Name(overview.Country)} · {overview.Isp ?? "провайдер неизвестен"}",
            overview.ExternalIp is null ? "warn" : "good"));

        SimpleFacts.Add(new SimpleNetFact(
            "DNS-серверы",
            overview.Dns.Servers.Count == 0 ? "автоматически" : string.Join(", ", overview.Dns.Servers.Take(2)),
            overview.Dns.HasLoopbackServer
                ? "Один из DNS — локальный (127.0.0.1): так бывает, когда DNS обслуживает VPN или прокси."
                : "Обычное разрешение имён.",
            overview.Dns.HasLoopbackServer ? "warn" : "good"));

        SimpleFacts.Add(new SimpleNetFact(
            "Размер пакета (MTU)",
            primary is null ? "—" : $"{primary.Mtu}",
            tunnels.Count > 0 && tunnels.All(t => t.Mtu is not 1500 and not 1420)
                ? "Нестандартный MTU туннеля — так обычно настраивают клиенты обхода."
                : "Стандартный размер пакета.",
            tunnels.Count > 0 && tunnels.All(t => t.Mtu is not 1500 and not 1420) ? "warn" : "good"));

        var bad = SimpleFacts.Any(f => f.IsBad);
        var odd = SimpleFacts.Count(f => !f.IsGood);

        if (bad)
        {
            SimpleSummary = "В сети есть VPN, прокси или туннель";
            SimpleTone = "#F0524C";
        }
        else if (odd > 0)
        {
            SimpleSummary = "Сеть работает обычно, но есть пара отличий от типичной настройки";
            SimpleTone = "#F5C542";
        }
        else
        {
            SimpleSummary = "Настройки сети выглядят обычным образом";
            SimpleTone = "#35C48A";
        }
        SimpleToneBrush = Ui.Brush(SimpleTone);
    }

    private bool CanLoadOverview() => !IsLoadingOverview;

    [RelayCommand(CanExecute = nameof(CanRunDiagnostics))]
    private async Task RunDiagnosticsAsync()
    {
        IsRunningDiagnostics = true;
        RunDiagnosticsCommand.NotifyCanExecuteChanged();
        var progress = new Progress<string>(text => StatusLine = text);
        try
        {
            var diagnostics = await _service.RunDiagnosticsAsync(_options, progress, CancellationToken.None).ConfigureAwait(true);
            Latency.Clear();
            foreach (var row in diagnostics.Latency) Latency.Add(row);
            Mtu.Clear();
            foreach (var row in diagnostics.Mtu) Mtu.Add(row);
            Dns.Clear();
            foreach (var row in diagnostics.Dns) Dns.Add(row);
            Tls.Clear();
            foreach (var row in diagnostics.Tls) Tls.Add(row);
            DiagnosticsRefreshed = $"диагностика завершена за {diagnostics.Duration.TotalSeconds:F1} с";
            StatusLine = "Диагностика завершена.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка диагностики");
            StatusLine = "Ошибка: " + ex.GetBaseException().Message;
        }
        finally
        {
            IsRunningDiagnostics = false;
            RunDiagnosticsCommand.NotifyCanExecuteChanged();
        }
    }

    private bool CanRunDiagnostics() => !IsRunningDiagnostics;

    [RelayCommand(CanExecute = nameof(CanTrace))]
    private async Task RunTraceAsync()
    {
        IsTracing = true;
        RunTraceCommand.NotifyCanExecuteChanged();
        CancelTraceCommand.NotifyCanExecuteChanged();
        Hops.Clear();
        _cts = new CancellationTokenSource();
        TraceStatus = $"трассировка {TraceTarget}...";
        var progress = new Progress<TraceHop>(hop =>
        {
            Hops.Add(hop);
            TraceStatus = $"хоп {hop.Index}: {hop.HostText}";
        });
        try
        {
            var result = await _service.TraceAsync(TraceTarget, _options.MaxTraceHops, progress, _cts.Token).ConfigureAwait(true);
            TraceStatus = result.Error is null
                ? $"готово за {result.Duration.TotalSeconds:F1} с · {result.Hops.Count} хопов · режим: {result.Mode}"
                : "ошибка: " + result.Error;
        }
        catch (OperationCanceledException)
        {
            TraceStatus = "трассировка отменена";
        }
        finally
        {
            IsTracing = false;
            RunTraceCommand.NotifyCanExecuteChanged();
            CancelTraceCommand.NotifyCanExecuteChanged();
            _cts?.Dispose();
            _cts = null;
        }
    }

    private bool CanTrace() => !IsTracing;

    [RelayCommand(CanExecute = nameof(CanCancelTrace))]
    private void CancelTrace() => _cts?.Cancel();

    private bool CanCancelTrace() => IsTracing;
}
