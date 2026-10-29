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

public sealed partial class NetworkViewModel : ViewModelBase
{
    private readonly NetworkInfoService _service;
    private readonly RknOptions _options;
    private readonly ILogger<NetworkViewModel> _logger;
    private CancellationTokenSource? _cts;

    public NetworkViewModel(NetworkInfoService service, RknOptions options, ILogger<NetworkViewModel> logger)
    {
        _service = service;
        _options = options;
        _logger = logger;
        TraceTarget = options.DefaultTraceTarget;
    }

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

    public bool ShowOverview => ActiveTab == "Овервью";
    public bool ShowDiagnostics => ActiveTab == "Диагностика";
    public bool ShowTrace => ActiveTab == "Трассировка";

    partial void OnActiveTabChanged(string value)
    {
        OnPropertyChanged(nameof(ShowOverview));
        OnPropertyChanged(nameof(ShowDiagnostics));
        OnPropertyChanged(nameof(ShowTrace));
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
