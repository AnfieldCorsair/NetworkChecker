using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.NetInfo;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Platform;

namespace NetworkChecker.App.ViewModels;

public sealed class AdapterRowViewModel(AdapterInfo adapter)
{
    public string Name { get; } = adapter.Name;
    public string KindText { get; } = adapter.KindText;
    public string AddressText { get; } = adapter.AddressText;
    public string GatewayText { get; } = adapter.Gateways.Count == 0 ? "—" : string.Join(", ", adapter.Gateways);
    public string MtuText { get; } = adapter.Mtu.ToString(CultureInfo.InvariantCulture);
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
    public string MetricText { get; } = route.Metric.ToString(CultureInfo.InvariantCulture);
    public bool IsDefault { get; } = route.IsDefault;
}

/// <summary>Хоп для таблицы и схемы: одинаковый ASN получает одинаковый цвет.</summary>
public sealed class TraceHopViewModel(TraceHop hop)
{
    public int Index { get; } = hop.Index;
    public string HostText => hop.Address is null ? Localizer.T("нет ответа") : Masking.Ip(hop.Address);
    public bool HasPrevious => Index > 1;
    public string RttText { get; } = hop.RttText;
    public string Asn { get; } = TraceGraph.NormalizeAsn(hop.Asn) ?? "—";
    public string AsnLabel => Asn == "—" ? Localizer.T("ASN неизвестен") : Asn;
    public string AsName { get; } = string.IsNullOrWhiteSpace(hop.AsName) ? "—" : hop.AsName;
    public Avalonia.Media.IBrush AsnBrush { get; } = Ui.Brush(TraceGraph.ColorForAsn(hop.Asn));
}

public sealed class KeyValueRow(string key, string value, string? hint = null)
{
    public string Key { get; } = Localizer.T(key);
    public string Value { get; } = Localizer.T(value);
    public string? Hint { get; } = hint is null ? null : Localizer.T(hint);
}

/// <summary>Понятный факт о сети для простого режима.</summary>
public sealed class SimpleNetFact(string label, string value, string hint, string tone)
{
    public string Tone { get; } = tone;
    public bool IsGood => Tone == "good";
    public bool IsBad => Tone == "bad";
    public string Label { get; } = Localizer.T(label);
    public string Value { get; } = Localizer.T(value);
    public string Hint { get; } = Localizer.T(hint);
    public Avalonia.Media.IBrush DotBrush { get; } = Ui.Brush(tone switch
    {
        "good" => "#35C48A",
        "bad" => "#F0524C",
        _ => "#F5C542",
    });
}

public sealed partial class NetworkViewModel : ViewModelBase, IDisposable
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

    public override string Title => global::NetworkChecker.App.Localization.Localizer.T("Сеть");
    public override string Icon => global::NetworkChecker.App.Icons.Globe;
    public override string Description => global::NetworkChecker.App.Localization.Localizer.T("База, диагностика и трассировка");

    public ObservableCollection<AdapterRowViewModel> Adapters { get; } = [];
    public ObservableCollection<RouteRowViewModel> DefaultRoutes { get; } = [];
    public ObservableCollection<KeyValueRow> Overview { get; } = [];
    public ObservableCollection<HostLatency> Latency { get; } = [];
    public ObservableCollection<MtuProbe> Mtu { get; } = [];
    public ObservableCollection<DnsProbeResult> Dns { get; } = [];
    public ObservableCollection<TlsProbe> Tls { get; } = [];
    public ObservableCollection<TraceHopViewModel> Hops { get; } = [];
    public ObservableCollection<SimpleNetFact> SimpleFacts { get; } = [];

    /// <summary>Технические таблицы показываем только в подробном режиме.</summary>
    public bool ShowTechnicalOverview => ShowOverview && Mode.IsPro;
    public bool ShowSimpleOverview => Mode.IsSimple;

    [ObservableProperty]
    public partial string SimpleSummary { get; set; } = Localizer.T("Нажмите «Обновить», чтобы посмотреть состояние сети простыми словами.");

    [ObservableProperty]
    public partial string SimpleTone { get; set; } = "#5C7A99";

    [ObservableProperty]
    public partial Avalonia.Media.IBrush SimpleToneBrush { get; set; } = Ui.Brush("#5C7A99");

    [ObservableProperty] private string _traceTarget = "1.1.1.1";
    [ObservableProperty] private bool _isLoadingOverview;
    [ObservableProperty] private bool _isRunningDiagnostics;
    [ObservableProperty] private bool _isTracing;
    [ObservableProperty] private string _statusLine = Localizer.T("Нажмите «Обновить обзор», чтобы прочитать сетевую конфигурацию.");
    [ObservableProperty] private string _overviewRefreshed = "—";
    [ObservableProperty] private string _diagnosticsRefreshed = Localizer.T("диагностика ещё не запускалась");
    [ObservableProperty] private string _traceStatus = Localizer.T("трассировка не запускалась");
    [ObservableProperty] private string _externalIp = "—";
    [ObservableProperty] private string _externalDetails = Localizer.T("нет данных");
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
        StatusLine = Localizer.T("Читаю сетевую конфигурацию...");
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
            Overview.Add(new KeyValueRow("Прокси пользователя (WinINET)", overview.Proxy.HasProxy ? overview.Proxy.Display : "не обнаружен (данные могут быть неполными)", overview.Proxy.Source));
            if (overview.Proxy.HasMachineWideProxy)
                Overview.Add(new KeyValueRow("Прокси машины (WinHTTP)", overview.Proxy.WinHttpProxy!, "действует для служб и фоновых компонентов"));
            if (!string.IsNullOrWhiteSpace(overview.Proxy.PacUrl))
                Overview.Add(new KeyValueRow("PAC-файл", overview.Proxy.PacUrl, overview.Proxy.PacPointsToLocalhost ? "локальный адрес — типично для клиентов обхода" : "автоконфигурация прокси"));
            Overview.Add(new KeyValueRow("DNS", overview.Dns.Servers.Count == 0 ? "не удалось определить" : string.Join(", ", overview.Dns.Servers.Take(4)),
                overview.Dns.NameResolutionPolicy.Count > 0 ? $"NRPT-политик: {overview.Dns.NameResolutionPolicy.Count}" : null));
            Overview.Add(new KeyValueRow("Шлюз по умолчанию", overview.GatewaysText, overview.PrimaryAdapter?.Name));
            Overview.Add(new KeyValueRow("MTU основного интерфейса", overview.MtuText));
            Overview.Add(new KeyValueRow("Маршрутов по умолчанию", overview.DefaultRoutes.Count.ToString(CultureInfo.InvariantCulture)));

            ExternalIp = Masking.Ip(overview.ExternalIp);
            ExternalDetails = $"{GeoCountries.Name(overview.Country)} · {overview.City ?? "—"} · {overview.Isp ?? "—"}";
            StunText = Masking.Ip(overview.StunIp);
            ProxyText = overview.Proxy.HasProxy || overview.Proxy.HasMachineWideProxy
                ? overview.Proxy.Display
                : Localizer.T("не обнаружен (данные могут быть неполными)");
            DnsText = overview.Dns.Servers.Count == 0 ? Localizer.T("не удалось определить") : string.Join(", ", overview.Dns.Servers.Take(3));
            GatewayText = overview.GatewaysText;
            MtuText = overview.MtuText;
            AdaptersCountText = Localizer.Culture == "en-US" ? $"{overview.ActiveAdapters.Count} of {overview.Adapters.Count}" : $"{overview.ActiveAdapters.Count} из {overview.Adapters.Count}";
            OverviewRefreshed = Localizer.Culture == "en-US" ? $"updated {overview.RefreshedAt:HH:mm:ss}" : $"обновлено {overview.RefreshedAt:HH:mm:ss}";
            UpdateSimpleFacts(overview);
            StatusLine = Localizer.T("Обзор прочитан. Пустые данные не исключают ошибки доступа или недоступный компонент.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка чтения сетевой конфигурации");
            StatusLine = Localizer.T("Ошибка: ") + ex.GetBaseException().Message;
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
            primary is null ? "Сетевой адаптер не найден — возможно, нет подключения." : Localizer.Culture == "en-US" ? $"Address {primary.AddressText}" : $"Адрес {primary.AddressText}",
            primary is null ? "bad" : "good"));

        var tunnels = overview.Adapters.Where(a => a.IsUp && a.Kind == AdapterKind.Tunnel).ToList();
        SimpleFacts.Add(new SimpleNetFact(
            "VPN или туннель",
            tunnels.Count == 0 ? "не найден" : "включён",
            tunnels.Count == 0 ? "В доступном списке активные туннельные интерфейсы не найдены; это не исключает VPN." : string.Join(", ", tunnels.Select(t => t.Name)),
            tunnels.Count == 0 ? "good" : "bad"));

        var proxyAnywhere = overview.Proxy.HasProxy || overview.Proxy.HasMachineWideProxy;
        SimpleFacts.Add(new SimpleNetFact(
            "Прокси",
            proxyAnywhere ? "настроен" : "не обнаружен",
            proxyAnywhere
                ? overview.Proxy.Display
                : "В доступных источниках не найден; ошибки чтения и другие способы настройки не исключены.",
            proxyAnywhere ? "bad" : "good"));

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
            SimpleSummary = Localizer.T("В сети есть VPN, прокси или туннель");
            SimpleTone = "#F0524C";
        }
        else if (odd > 0)
        {
            SimpleSummary = Localizer.T("Сеть работает обычно, но есть пара отличий от типичной настройки");
            SimpleTone = "#F5C542";
        }
        else
        {
            SimpleSummary = Localizer.T("Настройки сети выглядят обычным образом");
            SimpleTone = "#35C48A";
        }
        SimpleToneBrush = Ui.Brush(SimpleTone);
    }

    private bool CanLoadOverview() => !IsLoadingOverview;

    [RelayCommand(CanExecute = nameof(CanRunDiagnostics))]
    private async Task RunDiagnosticsAsync()
    {
        if (_options.OfflineMode)
        {
            StatusLine = Localizer.T("Диагностика не запущена: включён офлайн-режим.");
            DiagnosticsRefreshed = Localizer.T("недоступно в офлайн-режиме");
            return;
        }
        IsRunningDiagnostics = true;
        RunDiagnosticsCommand.NotifyCanExecuteChanged();
        var progress = new Progress<string>(text => StatusLine = Localizer.T(text));
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
            DiagnosticsRefreshed = Localizer.Culture == "en-US" ? $"diagnostics completed in {diagnostics.Duration.TotalSeconds:F1} s" : $"диагностика завершена за {diagnostics.Duration.TotalSeconds:F1} с";
            StatusLine = Localizer.T("Диагностика завершена.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка диагностики");
            StatusLine = Localizer.T("Ошибка: ") + ex.GetBaseException().Message;
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
        if (_options.OfflineMode)
        {
            TraceStatus = Localizer.T("Трассировка не запущена: включён офлайн-режим.");
            return;
        }
        IsTracing = true;
        RunTraceCommand.NotifyCanExecuteChanged();
        CancelTraceCommand.NotifyCanExecuteChanged();
        Hops.Clear();
        _cts = new CancellationTokenSource();
        TraceStatus = Localizer.Culture == "en-US" ? $"tracing {TraceTarget}..." : $"трассировка {TraceTarget}...";
        try
        {
            var result = await NetworkInfoService.TraceAsync(TraceTarget, _options.MaxTraceHops, null, _cts.Token).ConfigureAwait(true);
            foreach (var hop in result.Hops) Hops.Add(new TraceHopViewModel(hop));
            TraceStatus = result.Error is null
                ? Localizer.Culture == "en-US"
                    ? $"completed in {result.Duration.TotalSeconds:F1} s · {result.Hops.Count} hops · mode: {result.Mode}"
                    : $"готово за {result.Duration.TotalSeconds:F1} с · {result.Hops.Count} хопов · режим: {result.Mode}"
                : Localizer.T("ошибка: ") + result.Error;
        }
        catch (OperationCanceledException)
        {
            TraceStatus = Localizer.T("трассировка отменена");
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

    /// <summary>Освобождает незавершённый прогон (например, при закрытии окна во время проверки).</summary>
    public void Dispose()
    {
        // Источник освобождается самой операцией в finally после завершения отмены.
        _cts?.Cancel();
    }
}
