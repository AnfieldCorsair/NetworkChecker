using System.Collections.ObjectModel;
using System.Globalization;
using System.Net.Sockets;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VpnChecker.App.Startup;
using VpnChecker.Core.VpnAudit;

namespace VpnChecker.App.ViewModels;

public sealed record AdapterDisplayItem(
    string Header,
    string Details,
    string DnsText);

public sealed record PortDisplayItem(
    string PortLabel,
    string StateText,
    IBrush StateBrush);

public sealed class SniNeighborDisplayItem
{
    private static readonly IBrush CleanBrush = new SolidColorBrush(Color.Parse("#4ADE80"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
    private static readonly IBrush MutedBrush = new SolidColorBrush(Color.Parse("#9BAAC2"));

    public SniNeighborDisplayItem(
        SubnetSniNeighbor item,
        Func<string, Task> onCopy,
        Func<string, bool, Task> onApplyToConfig)
    {
        ArgumentNullException.ThrowIfNull(item);
        Domain = item.Domain;
        IpAddress = item.IpAddress;
        SourceLabel = item.SourceLabel;
        Meta = string.Create(
            CultureInfo.InvariantCulture,
            $"{item.SourceLabel} · {item.TlsProtocol} · ALPN {item.Alpn} · {(item.CertChainValid ? "Сертификат ОК" : "Ошибка серт.")} · {item.HandshakeMs} мс");
        Verdict = !string.IsNullOrWhiteSpace(item.VerdictReason)
            ? item.VerdictReason
            : (item.IsRealityReady ? "ПОДХОДИТ ДЛЯ REALITY (TLS 1.3 + h2)" : "НЕ ПОДХОДИТ ДЛЯ REALITY");
        VerdictBrush = item.IsRealityReady
            ? CleanBrush
            : (Verdict.StartsWith("ЧАСТИЧНО", StringComparison.OrdinalIgnoreCase) ? WarnBrush : MutedBrush);
        CopyCommand = new AsyncRelayCommand(() => onCopy(item.Domain));
        ApplyToSelectedNodeCommand = new AsyncRelayCommand(() => onApplyToConfig(item.Domain, true));
        ApplyToAllNodesCommand = new AsyncRelayCommand(() => onApplyToConfig(item.Domain, false));
    }

    public string Domain { get; }
    public string IpAddress { get; }
    public string SourceLabel { get; }
    public string Meta { get; }
    public string Verdict { get; }
    public IBrush VerdictBrush { get; }
    public IAsyncRelayCommand CopyCommand { get; }
    public IAsyncRelayCommand ApplyToSelectedNodeCommand { get; }
    public IAsyncRelayCommand ApplyToAllNodesCommand { get; }
}

/// <summary>
/// Вкладка 4: Нативный аудит сетевого стека Windows (TUN/MTU/DNS/IPv6/порты) и комбинированный охотник/переборщик SNI
/// (SNI из подписки + база белых доменов РФ/CDN + соседи подсети /24 с точечной врезкой в конфиг).
/// </summary>
public sealed partial class WindowsStackSniViewModel : ViewModelBase
{
    private static readonly IBrush DangerBrush = new SolidColorBrush(Color.Parse("#F87171"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
    private static readonly IBrush CleanBrush = new SolidColorBrush(Color.Parse("#4ADE80"));
    private static readonly IBrush MutedBrush = new SolidColorBrush(Color.Parse("#9BAAC2"));

    private readonly ConfigAuditViewModel _configAudit;
    private readonly IDesktopUiService _ui;

    public WindowsStackSniViewModel(ConfigAuditViewModel configAudit, IDesktopUiService ui)
    {
        _configAudit = configAudit;
        _ui = ui;
        RefreshOsStack();
    }

    public override string Title => "Сетевой стек Windows и SNI";
    public override string Subtitle => "Адаптеры · Перебор SNI · Врезка";
    public override string Description => "Проверяет настройки вашей Windows (TUN-адаптер ВПН, DNS, IPv6) и перебирает рабочие сайты прикрытия (SNI) из вашей подписки, базы белых доменов РФ и подсети /24 с врезкой в конфиг одним кликом.";
    public override string SimpleGuideText =>
        "Справа находится улучшенный перебор SNI для конфигураций: нажмите «Запустить полный перебор SNI», чтобы проверить все домены из вашей подписки, белый список РФ и соседей подсети /24, а затем нажмите «Вшить в узел и скопировать» напротив самого быстрого домена.";

    [ObservableProperty]
    public partial string OsSummary { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string TargetVpsHost { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string CustomSniDomains { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool IncludeSubscriptionSnis { get; set; } = true;

    [ObservableProperty]
    public partial bool IncludeRfWhiteList { get; set; } = true;

    [ObservableProperty]
    public partial bool IncludeSlash24 { get; set; } = true;

    [ObservableProperty]
    public partial bool IsScanningSubnet { get; set; }

    [ObservableProperty]
    public partial string SubnetStatus { get; set; } = "Отметьте нужные источники (SNI из подписки, белый список РФ, соседи /24) и нажмите «Запустить полный перебор SNI».";

    public ObservableCollection<AuditFindingDisplayItem> OsFindings { get; } = [];
    public ObservableCollection<AdapterDisplayItem> Adapters { get; } = [];
    public ObservableCollection<PortDisplayItem> LocalPorts { get; } = [];
    public ObservableCollection<SniNeighborDisplayItem> SniNeighbors { get; } = [];

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName == nameof(ShowTechnicalDetails))
        {
            foreach (var item in OsFindings)
            {
                item.IsExpanded = ShowTechnicalDetails;
            }
        }
    }

    [RelayCommand]
    private void RefreshOsStack()
    {
        var report = WindowsNetworkStackAuditor.AuditLiveOsStack();

        OsFindings.Clear();
        foreach (var f in report.Findings.OrderByDescending(x => x.Severity))
        {
            var brush = f.Severity switch
            {
                AuditSeverity.Critical => DangerBrush,
                AuditSeverity.Warning => WarnBrush,
                _ => CleanBrush,
            };
            OsFindings.Add(new AuditFindingDisplayItem(
                f.SeverityLabel,
                brush,
                f.Title,
                f.SimpleSummary,
                f.TechnicalDetail,
                f.Evidence,
                f.Remediation,
                ShowTechnicalDetails));
        }

        Adapters.Clear();
        foreach (var a in report.Adapters)
        {
            var tag = a.IsTunOrVpn ? "[ВПН-ТУННЕЛЬ]" : "[ОСНОВНАЯ СЕТЬ]";
            var header = string.Create(CultureInfo.InvariantCulture, $"{tag} {a.Name} (размер пакета MTU {a.Mtu})");
            var v4 = a.Ipv4Addresses.Count > 0 ? string.Join(", ", a.Ipv4Addresses) : "—";
            var v6 = a.Ipv6Addresses.Count > 0 ? string.Join(", ", a.Ipv6Addresses) : "отключён (безопасно)";
            var details = $"{a.Description} · IPv4: {v4} · IPv6: {v6}";

            string dns;
            if (a.DnsServers.Count > 0)
            {
                dns = $"DNS-серверы: {string.Join(", ", a.DnsServers)}";
            }
            else if (a.IsTunOrVpn)
            {
                dns = "DNS: защищённый перехват внутри ВПН-туннеля (FakeIP / DoH)";
            }
            else
            {
                dns = "DNS: автоматический от роутера";
            }

            Adapters.Add(new AdapterDisplayItem(header, details, dns));
        }

        LocalPorts.Clear();
        foreach (var p in report.LocalProxyPorts)
        {
            var label = string.Create(CultureInfo.InvariantCulture, $"Порт :{p.Port} · {p.ExpectedClient}");
            var state = p.IsListening ? $"РАБОТАЕТ ({p.BindAddress})" : "не запущен";
            LocalPorts.Add(new PortDisplayItem(label, state, p.IsListening ? CleanBrush : MutedBrush));
        }

        var tunState = report.HasActiveTunAdapter ? $"ВПН-адаптер включён ({report.ActiveTunName})" : "ВПН-адаптер (TUN) сейчас выключен";
        var dnsState = report.HasPlainIspDnsOutsideTun ? "есть риск утечки DNS" : "DNS защищён";
        var v6State = report.HasGlobalIpv6OutsideTun ? "внимание: активен IPv6 вне ВПН!" : "утечек IPv6 нет";
        var hiddenNote = report.HiddenServiceAdaptersCount > 0
            ? string.Create(CultureInfo.InvariantCulture, $" · скрыто системных адаптеров: {report.HiddenServiceAdaptersCount}")
            : string.Empty;
        OsSummary = $"{tunState} · {dnsState} · {v6State}{hiddenNote}";
    }

    [RelayCommand]
    private void FillFromActiveAudit()
    {
        var host = _configAudit.CurrentReport?.Profile.ServerHost;
        var subSnis = SubnetSniScanner.ExtractSniDomainsFromConfig(_configAudit.RawConfig);
        if (!string.IsNullOrWhiteSpace(host))
        {
            TargetVpsHost = host;
            SubnetStatus = string.Create(
                CultureInfo.InvariantCulture,
                $"Подставлен сервер из Шага 1: {host} (найдено SNI в текущей подписке: {subSnis.Count}). Нажмите «Запустить полный перебор SNI».");
        }
        else
        {
            SubnetStatus = "В текущем профиле на Шаге 1 не найден адрес сервера, но можно проверить SNI из подписки и белый список РФ.";
        }
    }

    [RelayCommand]
    private async Task ScanSubnetAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(TargetVpsHost) && !string.IsNullOrWhiteSpace(_configAudit.CurrentReport?.Profile.ServerHost))
        {
            TargetVpsHost = _configAudit.CurrentReport!.Profile.ServerHost!;
        }

        if (!IncludeSubscriptionSnis && !IncludeRfWhiteList && !IncludeSlash24 && string.IsNullOrWhiteSpace(CustomSniDomains))
        {
            SubnetStatus = "Включите хотя бы один источник перебора SNI (из подписки, белый список РФ или подсеть /24).";
            return;
        }

        IsScanningSubnet = true;
        SniNeighbors.Clear();
        SubnetStatus = "Запущен многопоточный перебор SNI (проверка TLS 1.3 + ALPN h2 + цепочка сертификата + замер пинга)...";

        try
        {
            var results = await SubnetSniScanner.HuntMultiSourceSniAsync(
                    _configAudit.RawConfig,
                    TargetVpsHost,
                    IncludeSubscriptionSnis,
                    IncludeRfWhiteList,
                    IncludeSlash24,
                    CustomSniDomains,
                    timeoutMs: 1900,
                    cancellationToken: ct)
                .ConfigureAwait(true);

            foreach (var n in results)
            {
                SniNeighbors.Add(new SniNeighborDisplayItem(n, CopySniAsync, ApplySniToConfigAsync));
            }

            var ready = results.Where(x => x.IsRealityReady).OrderBy(x => x.HandshakeMs).ToList();
            var best = ready.FirstOrDefault();
            SubnetStatus = best is not null
                ? string.Create(
                    CultureInfo.InvariantCulture,
                    $"Перебор SNI завершён: проверено {results.Count}, подходят для Reality (TLS 1.3 + h2): {ready.Count}. Лучший SNI: «{best.Domain}» ({best.HandshakeMs} мс, {best.SourceLabel}).")
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Перебор завершён: проверено кандидатов {results.Count}, подходящих под TLS 1.3 + h2 не найдено.");
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            SubnetStatus = $"Ошибка перебора SNI: {ex.Message}";
        }
        finally
        {
            IsScanningSubnet = false;
        }
    }

    private async Task CopySniAsync(string domain)
    {
        var ok = await _ui.CopyTextAsync(domain).ConfigureAwait(true);
        SubnetStatus = ok ? $"Домен прикрытия «{domain}» скопирован в буфер обмена." : "Буфер обмена недоступен.";
    }

    private async Task ApplySniToConfigAsync(string domain, bool singleNodeOnly)
    {
        var targetIdx = singleNodeOnly ? (_configAudit.SelectedNode?.Index ?? 1) : (int?)null;
        if (!SubscriptionService.TryPatchSniInConfig(
                _configAudit.RawConfig,
                domain,
                out var patchedText,
                out var summaryMessage,
                targetNodeIndex: targetIdx,
                extractSingleNodeOnly: singleNodeOnly))
        {
            SubnetStatus = summaryMessage;
            return;
        }

        if (!singleNodeOnly)
        {
            _configAudit.UpdateRawConfigFromPatcher(patchedText, summaryMessage);
        }

        var copied = await _ui.CopyTextAsync(patchedText).ConfigureAwait(true);
        SubnetStatus = copied
            ? (singleNodeOnly
                ? string.Create(CultureInfo.InvariantCulture, $"{summaryMessage} Готовый конфиг узла #{targetIdx} с новым SNI «{domain}» скопирован в буфер обмена (для вставки в Happ / v2rayN)!")
                : $"{summaryMessage} Вся обновлённая подписка с новым SNI «{domain}» скопирована в буфер обмена!")
            : summaryMessage;
    }
}
