using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

public sealed record AdapterDisplayItem(
    string Header,
    string Details,
    string DnsText);

public sealed record PortDisplayItem(
    string PortLabel,
    string StateText);

public sealed class SniNeighborDisplayItem
{
    public SniNeighborDisplayItem(SubnetSniNeighbor item, Func<string, Task> onCopy)
    {
        Domain = item.Domain;
        IpAddress = item.IpAddress;
        Meta = string.Create(
            CultureInfo.InvariantCulture,
            $"{item.TlsProtocol} · ALPN {item.Alpn} · {(item.CertChainValid ? "Cert OK" : "Cert err")} · {item.HandshakeMs} мс");
        Verdict = item.IsRealityReady ? "REALITY READY" : "НЕ ПОДХОДИТ";
        CopyCommand = new AsyncRelayCommand(() => onCopy(item.Domain));
    }

    public string Domain { get; }
    public string IpAddress { get; }
    public string Meta { get; }
    public string Verdict { get; }
    public IAsyncRelayCommand CopyCommand { get; }
}

/// <summary>
/// Вкладка 4: Нативный аудит сетевого стека Windows (TUN/MTU/DNS/IPv6/порты) и сканер соседей SNI в подсети /24.
/// </summary>
public sealed partial class WindowsStackSniViewModel : ViewModelBase
{
    private readonly ConfigAuditViewModel _configAudit;
    private readonly IDesktopUiService _ui;

    public WindowsStackSniViewModel(ConfigAuditViewModel configAudit, IDesktopUiService ui)
    {
        _configAudit = configAudit;
        _ui = ui;
        RefreshOsStack();
    }

    public override string Title => "Стек ОС и /24 SNI";
    public override string Subtitle => "Wintun · DNS · Подсеть /24";
    public override string Description => "Низкоуровневый аудит сетевого стека Windows (недоступный из браузера) и многопоточный поиск «родного» Reality SNI среди соседей VPS в подсети /24.";

    [ObservableProperty]
    public partial string OsSummary { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string TargetVpsHost { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool IsScanningSubnet { get; set; }

    [ObservableProperty]
    public partial string SubnetStatus { get; set; } = "Введите публичный IP или домен вашего VPS, чтобы найти соседние серверы с TLS 1.3 + ALPN h2 в той же подсети /24.";

    public ObservableCollection<VpnAuditFinding> OsFindings { get; } = [];
    public ObservableCollection<AdapterDisplayItem> Adapters { get; } = [];
    public ObservableCollection<PortDisplayItem> LocalPorts { get; } = [];
    public ObservableCollection<SniNeighborDisplayItem> SniNeighbors { get; } = [];

    [RelayCommand]
    private void RefreshOsStack()
    {
        var report = WindowsNetworkStackAuditor.AuditLiveOsStack();

        OsFindings.Clear();
        foreach (var f in report.Findings.OrderByDescending(x => x.Severity))
        {
            OsFindings.Add(f);
        }

        Adapters.Clear();
        foreach (var a in report.Adapters.Where(x => x.IsUp))
        {
            var tag = a.IsTunOrVpn ? "[TUN/VPN]" : "[ФИЗ]";
            var header = string.Create(CultureInfo.InvariantCulture, $"{tag} {a.Name} (MTU {a.Mtu})");
            var v4 = a.Ipv4Addresses.Count > 0 ? string.Join(", ", a.Ipv4Addresses) : "нет";
            var v6 = a.Ipv6Addresses.Count > 0 ? string.Join(", ", a.Ipv6Addresses) : "нет";
            var details = $"{a.Description} · IPv4: {v4} · IPv6: {v6}";
            var dns = a.DnsServers.Count > 0 ? $"DNS: {string.Join(", ", a.DnsServers)}" : "DNS: не задан";
            Adapters.Add(new AdapterDisplayItem(header, details, dns));
        }

        LocalPorts.Clear();
        foreach (var p in report.LocalProxyPorts)
        {
            var label = string.Create(CultureInfo.InvariantCulture, $":{p.Port} · {p.ExpectedClient}");
            var state = p.IsListening ? $"СЛУШАЕТ ({p.BindAddress})" : "свободен";
            LocalPorts.Add(new PortDisplayItem(label, state));
        }

        var tunState = report.HasActiveTunAdapter ? $"TUN активен ({report.ActiveTunName})" : "TUN не найден";
        var dnsState = report.HasPlainIspDnsOutsideTun ? "риск SMHNR DNS" : "DNS в норме";
        var v6State = report.HasGlobalIpv6OutsideTun ? "глобальный IPv6 вне TUN!" : "IPv6 под контролем";
        OsSummary = $"{tunState} · {dnsState} · {v6State}";
    }

    [RelayCommand]
    private void FillFromActiveAudit()
    {
        var host = _configAudit.CurrentReport?.Profile.ServerHost;
        if (!string.IsNullOrWhiteSpace(host))
        {
            TargetVpsHost = host;
            SubnetStatus = $"Подставлен хост из вкладки «Аудит и подписки»: {host}";
        }
        else
        {
            SubnetStatus = "В текущем профиле аудита не указан хост сервера.";
        }
    }

    [RelayCommand]
    private async Task ScanSubnetAsync(CancellationToken ct)
    {
        var input = TargetVpsHost.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            SubnetStatus = "Введите публичный IPv4 или домен вашего VPS.";
            return;
        }

        IsScanningSubnet = true;
        SniNeighbors.Clear();
        SubnetStatus = $"Определение IPv4 и сканирование до 48 соседей в подсети /24 для {input}...";

        try
        {
            string? targetIpv4 = null;
            if (IPAddress.TryParse(input, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork)
            {
                targetIpv4 = parsed.ToString();
            }
            else
            {
                var resolved = await Dns.GetHostAddressesAsync(input, ct).ConfigureAwait(true);
                targetIpv4 = resolved.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();
            }

            if (string.IsNullOrWhiteSpace(targetIpv4))
            {
                SubnetStatus = "Не удалось получить публичный IPv4 для указанного хоста.";
                return;
            }

            var neighbors = await SubnetSniScanner
                .ScanSlash24Async(targetIpv4, maxHosts: 48, concurrency: 16, timeoutMs: 1800, cancellationToken: ct)
                .ConfigureAwait(true);

            foreach (var n in neighbors)
            {
                SniNeighbors.Add(new SniNeighborDisplayItem(n, CopySniAsync));
            }

            var readyCount = neighbors.Count(x => x.IsRealityReady);
            SubnetStatus = neighbors.Count == 0
                ? $"Для {targetIpv4}/24 соседей с открытым :443 TLS не найдено (либо передан приватный IP)."
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Сканирование {targetIpv4}/24 завершено: найдено доменов {neighbors.Count}, готовых для Reality (TLS 1.3 + h2): {readyCount}.");
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            SubnetStatus = $"Ошибка сканирования подсети: {ex.Message}";
        }
        finally
        {
            IsScanningSubnet = false;
        }
    }

    private async Task CopySniAsync(string domain)
    {
        var ok = await _ui.CopyTextAsync(domain).ConfigureAwait(true);
        SubnetStatus = ok ? $"SNI «{domain}» скопирован в буфер обмена." : "Буфер обмена недоступен.";
    }
}
