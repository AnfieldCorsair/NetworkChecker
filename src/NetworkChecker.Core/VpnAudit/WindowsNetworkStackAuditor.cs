using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetworkChecker.Core.VpnAudit;

public sealed record NetworkAdapterSnapshot(
    string Name,
    string Description,
    string InterfaceType,
    bool IsUp,
    bool IsTunOrVpn,
    IReadOnlyList<string> Ipv4Addresses,
    IReadOnlyList<string> Ipv6Addresses,
    IReadOnlyList<string> DnsServers,
    IReadOnlyList<string> Gateways,
    int Mtu);

public sealed record LocalProxyPortStatus(
    int Port,
    string ExpectedClient,
    bool IsListening,
    string BindAddress);

public sealed record WindowsNetworkStackReport(
    DateTimeOffset AuditedAt,
    bool HasActiveTunAdapter,
    string? ActiveTunName,
    bool HasPlainIspDnsOutsideTun,
    bool HasGlobalIpv6OutsideTun,
    IReadOnlyList<NetworkAdapterSnapshot> Adapters,
    IReadOnlyList<LocalProxyPortStatus> LocalProxyPorts,
    IReadOnlyList<VpnAuditFinding> Findings);

/// <summary>
/// Нативный аудит сетевого стека ОС Windows (недоступный из браузера):
/// - обнаружение виртуальных интерфейсов Wintun / Sing-box TUN / WireGuard / AmneziaWG и их MTU,
/// - выявление утечек DNS на физических адаптерах мимо TUN,
/// - обнаружение глобальных маршрутов IPv6 вне туннеля,
/// - проверка занятости локальных портов прокси (10808, 10809, 2080, 7890).
/// </summary>
public static class WindowsNetworkStackAuditor
{
    private static readonly (int Port, string Label)[] KnownProxyPorts =
    [
        (10808, "v2rayN / Xray SOCKS5"),
        (10809, "v2rayN / Xray HTTP"),
        (2080, "Sing-box / NekoBox Mixed"),
        (7890, "Clash / Mihomo Mixed"),
        (1080, "Standard SOCKS5"),
    ];

    private static readonly string[] TunKeywords =
    [
        "wintun",
        "sing-box",
        "tun",
        "wireguard",
        "amnezia",
        "hiddify",
        "nekobox",
        "tap-windows",
    ];

    public static WindowsNetworkStackReport AuditLiveOsStack()
    {
        var adapters = new List<NetworkAdapterSnapshot>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            IPInterfaceProperties ipProps;
            try
            {
                ipProps = nic.GetIPProperties();
            }
            catch
            {
                continue;
            }

            var isUp = nic.OperationalStatus == OperationalStatus.Up;
            var combinedName = $"{nic.Name} {nic.Description}".ToLowerInvariant();
            var isTun = nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Ppp ||
                        TunKeywords.Any(k => combinedName.Contains(k, StringComparison.Ordinal));

            var ipv4 = ipProps.UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(u => u.Address.ToString())
                .ToList();

            var ipv6 = ipProps.UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                            !u.Address.IsIPv6LinkLocal)
                .Select(u => u.Address.ToString())
                .ToList();

            var dns = ipProps.DnsAddresses
                .Select(d => d.ToString())
                .ToList();

            var gateways = ipProps.GatewayAddresses
                .Where(g => g.Address is not null && !g.Address.Equals(IPAddress.Any))
                .Select(g => g.Address.ToString())
                .ToList();

            var mtu = 1500;
            try
            {
                mtu = ipProps.GetIPv4Properties()?.Mtu ?? 1500;
            }
            catch
            {
                // ignore if IPv4 properties unavailable
            }

            adapters.Add(new NetworkAdapterSnapshot(
                nic.Name,
                nic.Description,
                nic.NetworkInterfaceType.ToString(),
                isUp,
                isTun,
                ipv4,
                ipv6,
                dns,
                gateways,
                mtu));
        }

        var activeListeners = Array.Empty<IPEndPoint>();
        try
        {
            activeListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
        }
        catch
        {
            // ignore permission issues
        }

        var portStatuses = KnownProxyPorts
            .Select(kp =>
            {
                var match = activeListeners.FirstOrDefault(ep => ep.Port == kp.Port);
                return new LocalProxyPortStatus(
                    kp.Port,
                    kp.Label,
                    match is not null,
                    match?.Address.ToString() ?? "—");
            })
            .ToList();

        return EvaluateSnapshots(adapters, portStatuses);
    }

    public static WindowsNetworkStackReport EvaluateSnapshots(
        IReadOnlyList<NetworkAdapterSnapshot> adapters,
        IReadOnlyList<LocalProxyPortStatus> localPorts)
    {
        var findings = new List<VpnAuditFinding>();
        var activeTuns = adapters.Where(a => a.IsUp && a.IsTunOrVpn).ToList();
        var activePhysical = adapters.Where(a => a.IsUp && !a.IsTunOrVpn && a.Gateways.Count > 0).ToList();

        var hasActiveTun = activeTuns.Count > 0;
        var activeTunName = activeTuns.FirstOrDefault()?.Name;

        if (hasActiveTun)
        {
            var tun = activeTuns[0];
            findings.Add(new VpnAuditFinding(
                "os-tun-active",
                AuditCategory.TransportDpi,
                AuditSeverity.Ok,
                $"Активен виртуальный TUN-адаптер ({tun.Name}, MTU {tun.Mtu})",
                "Весь трафик системы перехватывается на уровне сетевого интерфейса L3.",
                $"Интерфейс: {tun.Description}, IPv4: {string.Join(", ", tun.Ipv4Addresses)}, DNS: {string.Join(", ", tun.DnsServers)}",
                $"MTU={tun.Mtu}",
                "Для сетей с ТСПУ и PPPoE/LTE рекомендуется держать MTU на TUN-интерфейсе в пределах 1280–1400."));

            if (tun.Mtu > 1420)
            {
                findings.Add(new VpnAuditFinding(
                    "os-tun-high-mtu",
                    AuditCategory.TransportDpi,
                    AuditSeverity.Warning,
                    $"Завышенный MTU ({tun.Mtu}) на TUN-интерфейсе {tun.Name}",
                    "При инкапсуляции VLESS/AmneziaWG возможна фрагментация пакетов и зависание загрузки больших страниц.",
                    $"Текущий MTU={tun.Mtu} превышает безопасный порог 1400 байт.",
                    $"MTU={tun.Mtu}",
                    "Укажите \"mtu\": 1400 в секции tun inbound Sing-box или MTU = 1280 в конфиге AmneziaWG."));
            }
        }
        else
        {
            findings.Add(new VpnAuditFinding(
                "os-no-tun",
                AuditCategory.Routing,
                AuditSeverity.Warning,
                "Активный TUN/Wintun-интерфейс не обнаружен",
                "Клиент работает в режиме системного HTTP/SOCKS-прокси или ВПН сейчас выключен.",
                "В режиме системного прокси приложения, игнорирующие настройки WinINET (игры, торренты, STUN/UDP), идут напрямую мимо ВПН.",
                "Active TUN = 0",
                "Включите режим TUN (Sing-box / NekoBox / v2rayN Enable Tun) для перехвата всего UDP и TCP трафика ОС."));
        }

        // Проверка утечки DNS на физических интерфейсах
        var hasPlainIspDnsOutsideTun = activePhysical.Any(a =>
            a.DnsServers.Any(ip =>
                !ip.StartsWith("198.18.", StringComparison.Ordinal) &&
                !ip.StartsWith("172.19.", StringComparison.Ordinal) &&
                !ip.StartsWith("127.", StringComparison.Ordinal)));

        if (hasActiveTun && hasPlainIspDnsOutsideTun)
        {
            var leakedDns = string.Join(", ", activePhysical.SelectMany(a => a.DnsServers).Distinct());
            findings.Add(new VpnAuditFinding(
                "os-dns-leak-risk",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "На физическом адаптере Windows сохранены внешние/провайдерские DNS",
                "Без правила hijack-dns (Sing-box) или block-outside-dns (OpenVPN) сервис Smart Multi-Homed Name Resolution (SMHNR) в Windows отправляет DNS-запросы параллельно во все адаптеры.",
                $"DNS физического адаптера: {leakedDns}",
                leakedDns,
                "Убедитесь, что в Sing-box включены strict_route: true и правило action: \"hijack-dns\" для протокола dns."));
        }

        // Проверка глобального IPv6 вне TUN
        var hasGlobalIpv6OutsideTun = activePhysical.Any(a => a.Ipv6Addresses.Count > 0);
        if (hasGlobalIpv6OutsideTun)
        {
            var v6List = string.Join(", ", activePhysical.SelectMany(a => a.Ipv6Addresses));
            findings.Add(new VpnAuditFinding(
                "os-ipv6-outside-tun",
                AuditCategory.Leaks,
                AuditSeverity.Critical,
                "Обнаружен глобальный IPv6-адрес на физическом интерфейсе вне ВПН",
                "Браузеры по алгоритму Happy Eyeballs (RFC 8305) могут отправлять трафик по IPv6 напрямую через провайдера в обход IPv4-туннеля.",
                $"Глобальные IPv6 на физическом адаптере: {v6List}",
                v6List,
                "Добавьте ::/0 в маршрут TUN-интерфейса или установите strategy: \"ipv4_only\" в настройках DNS/Inbound."));
        }

        // Проверка локальных портов прокси
        var activePorts = localPorts.Where(p => p.IsListening).ToList();
        if (activePorts.Count > 0)
        {
            var summary = string.Join(", ", activePorts.Select(p => $"{p.Port} ({p.ExpectedClient})"));
            findings.Add(new VpnAuditFinding(
                "os-local-proxy-ports",
                AuditCategory.Routing,
                AuditSeverity.Ok,
                $"Обнаружены активные локальные прокси-сокеты: {summary}",
                "Локальное ядро прокси принимает подключения.",
                $"Слушающие порты: {summary}",
                summary,
                "Если запускаете второй клиент параллельно, следите за отсутствием конфликта портов (EADDRINUSE)."));
        }

        return new WindowsNetworkStackReport(
            DateTimeOffset.UtcNow,
            hasActiveTun,
            activeTunName,
            hasPlainIspDnsOutsideTun,
            hasGlobalIpv6OutsideTun,
            adapters,
            localPorts,
            findings);
    }
}
