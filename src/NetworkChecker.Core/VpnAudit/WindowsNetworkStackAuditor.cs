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
    IReadOnlyList<VpnAuditFinding> Findings,
    int HiddenServiceAdaptersCount = 0);

/// <summary>
/// Нативный аудит сетевого стека ОС Windows (недоступный из браузера):
/// - обнаружение виртуальных интерфейсов Wintun / Sing-box TUN / WireGuard / AmneziaWG и их MTU,
/// - фильтрация служебных интерфейсов (WSL / Hyper-V / Bluetooth) и фиктивных Windows DNS-заглушек fec0:0:0:ffff::,
/// - выявление утечек DNS на физических адаптерах мимо TUN (SMHNR),
/// - точное обнаружение глобальных маршрутов IPv6 (2000::/3) вне туннеля,
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
        "outline",
        "xray",
        "v2ray",
    ];

    private static readonly string[] ServiceNoiseKeywords =
    [
        "bluetooth",
        "hyper-v",
        "vethernet",
        "wsl",
        "vmware",
        "virtualbox",
        "teredo",
        "isatap",
        "6to4",
        "km-test",
        "loopback",
        "npcap",
    ];

    public static WindowsNetworkStackReport AuditLiveOsStack()
    {
        var adapters = new List<NetworkAdapterSnapshot>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.IsReceiveOnly)
            {
                continue;
            }

            IPInterfaceProperties ipProps;
            try
            {
                ipProps = nic.GetIPProperties();
            }
            catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException or NotSupportedException or UnauthorizedAccessException)
            {
                continue;
            }

            var isUp = nic.OperationalStatus == OperationalStatus.Up;
            var combinedName = $"{nic.Name} {nic.Description}".ToLowerInvariant();
            var isTun = nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Ppp ||
                        TunKeywords.Any(k => combinedName.Contains(k, StringComparison.Ordinal));

            var ipv4 = ipProps.UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork &&
                            !IPAddress.IsLoopback(u.Address))
                .Select(u => u.Address.ToString())
                .ToList();

            // Учитываем только глобальные маршрутизируемые IPv6 (2000::/3), отсекая link-local fe80:: и локальные ULA fd00::/fc00::
            var ipv6 = ipProps.UnicastAddresses
                .Where(u => IsGlobalUnicastIpv6(u.Address))
                .Select(u => u.Address.ToString())
                .ToList();

            // Отфильтровываем фиктивные Windows IPv6 site-local DNS-заглушки (fec0:0:0:ffff::1..3)
            var dns = ipProps.DnsAddresses
                .Where(d => !IsWindowsFakeSiteLocalDns(d))
                .Select(d => d.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var gateways = ipProps.GatewayAddresses
                .Where(g => g.Address is not null &&
                            !g.Address.Equals(IPAddress.Any) &&
                            !g.Address.Equals(IPAddress.IPv6Any))
                .Select(g => g.Address.ToString())
                .ToList();

            var mtu = 1500;
            try
            {
                mtu = ipProps.GetIPv4Properties()?.Mtu ?? 1500;
            }
            catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException or NotSupportedException or InvalidOperationException)
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
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException or NotSupportedException or UnauthorizedAccessException)
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

        // Отделяем реальные рабочие адаптеры (TUN/VPN или активные с шлюзом/IPv4) от служебных (WSL, Hyper-V, Bluetooth)
        var relevantAdapters = new List<NetworkAdapterSnapshot>();
        var hiddenServiceCount = 0;

        foreach (var adapter in adapters)
        {
            if (!adapter.IsUp) continue;

            var combined = $"{adapter.Name} {adapter.Description}".ToLowerInvariant();
            var isNoise = !adapter.IsTunOrVpn &&
                          adapter.Gateways.Count == 0 &&
                          (ServiceNoiseKeywords.Any(k => combined.Contains(k, StringComparison.Ordinal)) ||
                           (adapter.DnsServers.Count == 0 && adapter.Ipv6Addresses.Count == 0));

            if (isNoise)
            {
                hiddenServiceCount++;
                continue;
            }

            relevantAdapters.Add(adapter);
        }

        var activeTuns = relevantAdapters.Where(a => a.IsTunOrVpn).ToList();
        var activePhysical = relevantAdapters.Where(a => !a.IsTunOrVpn && a.Gateways.Count > 0).ToList();

        var hasActiveTun = activeTuns.Count > 0;
        var activeTunName = activeTuns.FirstOrDefault()?.Name;

        if (hasActiveTun)
        {
            var tun = activeTuns[0];
            var tunDnsText = tun.DnsServers.Count > 0
                ? string.Join(", ", tun.DnsServers)
                : "перехват через TUN (hijack-dns / FakeIP)";

            findings.Add(new VpnAuditFinding(
                "os-tun-active",
                AuditCategory.TransportDpi,
                AuditSeverity.Ok,
                $"Активен виртуальный TUN-адаптер ({tun.Name}, MTU {tun.Mtu})",
                "Весь трафик системы перехватывается на уровне сетевого интерфейса L3.",
                $"Интерфейс: {tun.Description}, IPv4: {(tun.Ipv4Addresses.Count > 0 ? string.Join(", ", tun.Ipv4Addresses) : "—")}, DNS: {tunDnsText}",
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

        // Проверка утечки DNS на физических интерфейсах (с фильтрацией заглушек fec0::)
        var cleanedPhysicalDns = activePhysical
            .SelectMany(a => a.DnsServers)
            .Where(ip => !ip.StartsWith("fec0:", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var hasPlainIspDnsOutsideTun = cleanedPhysicalDns.Any(ip =>
            !ip.StartsWith("198.18.", StringComparison.Ordinal) &&
            !ip.StartsWith("172.19.", StringComparison.Ordinal) &&
            !ip.StartsWith("127.", StringComparison.Ordinal) &&
            !string.Equals(ip, "::1", StringComparison.Ordinal));

        if (hasActiveTun && hasPlainIspDnsOutsideTun)
        {
            var leakedDns = string.Join(", ", cleanedPhysicalDns);
            findings.Add(new VpnAuditFinding(
                "os-dns-leak-risk",
                AuditCategory.Leaks,
                AuditSeverity.Warning,
                "На физическом адаптере Windows сохранены внешние/провайдерские DNS",
                "Без правила hijack-dns (Sing-box) или block-outside-dns сервис Smart Multi-Homed Name Resolution (SMHNR) в Windows отправляет DNS-запросы параллельно во все адаптеры.",
                $"DNS физического адаптера: {leakedDns}",
                leakedDns,
                "Убедитесь, что в Sing-box включены strict_route: true и правило action: \"hijack-dns\" для протокола dns."));
        }

        // Проверка глобального маршрутизируемого IPv6 вне TUN (игнорируя ULA fd00::/fc00:: и link-local fe80::)
        var globalV6List = activePhysical
            .SelectMany(a => a.Ipv6Addresses)
            .Where(addrStr => IPAddress.TryParse(addrStr, out var parsed) && IsGlobalUnicastIpv6(parsed))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var hasGlobalIpv6OutsideTun = globalV6List.Count > 0;
        if (hasGlobalIpv6OutsideTun)
        {
            var v6List = string.Join(", ", globalV6List);
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
            relevantAdapters,
            localPorts,
            findings,
            hiddenServiceCount);
    }

    public static bool IsGlobalUnicastIpv6(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal || IPAddress.IsLoopback(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        // Глобальный Unicast IPv6 по RFC 4291: диапазон 2000::/3 (старшие 3 бита == 001)
        return bytes.Length == 16 && (bytes[0] & 0xE0) == 0x20;
    }

    public static bool IsWindowsFakeSiteLocalDns(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        // Windows подставляет fec0:0:0:ffff::1..3, когда IPv6 DNS на интерфейсе не настроен
        return address.ToString().StartsWith("fec0:0:0:ffff::", StringComparison.OrdinalIgnoreCase);
    }
}
