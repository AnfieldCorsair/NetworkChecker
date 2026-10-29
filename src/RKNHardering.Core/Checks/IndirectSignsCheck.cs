using System.Diagnostics;
using System.Net;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Core.Platform;

namespace RKNHardering.Core.Checks;

/// <summary>
/// Косвенные признаки: интерфейсы, маршруты по умолчанию, DNS (включая split-DNS),
/// hosts-файл, MTU туннелей. Аналог IndirectSignsChecker (Android).
/// </summary>
public sealed class IndirectSignsCheck : ICheck
{
    private readonly IPlatformProbe _platform;

    public IndirectSignsCheck(IPlatformProbe platform) => _platform = platform;

    public CheckCategory Category => CheckCategory.IndirectSigns;
    public string Title => "Косвенные признаки";
    public string Subtitle => "Интерфейсы, маршруты, DNS, MTU, hosts";
    public int Weight => 20;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();

        var adapters = await _platform.GetAdaptersAsync(ct).ConfigureAwait(false);
        var routes = await _platform.GetRoutesAsync(ct).ConfigureAwait(false);
        var dns = await _platform.GetDnsConfigurationAsync(ct).ConfigureAwait(false);
        var hosts = await _platform.GetHostsEntriesAsync(ct).ConfigureAwait(false);

        // --- адаптеры и подозрительные имена ---
        var suspiciousAdapters = adapters
            .Where(a => a.IsUp && (a.Kind == Models.AdapterKind.Tunnel || InterfaceNaming.IsVpnLikeName(a.Name)))
            .ToList();
        metrics.Add(new Metric("Активных интерфейсов", adapters.Count(a => a.IsUp).ToString(),
            string.Join(", ", adapters.Where(a => a.IsUp).Select(a => a.Name).Take(6))));
        foreach (var adapter in suspiciousAdapters)
        {
            findings.Add(Finding.Critical(
                $"Интерфейс с VPN-подобным именем: {adapter.Name}",
                $"MTU {adapter.Mtu}, {adapter.AddressText}. Методика считает такие имена признаком туннеля.",
                adapter.Description));
        }

        var oddMtu = adapters.Where(a => a.IsUp && a.Kind == Models.AdapterKind.Tunnel && a.Mtu is > 0 and not 1500).ToList();
        foreach (var adapter in oddMtu)
        {
            findings.Add(Finding.Notice(
                $"Нетипичный MTU туннеля: {adapter.Mtu}",
                "Стандартный MTU туннеля — 1500 или 1420. Значения 1280/1300/9000 часто выдают конкретный клиент.",
                adapter.Name));
        }

        // --- маршруты по умолчанию ---
        var defaultRoutes = routes.Where(r => r.IsDefault).ToList();
        metrics.Add(new Metric("Маршрутов по умолчанию", defaultRoutes.Count.ToString(),
            string.Join(", ", defaultRoutes.Select(r => r.InterfaceName).Where(n => n is not null))));
        var tunnelDefault = defaultRoutes.FirstOrDefault(r =>
            r.InterfaceName is not null && suspiciousAdapters.Any(a => a.Name == r.InterfaceName));
        if (tunnelDefault is not null)
        {
            findings.Add(Finding.Critical(
                $"Маршрут по умолчанию идёт через {tunnelDefault.InterfaceName}",
                "Весь трафик направлен в туннель — полный перехват, а не выборочный.",
                $"gateway={tunnelDefault.Gateway}, metric={tunnelDefault.Metric}"));
        }

        // «подозрительный» шлюз в локальной сети: /32 host route — типовой приём tun2socks
        var hostRoutes = routes.Where(r => r.Destination.EndsWith("/32", StringComparison.Ordinal) ||
                                           (r.Destination.Count(c => c == '.') == 3 && r.Gateway is not null)).ToList();
        if (hostRoutes.Count > 0)
        {
            findings.Add(Finding.Notice(
                $"Хостовые маршруты /32 ({hostRoutes.Count})",
                "Маршруты на отдельные адреса — типовой способ завернуть трафик в локальный прокси.",
                string.Join("; ", hostRoutes.Take(5).Select(r => $"{r.Destination} → {r.Gateway} ({r.InterfaceName})"))));
        }

        // --- DNS ---
        var dnsServers = dns.Servers.Concat(adapters.SelectMany(a => a.DnsServers)).Distinct().ToList();
        metrics.Add(new Metric("DNS-серверы", dnsServers.Count == 0 ? "авто" : string.Join(", ", dnsServers.Take(4)),
            dns.NameResolutionPolicy.Count > 0 ? "есть NRPT-политики" : null));
        var loopbackDns = dnsServers.Where(DnsConfiguration.IsLoopback).ToList();
        if (loopbackDns.Count > 0)
        {
            findings.Add(Finding.Critical(
                "DNS указывает на loopback",
                "Локальный DNS-резолвер (127.0.0.1 или ::1) — признак локального прокси/DNS-туннеля.",
                string.Join(", ", loopbackDns)));
        }

        var privateDns = dnsServers.Where(DnsConfiguration.IsPrivate).Except(loopbackDns).ToList();
        if (privateDns.Count > 0)
        {
            findings.Add(Finding.Notice("Приватные DNS-серверы",
                "Резолвер в локальной сети может быть перехватчиком DNS.", string.Join(", ", privateDns)));
        }

        var tunnelDns = adapters.Where(a => a.Kind == Models.AdapterKind.Tunnel).SelectMany(a => a.DnsServers).Distinct().ToList();
        if (tunnelDns.Count > 0)
        {
            findings.Add(Finding.Warning("DNS туннеля перекрывает системный",
                "Туннельный адаптер публикует собственные DNS-серверы — трафик резолвинга идёт внутрь туннеля.",
                string.Join(", ", tunnelDns)));
        }
        if (dns.NameResolutionPolicy.Count > 0)
        {
            findings.Add(Finding.Notice("Настроены NRPT-политики (split DNS)",
                "Windows разрешает часть доменов через отдельный резолвер — типично для корпоративных и VPN-профилей.",
                string.Join("; ", dns.NameResolutionPolicy.Take(4))));
        }

        // --- hosts ---
        var suspiciousHosts = hosts.Where(h => !IsBenignHostsEntry(h)).ToList();
        metrics.Add(new Metric("Записей в hosts", hosts.Count.ToString(),
            suspiciousHosts.Count == 0 ? "только стандартные" : $"{suspiciousHosts.Count} нестандартных"));
        if (suspiciousHosts.Count > 0)
        {
            findings.Add(Finding.Notice(
                $"Нестандартные записи в hosts ({suspiciousHosts.Count})",
                "Перенаправление доменов через hosts часто используется для блокировки телеметрии или подмены резолвинга.",
                string.Join("; ", suspiciousHosts.Take(5).Select(h => $"{h.Address} {h.HostName}"))));
        }

        // --- подозрительные виртуальные адаптеры ---
        var virtualAdapters = adapters.Where(a => a.IsUp && a.Kind == Models.AdapterKind.Virtual).ToList();
        if (virtualAdapters.Count > 0)
        {
            findings.Add(Finding.Notice($"Активны виртуальные адаптеры ({virtualAdapters.Count})",
                "Виртуальные адаптеры сами по себе не признак обхода, но используются tun2socks-схемами.",
                string.Join(", ", virtualAdapters.Select(a => a.Name).Take(5))));
        }

        var detected = findings.Any(f => f.Severity == Severity.Critical);
        var review = findings.Any(f => f.Severity is Severity.Warning or Severity.Notice);

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = detected ? CheckStatus.Detected : review ? CheckStatus.NeedsReview : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }

    private static bool IsBenignHostsEntry(HostsEntry entry)
    {
        if (entry.Comment is not null && entry.Comment.Contains("RKNHardering", StringComparison.OrdinalIgnoreCase)) return true;
        if (entry.Address is "127.0.0.1" or "::1" or "0.0.0.0")
        {
            return entry.HostName.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                   || entry.HostName.EndsWith(".local", StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }
}

/// <summary>Эвристики имён сетевых интерфейсов (порт NetworkInterfacePatterns с Android-версии).</summary>
public static class InterfaceNaming
{
    private static readonly string[] TunnelPrefixes =
    [
        "tun", "tap", "wg", "utun", "ppp", "ipsec", "wireguard", "nordlynx", "proton",
        "wintun", "sing", "clash", "mihomo", "v2ray", "xray", "nekoray", "outline",
        "amnezia", "warp", "tailscale", "zerotier", "hamachi", "openvpn", "softether",
        "vpn", "sstp", "l2tp", "ikev2", "shadowsocks", "hiddify", "dummy",
    ];

    private static readonly string[] VirtualHints =
    [
        "virtual", "vmware", "hyper-v", "vethernet", "docker", "loopback adapter",
        "npcap", "tap-windows", "wsl",
    ];

    private static readonly string[] CellularHints = ["cellular", "wwan", "mobile", "lte", "4g", "5g", "modem"];

    public static bool IsVpnLikeName(string name) =>
        TunnelPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase) ||
                                name.Contains(p, StringComparison.OrdinalIgnoreCase));

    public static bool IsVirtualName(string name) =>
        VirtualHints.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase));

    public static bool IsCellularName(string name) =>
        CellularHints.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase));
}
