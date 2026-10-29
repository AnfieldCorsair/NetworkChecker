using System.Diagnostics;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Options;
using RKNHardering.Core.Platform;

namespace RKNHardering.Core.Checks;

/// <summary>
/// Прямые признаки на ПК: системный прокси, TUN/TAP-адаптеры, VPN-подключения ОС,
/// запущенные клиенты обхода, установленные приложения и правила файрвола (kill switch).
/// Аналог DirectSignsChecker (Android: NetworkCapabilities, VpnService, список пакетов).
/// </summary>
public sealed class DirectSignsCheck : ICheck
{
    private readonly IPlatformProbe _platform;
    private readonly VpnClientCatalog _catalog;

    public DirectSignsCheck(IPlatformProbe platform, VpnClientCatalog catalog)
    {
        _platform = platform;
        _catalog = catalog;
    }

    public CheckCategory Category => CheckCategory.DirectSigns;
    public string Title => "Прямые признаки";
    public string Subtitle => "Прокси в системе, TUN-адаптеры, VPN-профили, запущенные клиенты";
    public int Weight => 30;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();

        var proxy = await _platform.GetSystemProxyAsync(ct).ConfigureAwait(false);
        var adapters = await _platform.GetAdaptersAsync(ct).ConfigureAwait(false);
        var apps = await _platform.GetInstalledAppsAsync(ct).ConfigureAwait(false);
        var processes = await _platform.GetSuspiciousProcessesAsync(ct).ConfigureAwait(false);
        var connections = await _platform.GetVpnConnectionsAsync(ct).ConfigureAwait(false);
        var services = await _platform.GetTunnelServicesAsync(ct).ConfigureAwait(false);
        var firewall = await _platform.GetFirewallRulesAsync(ct).ConfigureAwait(false);

        // --- системный прокси ---
        metrics.Add(new Metric("Системный прокси", proxy.HasProxy ? proxy.Display : "не настроен", proxy.Source));
        if (proxy.HasProxy)
        {
            var detail = proxy.PacUrl is not null
                ? $"Задан PAC-файл: {proxy.PacUrl}"
                : "В системе задан прокси-сервер (WinINET/WinHTTP/переменные окружения).";
            findings.Add(Finding.Critical("Системный прокси включён", detail,
                $"{proxy.HttpProxy ?? proxy.SocksProxy} {proxy.BypassList}".Trim()));
        }
        else
        {
            findings.Add(Finding.Info("Системный прокси не настроен"));
        }

        // --- TUN/TAP-адаптеры ---
        var tunnels = adapters.Where(a => a.Kind == Models.AdapterKind.Tunnel && a.IsUp).ToList();
        metrics.Add(new Metric("Активных туннелей", tunnels.Count.ToString(),
            tunnels.Count == 0 ? null : string.Join(", ", tunnels.Select(t => t.Name))));
        foreach (var tunnel in tunnels)
        {
            findings.Add(Finding.Critical(
                $"Активен туннельный интерфейс «{tunnel.Name}»",
                $"MTU {tunnel.Mtu}, адрес {tunnel.AddressText}. Туннель перехватывает трафик системы.",
                tunnel.Description));
        }

        // --- VPN-подключения ОС (RAS) ---
        var activeConnections = connections.Where(c => c.Status?.Contains("Connected", StringComparison.OrdinalIgnoreCase) == true
                                                       || c.Status?.Contains("Подключ", StringComparison.OrdinalIgnoreCase) == true).ToList();
        metrics.Add(new Metric("VPN-профили ОС", connections.Count.ToString(),
            connections.Count == 0 ? "нет" : string.Join(", ", connections.Select(c => c.Name))));
        foreach (var connection in activeConnections)
        {
            findings.Add(Finding.Critical($"Активно VPN-подключение ОС «{connection.Name}»",
                $"{connection.TunnelType} → {connection.Server}", connection.DeviceType));
        }

        // --- запущенные клиенты обхода ---
        foreach (var process in processes)
        {
            findings.Add(Finding.Critical(
                $"Запущен клиент обхода: {process.Name}",
                $"Процесс совпал с маркером «{process.MatchedMarker}».",
                process.Path));
        }
        metrics.Add(new Metric("Подозрительных процессов", processes.Count.ToString(),
            processes.Count == 0 ? "не найдено" : string.Join(", ", processes.Select(p => p.Name))));

        // --- установленные клиенты обхода ---
        var matchedApps = apps.Where(a => a.Kind is not null).ToList();
        metrics.Add(new Metric("Клиентов обхода установлено", matchedApps.Count.ToString(),
            matchedApps.Count == 0 ? "не найдено" : string.Join(", ", matchedApps.Select(a => a.Name).Distinct().Take(6))));
        if (matchedApps.Count > 0)
        {
            findings.Add(Finding.Warning(
                $"Установлены клиенты обхода ({matchedApps.Count})",
                "Факт установки сам по себе не доказывает активный обход, но методика учитывает его как отягчающий контекст.",
                string.Join("; ", matchedApps.Select(a => $"{a.Name} {a.Version}").Take(8))));
        }

        // --- службы/драйверы туннелей ---
        var runningServices = services.Where(s => s.State.Equals("Running", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var service in runningServices)
        {
            findings.Add(Finding.Warning(
                $"Служба туннеля запущена: {service.Name}",
                service.DisplayName ?? service.Path ?? string.Empty,
                service.Path));
        }
        metrics.Add(new Metric("Служб туннелей", runningServices.Count.ToString()));

        // --- kill switch ---
        var killSwitch = firewall.Where(r => r.Enabled && r.Action.Contains("Block", StringComparison.OrdinalIgnoreCase)
                                             && r.Direction.Contains("Out", StringComparison.OrdinalIgnoreCase)
                                             && _catalog.IsVpnRelated(r.ApplicationName ?? r.Name)).ToList();
        if (killSwitch.Count > 0)
        {
            findings.Add(Finding.Warning(
                "Похоже на kill switch в файрволе",
                "Исходящие блокируются правилами, связанными с VPN-клиентом: типичная настройка «защиты от утечек».",
                string.Join("; ", killSwitch.Select(r => r.Name).Take(5))));
            metrics.Add(new Metric("Правил kill switch", killSwitch.Count.ToString()));
        }

        var detected = findings.Any(f => f.Severity == Severity.Critical);
        var review = findings.Any(f => f.Severity == Severity.Warning);

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
}
