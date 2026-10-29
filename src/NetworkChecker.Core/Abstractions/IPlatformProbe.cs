using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Platform;

namespace NetworkChecker.Core.Abstractions;

/// <summary>Платформенный слой: всё, что зависит от ОС.</summary>
public interface IPlatformProbe
{
    Task<OsInfo> GetOsInfoAsync(CancellationToken ct = default);
    Task<IReadOnlyList<AdapterInfo>> GetAdaptersAsync(CancellationToken ct = default);
    Task<IReadOnlyList<RouteInfo>> GetRoutesAsync(CancellationToken ct = default);
    Task<DnsConfiguration> GetDnsConfigurationAsync(CancellationToken ct = default);
    Task<ProxySettings> GetSystemProxyAsync(CancellationToken ct = default);
    Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ProcessInfo>> GetSuspiciousProcessesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ServiceInfo>> GetTunnelServicesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<VpnConnectionInfo>> GetVpnConnectionsAsync(CancellationToken ct = default);
    Task<IReadOnlyList<HostsEntry>> GetHostsEntriesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<FirewallRuleInfo>> GetFirewallRulesAsync(CancellationToken ct = default);
}

/// <summary>Контекст выполнения прогона: отмена, прогресс, сбор IP-наблюдений.</summary>
public sealed class CheckContext
{
    private readonly List<IpObservation> _ipObservations = [];
    private readonly Lock _ipLock = new();

    public required RknOptions Options { get; init; }
    public Action<string>? Report { get; init; }
    public Action<IpObservation>? IpObserved { get; init; }

    public void Progress(string message) => Report?.Invoke(message);

    public void CollectIp(string source, string ip, bool? isRussian, string? note = null, IpChannel channel = IpChannel.Unknown)
    {
        if (!System.Net.IPAddress.TryParse(ip?.Trim(), out var parsed)) return;
        if (parsed.IsIPv4MappedToIPv6) parsed = parsed.MapToIPv4();
        var observation = new IpObservation(source, parsed.ToString(), isRussian, note, channel);
        lock (_ipLock) _ipObservations.Add(observation);
        IpObserved?.Invoke(observation);
    }

    public IReadOnlyList<IpObservation> IpObservations
    {
        get { lock (_ipLock) return [.. _ipObservations]; }
    }
}

/// <summary>Модуль проверки. Все модули запускаются параллельно и независимо.</summary>
public interface ICheck
{
    CheckCategory Category { get; }
    string Title { get; }
    string Subtitle { get; }
    /// <summary>Вес в итоговом вердикте. 0 — чисто диагностическая проверка.</summary>
    int Weight { get; }
    Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct);
}

/// <summary>Провайдер актуального прокси-окружения для HTTP-запросов.</summary>
public interface IHttpProbe
{
    /// <summary>Строка User-Agent, которую отправляет зонд. Нужна экрану «глазами сайта».</summary>
    string UserAgent { get; }

    /// <summary>GET с таймаутом; игнорирует системный прокси, если ignoreProxy = true.</summary>
    Task<HttpProbeResult> GetAsync(Uri uri, TimeSpan timeout, bool ignoreProxy, CancellationToken ct = default);
}

public sealed record HttpProbeResult(
    bool Success,
    int StatusCode,
    string? Body,
    string? Error,
    TimeSpan Elapsed,
    string? FinalUri,
    string? ServerHeader);
