using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Platform;

namespace NetworkChecker.TestKit;

/// <summary>Платформа-заглушка: отдаёт заранее заданные данные, ничего не читает из ОС.</summary>
public sealed class FakePlatformProbe : IPlatformProbe
{
    public OsInfo Os { get; set; } = new() { Description = "Windows 11 (тест)", IsWindows = true, WindowsBuild = "26100" };
    public List<AdapterInfo> Adapters { get; set; } = [];
    public List<RouteInfo> Routes { get; set; } = [];
    public DnsConfiguration Dns { get; set; } = new();
    public ProxySettings Proxy { get; set; } = new();
    public List<InstalledApp> Apps { get; set; } = [];
    public List<ProcessInfo> Processes { get; set; } = [];
    public List<ServiceInfo> Services { get; set; } = [];
    public List<VpnConnectionInfo> VpnConnections { get; set; } = [];
    public List<HostsEntry> Hosts { get; set; } = [];
    public List<FirewallRuleInfo> Firewall { get; set; } = [];
    public Exception? ThrowOn { get; set; }

    /// <summary>Задержка ответа — чтобы проверить параллельность раннера.</summary>
    public TimeSpan Delay { get; set; } = TimeSpan.Zero;

    private async Task<T> RespondAsync<T>(T value)
    {
        if (Delay > TimeSpan.Zero) await Task.Delay(Delay).ConfigureAwait(false);
        if (ThrowOn is not null) throw ThrowOn;
        return value;
    }

    public Task<OsInfo> GetOsInfoAsync(CancellationToken ct = default) => RespondAsync(Os);
    public Task<IReadOnlyList<AdapterInfo>> GetAdaptersAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<AdapterInfo>>(Adapters);
    public Task<IReadOnlyList<RouteInfo>> GetRoutesAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<RouteInfo>>(Routes);
    public Task<DnsConfiguration> GetDnsConfigurationAsync(CancellationToken ct = default) => RespondAsync(Dns);
    public Task<ProxySettings> GetSystemProxyAsync(CancellationToken ct = default) => RespondAsync(Proxy);
    public Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<InstalledApp>>(Apps);
    public Task<IReadOnlyList<ProcessInfo>> GetSuspiciousProcessesAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<ProcessInfo>>(Processes);
    public Task<IReadOnlyList<ServiceInfo>> GetTunnelServicesAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<ServiceInfo>>(Services);
    public Task<IReadOnlyList<VpnConnectionInfo>> GetVpnConnectionsAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<VpnConnectionInfo>>(VpnConnections);
    public Task<IReadOnlyList<HostsEntry>> GetHostsEntriesAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<HostsEntry>>(Hosts);
    public Task<IReadOnlyList<FirewallRuleInfo>> GetFirewallRulesAsync(CancellationToken ct = default) => RespondAsync<IReadOnlyList<FirewallRuleInfo>>(Firewall);

    /// <summary>Готовая «типичная домашняя» конфигурация.</summary>
    public static FakePlatformProbe Clean() => new()
    {
        Adapters =
        [
            new AdapterInfo
            {
                Id = "{eth}", Name = "eth0", Description = "Intel(R) Ethernet", Kind = AdapterKind.Ethernet,
                IsUp = true, Mtu = 1500, MacAddress = "AA:BB:CC:11:22:33",
                IPv4 = ["192.168.1.20"], Gateways = ["192.168.1.1"], DnsServers = ["192.168.1.1"],
            },
        ],
        Routes =
        [
            new RouteInfo { Destination = "0.0.0.0/0", Gateway = "192.168.1.1", Metric = 25, InterfaceName = "eth0" },
            new RouteInfo { Destination = "192.168.1.0/24", Gateway = null, Metric = 0, InterfaceName = "eth0" },
        ],
        Dns = new DnsConfiguration { Servers = ["192.168.1.1"] },
        Proxy = new ProxySettings(),
        Hosts = [new HostsEntry("127.0.0.1", "localhost", null)],
    };

    /// <summary>«Грязная» конфигурация: туннель, прокси, клиент, файрвол.</summary>
    public static FakePlatformProbe Tunneled() => new()
    {
        Adapters =
        [
            new AdapterInfo
            {
                Id = "{eth}", Name = "eth0", Kind = AdapterKind.Ethernet, IsUp = true, Mtu = 1500,
                IPv4 = ["192.168.1.20"], Gateways = ["192.168.1.1"], DnsServers = ["127.0.0.1"],
            },
            new AdapterInfo
            {
                Id = "{wg}", Name = "wg0", Description = "WireGuard Tunnel", Kind = AdapterKind.Tunnel,
                IsUp = true, Mtu = 1420, IPv4 = ["10.8.0.2"], DnsServers = ["10.8.0.1"],
            },
        ],
        Routes =
        [
            new RouteInfo { Destination = "0.0.0.0/0", Gateway = "0.0.0.0", Metric = 5, InterfaceName = "wg0" },
            new RouteInfo { Destination = "203.0.113.42/32", Gateway = "192.168.1.1", Metric = 0, InterfaceName = "eth0" },
        ],
        Dns = new DnsConfiguration { Servers = ["127.0.0.1"], NameResolutionPolicy = ["corp.local → 10.8.0.1"] },
        Proxy = new ProxySettings
        {
            Enabled = true,
            HttpProxy = "http://127.0.0.1:8080",
            Source = "WinINET (реестр пользователя)",
        },
        Processes = [new ProcessInfo { Name = "xray.exe", ProcessId = 4242, Path = @"C:\Tools\xray.exe", MatchedMarker = "Xray / Xray-core" }],
        Apps = [new InstalledApp { Name = "Amnezia VPN", Version = "4.8.0", Kind = "vpn", MatchedMarker = "Amnezia VPN" }],
        Services = [new ServiceInfo { Name = "WireGuardTunnel$wg0", DisplayName = "WireGuard", State = "Running", MatchedMarker = "WireGuard" }],
        VpnConnections = [new VpnConnectionInfo { Name = "Office", Server = "vpn.example.com", Status = "Connected", TunnelType = "Ikev2" }],
        Hosts = [new HostsEntry("0.0.0.0", "telemetry.example.com", "блокировка телеметрии")],
        Firewall =
        [
            new FirewallRuleInfo { Name = "Amnezia kill switch", Enabled = true, Direction = "Outbound", Action = "Block" },
        ],
    };
}

/// <summary>HTTP-заглушка: отвечает по словарю «подстрока URL → тело».</summary>
public sealed class FakeHttpProbe : IHttpProbe
{
    public string UserAgent { get; set; } = "NetworkChecker/1.1 (+Windows; local diagnostics, test)";
    public Dictionary<string, string> Responses { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Requested { get; } = [];

    /// <summary>Удобный конструктор: new FakeHttpProbe().With(...).With(...).</summary>
    public static FakeHttpProbe For(string urlFragment, string body) => new FakeHttpProbe().With(urlFragment, body);

    public FakeHttpProbe With(string urlFragment, string body)
    {
        Responses[urlFragment] = body;
        return this;
    }

    public Task<HttpProbeResult> GetAsync(Uri uri, TimeSpan timeout, bool ignoreProxy, CancellationToken ct = default)
    {
        Requested.Add(uri.ToString());
        var match = Responses.FirstOrDefault(pair => uri.ToString().Contains(pair.Key, StringComparison.OrdinalIgnoreCase));
        if (match.Value is null)
            return Task.FromResult(new HttpProbeResult(false, 0, null, "нет ответа (тест)", TimeSpan.Zero, null, null));

        return Task.FromResult(new HttpProbeResult(true, 200, match.Value, null, TimeSpan.FromMilliseconds(12), uri.ToString(), "test"));
    }
}

/// <summary>Проверка-заглушка с управляемым результатом.</summary>
public sealed class FakeCheck(
    CheckCategory category,
    string title = "Тестовая проверка",
    int weight = 10,
    Func<CheckContext, CancellationToken, Task<CheckResult>>? behaviour = null) : ICheck
{
    public CheckCategory Category { get; } = category;
    public string Title { get; } = title;
    public string Subtitle => "заглушка";
    public int Weight { get; } = weight;
    public int RunCount { get; private set; }

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        RunCount++;
        if (behaviour is not null) return await behaviour(context, ct).ConfigureAwait(false);
        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Status = CheckStatus.Clean,
            Weight = Weight,
            Findings = [Finding.Info("Проверено")],
        };
    }

    public static FakeCheck Detected(CheckCategory category, int weight = 10, Severity severity = Severity.Critical) =>
        new(category, weight: weight, behaviour: (_, _) => Task.FromResult(new CheckResult
        {
            Category = category,
            Title = category.ToString(),
            Status = CheckStatus.Detected,
            Weight = weight,
            Findings = [new Finding { Severity = severity, Title = "Найдено" }],
        }));

    public static FakeCheck Failing(CheckCategory category) =>
        new(category, behaviour: (_, _) => throw new InvalidOperationException("сломалось"));

    public static FakeCheck Slow(CheckCategory category, int milliseconds) =>
        new(category, behaviour: async (_, ct) =>
        {
            await Task.Delay(milliseconds, ct).ConfigureAwait(false);
            return new CheckResult
            {
                Category = category,
                Title = category.ToString(),
                Status = CheckStatus.Clean,
                Weight = 10,
            };
        });

    public static FakeCheck ReportingIp(CheckCategory category, string ip) =>
        new(category, behaviour: (context, _) =>
        {
            context.CollectIp("тест", ip, null);
            return Task.FromResult(new CheckResult
            {
                Category = category,
                Title = category.ToString(),
                Status = CheckStatus.Clean,
                Weight = 10,
            });
        });
}
