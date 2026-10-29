using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Checks;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Platform;

namespace NetworkChecker.Platform.Windows;

/// <summary>
/// Реализация платформенного слоя для Windows.
/// На не-Windows среде методы деградируют: сетевые интерфейсы и DNS читаются кроссплатформенно,
/// реестр/PowerShell-часть помечается как недоступная.
/// </summary>
public sealed class WindowsPlatformProbe(VpnClientCatalog catalog) : IPlatformProbe
{
    private readonly VpnClientCatalog _catalog = catalog;
    private readonly Dictionary<string, (DateTimeOffset At, object Value)> _cache = [];
    private readonly Lock _cacheLock = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(15);

    public event EventHandler<string>? Trace;

    private void Log(string message) => Trace?.Invoke(this, message);

    private async Task<T> CachedAsync<T>(string key, Func<Task<T>> factory)
    {
        lock (_cacheLock)
        {
            if (_cache.TryGetValue(key, out var entry) && DateTimeOffset.Now - entry.At < CacheTtl && entry.Value is T typed)
                return typed;
        }
        var value = await factory().ConfigureAwait(false);
        lock (_cacheLock)
        {
            _cache[key] = (DateTimeOffset.Now, value!);
        }
        return value;
    }

    // ---------------------------------------------------------------- ОС -----

    public Task<OsInfo> GetOsInfoAsync(CancellationToken ct = default) => CachedAsync("os", () =>
    {
        var elevated = false;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                elevated = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }
        catch { }

        var build = OperatingSystem.IsWindows() ? Environment.OSVersion.Version.Build.ToString(CultureInfo.InvariantCulture) : null;
        return Task.FromResult(new OsInfo
        {
            Description = OperatingSystem.IsWindows()
                ? $"Windows {Environment.OSVersion.Version.Major}.{Environment.OSVersion.Version.Minor} (build {build})"
                : System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            Architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            IsWindows = OperatingSystem.IsWindows(),
            IsElevated = elevated,
            WindowsBuild = build,
            DotNetVersion = Environment.Version.ToString(),
        });
    });

    // --------------------------------------------------------- Адаптеры ------

    public Task<IReadOnlyList<AdapterInfo>> GetAdaptersAsync(CancellationToken ct = default) => CachedAsync<IReadOnlyList<AdapterInfo>>("adapters", () =>
    {
        var list = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()).ToList();
            var ipv6 = props.UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                            !a.Address.IsIPv6LinkLocal && !a.Address.IsIPv6Multicast)
                .Select(a => a.Address.ToString()).ToList();
            var gateways = props.GatewayAddresses
                .Where(g => g.Address != null && !g.Address.Equals(IPAddress.Any))
                .Select(g => g.Address.ToString()).Distinct().ToList();

            var kind = ClassifyAdapter(nic, ipv4);
            var mtu = 1500;
            if (OperatingSystem.IsLinux())
            {
                mtu = ReadLinuxMtu(nic.Name) ?? mtu;
            }
            else if (OperatingSystem.IsWindows())
            {
                mtu = props.GetIPv4Properties()?.Mtu is > 0 and var value ? value : mtu;
            }

            list.Add(new AdapterInfo
            {
                Id = nic.Id,
                Name = nic.Name,
                Description = nic.Description,
                Kind = kind,
                IsUp = nic.OperationalStatus == OperationalStatus.Up,
                Mtu = mtu,
                MacAddress = FormatMac(nic.GetPhysicalAddress()),
                IPv4 = ipv4,
                IPv6 = ipv6,
                Gateways = gateways,
                DnsServers = [.. props.DnsAddresses.Select(d => d.ToString()).Distinct()],
                DhcpServer = SafeDhcp(props),
                SpeedBitsPerSecond = nic.Speed > 0 ? nic.Speed : 0,
                IsTunnelHint = nic.NetworkInterfaceType is NetworkInterfaceType.Tunnel ||
                               InterfaceNaming.IsVpnLikeName(nic.Name) || InterfaceNaming.IsVpnLikeName(nic.Description),
            });
        }
        return Task.FromResult<IReadOnlyList<AdapterInfo>>([.. list.OrderBy(a => a.Kind).ThenBy(a => a.Name)]);
    });

    private static string? SafeDhcp(IPInterfaceProperties props)
    {
        try { return props.DhcpServerAddresses.FirstOrDefault()?.ToString(); }
        catch { return null; }
    }

    private static int? ReadLinuxMtu(string name)
    {
        try
        {
            var text = File.ReadAllText($"/sys/class/net/{name}/mtu");
            return int.TryParse(text.Trim(), out var mtu) ? mtu : null;
        }
        catch { return null; }
    }

    private static string? FormatMac(PhysicalAddress? address)
    {
        if (address is null) return null;
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 0) return null;
        return string.Join(":", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    private static AdapterKind ClassifyAdapter(NetworkInterface nic, List<string> ipv4)
    {
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) return AdapterKind.Loopback;
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) return AdapterKind.Tunnel;
        if (InterfaceNaming.IsVpnLikeName(nic.Name) || InterfaceNaming.IsVpnLikeName(nic.Description))
            return AdapterKind.Tunnel;
        if (InterfaceNaming.IsCellularName(nic.Name) || InterfaceNaming.IsCellularName(nic.Description))
            return AdapterKind.Cellular;
        if (InterfaceNaming.IsVirtualName(nic.Name) || InterfaceNaming.IsVirtualName(nic.Description))
            return AdapterKind.Virtual;
        return nic.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => AdapterKind.Wifi,
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet
                or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx
                or NetworkInterfaceType.Ethernet3Megabit => AdapterKind.Ethernet,
            NetworkInterfaceType.Wman or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2
                => AdapterKind.Cellular,
            _ => ipv4.Count > 0 ? AdapterKind.Ethernet : AdapterKind.Unknown,
        };
    }

    // ---------------------------------------------------------- Маршруты -----

    public async Task<IReadOnlyList<RouteInfo>> GetRoutesAsync(CancellationToken ct = default)
    {
        if (OperatingSystem.IsWindows())
        {
            var json = await PowerShell.QueryJsonAsync(
                "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,RouteMetric,ifIndex",
                TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
            var ifIndexMap = await GetInterfaceIndexMapAsync(ct).ConfigureAwait(false);
            var routes = new List<RouteInfo>();
            foreach (var item in PowerShell.Enumerate(json))
            {
                var destination = item.Text("DestinationPrefix") ?? string.Empty;
                var index = item.Text("ifIndex") ?? string.Empty;
                routes.Add(new RouteInfo
                {
                    Destination = NormalizeDestination(destination),
                    Gateway = item.Text("NextHop"),
                    Metric = item.Number("RouteMetric"),
                    InterfaceName = ifIndexMap.GetValueOrDefault(index, index),
                });
            }
            return routes; // Не пытаться читать Linux /proc на Windows. Пустой результат не доказывает отсутствие маршрутов.
        }
        return ReadProcRoutes();
    }

    private static string NormalizeDestination(string destination)
    {
        if (destination.Contains('/')) return destination;
        return destination;
    }

    private static List<RouteInfo> ReadProcRoutes()
    {
        var list = new List<RouteInfo>();
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try { names[nic.GetIPProperties().GetIPv4Properties()?.Index.ToString(CultureInfo.InvariantCulture) ?? ""] = nic.Name; }
                catch { }
            }
        }
        catch { }

        try
        {
            foreach (var line in File.ReadLines("/proc/net/route").Skip(1))
            {
                var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 8) continue;
                var iface = parts[0];
                var destination = ParseLeHex(parts[1]);
                var gateway = ParseLeHex(parts[2]);
                var metric = int.TryParse(parts[6], out var m) ? m : 0;
                list.Add(new RouteInfo
                {
                    Destination = destination == "0.0.0.0" ? "0.0.0.0" : destination,
                    Gateway = gateway == "0.0.0.0" ? null : gateway,
                    Metric = metric,
                    InterfaceName = iface,
                });
            }
        }
        catch { }
        return list;

        static string ParseLeHex(string value)
        {
            if (value.Length != 8) return value;
            try
            {
                var number = Convert.ToUInt32(value, 16);
                return string.Join('.',
                [
                    number & 0xFF, (number >> 8) & 0xFF, (number >> 16) & 0xFF, (number >> 24) & 0xFF,
                ]);
            }
            catch { return value; }
        }
    }

    private static async Task<Dictionary<string, string>> GetInterfaceIndexMapAsync(CancellationToken ct)
    {
        var json = await PowerShell.QueryJsonAsync(
            "Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object ifIndex,Name",
            TimeSpan.FromSeconds(6), ct).ConfigureAwait(false);
        var map = new Dictionary<string, string>();
        foreach (var item in PowerShell.Enumerate(json))
        {
            var index = item.Text("ifIndex");
            var name = item.Text("Name");
            if (index is not null && name is not null) map[index] = name;
        }
        return map;
    }

    // --------------------------------------------------------------- DNS -----

    public Task<DnsConfiguration> GetDnsConfigurationAsync(CancellationToken ct = default) => CachedAsync("dns", () =>
    {
        var servers = new List<string>();
        var suffixes = new List<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var props = nic.GetIPProperties();
                servers.AddRange(props.DnsAddresses.Select(d => d.ToString()));
                try { if (!string.IsNullOrWhiteSpace(props.DnsSuffix)) suffixes.Add(props.DnsSuffix); } catch { }
            }
        }
        catch { }

        var nrpt = ReadNrptPolicies();
        return Task.FromResult(new DnsConfiguration
        {
            Servers = [.. servers.Distinct()],
            NameResolutionPolicy = nrpt,
            Suffixes = [.. suffixes.Distinct()],
        });
    });

    private static List<string> ReadNrptPolicies()
    {
        var list = new List<string>();
        if (!OperatingSystem.IsWindows()) return list;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig");
            if (key is null) return list;
            foreach (var name in key.GetSubKeyNames())
            {
                using var sub = key.OpenSubKey(name);
                var servers = sub?.GetValue("GenericDNSServers") as string;
                if (sub?.GetValue("Name") is not string[] names || names.Length == 0) continue;
                list.Add($"{string.Join(", ", names)} → {servers ?? "?"}");
            }
        }
        catch { }
        return list;
    }

    // ------------------------------------------------------------ Прокси -----

    public Task<ProxySettings> GetSystemProxyAsync(CancellationToken ct = default) => CachedAsync("proxy", () =>
    {
        bool enabled = false;
        string? server = null, pac = null, bypass = null;
        var source = "нет";

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (key is not null)
                {
                    enabled = Convert.ToInt32(key.GetValue("ProxyEnable") ?? 0, CultureInfo.InvariantCulture) == 1;
                    server = key.GetValue("ProxyServer") as string;
                    pac = key.GetValue("AutoConfigURL") as string;
                    bypass = key.GetValue("ProxyOverride") as string;
                    if (enabled || !string.IsNullOrWhiteSpace(server) || !string.IsNullOrWhiteSpace(pac))
                        source = "WinINET (реестр пользователя)";
                }
                using var machine = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
                if (!enabled && machine is not null && machine.GetValue("DefaultConnectionSettings") is byte[] data && data.Length > 12)
                {
                    if ((data[8] & 0x02) != 0)
                    {
                        enabled = true;
                        server ??= System.Text.Encoding.ASCII.GetString(data, 12, Math.Min(120, data.Length - 12)).Split('\0')[0];
                        source = "WinINET (машинные настройки)";
                    }
                }
            }
            catch { }
        }

        var winHttp = OperatingSystem.IsWindows() ? ReadWinHttpProxy() : null;

        var env = Environment.GetEnvironmentVariable("HTTP_PROXY") ?? Environment.GetEnvironmentVariable("http_proxy");
        var envSocks = Environment.GetEnvironmentVariable("ALL_PROXY") ?? Environment.GetEnvironmentVariable("all_proxy");

        string? http = null, https = null, socks = null;
        if (enabled && !string.IsNullOrWhiteSpace(server))
        {
            foreach (var part in server.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var index = part.IndexOf('=');
                if (index < 0)
                {
                    http ??= "http://" + part.Trim();
                    https ??= "http://" + part.Trim();
                }
                else
                {
                    var scheme = part[..index].Trim().ToLowerInvariant();
                    var value = part[(index + 1)..].Trim();
                    if (scheme.Equals("https", StringComparison.Ordinal)) https = value;
                    else if (scheme.Equals("http", StringComparison.Ordinal)) http = value;
                    else if (scheme.StartsWith("socks", StringComparison.Ordinal)) socks = value;
                }
            }
        }
        if (http is null && !string.IsNullOrWhiteSpace(env)) { http = env; source = "переменная окружения HTTP_PROXY"; }
        if (envSocks is not null) { socks = envSocks; source = "переменная окружения ALL_PROXY"; }

        if (winHttp is not null && source == "нет") source = "WinHTTP (машинные настройки)";

        return Task.FromResult(new ProxySettings
        {
            Enabled = enabled || (http is not null && OperatingSystem.IsWindows() && source != "нет"),
            HttpProxy = http,
            HttpsProxy = https,
            SocksProxy = socks,
            PacUrl = pac,
            BypassList = bypass,
            WinHttpProxy = winHttp,
            Source = source,
        });
    });

    /// <summary>
    /// Машинный прокси WinHTTP (его используют службы, Windows Update, фоновые агенты).
    /// В реестре это бинарный WinHttpSettings: 12 байт заголовка, дальше две UTF-16 строки —
    /// «сервер» и «список исключений». Флаг включения — бит 0x02 в байте 8.
    /// </summary>
    private static string? ReadWinHttpProxy()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
            if (key?.GetValue("WinHttpSettings") is not byte[] data || data.Length <= 12) return null;
            if ((data[8] & 0x02) == 0) return null;

            var text = System.Text.Encoding.Unicode.GetString(data, 12, data.Length - 12);
            var server = text.Split('\0')[0].Trim();
            return string.IsNullOrWhiteSpace(server) ? null : server;
        }
        catch
        {
            return null;
        }
    }

    // --------------------------------------------------- Установленные app ---

    public Task<IReadOnlyList<InstalledApp>> GetInstalledAppsAsync(CancellationToken ct = default) =>
        CachedAsync<IReadOnlyList<InstalledApp>>("apps", () =>
        {
            var apps = new List<InstalledApp>();
            if (!OperatingSystem.IsWindows()) return Task.FromResult<IReadOnlyList<InstalledApp>>(apps);

            var roots = new (RegistryKey Root, string Path, string Label)[]
            {
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM-32"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
            };

            foreach (var (root, path, label) in roots)
            {
                try
                {
                    using var key = root.OpenSubKey(path);
                    if (key is null) continue;
                    foreach (var subName in key.GetSubKeyNames())
                    {
                        using var sub = key.OpenSubKey(subName);
                        if (sub is null) continue;
                        var name = sub.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(name)) continue;
                        var location = sub.GetValue("InstallLocation") as string;
                        var publisher = sub.GetValue("Publisher") as string;
                        var uninstall = sub.GetValue("UninstallString") as string;
                        var match = _catalog.Match(name) ?? _catalog.Match(location) ?? _catalog.Match(uninstall);
                        apps.Add(new InstalledApp
                        {
                            Name = name,
                            Version = sub.GetValue("DisplayVersion") as string,
                            Publisher = publisher,
                            InstallLocation = location,
                            UninstallString = uninstall,
                            Source = label,
                            MatchedMarker = match?.Name,
                            Kind = match?.Category,
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log($"Реестр Uninstall {label}: {ex.Message}");
                }
            }
            return Task.FromResult<IReadOnlyList<InstalledApp>>([.. apps
                .GroupBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)]);
        });

    // ---------------------------------------------------------- Процессы -----

    public Task<IReadOnlyList<ProcessInfo>> GetSuspiciousProcessesAsync(CancellationToken ct = default) =>
        CachedAsync<IReadOnlyList<ProcessInfo>>("processes", () =>
        {
            var result = new List<ProcessInfo>();
            if (!OperatingSystem.IsWindows()) return Task.FromResult<IReadOnlyList<ProcessInfo>>(result);
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    string? path = null;
                    try { path = process.MainModule?.FileName; } catch { }
                    var match = _catalog.Match(process.ProcessName) ?? _catalog.Match(path);
                    if (match is null) continue;
                    result.Add(new ProcessInfo
                    {
                        Name = process.ProcessName + ".exe",
                        ProcessId = process.Id,
                        Path = path,
                        MatchedMarker = match.Name,
                    });
                }
                catch { }
                finally { process.Dispose(); }
            }
            return Task.FromResult<IReadOnlyList<ProcessInfo>>(result);
        });

    // ------------------------------------------------------ Службы/драйверы --

    public Task<IReadOnlyList<ServiceInfo>> GetTunnelServicesAsync(CancellationToken ct = default) =>
        CachedAsync<IReadOnlyList<ServiceInfo>>("services", async () =>
        {
            var list = new List<ServiceInfo>();
            if (!OperatingSystem.IsWindows()) return list;

            var json = await PowerShell.QueryJsonAsync(
                "Get-Service -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,@{Name='Status';Expression={$_.Status.ToString()}},@{Name='StartType';Expression={$_.StartType.ToString()}}",
                TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);

            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            foreach (var item in PowerShell.Enumerate(json))
            {
                var name = item.Text("Name");
                var display = item.Text("DisplayName");
                if (name is null) continue;
                var match = _catalog.Match(name) ?? _catalog.Match(display);
                if (match is null) continue;
                string? path = null;
                try { path = servicesKey?.OpenSubKey(name)?.GetValue("ImagePath") as string; } catch { }
                list.Add(new ServiceInfo
                {
                    Name = name,
                    DisplayName = display,
                    State = item.Text("Status") ?? "Unknown",
                    StartMode = item.Text("StartType"),
                    Path = path,
                    MatchedMarker = match.Name,
                });
            }
            return list;
        });

    // ---------------------------------------------------- VPN-подключения ----

    public Task<IReadOnlyList<VpnConnectionInfo>> GetVpnConnectionsAsync(CancellationToken ct = default) =>
        CachedAsync<IReadOnlyList<VpnConnectionInfo>>("vpn", async () =>
        {
            var list = new List<VpnConnectionInfo>();
            if (!OperatingSystem.IsWindows()) return list;

            var json = await PowerShell.QueryJsonAsync(
                "Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | Select-Object Name,ServerAddress,@{Name='ConnectionStatus';Expression={$_.ConnectionStatus.ToString()}},TunnelType,DnsSuffix",
                TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
            foreach (var item in PowerShell.Enumerate(json))
            {
                var name = item.Text("Name");
                if (name is null) continue;
                list.Add(new VpnConnectionInfo
                {
                    Name = name,
                    Server = item.Text("ServerAddress"),
                    Status = item.Text("ConnectionStatus"),
                    TunnelType = item.Text("TunnelType"),
                    DeviceType = item.Text("DnsSuffix"),
                });
            }

            // RAS-подключения текущего пользователя (в т.ч. созданные клиентами)
            var ras = await PowerShell.QueryJsonAsync(
                "Get-VpnConnection -ErrorAction SilentlyContinue | Select-Object Name,ServerAddress,@{Name='ConnectionStatus';Expression={$_.ConnectionStatus.ToString()}},TunnelType",
                TimeSpan.FromSeconds(6), ct).ConfigureAwait(false);
            foreach (var item in PowerShell.Enumerate(ras))
            {
                var name = item.Text("Name");
                if (name is null || list.Any(l => l.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) continue;
                list.Add(new VpnConnectionInfo
                {
                    Name = name,
                    Server = item.Text("ServerAddress"),
                    Status = item.Text("ConnectionStatus"),
                    TunnelType = item.Text("TunnelType"),
                });
            }
            return list;
        });

    // ------------------------------------------------------------ Hosts ------

    public Task<IReadOnlyList<HostsEntry>> GetHostsEntriesAsync(CancellationToken ct = default)
    {
        var path = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts")
            : "/etc/hosts";
        var list = new List<HostsEntry>();
        try
        {
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                string? comment = null;
                var commentIndex = line.IndexOf('#');
                if (commentIndex > 0)
                {
                    comment = line[(commentIndex + 1)..].Trim();
                    line = line[..commentIndex].Trim();
                }
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                foreach (var host in parts.Skip(1))
                {
                    list.Add(new HostsEntry(parts[0], host, comment));
                }
            }
        }
        catch (Exception ex)
        {
            Log($"hosts: {ex.Message}");
        }
        return Task.FromResult<IReadOnlyList<HostsEntry>>(list);
    }

    // ---------------------------------------------------------- Файрвол ------

    public Task<IReadOnlyList<FirewallRuleInfo>> GetFirewallRulesAsync(CancellationToken ct = default) =>
        CachedAsync<IReadOnlyList<FirewallRuleInfo>>("firewall", async () =>
        {
            var list = new List<FirewallRuleInfo>();
            if (!OperatingSystem.IsWindows()) return list;
            var json = await PowerShell.QueryJsonAsync(
                "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block -ErrorAction SilentlyContinue | " +
                "Select-Object -First 300 DisplayName,Group,@{Name='Direction';Expression={$_.Direction.ToString()}},@{Name='Action';Expression={$_.Action.ToString()}},@{Name='Enabled';Expression={$_.Enabled.ToString()}}",
                TimeSpan.FromSeconds(12), ct).ConfigureAwait(false);
            foreach (var item in PowerShell.Enumerate(json))
            {
                var name = item.Text("DisplayName");
                if (name is null) continue;
                list.Add(new FirewallRuleInfo
                {
                    Name = name,
                    Group = item.Text("Group"),
                    Direction = item.Text("Direction") ?? "Out",
                    Action = item.Text("Action") ?? "Block",
                    Enabled = !string.Equals(item.Text("Enabled"), "False", StringComparison.OrdinalIgnoreCase),
                });
            }
            return list;
        });
}
