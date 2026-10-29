using System.Net;
using RKNHardering.Core.Models;

namespace RKNHardering.Core.Platform;

/// <summary>Сетевой адаптер в терминах методики обнаружения.</summary>
public sealed record AdapterInfo
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string Description { get; init; } = string.Empty;
    public AdapterKind Kind { get; init; } = AdapterKind.Unknown;
    public bool IsUp { get; init; }
    public int Mtu { get; init; }
    public string? MacAddress { get; init; }
    public IReadOnlyList<string> IPv4 { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> IPv6 { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Gateways { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> DnsServers { get; init; } = Array.Empty<string>();
    public string? DhcpServer { get; init; }
    public long SpeedBitsPerSecond { get; init; }
    /// <summary>Драйвер/вендор, если платформа позволяет (Windows: PnP-устройство).</summary>
    public string? DriverVendor { get; init; }
    public bool IsTunnelHint { get; init; }

    public string KindText => Kind switch
    {
        AdapterKind.Ethernet => "Ethernet",
        AdapterKind.Wifi => "Wi-Fi",
        AdapterKind.Cellular => "Cellular",
        AdapterKind.Tunnel => "Туннель",
        AdapterKind.Loopback => "Loopback",
        AdapterKind.Virtual => "Виртуальный",
        _ => "Неизвестно",
    };

    public string AddressText => IPv4.Count > 0 ? string.Join(", ", IPv4)
        : IPv6.Count > 0 ? string.Join(", ", IPv6)
        : "—";
}

/// <summary>Запись таблицы маршрутизации.</summary>
public sealed record RouteInfo
{
    public required string Destination { get; init; }
    public string? Gateway { get; init; }
    public int Metric { get; init; }
    public string? InterfaceName { get; init; }
    public bool IsDefault => Destination is "0.0.0.0" or "::" or "0.0.0.0/0" or "::/0";
}

/// <summary>Системные настройки прокси (WinINET/WinHTTP/переменные окружения).</summary>
public sealed record ProxySettings
{
    public bool Enabled { get; init; }
    public string? HttpProxy { get; init; }
    public string? HttpsProxy { get; init; }
    public string? SocksProxy { get; init; }
    public string? PacUrl { get; init; }
    public string? BypassList { get; init; }
    /// <summary>Источник данных: WinINET, WinHTTP, env, GNOME/KDE.</summary>
    public string? Source { get; init; }

    public bool HasProxy => Enabled || !string.IsNullOrWhiteSpace(HttpProxy) ||
                            !string.IsNullOrWhiteSpace(SocksProxy) || !string.IsNullOrWhiteSpace(PacUrl);

    public string Display => !Enabled && string.IsNullOrWhiteSpace(HttpProxy) && string.IsNullOrWhiteSpace(SocksProxy)
        ? "не настроен"
        : $"{HttpProxy ?? SocksProxy ?? PacUrl}";
}

/// <summary>Установленное приложение (клиент обхода или обычное).</summary>
public sealed record InstalledApp
{
    public required string Name { get; init; }
    public string? Version { get; init; }
    public string? Publisher { get; init; }
    public string? InstallLocation { get; init; }
    public string? UninstallString { get; init; }
    public string? Source { get; init; }  // Registry, Store, Steam...
    public string? MatchedMarker { get; init; }
    public string? Kind { get; init; }    // vpn / proxy / anti-censor / residual-service
}

/// <summary>Служба/драйвер, связанный с туннелем.</summary>
public sealed record ServiceInfo
{
    public required string Name { get; init; }
    public string? DisplayName { get; init; }
    public required string State { get; init; }
    public string? StartMode { get; init; }
    public string? Path { get; init; }
    public string? MatchedMarker { get; init; }
}

/// <summary>Активное VPN-подключение ОС (RAS / Windows VPN profile).</summary>
public sealed record VpnConnectionInfo
{
    public required string Name { get; init; }
    public string? Server { get; init; }
    public string? Status { get; init; }
    public string? DeviceType { get; init; }
    public string? TunnelType { get; init; }
}

/// <summary>Запущенный процесс, потенциально прокси-клиент.</summary>
public sealed record ProcessInfo
{
    public required string Name { get; init; }
    public int ProcessId { get; init; }
    public string? Path { get; init; }
    public string? MatchedMarker { get; init; }
}

/// <summary>Правило системного файрвола (для детекта kill switch).</summary>
public sealed record FirewallRuleInfo
{
    public required string Name { get; init; }
    public string? Group { get; init; }
    public string? ApplicationName { get; init; }
    public bool Enabled { get; init; }
    public string Direction { get; init; } = "Out";
    public string Action { get; init; } = "Block";
}

/// <summary>Информация об ОС.</summary>
public sealed record OsInfo
{
    public required string Description { get; init; }
    public string Architecture { get; init; } = string.Empty;
    public bool IsWindows { get; init; }
    public bool IsElevated { get; init; }
    public string? WindowsBuild { get; init; }
    public string? DotNetVersion { get; init; }
}

/// <summary>Строка файла hosts.</summary>
public sealed record HostsEntry(string Address, string HostName, string? Comment);

/// <summary>DNS-конфигурация, включая политики раздельного разрешения.</summary>
public sealed record DnsConfiguration
{
    public IReadOnlyList<string> Servers { get; init; } = Array.Empty<string>();
    /// <summary>Windows NRPT (раздельное разрешение через VPN).</summary>
    public IReadOnlyList<string> NameResolutionPolicy { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Suffixes { get; init; } = Array.Empty<string>();
    public bool HasLoopbackServer => Servers.Any(IsLoopback);

    public static bool IsLoopback(string server) =>
        IPAddress.TryParse(server, out var ip) && IPAddress.IsLoopback(ip);

    public static bool IsPrivate(string server) =>
        IPAddress.TryParse(server, out var ip) &&
        (IsLoopback(server) ||
         (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
          (ip.GetAddressBytes()[0] == 10 ||
           (ip.GetAddressBytes()[0] == 172 && ip.GetAddressBytes()[1] >= 16 && ip.GetAddressBytes()[1] <= 31) ||
           (ip.GetAddressBytes()[0] == 192 && ip.GetAddressBytes()[1] == 168))));
}
