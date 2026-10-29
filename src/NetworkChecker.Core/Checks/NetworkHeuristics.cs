using System.Net;
using System.Net.Sockets;
using NetworkChecker.Core.Platform;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// Небольшие эвристики «это нормально или это повод присмотреться», вынесенные из чекеров,
/// чтобы их можно было покрыть тестами по отдельности.
/// </summary>
public static class NetworkHeuristics
{
    /// <summary>Стандартные имена из штатного hosts (Linux, Windows, macOS, Docker) — не повод для тревоги.</summary>
    private static readonly HashSet<string> StandardHostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "localhost.localdomain", "localhost4", "localhost4.localdomain4",
        "localhost6", "localhost6.localdomain6", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
        "broadcasthost", "local", "wpad",
    };

    /// <summary>
    /// Хостовый маршрут (/32 или адрес без маски) на конкретный адрес. Служебные адреса
    /// (link-local, multicast, loopback, ограниченный broadcast) сюда не попадают: их ставят
    /// автоматически DHCP/ND, а не программы обхода.
    /// </summary>
    public static bool IsSuspiciousHostRoute(string? destination)
    {
        if (string.IsNullOrWhiteSpace(destination)) return false;

        var text = destination.Trim();
        var hasHostMask = text.EndsWith("/32", StringComparison.Ordinal)
                          || text.EndsWith("/128", StringComparison.Ordinal);
        if (!hasHostMask && text.Contains('/')) return false;

        var addressPart = hasHostMask ? text[..text.IndexOf('/')] : text;
        if (!IPAddress.TryParse(addressPart, out var address)) return false;

        return !IsServiceAddress(address);
    }

    /// <summary>Запись hosts безобидна: либо комментарий наш, либо служебное имя и служебный адрес.</summary>
    public static bool IsBenignHostsEntry(HostsEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (entry.Comment is not null && entry.Comment.Contains("NetworkChecker", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var name = entry.HostName.TrimEnd('.');
        if (name.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) return true;

        // Решаем по имени, а не по адресу: запись вида «0.0.0.0 vk.com» — это как раз то,
        // что стоит показать, даже если адрес служебный.
        return StandardHostNames.Contains(name);
    }

    /// <summary>Адрес из диапазонов, которые ОС назначает сама (или которые заведомо не «внешний адрес»).</summary>
    private static bool IsServiceAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address)) return true;
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast) || address.Equals(IPAddress.None)
            || address.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork && bytes.Length == 4)
        {
            // 169.254.0.0/16 — link-local (APIPA), 224.0.0.0/4 — multicast, 255.255.255.255 уже выше.
            return (bytes[0] == 169 && bytes[1] == 254) || (bytes[0] >= 224 && bytes[0] <= 239);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // fe80::/10 — link-local, fec0::/10 — site-local (устаревший), ff00::/8 — multicast.
            return address.IsIPv6LinkLocal || address.IsIPv6Multicast
                   || (bytes[0] == 0xfe && (bytes[1] & 0xC0) == 0xC0);
        }

        return false;
    }
}
