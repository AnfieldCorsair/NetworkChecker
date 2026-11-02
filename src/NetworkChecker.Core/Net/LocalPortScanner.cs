using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using NetworkChecker.Core.Options;

namespace NetworkChecker.Core.Net;

/// <summary>
/// Подбор локальных TCP-портов для BypassCheck: фиксированный список,
/// диапазоны из опубликованной методики и реальные слушающие сокеты ОС.
/// Сам класс не делает сетевых запросов и не подключается к портам.
/// </summary>
public static class LocalPortScanner
{
    /// <summary>Максимум портов в одном прогоне по умолчанию.</summary>
    public const int DefaultMaxPorts = 200;

    /// <summary>Порты из настроек плюс развёрнутые диапазоны (например, 16000-16100).</summary>
    public static IReadOnlyList<int> ConfiguredPorts(RknOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var ports = new List<int>();
        foreach (var port in options.LocalProxyPorts)
        {
            if (port is > 0 and < 65536) ports.Add(port);
        }
        foreach (var range in options.LocalProxyPortRanges)
        {
            ports.AddRange(ParseRange(range));
        }
        return ports.Distinct().OrderBy(p => p).Take(Limit(options)).ToArray();
    }

    /// <summary>
    /// Объединяет настроенные порты с портами, которые ОС сообщила как LISTEN.
    /// Настроенные порты идут первыми: они не теряются при большом числе системных слушателей.
    /// </summary>
    public static IReadOnlyList<int> Merge(IReadOnlyList<int> configured, IReadOnlyList<int> listeners, int maxPorts)
    {
        ArgumentNullException.ThrowIfNull(configured);
        ArgumentNullException.ThrowIfNull(listeners);
        var result = new List<int>(configured.Count + listeners.Count);
        var seen = new HashSet<int>();
        foreach (var port in configured.Concat(listeners))
        {
            if (port is > 0 and < 65536 && seen.Add(port)) result.Add(port);
        }
        return result.Take(Math.Clamp(maxPorts, 1, 4096)).ToArray();
    }

    /// <summary>Разбирает «16000-16100» или одиночный порт. Некорректные записи игнорируются.</summary>
    public static IReadOnlyList<int> ParseRange(string? range)
    {
        if (string.IsNullOrWhiteSpace(range)) return Array.Empty<int>();
        var parts = range.Split('-', 2, StringSplitOptions.TrimEntries);
        if (parts.Length == 1)
        {
            return int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var single)
                   && single is > 0 and < 65536
                ? [single]
                : Array.Empty<int>();
        }
        if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var start) ||
            !int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var end) ||
            start < 1 || end > 65535 || end < start || end - start > 4096)
        {
            return Array.Empty<int>();
        }
        var result = new List<int>(end - start + 1);
        for (var port = start; port <= end; port++) result.Add(port);
        return result;
    }

    /// <summary>
    /// Порты, на которых ОС слушает локальные подключения (loopback или 0.0.0.0/[::]).
    /// Возвращает только номера портов: адреса и процессы не собираются.
    /// </summary>
    public static IReadOnlyList<int> GetLoopbackListeners() => GetLoopbackListeners(DefaultMaxPorts);

    public static IReadOnlyList<int> GetLoopbackListeners(int maxPorts)
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                .Where(endpoint => IsLocalBinding(endpoint.Address))
                .Select(endpoint => endpoint.Port)
                .Where(port => port is > 0 and < 65536)
                .Distinct()
                .OrderBy(port => port)
                .Take(Math.Clamp(maxPorts, 1, 4096))
                .ToArray();
        }
        catch (NetworkInformationException) { return Array.Empty<int>(); }
        catch (PlatformNotSupportedException) { return Array.Empty<int>(); }
        catch
        {
            // Отсутствие списка слушателей — отсутствие данных, а не «портов нет».
            return Array.Empty<int>();
        }
    }

    private static bool IsLocalBinding(IPAddress address) =>
        IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    private static int Limit(RknOptions options) => Math.Clamp(options.MaxLocalProxyPorts, 1, 4096);
}
