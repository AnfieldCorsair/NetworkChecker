using System.Net;
using System.Net.Sockets;
using NetworkChecker.Core.Models;

namespace NetworkChecker.Core.Verdict;

/// <summary>Диагностическое сравнение адресов: разные семейства не являются конфликтом.</summary>
public static class IpConsensusBuilder
{
    public static IpConsensus Build(IReadOnlyList<IpObservation> observations)
    {
        var valid = observations.Select(o =>
        {
            if (!IPAddress.TryParse(o.Ip?.Trim(), out var ip)) return null;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            return new { Observation = o with { Ip = ip.ToString() }, Family = ip.AddressFamily };
        }).Where(x => x is not null).Select(x => x!).ToArray();
        if (valid.Length == 0) return new IpConsensus();

        // Семейства сравниваются только внутри себя. При равенстве — стабильный порядок,
        // а не порядок завершения параллельных запросов. Это выбранный адрес, не доказанный маршрут.
        var preferred = valid.Any(x => x.Family == AddressFamily.InterNetwork)
            ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        var chosen = valid.Where(x => x.Family == preferred)
            .GroupBy(x => x.Observation.Ip, StringComparer.Ordinal)
            .OrderByDescending(g => g.Select(x => x.Observation.Source).Distinct(StringComparer.OrdinalIgnoreCase).Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal).First().Key;
        var split = valid.GroupBy(x => x.Family)
            .Any(g => g.Select(x => x.Observation.Ip).Distinct(StringComparer.Ordinal).Skip(1).Any());
        return new IpConsensus
        {
            ConsensusIp = chosen,
            Observations = valid.Select(x => x.Observation).ToArray(),
            RussianVotes = valid.Count(x => x.Observation.IsRussian == true),
            ForeignVotes = valid.Count(x => x.Observation.IsRussian == false),
            IsSplit = split,
            WithinChannelConflict = valid.GroupBy(x => (x.Family, x.Observation.Channel))
                .Any(g => g.Select(x => x.Observation.Ip).Distinct(StringComparer.Ordinal).Skip(1).Any()),
            CrossChannelMismatch = valid.GroupBy(x => x.Family).Any(g =>
            {
                var web = g.Where(x => x.Observation.Channel == IpChannel.Web).Select(x => x.Observation.Ip).ToHashSet(StringComparer.Ordinal);
                var udp = g.Where(x => x.Observation.Channel == IpChannel.Udp).Select(x => x.Observation.Ip).ToHashSet(StringComparer.Ordinal);
                return web.Count > 0 && udp.Count > 0 && !web.Overlaps(udp);
            }),
        };
    }
}
