using RKNHardering.Core.Models;

namespace RKNHardering.Core.Verdict;

/// <summary>Кросс-модульный консенсус по внешнему IP (порт IpConsensusBuilder).</summary>
public static class IpConsensusBuilder
{
    public static IpConsensus Build(IReadOnlyList<IpObservation> observations)
    {
        if (observations.Count == 0)
            return new IpConsensus();

        var groups = observations
            .Where(o => !string.IsNullOrWhiteSpace(o.Ip))
            .GroupBy(o => o.Ip.Trim())
            .OrderByDescending(g => g.Count())
            .ToList();

        var consensus = groups.First().Key;
        var russianVotes = groups.Sum(g => g.Count(o => o.IsRussian == true));
        var foreignVotes = groups.Sum(g => g.Count(o => o.IsRussian == false));
        var isSplit = groups.Count > 1;

        return new IpConsensus
        {
            ConsensusIp = consensus,
            Observations = observations,
            RussianVotes = russianVotes,
            ForeignVotes = foreignVotes,
            IsSplit = isSplit,
        };
    }
}
