using RKNHardering.Core.Models;
using RKNHardering.Core.Verdict;
using Xunit;

namespace RKNHardering.Core.Tests;

public class IpConsensusTests
{
    [Fact]
    public void Empty_observations_give_empty_consensus()
    {
        var consensus = IpConsensusBuilder.Build([]);
        Assert.False(consensus.HasConsensus);
        Assert.Equal("нет данных", consensus.Summary);
    }

    [Fact]
    public void Majority_ip_wins()
    {
        var observations = new List<IpObservation>
        {
            new("ipify", "1.1.1.1", null),
            new("myip", "1.1.1.1", null),
            new("stun", "2.2.2.2", null),
        };

        var consensus = IpConsensusBuilder.Build(observations);

        Assert.Equal("1.1.1.1", consensus.ConsensusIp);
        Assert.True(consensus.IsSplit);
    }

    [Fact]
    public void Same_ip_everywhere_is_not_split()
    {
        var observations = new List<IpObservation>
        {
            new("ipify", "5.5.5.5", false),
            new("ipapi", "5.5.5.5", false),
        };

        var consensus = IpConsensusBuilder.Build(observations);

        Assert.False(consensus.IsSplit);
        Assert.Equal(2, consensus.ForeignVotes);
        Assert.Equal(0, consensus.RussianVotes);
    }

    [Fact]
    public void Votes_are_counted_by_flag()
    {
        var observations = new List<IpObservation>
        {
            new("a", "5.5.5.5", true),
            new("b", "5.5.5.5", false),
            new("c", "5.5.5.5", null),
        };

        var consensus = IpConsensusBuilder.Build(observations);

        Assert.Equal(1, consensus.RussianVotes);
        Assert.Equal(1, consensus.ForeignVotes);
        Assert.False(consensus.IsSplit);
    }
}
