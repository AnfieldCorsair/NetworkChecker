using NetworkChecker.Core.Observation;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class ObservationBufferTests
{
    [Fact]
    public void Limit_and_drop_count_are_correct_under_concurrency()
    {
        var buffer = new ObservationBuffer(25);
        Parallel.For(0, 1000, i => buffer.Add(new ObservationEvent("ETW", "event", i.ToString(System.Globalization.CultureInfo.InvariantCulture), DateTimeOffset.UtcNow)));
        var result = buffer.Snapshot();
        Assert.Equal(25, result.Events.Count);
        Assert.Equal(975, result.Dropped);
    }

    [Fact]
    public void Negative_limit_is_treated_as_zero()
    {
        var buffer = new ObservationBuffer(-1);
        buffer.Add(new ObservationEvent("WFP", "test", "", DateTimeOffset.UtcNow));
        Assert.Empty(buffer.Snapshot().Events);
        Assert.Equal(1, buffer.Snapshot().Dropped);
    }
}
