using NetworkChecker.Core.Models;
using NetworkChecker.Core.Platform;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class CheckRunnerTests
{
    [Fact]
    public async Task Runs_all_checks_and_preserves_declared_order()
    {
        var checks = new Core.Abstractions.ICheck[]
        {
            FakeCheck.Detected(CheckCategory.DirectSigns, 30),
            FakeCheck.Slow(CheckCategory.GeoIp, 40),
            FakeCheck.Detected(CheckCategory.Bypass, 30),
        };
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());

        var result = await runner.RunAsync(Sample.Options(), privacyMode: false, CancellationToken.None);

        Assert.Equal(3, result.Checks.Count);
        Assert.Equal(CheckCategory.DirectSigns, result.Checks[0].Category);
        Assert.Equal(CheckCategory.GeoIp, result.Checks[1].Category);
        Assert.Equal(CheckCategory.Bypass, result.Checks[2].Category);
        Assert.True(result.FinishedAt >= result.StartedAt);
    }

    [Fact]
    public async Task Failing_check_becomes_failed_result_and_does_not_break_run()
    {
        var checks = new Core.Abstractions.ICheck[]
        {
            FakeCheck.Failing(CheckCategory.CdnPulling),
            FakeCheck.Detected(CheckCategory.DirectSigns, 30),
        };
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());

        var result = await runner.RunAsync(Sample.Options(), false, CancellationToken.None);

        var failed = result.Checks.Single(c => c.Category == CheckCategory.CdnPulling);
        Assert.Equal(CheckStatus.Failed, failed.Status);
        Assert.Contains("сломалось", failed.Error);
        Assert.Equal(CheckStatus.Detected, result.Checks.Single(c => c.Category == CheckCategory.DirectSigns).Status);
    }

    [Fact]
    public async Task Progress_events_fire_once_per_check()
    {
        var checks = new Core.Abstractions.ICheck[]
        {
            FakeCheck.Slow(CheckCategory.GeoIp, 10),
            FakeCheck.Slow(CheckCategory.Bypass, 20),
            FakeCheck.Slow(CheckCategory.CallTransport, 5),
        };
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());
        var events = new List<CheckProgressEventArgs>();
        runner.Progress += (_, args) => events.Add(args);

        await runner.RunAsync(Sample.Options(), false, CancellationToken.None);

        Assert.Equal(3, events.Count);
        Assert.Equal([1, 2, 3], events.Select(e => e.Completed).OrderBy(v => v));
        Assert.Equal(100, events[^1].Percent, 3);
        Assert.All(events, e => Assert.InRange(e.Percent, 1, 100));
        Assert.All(events, e => Assert.NotNull(e.Result));
        Assert.All(events, e => Assert.Equal(3, e.Total));
    }

    [Fact]
    public async Task Ip_observations_from_different_checks_build_consensus()
    {
        var checks = new Core.Abstractions.ICheck[]
        {
            FakeCheck.ReportingIp(CheckCategory.GeoIp, "1.1.1.1"),
            FakeCheck.ReportingIp(CheckCategory.CdnPulling, "1.1.1.1"),
            FakeCheck.ReportingIp(CheckCategory.CallTransport, "2.2.2.2"),
        };
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());

        var result = await runner.RunAsync(Sample.Options(), false, CancellationToken.None);

        Assert.Equal("1.1.1.1", result.IpConsensus.ConsensusIp);
        Assert.True(result.IpConsensus.IsSplit);
        Assert.Equal(3, result.IpConsensus.Observations.Count);
    }

    [Fact]
    public async Task Environment_snapshot_is_taken_from_platform_probe()
    {
        var platform = FakePlatformProbe.Clean();
        platform.Os = new OsInfo { Description = "Windows 11 (build 26100)", IsWindows = true };
        var runner = new CheckRunner([FakeCheck.Detected(CheckCategory.GeoIp)], platform);

        var result = await runner.RunAsync(Sample.Options(), privacyMode: false, CancellationToken.None);

        Assert.Contains("26100", result.Environment.OsDescription);
        Assert.Single(result.Environment.Adapters);
        Assert.Equal(Environment.MachineName, result.Environment.MachineName);
    }

    [Fact]
    public async Task Privacy_mode_masks_machine_and_user()
    {
        var runner = new CheckRunner([FakeCheck.Detected(CheckCategory.GeoIp)], FakePlatformProbe.Clean());

        var result = await runner.RunAsync(Sample.Options(), privacyMode: true, CancellationToken.None);

        Assert.True(result.Environment.PrivacyMode);
        Assert.Equal("•••", result.Environment.MachineName);
        Assert.Equal("•••", result.Environment.UserName);
    }

    [Fact]
    public async Task Environment_falls_back_when_platform_throws()
    {
        var platform = new FakePlatformProbe { ThrowOn = new InvalidOperationException("нет доступа") };
        var runner = new CheckRunner([FakeCheck.Detected(CheckCategory.GeoIp)], platform);

        var result = await runner.RunAsync(Sample.Options(), false, CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(result.Environment.OsDescription));
        Assert.Empty(result.Environment.Adapters);
    }

    [Fact]
    public async Task Cancellation_stops_the_run()
    {
        var runner = new CheckRunner(
            [FakeCheck.Slow(CheckCategory.GeoIp, 5000), FakeCheck.Slow(CheckCategory.Bypass, 5000)],
            FakePlatformProbe.Clean());
        using var cts = new CancellationTokenSource(50);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.RunAsync(Sample.Options(), false, cts.Token));
    }

    /// <summary>Счётчик одновременно выполняющихся проверок — детерминированнее секундомера.</summary>
    private static (Core.Abstractions.ICheck[] Checks, Func<int> MaxSeen) ConcurrencyProbe(int count, int delayMs)
    {
        var active = 0;
        var max = 0;
        var sync = new Lock();
        var checks = Enumerable.Range(0, count).Select(_ => (Core.Abstractions.ICheck)new FakeCheck(
            CheckCategory.GeoIp,
            behaviour: async (_, ct) =>
            {
                lock (sync) { active++; max = Math.Max(max, active); }
                try { await Task.Delay(delayMs, ct).ConfigureAwait(false); }
                finally { lock (sync) { active--; } }
                return new CheckResult
                {
                    Category = CheckCategory.GeoIp,
                    Title = "Тест",
                    Status = CheckStatus.Clean,
                    Weight = 10,
                };
            })).ToArray();
        return (checks, () => max);
    }

    [Fact]
    public async Task Checks_run_in_parallel()
    {
        var (checks, maxSeen) = ConcurrencyProbe(count: 6, delayMs: 40);
        var options = Sample.Options();
        options.MaxParallelChecks = 6;
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());

        await runner.RunAsync(options, false, CancellationToken.None);

        Assert.True(maxSeen() > 1, $"проверки шли последовательно (одновременно выполнялось {maxSeen()})");
    }

    [Fact]
    public async Task MaxParallelChecks_is_respected()
    {
        var (checks, maxSeen) = ConcurrencyProbe(count: 8, delayMs: 40);
        var options = Sample.Options();
        options.MaxParallelChecks = 2;
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());

        await runner.RunAsync(options, false, CancellationToken.None);

        Assert.InRange(maxSeen(), 1, 2);
    }

    [Fact]
    public async Task Verdict_is_detected_when_direct_and_geo_signals_agree()
    {
        var checks = new Core.Abstractions.ICheck[]
        {
            FakeCheck.Detected(CheckCategory.DirectSigns, 30),
            FakeCheck.Detected(CheckCategory.GeoIp, 20, Severity.Warning),
        };
        var runner = new CheckRunner(checks, FakePlatformProbe.Clean());

        var result = await runner.RunAsync(Sample.Options(), false, CancellationToken.None);

        Assert.Equal(RiskLevel.Detected, result.Verdict.Level);
        Assert.NotEmpty(result.Verdict.Reasons);
    }
}
