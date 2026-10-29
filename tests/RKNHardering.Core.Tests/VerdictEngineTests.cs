using RKNHardering.Core.Models;
using RKNHardering.Core.Verdict;
using Xunit;

namespace RKNHardering.Core.Tests;

public class VerdictEngineTests
{
    private static CheckResult Check(
        CheckCategory category,
        int weight,
        CheckStatus status,
        params Severity[] severities)
    {
        return new CheckResult
        {
            Category = category,
            Title = category.ToString(),
            Status = status,
            Weight = weight,
            Findings = severities.Select(s => new Finding { Severity = s, Title = s.ToString() }).ToArray(),
        };
    }

    [Fact]
    public void All_clean_gives_clean_verdict()
    {
        var checks = new[]
        {
            Check(CheckCategory.DirectSigns, 30, CheckStatus.Clean),
            Check(CheckCategory.IndirectSigns, 20, CheckStatus.Clean),
            Check(CheckCategory.GeoIp, 20, CheckStatus.Clean),
        };

        var verdict = VerdictEngine.Build(checks, new IpConsensus { ConsensusIp = "5.5.5.5" });

        Assert.Equal(RiskLevel.Clean, verdict.Level);
        Assert.Equal(0, verdict.Score);
    }

    [Fact]
    public void Direct_critical_plus_geo_gives_detected()
    {
        var checks = new[]
        {
            Check(CheckCategory.DirectSigns, 30, CheckStatus.Detected, Severity.Critical),
            Check(CheckCategory.GeoIp, 20, CheckStatus.Detected, Severity.Warning),
        };

        var verdict = VerdictEngine.Build(checks, new IpConsensus { ConsensusIp = "1.2.3.4" });

        Assert.Equal(RiskLevel.Detected, verdict.Level);
        Assert.True(verdict.Score >= 60);
        Assert.NotEmpty(verdict.Reasons);
    }

    [Fact]
    public void Foreign_ip_without_hosting_is_only_needs_review()
    {
        var checks = new[]
        {
            Check(CheckCategory.GeoIp, 20, CheckStatus.NeedsReview, Severity.Notice),
        };

        var verdict = VerdictEngine.Build(checks, new IpConsensus { ConsensusIp = "1.2.3.4" });

        Assert.Equal(RiskLevel.NeedsReview, verdict.Level);
        Assert.InRange(verdict.Score, 25, 59);
    }

    [Fact]
    public void Split_ip_consensus_forces_review_even_without_checks()
    {
        var checks = new[] { Check(CheckCategory.DirectSigns, 30, CheckStatus.Clean) };
        var consensus = new IpConsensus { ConsensusIp = "1.2.3.4", IsSplit = true };

        var verdict = VerdictEngine.Build(checks, consensus);

        Assert.True(verdict.Level >= RiskLevel.NeedsReview);
        Assert.Contains(verdict.Reasons, r => r.Contains("разные внешние IP"));
    }

    [Fact]
    public void Diagnostic_check_with_zero_weight_does_not_affect_score()
    {
        var baseline = VerdictEngine.Build([Check(CheckCategory.DirectSigns, 30, CheckStatus.Clean)], new IpConsensus());
        var withDiagnostics = VerdictEngine.Build(
        [
            Check(CheckCategory.DirectSigns, 30, CheckStatus.Clean),
            Check(CheckCategory.IpComparison, 0, CheckStatus.Detected, Severity.Critical),
        ], new IpConsensus());

        Assert.Equal(baseline.Score, withDiagnostics.Score);
        Assert.Equal(baseline.Level, withDiagnostics.Level);
    }

    [Fact]
    public void Score_is_clamped_and_failed_modules_are_reported()
    {
        var checks = new[]
        {
            Check(CheckCategory.DirectSigns, 30, CheckStatus.Detected, Severity.Critical),
            Check(CheckCategory.Bypass, 30, CheckStatus.Detected, Severity.Critical),
            Check(CheckCategory.GeoIp, 20, CheckStatus.Detected, Severity.Critical),
            Check(CheckCategory.IndirectSigns, 20, CheckStatus.Detected, Severity.Critical),
            Check(CheckCategory.CallTransport, 10, CheckStatus.Failed),
        };

        var verdict = VerdictEngine.Build(checks, new IpConsensus { ConsensusIp = "1.2.3.4" });

        Assert.InRange(verdict.Score, 0, 100);
        Assert.Equal(RiskLevel.Detected, verdict.Level);
        Assert.Contains("неполный", verdict.Summary);
    }
}
