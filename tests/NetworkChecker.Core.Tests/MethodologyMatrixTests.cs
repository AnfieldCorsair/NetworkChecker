using System.Text.Json;
using NetworkChecker.Core.Export;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Verdict;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>Матрица решений из опубликованной методики и её экспорт.</summary>
public class MethodologyMatrixTests
{
    private static CheckResult Detected(CheckCategory category, params Finding[] findings) =>
        Sample.Check(category, status: CheckStatus.Detected, findings: findings);

    private static CheckResult Clean(CheckCategory category) =>
        Sample.Check(category, status: CheckStatus.Clean, findings: []);

    [Fact]
    public void Server_and_device_signals_together_are_not_called_a_verdict()
    {
        var checks = new[]
        {
            Detected(CheckCategory.GeoIp, Finding.Warning("IP помечен как proxy/VPN/Tor")),
            Detected(CheckCategory.DirectSigns,
                new Finding { Severity = Severity.Critical, Title = "Системный прокси включён", Kind = EvidenceKind.ConfiguredProxy }),
        };

        var matrix = MethodologyMatrix.Build(checks, new IpConsensus { ConsensusIp = "203.0.113.7" });

        Assert.True(matrix.HasServerSideSignal);
        Assert.True(matrix.HasDeviceSideSignal);
        Assert.Contains("совпали", matrix.Decision);
        Assert.Contains("только модель", matrix.Explanation);
        Assert.False(matrix.RouterVpnHint);
        Assert.NotEmpty(matrix.Signals);
    }

    [Fact]
    public void Server_signal_without_local_traces_suggests_router_or_bad_geoip()
    {
        var checks = new[]
        {
            Detected(CheckCategory.GeoIp, Finding.Warning("IP помечен как proxy/VPN/Tor")),
            Clean(CheckCategory.DirectSigns),
            Clean(CheckCategory.IndirectSigns),
            Clean(CheckCategory.Bypass),
            Clean(CheckCategory.CallTransport),
            Clean(CheckCategory.CdnPulling),
            Clean(CheckCategory.RttTriangulation),
            Clean(CheckCategory.IcmpSpoofing),
        };

        var matrix = MethodologyMatrix.Build(checks, new IpConsensus { ConsensusIp = "203.0.113.7", IsSplit = true });

        Assert.True(matrix.HasServerSideSignal);
        Assert.False(matrix.HasDeviceSideSignal);
        Assert.True(matrix.RouterVpnHint);
        Assert.Contains("одного сигнала недостаточно", matrix.Decision);
        Assert.Contains("роутер", string.Join(" ", matrix.FalsePositiveCaveats));
    }

    [Fact]
    public void Failed_or_skipped_checks_are_missing_data_not_absence()
    {
        var checks = new[]
        {
            Sample.Check(CheckCategory.GeoIp, status: CheckStatus.Skipped, findings: []),
            Clean(CheckCategory.DirectSigns),
        };

        var matrix = MethodologyMatrix.Build(checks, new IpConsensus());

        Assert.True(matrix.HasMissingData);
        Assert.Equal("Данных недостаточно для вывода по матрице", matrix.Decision);
        Assert.Equal(MethodologySignalState.Unknown,
            matrix.Signals.First(s => s.Name.Contains("Метка VPN")).State);
        Assert.NotEmpty(matrix.NotMeasurable);
    }

    [Fact]
    public void Mobile_stage_is_always_marked_not_applicable()
    {
        var matrix = MethodologyMatrix.Build([Clean(CheckCategory.GeoIp), Clean(CheckCategory.DirectSigns)], new IpConsensus());

        Assert.Contains(matrix.Signals, s => s.Stage.Contains("Мобильное") && s.State == MethodologySignalState.Unknown);
        Assert.Contains("ТСПУ", string.Join(" ", matrix.NotMeasurable));
    }

    private static CheckRunResult Run(IReadOnlyList<CheckResult> checks)
    {
        var now = DateTimeOffset.UtcNow;
        return new CheckRunResult
        {
            StartedAt = now,
            FinishedAt = now.AddSeconds(3),
            Checks = checks,
            Verdict = VerdictEngine.Build(checks, new IpConsensus()),
            Environment = new EnvironmentSnapshot { OsDescription = "Windows 11 (тест)" },
        };
    }

    [Fact]
    public void Markdown_export_contains_the_methodology_section()
    {
        var markdown = ResultExport.ToMarkdown(Run([Clean(CheckCategory.DirectSigns), Clean(CheckCategory.GeoIp)]));

        Assert.Contains("# NetworkChecker", markdown);
        Assert.Contains("## Соответствие методике", markdown);
        Assert.Contains("Что локально измерить нельзя", markdown);
        Assert.Contains("Почему одного сигнала недостаточно", markdown);
    }

    [Fact]
    public void Json_export_includes_methodology_and_keeps_score()
    {
        var json = ResultExport.ToJson(Run([Clean(CheckCategory.DirectSigns), Clean(CheckCategory.GeoIp)]));
        using var doc = JsonDocument.Parse(json);
        var verdict = doc.RootElement.GetProperty("verdict");

        Assert.True(verdict.TryGetProperty("score", out _));
        Assert.True(verdict.TryGetProperty("methodology", out var matrix));
        Assert.True(matrix.TryGetProperty("decision", out _));
        Assert.True(matrix.TryGetProperty("signals", out var signals));
        Assert.True(signals.GetArrayLength() > 0);
        Assert.True(doc.RootElement.TryGetProperty("checks", out _));
    }
}
