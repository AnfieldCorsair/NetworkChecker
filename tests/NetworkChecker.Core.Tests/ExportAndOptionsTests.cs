using NetworkChecker.Core.Export;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class ExportTests
{
    private static CheckRunResult Sample()
    {
        var checks = new List<CheckResult>
        {
            new()
            {
                Category = CheckCategory.DirectSigns,
                Title = "Прямые признаки",
                Subtitle = "Прокси в системе",
                Status = CheckStatus.Detected,
                Weight = 30,
                Duration = TimeSpan.FromSeconds(1.5),
                Metrics = [new Metric("Системный прокси", "http://127.0.0.1:8080", "WinINET")],
                Findings =
                [
                    Finding.Critical("Системный прокси включён", "В системе задан прокси", "127.0.0.1:8080"),
                    Finding.Info("Прочее"),
                ],
            },
            new()
            {
                Category = CheckCategory.GeoIp,
                Title = "GeoIP и репутация IP",
                Status = CheckStatus.Clean,
                Weight = 20,
            },
        };

        return new CheckRunResult
        {
            StartedAt = new DateTimeOffset(2026, 10, 29, 12, 0, 0, TimeSpan.Zero),
            FinishedAt = new DateTimeOffset(2026, 10, 29, 12, 0, 9, TimeSpan.Zero),
            Checks = checks,
            Verdict = new VerdictResult
            {
                Level = RiskLevel.Detected,
                Score = 82,
                Headline = "Обнаружен обход",
                Summary = "Прямые признаки подтверждены.",
                Reasons = ["Прямые признаки: системный прокси"],
            },
            IpConsensus = new IpConsensus { ConsensusIp = "1.2.3.4" },
            Environment = new EnvironmentSnapshot { OsDescription = "Windows 11 (build 26100)" },
        };
    }

    [Fact]
    public void Markdown_contains_key_sections()
    {
        var md = ResultExport.ToMarkdown(Sample());

        Assert.Contains("# NetworkChecker", md);
        Assert.Contains("## Сводка", md);
        Assert.Contains("## Модули", md);
        Assert.Contains("| Прямые признаки | Обнаружено |", md);
        Assert.Contains("🔴 critical", md);
        Assert.Contains("127.0.0.1:8080", md);
    }

    [Fact]
    public void Json_is_parseable_and_roundtrips_verdict()
    {
        var json = ResultExport.ToJson(Sample());
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var verdict = doc.RootElement.GetProperty("verdict");
        Assert.Equal(82, verdict.GetProperty("score").GetInt32());
        Assert.Equal(2, doc.RootElement.GetProperty("checks").GetArrayLength());
    }
}

public class OptionsTests
{
    [Fact]
    public void Clone_is_deep_for_lists()
    {
        var options = new RknOptions();
        var clone = options.Clone();

        clone.ReachabilityTargets.Add("added.test");

        Assert.DoesNotContain("added.test", options.ReachabilityTargets);
        Assert.NotSame(options.LocalProxyPorts, clone.LocalProxyPorts);
    }

    [Fact]
    public void Defaults_are_sane()
    {
        var options = new RknOptions();

        Assert.Contains(1080, options.LocalProxyPorts);
        Assert.Contains("stun.l.google.com:19302", options.StunServers);
        Assert.True(options.GeoIpProviders.All(p => p.StartsWith("https://", StringComparison.Ordinal)));
        Assert.InRange(options.MaxTraceHops, 1, 64);
    }
}
