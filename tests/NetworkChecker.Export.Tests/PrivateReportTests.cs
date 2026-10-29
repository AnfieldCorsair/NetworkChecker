using System.IO.Compression;
using System.Text;
using NetworkChecker.Core.Models;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Export.Tests;

public class PrivateReportTests
{
    [Theory]
    [InlineData(ReportFormat.Json)]
    [InlineData(ReportFormat.Html)]
    [InlineData(ReportFormat.Csv)]
    [InlineData(ReportFormat.Markdown)]
    [InlineData(ReportFormat.Docx)]
    [InlineData(ReportFormat.Xlsx)]
    public void Forced_private_export_removes_raw_diagnostics(ReportFormat format)
    {
        var original = Sample.RichRun();
        var file = ReportExporter.Build(format, original, forcePrivate: true);
        var content = format is ReportFormat.Docx or ReportFormat.Xlsx ? ReadArchiveText(file.Content) : Encoding.UTF8.GetString(file.Content);
        Assert.DoesNotContain("127.0.0.1", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\Tools", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(original.IpConsensus.ConsensusIp!, content, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("скрыт", content, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(original.IpConsensus.Observations); // projection must not mutate the original
    }

    [Fact]
    public void Projection_drops_arbitrary_sensitive_strings_and_environment()
    {
        var original = Sample.RichRun();
        var safe = PrivateRunProjection.Create(original);
        Assert.Null(safe.IpConsensus.ConsensusIp);
        Assert.Empty(safe.IpConsensus.Observations);
        Assert.Empty(safe.Environment.Adapters);
        Assert.Empty(safe.Verdict.Reasons);
        Assert.All(safe.Checks, c => { Assert.Empty(c.Metrics); Assert.All(c.Findings, f => Assert.Null(f.Evidence)); });
    }

    [Fact]
    public void Private_mode_on_original_run_automatically_sanitizes_export()
    {
        var source = Sample.RichRun();
        var marked = new CheckRunResult
        {
            Id = source.Id,
            StartedAt = source.StartedAt,
            FinishedAt = source.FinishedAt,
            Checks = source.Checks,
            Verdict = source.Verdict,
            IpConsensus = source.IpConsensus,
            Environment = new EnvironmentSnapshot { OsDescription = "sensitive-machine", PrivacyMode = true },
        };
        var text = Encoding.UTF8.GetString(ReportExporter.Build(ReportFormat.Json, marked).Content);
        Assert.DoesNotContain(source.IpConsensus.ConsensusIp!, text, StringComparison.Ordinal);
        Assert.DoesNotContain("sensitive-machine", text, StringComparison.Ordinal);
    }

    private static string ReadArchiveText(byte[] bytes)
    {
        using var archive = new ZipArchive(new MemoryStream(bytes));
        var text = new StringBuilder();
        foreach (var entry in archive.Entries.Where(e => e.FullName.EndsWith(".xml", StringComparison.Ordinal)))
        {
            using var reader = new StreamReader(entry.Open());
            text.Append(reader.ReadToEnd());
        }
        return text.ToString();
    }
}
