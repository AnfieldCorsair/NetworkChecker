using System.Text;
using NetworkChecker.Core.Models;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Export.Tests;

public class HtmlReportTests
{
    private static string Html(CheckRunResult result) =>
        Encoding.UTF8.GetString(ReportExporter.Build(ReportFormat.Html, result, "report").Content);

    [Fact]
    public void Html_is_registered_in_catalog()
    {
        var entry = Assert.Single(ReportExporter.Catalog, e => e.Format == ReportFormat.Html);
        Assert.Equal(".html", entry.Extension);
    }

    [Fact]
    public void File_has_correct_extension_and_mime()
    {
        var file = ReportExporter.Build(ReportFormat.Html, Sample.RichRun(), "rkn");

        Assert.Equal("rkn.html", file.FileName);
        Assert.Equal("text/html", file.MimeType);
    }

    [Fact]
    public void Document_is_self_contained()
    {
        var html = Html(Sample.RichRun());

        Assert.StartsWith("<!DOCTYPE html>", html);
        // Никаких внешних ресурсов: отчёт должен открываться без интернета.
        // (Ссылки в данных — например адрес прокси — это содержимое, а не загрузка ресурсов.)
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<style>", html);
    }

    [Fact]
    public void Verdict_and_plain_language_are_present()
    {
        var run = Sample.RichRun();
        var html = Html(run);

        Assert.Contains(run.Verdict.Headline, html);
        Assert.Contains(run.Verdict.Score.ToString(System.Globalization.CultureInfo.InvariantCulture), html);
        Assert.Contains("Коротко по фактам", html);
        Assert.Contains("Общая картина", html);
    }

    [Fact]
    public void Every_module_gets_a_table_row()
    {
        var run = Sample.RichRun();
        var html = Html(run);

        foreach (var check in run.Checks)
            Assert.Contains(check.Title, html);
    }

    [Fact]
    public void Findings_are_rendered_with_severity()
    {
        var html = Html(Sample.RichRun());

        Assert.Contains("Находки", html);
        Assert.Contains("КРИТИЧНО", html);
        Assert.Contains("Локальный прокси на 127.0.0.1:1080", html);
    }

    [Fact]
    public void Environment_block_shows_privileges_and_privacy()
    {
        var html = Html(Sample.RichRun());

        Assert.Contains("Окружение", html);
        Assert.Contains("Права администратора", html);
        Assert.Contains("Приватный режим", html);
    }

    [Fact]
    public void Dangerous_characters_are_escaped()
    {
        var run = Sample.CleanRun();
        var tampered = new CheckRunResult
        {
            StartedAt = run.StartedAt,
            FinishedAt = run.FinishedAt,
            Checks =
            [
                new CheckResult
                {
                    Category = CheckCategory.GeoIp,
                    Title = "<script>alert('xss')</script>",
                    Subtitle = "a & b",
                    Status = CheckStatus.Clean,
                    Weight = 10,
                },
            ],
            Verdict = run.Verdict,
            IpConsensus = run.IpConsensus,
            Environment = run.Environment,
        };

        var html = Html(tampered);

        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("a &amp; b", html);
    }

    [Fact]
    public void Html_is_larger_than_markdown_but_reasonable()
    {
        var html = Encoding.UTF8.GetByteCount(Html(Sample.RichRun()));

        Assert.InRange(html, 4_000, 400_000);
    }
}
