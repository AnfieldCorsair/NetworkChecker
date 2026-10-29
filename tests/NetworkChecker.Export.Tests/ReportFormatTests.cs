using System.IO.Compression;
using System.Text;
using NetworkChecker.Core.Models;
using NetworkChecker.Export.Formats;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Export.Tests;

public class ReportFormatTests
{
    private static readonly CheckRunResult Rich = Sample.RichRun();

    [Fact]
    public void Catalog_lists_all_formats_with_extensions()
    {
        Assert.Equal(7, ReportExporter.Catalog.Count);
        Assert.All(ReportExporter.Catalog, entry =>
        {
            Assert.StartsWith(".", entry.Extension);
            Assert.False(string.IsNullOrWhiteSpace(entry.Title));
            Assert.False(string.IsNullOrWhiteSpace(entry.Description));
        });
        Assert.Contains(ReportExporter.Catalog, e => e.Format == ReportFormat.Pdf);
        Assert.Contains(ReportExporter.Catalog, e => e.Format == ReportFormat.Xlsx);
    }

    [Theory]
    [InlineData(ReportFormat.Pdf, ".pdf")]
    [InlineData(ReportFormat.Docx, ".docx")]
    [InlineData(ReportFormat.Xlsx, ".xlsx")]
    [InlineData(ReportFormat.Csv, ".csv")]
    [InlineData(ReportFormat.Markdown, ".md")]
    [InlineData(ReportFormat.Json, ".json")]
    public void Build_returns_named_non_empty_file(ReportFormat format, string extension)
    {
        var file = ReportExporter.Build(format, Rich);

        Assert.EndsWith(extension, file.FileName);
        Assert.True(file.Content.Length > 200, $"{format}: слишком маленький файл");
        Assert.False(string.IsNullOrWhiteSpace(file.MimeType));
        Assert.Contains("rkn-hardering-", file.FileName);
    }

    [Fact]
    public void Custom_base_name_is_respected()
    {
        var file = ReportExporter.Build(ReportFormat.Json, Rich, "my-report");
        Assert.Equal("my-report.json", file.FileName);
    }

    // ------------------------------------------------------------------ ZIP-форматы

    [Theory]
    [InlineData(ReportFormat.Docx, "word/document.xml", "Обнаружен активный обход")]
    [InlineData(ReportFormat.Xlsx, "xl/workbook.xml", "Итог")]
    [InlineData(ReportFormat.Xlsx, "xl/sharedStrings.xml", "Обнаружен активный обход")]
    public void OpenXml_formats_are_valid_archives(ReportFormat format, string entryPath, string expectedText)
    {
        var file = ReportExporter.Build(format, Rich);
        using var archive = new ZipArchive(new MemoryStream(file.Content), ZipArchiveMode.Read);

        Assert.NotNull(archive.GetEntry("[Content_Types].xml"));
        var entry = archive.GetEntry(entryPath);
        Assert.NotNull(entry);

        using var reader = new StreamReader(entry!.Open());
        var xml = reader.ReadToEnd();
        Assert.False(string.IsNullOrWhiteSpace(xml));
        Assert.Contains(expectedText, xml);
    }

    [Fact]
    public void Docx_contains_plain_language_and_all_modules()
    {
        var xml = ReadZipEntry(ReportExporter.Build(ReportFormat.Docx, Rich), "word/document.xml");

        Assert.Contains("Вердикт", xml);
        Assert.Contains("Что делать", xml);
        foreach (var check in Rich.Checks)
            Assert.Contains(check.Title, xml);
        Assert.Contains("Локальный прокси на 127.0.0.1:1080", xml);
    }

    [Fact]
    public void Xlsx_contains_all_sheets()
    {
        using var archive = new ZipArchive(new MemoryStream(ReportExporter.Build(ReportFormat.Xlsx, Rich).Content));
        var workbook = ReadEntry(archive, "xl/workbook.xml");

        Assert.Contains("Итог", workbook);
        Assert.Contains("Проверки", workbook);
        Assert.Contains("Находки", workbook);
        Assert.Contains("IP-наблюдения", workbook);
    }

    [Fact]
    public void Xlsx_shared_strings_hold_findings()
    {
        using var archive = new ZipArchive(new MemoryStream(ReportExporter.Build(ReportFormat.Xlsx, Rich).Content));
        var shared = ReadEntry(archive, "xl/sharedStrings.xml");

        Assert.Contains("Системный прокси включён", shared);
        Assert.Contains("Локальный обход", shared);
    }

    // ------------------------------------------------------------------------ CSV

    [Fact]
    public void Csv_has_bom_and_semicolon_columns()
    {
        var bytes = ReportExporter.Build(ReportFormat.Csv, Rich).Content;

        Assert.Equal(0xEF, bytes[0]);
        Assert.Equal(0xBB, bytes[1]);
        Assert.Equal(0xBF, bytes[2]);

        var text = Encoding.UTF8.GetString(bytes[3..]);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length >= Rich.Checks.Count);
        Assert.StartsWith("Модуль;Статус;", lines[0]);
        Assert.Contains("ИТОГ;", text);
    }

    [Fact]
    public void Csv_escapes_semicolons_and_quotes()
    {
        var check = Sample.Check(findings: [Finding.Critical("Находка; с точкой с запятой", "Кавычка \" внутри")]);
        var run = WithChecks(Sample.CleanRun(), [check]);

        var text = Encoding.UTF8.GetString(ReportExporter.Build(ReportFormat.Csv, run).Content);
        Assert.Contains("\"Находка; с точкой с запятой\"", text);
        Assert.Contains("\"\"", text);
    }

    // ------------------------------------------------------------------------ PDF

    [Fact]
    public void Pdf_has_valid_header_and_eof()
    {
        var bytes = ReportExporter.Build(ReportFormat.Pdf, Rich).Content;
        var head = Encoding.ASCII.GetString(bytes, 0, 5);
        Assert.Equal("%PDF-", head);

        var tail = Encoding.ASCII.GetString(bytes, bytes.Length - 32, 32);
        Assert.Contains("%%EOF", tail);
    }

    [Fact]
    public void Pdf_is_multi_page_and_uses_embedded_cyrillic_font()
    {
        var bytes = ReportExporter.Build(ReportFormat.Pdf, Rich).Content;
        Assert.True(bytes.Length > 8000, "PDF подозрительно маленький");

        // Встроенный TrueType-шрифт обязан присутствовать, иначе кириллица станет квадратиками.
        Assert.Contains("FontFile2", Encoding.Latin1.GetString(bytes));
    }

    [Fact]
    public void Pdf_fonts_are_embedded_in_assembly()
    {
        Assert.True(PdfExporter.FontsAvailable());
    }

    [Fact]
    public void Pdf_renders_clean_run_too()
    {
        var bytes = ReportExporter.Build(ReportFormat.Pdf, Sample.CleanRun()).Content;
        Assert.Equal("%PDF-", Encoding.ASCII.GetString(bytes, 0, 5));
        Assert.True(bytes.Length > 3000);
    }

    // --------------------------------------------------------------------- helpers

    private static string ReadZipEntry(ReportFile file, string path)
    {
        using var archive = new ZipArchive(new MemoryStream(file.Content), ZipArchiveMode.Read);
        return ReadEntry(archive, path);
    }

    private static string ReadEntry(ZipArchive archive, string path)
    {
        var entry = archive.GetEntry(path);
        Assert.NotNull(entry);
        using var reader = new StreamReader(entry!.Open());
        return reader.ReadToEnd();
    }

    private static CheckRunResult WithChecks(CheckRunResult template, IReadOnlyList<CheckResult> checks) =>
        new()
        {
            StartedAt = template.StartedAt,
            FinishedAt = template.FinishedAt,
            Checks = checks,
            Verdict = template.Verdict,
            IpConsensus = template.IpConsensus,
            Environment = template.Environment,
        };
}
