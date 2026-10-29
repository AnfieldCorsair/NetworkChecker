using RKNHardering.Core.Export;
using RKNHardering.Core.Models;
using RKNHardering.Export.Formats;

namespace RKNHardering.Export;

/// <summary>Форматы отчёта, которые понимает обычный пользователь.</summary>
public enum ReportFormat
{
    /// <summary>PDF — читать и печатать.</summary>
    Pdf,
    /// <summary>DOCX — править в Word.</summary>
    Docx,
    /// <summary>XLSX — таблицы с фильтрами.</summary>
    Xlsx,
    /// <summary>CSV — открыть где угодно, вплоть до блокнота.</summary>
    Csv,
    /// <summary>Markdown — для git/вики/issue.</summary>
    Markdown,
    /// <summary>JSON — для автоматизации.</summary>
    Json,
}

public sealed record ReportFile(string FileName, byte[] Content, string MimeType, string Description);

/// <summary>Единая точка экспорта: формат → готовый файл.</summary>
public static class ReportExporter
{
    public static IReadOnlyList<(ReportFormat Format, string Title, string Extension, string Description)> Catalog { get; } =
    [
        (ReportFormat.Pdf, "PDF", ".pdf", "отчёт для чтения и печати"),
        (ReportFormat.Docx, "Word (DOCX)", ".docx", "документ, который можно править"),
        (ReportFormat.Xlsx, "Excel (XLSX)", ".xlsx", "таблицы с фильтрами"),
        (ReportFormat.Csv, "CSV", ".csv", "универсальная таблица"),
        (ReportFormat.Markdown, "Markdown", ".md", "для вики и issue"),
        (ReportFormat.Json, "JSON", ".json", "сырые данные для автоматизации"),
    ];

    public static ReportFile Build(ReportFormat format, CheckRunResult result, string? baseName = null)
    {
        var name = baseName ?? $"rkn-hardering-{result.StartedAt.ToLocalTime():yyyyMMdd-HHmm}";
        return format switch
        {
            ReportFormat.Pdf => new ReportFile(name + ".pdf", PdfExporter.Build(result), "application/pdf", "PDF-отчёт"),
            ReportFormat.Docx => new ReportFile(name + ".docx", DocxExporter.Build(result),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "документ Word"),
            ReportFormat.Xlsx => new ReportFile(name + ".xlsx", XlsxExporter.Build(result),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "книга Excel"),
            ReportFormat.Csv => new ReportFile(name + ".csv", CsvExporter.Build(result), "text/csv", "таблица CSV"),
            ReportFormat.Markdown => new ReportFile(name + ".md", System.Text.Encoding.UTF8.GetBytes(ResultExport.ToMarkdown(result)),
                "text/markdown", "Markdown-отчёт"),
            ReportFormat.Json => new ReportFile(name + ".json", System.Text.Encoding.UTF8.GetBytes(ResultExport.ToJson(result)),
                "application/json", "JSON-данные"),
            _ => throw new ArgumentOutOfRangeException(nameof(format), format, "Неизвестный формат отчёта"),
        };
    }
}
