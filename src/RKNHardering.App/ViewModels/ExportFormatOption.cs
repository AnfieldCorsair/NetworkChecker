using RKNHardering.Export;

namespace RKNHardering.App.ViewModels;

/// <summary>Пункт выпадающего списка форматов отчёта.</summary>
public sealed record ExportFormatOption(ReportFormat Format, string Title, string Extension, string Description)
{
    public string Display => $"{Title} — {Description}";

    public static IReadOnlyList<ExportFormatOption> All { get; } = ReportExporter.Catalog
        .Select(entry => new ExportFormatOption(entry.Format, entry.Title, entry.Extension, entry.Description))
        .ToList();
}
