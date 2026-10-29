using System.Globalization;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using RKNHardering.Core.Models;
using RKNHardering.Core.Plain;

namespace RKNHardering.Export.Formats;

/// <summary>DOCX: обычный документ, который можно открыть в Word и распечатать.</summary>
public static class DocxExporter
{
    private const string Font = "Calibri";

    public static byte[] Build(CheckRunResult result)
    {
        using var stream = new MemoryStream();
        using (var document = WordprocessingDocument.Create(stream, WordprocessingDocumentType.Document))
        {
            var main = document.AddMainDocumentPart();
            var body = new Body();
            main.Document = new Document(body);

            body.Append(Paragraph("Отчёт RKNHardering PC", size: 36, bold: true, spaceAfter: 60));
            body.Append(Paragraph($"{result.StartedAt.ToLocalTime():dd.MM.yyyy HH:mm} · {result.Environment.OsDescription}",
                size: 18, color: "6B7C8F", spaceAfter: 240));

            // Вердикт
            var plain = PlainLanguage.ForVerdict(result.Verdict, result.Checks);
            body.Append(Heading("Вердикт"));
            body.Append(Paragraph($"{result.Verdict.Headline} · {result.Verdict.Score}/100", size: 26, bold: true,
                color: ColourOf(result.Verdict.Level), spaceAfter: 80));
            body.Append(Paragraph(plain.WhatItMeans, spaceAfter: 80));
            body.Append(Paragraph($"Что делать: {plain.Advice}", size: 20, color: "44546A", spaceAfter: 200));

            if (result.Verdict.Reasons.Count > 0)
            {
                body.Append(Heading("Почему такой вывод"));
                foreach (var reason in result.Verdict.Reasons)
                    body.Append(Bullet(reason));
            }

            body.Append(Heading("Коротко по проверкам"));
            body.Append(BuildChecksTable(result));

            body.Append(Heading("Подробности"));
            foreach (var check in result.Checks)
            {
                body.Append(Paragraph($"{check.Title} — {check.StatusText}", size: 24, bold: true, spaceAfter: 40));
                body.Append(Paragraph($"{PlainLanguage.WhatWeChecked(check.Category)}. {check.StatusText}. " +
                                      $"Находок: {check.Findings.Count}, время: {check.Duration.TotalSeconds.ToString("F1", CultureInfo.InvariantCulture)} с.",
                    size: 19, color: "6B7C8F", spaceAfter: 60));

                if (!string.IsNullOrWhiteSpace(check.Error))
                    body.Append(Paragraph($"Ошибка: {check.Error}", size: 19, color: "B03A38", spaceAfter: 60));

                if (check.Metrics.Count > 0)
                {
                    foreach (var metric in check.Metrics)
                        body.Append(Bullet($"{metric.Label}: {metric.Value}{(metric.Hint is null ? "" : $" ({metric.Hint})")}"));
                }

                foreach (var finding in check.Findings.OrderByDescending(f => f.Severity))
                {
                    body.Append(Bullet($"[{SeverityText(finding.Severity)}] {finding.Title}" +
                                       (string.IsNullOrWhiteSpace(finding.Detail) ? "" : $" — {finding.Detail}"),
                        severity: finding.Severity));
                    if (!string.IsNullOrWhiteSpace(finding.Evidence))
                        body.Append(Paragraph(finding.Evidence!, size: 17, color: "6B7C8F", indent: 720, spaceAfter: 60));
                }
            }

            body.Append(Heading("Служебное"));
            body.Append(Bullet($"Внешний IP: {result.IpConsensus.ConsensusIp ?? "нет данных"}"));
            body.Append(Bullet($"Наблюдений по IP: {result.IpConsensus.Observations.Count}"));
            body.Append(Bullet($"Длительность: {result.Duration.TotalSeconds:F1} с"));
            body.Append(Bullet($"Приватный режим: {(result.Environment.PrivacyMode ? "включён" : "выключен")}"));
            body.Append(Bullet($"Компьютер: {result.Environment.MachineName} · пользователь: {result.Environment.UserName}"));

            main.Document.Save();
        }

        return stream.ToArray();
    }

    private static Table BuildChecksTable(CheckRunResult result)
    {
        var table = new Table();
        table.AppendChild(new TableProperties(
            new TableBorders(
                new TopBorder { Val = BorderValues.Single, Size = 4, Color = "D5DCE5" },
                new BottomBorder { Val = BorderValues.Single, Size = 4, Color = "D5DCE5" },
                new LeftBorder { Val = BorderValues.Single, Size = 4, Color = "D5DCE5" },
                new RightBorder { Val = BorderValues.Single, Size = 4, Color = "D5DCE5" },
                new InsideHorizontalBorder { Val = BorderValues.Single, Size = 4, Color = "E7ECF2" }),
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct }));

        table.Append(TableRow(true, "Проверка", "Что проверяли", "Статус", "Находок"));
        foreach (var check in result.Checks)
        {
            table.Append(TableRow(false, check.Title, PlainLanguage.WhatWeChecked(check.Category),
                check.StatusText, check.Findings.Count.ToString()));
        }
        return table;
    }

    private static TableRow TableRow(bool header, params string[] cells)
    {
        var row = new TableRow();
        foreach (var cell in cells)
        {
            var run = new Run(new Text(cell) { Space = SpaceProcessingModeValues.Preserve });
            var props = new RunProperties(new RunFonts { Ascii = Font, HighAnsi = Font, ComplexScript = Font }, new FontSize { Val = "18" });
            if (header) props.Append(new Bold(), new Color { Val = "FFFFFF" });
            run.RunProperties = props;

            var cellProps = new TableCellProperties(new TableCellWidth { Type = TableWidthUnitValues.Auto });
            if (header)
                cellProps.Append(new Shading { Fill = "1F3A5F", Val = ShadingPatternValues.Clear });

            row.Append(new TableCell(cellProps, new Paragraph(new ParagraphProperties(
                new SpacingBetweenLines { Before = "40", After = "40" }), run)));
        }
        return row;
    }

    private static Paragraph Paragraph(string text, int size = 21, bool bold = false, string color = "1A2028",
        int spaceAfter = 120, int indent = 0)
    {
        var props = new ParagraphProperties(new SpacingBetweenLines { After = spaceAfter.ToString(CultureInfo.InvariantCulture) });
        if (indent > 0) props.Append(new Indentation { Left = indent.ToString(CultureInfo.InvariantCulture) });

        var runProps = new RunProperties(
            new RunFonts { Ascii = Font, HighAnsi = Font, ComplexScript = Font },
            new FontSize { Val = size.ToString(CultureInfo.InvariantCulture) })
        {
            Color = new Color { Val = color },
        };
        if (bold) runProps.Append(new Bold());

        return new Paragraph(props, new Run(runProps, new Text(text) { Space = SpaceProcessingModeValues.Preserve }));
    }

    private static Paragraph Heading(string text) =>
        Paragraph(text, size: 28, bold: true, spaceAfter: 120);

    private static Paragraph Bullet(string text, Severity? severity = null)
    {
        var color = severity switch
        {
            Severity.Critical => "B03A38",
            Severity.Warning => "C26A11",
            Severity.Notice => "9A7B13",
            _ => "1A2028",
        };
        var paragraph = Paragraph("• " + text, size: 19, color: color, spaceAfter: 60, indent: 360);
        return paragraph;
    }

    private static string SeverityText(Severity severity) => severity switch
    {
        Severity.Critical => "критично",
        Severity.Warning => "внимание",
        Severity.Notice => "заметка",
        _ => "инфо",
    };

    private static string ColourOf(RiskLevel level) => level switch
    {
        RiskLevel.Clean => "1F8A5B",
        RiskLevel.NeedsReview => "9A7B13",
        _ => "B03A38",
    };
}
