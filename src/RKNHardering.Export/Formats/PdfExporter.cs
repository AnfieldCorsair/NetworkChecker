using System.Globalization;
using QuestPDF.Drawing;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using RKNHardering.Core.Models;
using RKNHardering.Core.Plain;

namespace RKNHardering.Export.Formats;

/// <summary>
/// PDF-отчёт: титул с вердиктом, таблица проверок, находки. Шрифт DejaVu Sans встроен —
/// иначе кириллица в PDF не отрисуется на машинах без нужных системных шрифтов.
/// </summary>
public static class PdfExporter
{
    private const string FontFamily = "DejaVu Sans";
    private static readonly Lock FontLock = new();
    private static bool _fontsRegistered;

    public static byte[] Build(CheckRunResult result)
    {
        // QuestPDF Community License: бесплатна для проектов с оборотом менее 1 млн USD.
        // Если это не ваш случай — замените на свою лицензию.
        QuestPDF.Settings.License = LicenseType.Community;
        RegisterFonts();

        var plain = PlainLanguage.ForVerdict(result.Verdict, result.Checks);

        var document = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(28);
                page.DefaultTextStyle(style => style.FontFamily(FontFamily).FontSize(9).FontColor(Colors.Grey.Darken4));

                page.Header().Element(header => ComposeHeader(header, result));
                page.Content().Element(content => ComposeContent(content, result, plain));
                page.Footer().Element(footer => ComposeFooter(footer, result));
            });
        });

        return document.GeneratePdf();
    }

    private static void RegisterFonts()
    {
        if (_fontsRegistered) return;
        lock (FontLock)
        {
            if (_fontsRegistered) return;
            var assembly = typeof(PdfExporter).Assembly;
            foreach (var name in new[] { "DejaVuSans.ttf", "DejaVuSans-Bold.ttf" })
            {
                using var stream = assembly.GetManifestResourceStream($"RKNHardering.Export.Assets.{name}");
                if (stream is null) continue;
                using var memory = new MemoryStream();
                stream.CopyTo(memory);
                memory.Position = 0;
                FontManager.RegisterFontFromStream(memory);
            }
            _fontsRegistered = true;
        }
    }

    private static void ComposeHeader(IContainer container, CheckRunResult result)
    {
        container.Row(row =>
        {
            row.RelativeItem().Column(column =>
            {
                column.Item().Text("Отчёт RKNHardering PC").FontSize(16).SemiBold();
                column.Item().Text($"{result.StartedAt.ToLocalTime():dd.MM.yyyy HH:mm} · {result.Environment.OsDescription} · {result.Environment.MachineName}")
                    .FontSize(8).FontColor(Colors.Grey.Medium);
            });
            row.ConstantItem(150).AlignRight().Column(column =>
            {
                column.Item().Text($"{(result.Environment.PrivacyMode ? "приватный режим" : "полные данные")}")
                    .FontSize(8).FontColor(Colors.Grey.Medium);
                column.Item().Text($"{result.Duration.TotalSeconds:F1} с").FontSize(8).FontColor(Colors.Grey.Medium);
            });
        });
    }

    private static void ComposeContent(IContainer container, CheckRunResult result, PlainExplanation plain)
    {
        container.PaddingVertical(10).Column(column =>
        {
            column.Spacing(8);

            // Вердикт
            column.Item().Background(VerdictBackground(result.Verdict.Level)).Padding(12).Column(box =>
            {
                box.Item().Text(result.Verdict.Headline).FontSize(15).SemiBold().FontColor(VerdictColor(result.Verdict.Level));
                box.Item().PaddingTop(2).Text($"Балл {result.Verdict.Score}/100 · {result.Verdict.LevelText} · внешний IP: {result.IpConsensus.ConsensusIp ?? "нет данных"}")
                    .FontSize(8).FontColor(Colors.Grey.Darken2);
                box.Item().PaddingTop(6).Text(plain.WhatItMeans).FontSize(9);
                box.Item().PaddingTop(4).Text($"Что делать: {plain.Advice}").FontSize(9).Italic();
            });

            if (result.Verdict.Reasons.Count > 0)
            {
                column.Item().PaddingTop(4).Text("Почему такой вывод").FontSize(11).SemiBold();
                foreach (var reason in result.Verdict.Reasons)
                    column.Item().Text("• " + reason).FontSize(9);
            }

            // Таблица проверок
            column.Item().PaddingTop(6).Text("Коротко по проверкам").FontSize(11).SemiBold();
            column.Item().Table(table =>
            {
                table.ColumnsDefinition(columns =>
                {
                    columns.RelativeColumn(2.2f);
                    columns.RelativeColumn(3.4f);
                    columns.RelativeColumn(1.3f);
                    columns.ConstantColumn(46);
                });

                table.Header(header =>
                {
                    header.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Проверка").FontSize(8).SemiBold();
                    header.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Что проверяли").FontSize(8).SemiBold();
                    header.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Статус").FontSize(8).SemiBold();
                    header.Cell().Background(Colors.Grey.Lighten2).Padding(4).AlignRight().Text("Находок").FontSize(8).SemiBold();
                });

                foreach (var check in result.Checks)
                {
                    table.Cell().Padding(4).Text(check.Title).FontSize(8);
                    table.Cell().Padding(4).Text(PlainLanguage.WhatWeChecked(check.Category)).FontSize(8).FontColor(Colors.Grey.Darken2);
                    table.Cell().Padding(4).Text(check.StatusText).FontSize(8).FontColor(StatusColor(check.Status));
                    table.Cell().Padding(4).AlignRight().Text(check.Findings.Count.ToString()).FontSize(8);
                }
            });

            // Находки
            foreach (var check in result.Checks.Where(c => c.Findings.Count > 0))
            {
                column.Item().PaddingTop(8).Text(check.Title).FontSize(11).SemiBold();
                column.Item().Text($"{PlainLanguage.WhatWeChecked(check.Category)} · {check.StatusText}")
                    .FontSize(8).FontColor(Colors.Grey.Medium);

                foreach (var finding in check.Findings.OrderByDescending(f => f.Severity))
                {
                    column.Item().PaddingTop(3).Row(row =>
                    {
                        row.ConstantItem(52).Text(SeverityText(finding.Severity))
                            .FontSize(7).SemiBold().FontColor(SeverityColor(finding.Severity));
                        row.RelativeItem().Column(text =>
                        {
                            text.Item().Text(finding.Title).FontSize(9).SemiBold();
                            if (!string.IsNullOrWhiteSpace(finding.Detail))
                                text.Item().Text(finding.Detail).FontSize(8).FontColor(Colors.Grey.Darken2);
                            if (!string.IsNullOrWhiteSpace(finding.Evidence))
                                text.Item().PaddingTop(1).Text(finding.Evidence).FontSize(7).FontColor(Colors.Grey.Medium);
                        });
                    });
                }
            }

            if (result.IpConsensus.Observations.Count > 0)
            {
                column.Item().PaddingTop(8).Text("Наблюдения по внешнему IP").FontSize(11).SemiBold();
                foreach (var observation in result.IpConsensus.Observations)
                    column.Item().Text($"• {observation.Source}: {observation.Ip}{(observation.Note is null ? "" : $" — {observation.Note}")}")
                        .FontSize(8);
            }
        });
    }

    private static void ComposeFooter(IContainer container, CheckRunResult result)
    {
        container.Row(row =>
        {
            row.RelativeItem().Text($"{result.Verdict.Headline} · сформировано RKNHardering PC")
                .FontSize(7).FontColor(Colors.Grey.Medium);
            row.ConstantItem(80).AlignRight().Text(text =>
            {
                text.DefaultTextStyle(style => style.FontSize(7).FontColor(Colors.Grey.Medium));
                text.CurrentPageNumber();
                text.Span(" / ");
                text.TotalPages();
            });
        });
    }

    private static string SeverityText(Severity severity) => severity switch
    {
        Severity.Critical => "КРИТИЧНО",
        Severity.Warning => "ВНИМАНИЕ",
        Severity.Notice => "ЗАМЕТКА",
        _ => "ИНФО",
    };

    private static string SeverityColor(Severity severity) => severity switch
    {
        Severity.Critical => "#C0392B",
        Severity.Warning => "#C26A11",
        Severity.Notice => "#9A7B13",
        _ => "#44546A",
    };

    private static string StatusColor(CheckStatus status) => status switch
    {
        CheckStatus.Clean => "#1F8A5B",
        CheckStatus.NeedsReview => "#9A7B13",
        CheckStatus.Detected => "#C0392B",
        CheckStatus.Failed => "#7D5BA6",
        _ => "#6B7C8F",
    };

    private static string VerdictColor(RiskLevel level) => level switch
    {
        RiskLevel.Clean => "#1F8A5B",
        RiskLevel.NeedsReview => "#9A7B13",
        _ => "#C0392B",
    };

    private static string VerdictBackground(RiskLevel level) => level switch
    {
        RiskLevel.Clean => "#EAF7F0",
        RiskLevel.NeedsReview => "#FCF6E3",
        _ => "#FBEAE8",
    };

    /// <summary>Проверка, что шрифты действительно встроены (используется в тестах).</summary>
    public static bool FontsAvailable()
    {
        var assembly = typeof(PdfExporter).Assembly;
        return assembly.GetManifestResourceInfo("RKNHardering.Export.Assets.DejaVuSans.ttf") is not null;
    }

    internal static string Culture(double value) => value.ToString("F1", CultureInfo.InvariantCulture);
}
