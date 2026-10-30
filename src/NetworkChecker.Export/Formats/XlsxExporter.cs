using System.Globalization;
using ClosedXML.Excel;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Plain;

namespace NetworkChecker.Export.Formats;

/// <summary>XLSX с четырьмя листами: итог, проверки, находки, наблюдения по IP.</summary>
public static class XlsxExporter
{
    private static readonly XLColor Header = XLColor.FromHtml("#1F3A5F");
    private static readonly XLColor Accent = XLColor.FromHtml("#4EA1FF");

    public static byte[] Build(CheckRunResult result, string? language = null, Func<string, string>? translate = null)
    {
        var l = new ReportLanguage(language, translate);
        using var workbook = new XLWorkbook();

        BuildSummary(workbook, result, l);
        BuildChecks(workbook, result, l);
        BuildFindings(workbook, result, l);
        BuildObservations(workbook, result, l);

        using var stream = new MemoryStream();
        workbook.SaveAs(stream);
        return stream.ToArray();
    }

    private static void BuildSummary(XLWorkbook workbook, CheckRunResult result, ReportLanguage l)
    {
        var sheet = workbook.Worksheets.Add(l.Text("Итог"));
        sheet.Cell(1, 1).Value = l.Text("NetworkChecker — отчёт о проверке");
        sheet.Cell(1, 1).Style.Font.Bold = true;
        sheet.Cell(1, 1).Style.Font.FontSize = 15;
        sheet.Range(1, 1, 1, 2).Merge();

        var rows = new (string Key, string Value)[]
        {
            ("Вердикт", l.Text(result.Verdict.Headline)),
            ("Уровень", l.Text(result.Verdict.LevelText)),
            ("Условный индекс", l.Text(result.Verdict.ScoreText)),
            ("Что это значит", l.Text(PlainLanguage.ForVerdict(result.Verdict, result.Checks).WhatItMeans)),
            ("Что делать", l.Text(PlainLanguage.ForVerdict(result.Verdict, result.Checks).Advice)),
            ("Кратко", l.Text(result.Verdict.Summary)),
            ("Внешний IP", l.Text(result.IpConsensus.ConsensusIp ?? "нет данных")),
            ("Наблюдений по IP", result.IpConsensus.Observations.Count.ToString(CultureInfo.InvariantCulture)),
            ("Начало", result.StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture)),
            ("Длительность", $"{result.Duration.TotalSeconds:F1} {l.Choose("с", "s")}"),
            ("ОС", result.Environment.OsDescription),
            ("Компьютер", result.Environment.MachineName),
            ("Приватный режим", l.Text(result.Environment.PrivacyMode ? "включён" : "выключен")),
        };

        var row = 3;
        foreach (var (key, value) in rows)
        {
            sheet.Cell(row, 1).Value = l.Text(key);
            sheet.Cell(row, 1).Style.Font.Bold = true;
            sheet.Cell(row, 2).Value = value;
            sheet.Cell(row, 2).Style.Alignment.WrapText = true;
            row++;
        }

        if (result.Verdict.Reasons.Count > 0)
        {
            row++;
            sheet.Cell(row, 1).Value = l.Text("Причины");
            sheet.Cell(row, 1).Style.Font.Bold = true;
            row++;
            foreach (var reason in result.Verdict.Reasons)
            {
                sheet.Cell(row, 1).Value = "•";
                sheet.Cell(row, 2).Value = l.Text(reason);
                row++;
            }
        }

        sheet.Column(1).Width = 24;
        sheet.Column(2).Width = 96;
    }

    private static void BuildChecks(XLWorkbook workbook, CheckRunResult result, ReportLanguage l)
    {
        var sheet = workbook.Worksheets.Add(l.Text("Проверки"));
        string[] headers = ["Модуль", "Что проверяли", "Статус", "Простыми словами", "Находок", "Время, с", "Вес в вердикте"];
        WriteHeader(sheet, headers.Select(l.Text).ToArray());

        var row = 2;
        foreach (var check in result.Checks)
        {
            sheet.Cell(row, 1).Value = l.Text(check.Title);
            sheet.Cell(row, 2).Value = l.Text(PlainLanguage.WhatWeChecked(check.Category));
            sheet.Cell(row, 3).Value = l.Text(check.StatusText);
            sheet.Cell(row, 4).Value = l.Text(PlainLanguage.StatusInPlainWords(check.Status));
            sheet.Cell(row, 5).Value = check.Findings.Count;
            sheet.Cell(row, 6).Value = Math.Round(check.Duration.TotalSeconds, 1);
            sheet.Cell(row, 7).Value = check.Weight;

            var color = check.Status switch
            {
                CheckStatus.Clean => XLColor.FromHtml("#D8F3E4"),
                CheckStatus.NeedsReview => XLColor.FromHtml("#FBF0C4"),
                CheckStatus.Detected => XLColor.FromHtml("#FBD9D7"),
                CheckStatus.Failed => XLColor.FromHtml("#EADCF5"),
                _ => XLColor.NoColor,
            };
            if (color != XLColor.NoColor) sheet.Range(row, 3, row, 4).Style.Fill.BackgroundColor = color;
            row++;
        }

        sheet.SheetView.FreezeRows(1);
        sheet.Columns().AdjustToContents(8, 60);
    }

    private static void BuildFindings(XLWorkbook workbook, CheckRunResult result, ReportLanguage l)
    {
        var sheet = workbook.Worksheets.Add(l.Text("Находки"));
        string[] headers = ["Модуль", "Уровень", "Находка", "Подробности", "Доказательство"];
        WriteHeader(sheet, headers.Select(l.Text).ToArray());

        var row = 2;
        foreach (var check in result.Checks)
        {
            foreach (var finding in check.Findings.OrderByDescending(f => f.Severity))
            {
                sheet.Cell(row, 1).Value = l.Text(check.Title);
                sheet.Cell(row, 2).Value = l.Text(finding.Severity switch
                {
                    Severity.Critical => "критично",
                    Severity.Warning => "внимание",
                    Severity.Notice => "заметка",
                    _ => "инфо",
                });
                sheet.Cell(row, 3).Value = l.Text(finding.Title);
                sheet.Cell(row, 4).Value = l.Text(finding.Detail);
                sheet.Cell(row, 5).Value = finding.Evidence ?? string.Empty;

                var color = finding.Severity switch
                {
                    Severity.Critical => XLColor.FromHtml("#FBD9D7"),
                    Severity.Warning => XLColor.FromHtml("#FCE4CC"),
                    Severity.Notice => XLColor.FromHtml("#FBF0C4"),
                    _ => XLColor.NoColor,
                };
                if (color != XLColor.NoColor) sheet.Range(row, 1, row, 5).Style.Fill.BackgroundColor = color;
                row++;
            }
        }

        if (row == 2) sheet.Cell(2, 1).Value = l.Text("Находок нет");
        sheet.SheetView.FreezeRows(1);
        sheet.Columns().AdjustToContents(8, 60);
    }

    private static void BuildObservations(XLWorkbook workbook, CheckRunResult result, ReportLanguage l)
    {
        var sheet = workbook.Worksheets.Add(l.Text("IP-наблюдения"));
        string[] headers = ["Источник", "IP", "Страна", "Примечание"];
        WriteHeader(sheet, headers.Select(l.Text).ToArray());

        var row = 2;
        foreach (var observation in result.IpConsensus.Observations)
        {
            sheet.Cell(row, 1).Value = observation.Source;
            sheet.Cell(row, 2).Value = observation.Ip;
            sheet.Cell(row, 3).Value = l.Text(observation.IsRussian switch
            {
                true => "RU",
                false => "не RU",
                _ => "нет данных",
            });
            sheet.Cell(row, 4).Value = observation.Note ?? string.Empty;
            row++;
        }

        if (row == 2) sheet.Cell(2, 1).Value = l.Text("Наблюдений нет");
        sheet.SheetView.FreezeRows(1);
        sheet.Columns().AdjustToContents(8, 50);
    }

    private static void WriteHeader(IXLWorksheet sheet, string[] headers)
    {
        for (var i = 0; i < headers.Length; i++)
        {
            var cell = sheet.Cell(1, i + 1);
            cell.Value = headers[i];
            cell.Style.Font.Bold = true;
            cell.Style.Font.FontColor = XLColor.White;
            cell.Style.Fill.BackgroundColor = Header;
            cell.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
        }
        sheet.Row(1).Height = 20;
        sheet.Cell(1, 1).Style.Border.BottomBorder = XLBorderStyleValues.Thin;
        _ = Accent;
    }
}
