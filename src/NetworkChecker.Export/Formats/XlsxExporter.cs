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

    public static byte[] Build(CheckRunResult result)
    {
        using var workbook = new XLWorkbook();

        BuildSummary(workbook, result);
        BuildChecks(workbook, result);
        BuildFindings(workbook, result);
        BuildObservations(workbook, result);

        using var stream = new MemoryStream();
        workbook.SaveAs(stream);
        return stream.ToArray();
    }

    private static void BuildSummary(XLWorkbook workbook, CheckRunResult result)
    {
        var sheet = workbook.Worksheets.Add("Итог");
        sheet.Cell(1, 1).Value = "NetworkChecker — отчёт о проверке";
        sheet.Cell(1, 1).Style.Font.Bold = true;
        sheet.Cell(1, 1).Style.Font.FontSize = 15;
        sheet.Range(1, 1, 1, 2).Merge();

        var rows = new (string Key, string Value)[]
        {
            ("Вердикт", result.Verdict.Headline),
            ("Уровень", result.Verdict.LevelText),
            ("Балл", $"{result.Verdict.Score} / 100"),
            ("Что это значит", PlainLanguage.ForVerdict(result.Verdict, result.Checks).WhatItMeans),
            ("Что делать", PlainLanguage.ForVerdict(result.Verdict, result.Checks).Advice),
            ("Кратко", result.Verdict.Summary),
            ("Внешний IP", result.IpConsensus.ConsensusIp ?? "нет данных"),
            ("Наблюдений по IP", result.IpConsensus.Observations.Count.ToString(CultureInfo.InvariantCulture)),
            ("Начало", result.StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture)),
            ("Длительность", $"{result.Duration.TotalSeconds:F1} с"),
            ("ОС", result.Environment.OsDescription),
            ("Компьютер", result.Environment.MachineName),
            ("Приватный режим", result.Environment.PrivacyMode ? "включён" : "выключен"),
        };

        var row = 3;
        foreach (var (key, value) in rows)
        {
            sheet.Cell(row, 1).Value = key;
            sheet.Cell(row, 1).Style.Font.Bold = true;
            sheet.Cell(row, 2).Value = value;
            sheet.Cell(row, 2).Style.Alignment.WrapText = true;
            row++;
        }

        if (result.Verdict.Reasons.Count > 0)
        {
            row++;
            sheet.Cell(row, 1).Value = "Причины";
            sheet.Cell(row, 1).Style.Font.Bold = true;
            row++;
            foreach (var reason in result.Verdict.Reasons)
            {
                sheet.Cell(row, 1).Value = "•";
                sheet.Cell(row, 2).Value = reason;
                row++;
            }
        }

        sheet.Column(1).Width = 24;
        sheet.Column(2).Width = 96;
    }

    private static void BuildChecks(XLWorkbook workbook, CheckRunResult result)
    {
        var sheet = workbook.Worksheets.Add("Проверки");
        string[] headers = ["Модуль", "Что проверяли", "Статус", "Простыми словами", "Находок", "Время, с", "Вес в вердикте"];
        WriteHeader(sheet, headers);

        var row = 2;
        foreach (var check in result.Checks)
        {
            sheet.Cell(row, 1).Value = check.Title;
            sheet.Cell(row, 2).Value = PlainLanguage.WhatWeChecked(check.Category);
            sheet.Cell(row, 3).Value = check.StatusText;
            sheet.Cell(row, 4).Value = PlainLanguage.StatusInPlainWords(check.Status);
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

    private static void BuildFindings(XLWorkbook workbook, CheckRunResult result)
    {
        var sheet = workbook.Worksheets.Add("Находки");
        string[] headers = ["Модуль", "Уровень", "Находка", "Подробности", "Доказательство"];
        WriteHeader(sheet, headers);

        var row = 2;
        foreach (var check in result.Checks)
        {
            foreach (var finding in check.Findings.OrderByDescending(f => f.Severity))
            {
                sheet.Cell(row, 1).Value = check.Title;
                sheet.Cell(row, 2).Value = finding.Severity switch
                {
                    Severity.Critical => "критично",
                    Severity.Warning => "внимание",
                    Severity.Notice => "заметка",
                    _ => "инфо",
                };
                sheet.Cell(row, 3).Value = finding.Title;
                sheet.Cell(row, 4).Value = finding.Detail;
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

        if (row == 2) sheet.Cell(2, 1).Value = "Находок нет";
        sheet.SheetView.FreezeRows(1);
        sheet.Columns().AdjustToContents(8, 60);
    }

    private static void BuildObservations(XLWorkbook workbook, CheckRunResult result)
    {
        var sheet = workbook.Worksheets.Add("IP-наблюдения");
        string[] headers = ["Источник", "IP", "Страна", "Примечание"];
        WriteHeader(sheet, headers);

        var row = 2;
        foreach (var observation in result.IpConsensus.Observations)
        {
            sheet.Cell(row, 1).Value = observation.Source;
            sheet.Cell(row, 2).Value = observation.Ip;
            sheet.Cell(row, 3).Value = observation.IsRussian switch
            {
                true => "RU",
                false => "не RU",
                _ => "нет данных",
            };
            sheet.Cell(row, 4).Value = observation.Note ?? string.Empty;
            row++;
        }

        if (row == 2) sheet.Cell(2, 1).Value = "Наблюдений нет";
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
