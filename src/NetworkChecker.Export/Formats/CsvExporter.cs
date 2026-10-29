using System.Globalization;
using System.Text;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Plain;

namespace NetworkChecker.Export.Formats;

/// <summary>CSV для Excel/Google Sheets: одна строка — одна находка, плюс строка на модуль без находок.</summary>
public static class CsvExporter
{
    public static byte[] Build(CheckRunResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Модуль;Статус;Статус (простыми словами);Уровень;Находка;Подробности;Доказательство;Время, с");

        foreach (var check in result.Checks)
        {
            if (check.Findings.Count == 0)
            {
                sb.AppendLine(Row(
                    check.Title,
                    check.StatusText,
                    PlainLanguage.StatusInPlainWords(check.Status),
                    "",
                    check.Findings.Count == 0 ? "находок нет" : "",
                    PlainLanguage.WhatWeChecked(check.Category),
                    "",
                    check.Duration.TotalSeconds.ToString("F1", CultureInfo.InvariantCulture)));
                continue;
            }

            foreach (var finding in check.Findings.OrderByDescending(f => f.Severity))
            {
                sb.AppendLine(Row(
                    check.Title,
                    check.StatusText,
                    PlainLanguage.StatusInPlainWords(check.Status),
                    finding.Severity.ToString(),
                    finding.Title,
                    finding.Detail,
                    finding.Evidence ?? "",
                    check.Duration.TotalSeconds.ToString("F1", CultureInfo.InvariantCulture)));
            }
        }

        sb.AppendLine();
        sb.AppendLine(Row("ИТОГ", result.Verdict.LevelText, result.Verdict.Headline,
            result.Verdict.ScoreAvailable ? result.Verdict.Score.ToString(CultureInfo.InvariantCulture) : "", result.Verdict.Summary,
            string.Join(" | ", result.Verdict.Reasons), result.IpConsensus.Summary,
            result.Duration.TotalSeconds.ToString("F1", CultureInfo.InvariantCulture)));

        // BOM нужен, чтобы Excel корректно открыл кириллицу.
        var preamble = Encoding.UTF8.GetPreamble();
        var body = Encoding.UTF8.GetBytes(sb.ToString());
        var bytes = new byte[preamble.Length + body.Length];
        preamble.CopyTo(bytes, 0);
        body.CopyTo(bytes, preamble.Length);
        return bytes;
    }

    private static string Row(params string[] cells) =>
        string.Join(';', cells.Select(Escape));

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var clean = value.Replace("\r", " ").Replace("\n", " ").Trim();
        // Табличные программы могут выполнить строку из сетевых данных как формулу.
        if (clean.Length > 0 && clean[0] is '=' or '+' or '-' or '@') clean = "'" + clean;
        if (clean.Contains(';') || clean.Contains('"'))
            clean = '"' + clean.Replace("\"", "\"\"") + '"';
        return clean;
    }
}
