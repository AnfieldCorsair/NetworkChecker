using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkChecker.Core.Models;

namespace NetworkChecker.Core.Export;

/// <summary>
/// Markdown/JSON-представление прогона. Форматирование всегда инвариантное:
/// отчёт должен одинаково читаться машиной при любой локали ОС.
/// </summary>
public static class ResultExport
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ToJson(CheckRunResult result) => JsonSerializer.Serialize(result, JsonOptions);

    public static string ToMarkdown(CheckRunResult result, bool english = false, Func<string, string>? translate = null)
    {
        string Text(string text) => english && translate is not null ? translate(text) : text;
        string Label(string ru, string en) => english ? en : ru;
        var sb = new StringBuilder();
        sb.AppendLine(Label("# NetworkChecker — отчёт о проверке", "# NetworkChecker — diagnostic report"));
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Label("Вердикт", "Verdict")}:** {Text(result.Verdict.Headline)} ({result.Verdict.Level}, {Text(result.Verdict.ScoreText)})");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Label("Начато", "Started")}:** {result.StartedAt:dd.MM.yyyy HH:mm:ss zzz}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Label("Длительность", "Duration")}:** {result.Duration.TotalSeconds:F1} {Label("с", "s")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Label("Внешний IP", "Public IP")}:** {Text(result.IpConsensus.Summary)}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Label("ОС", "OS")}:** {result.Environment.OsDescription}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Label("Приватный режим", "Privacy mode")}:** {(result.Environment.PrivacyMode ? Label("включён (IP/имена маскированы)", "enabled (IP addresses and names masked)") : Label("выключен", "disabled"))}");
        sb.AppendLine();
        sb.AppendLine(Label("## Сводка", "## Summary"));
        sb.AppendLine();
        sb.AppendLine(Text(result.Verdict.Summary));
        if (result.Verdict.Reasons.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(Label("### Причины", "### Reasons"));
            foreach (var reason in result.Verdict.Reasons) sb.AppendLine(CultureInfo.InvariantCulture, $"- {Text(reason)}");
        }

        sb.AppendLine();
        sb.AppendLine(Label("## Модули", "## Checks"));
        sb.AppendLine();
        sb.AppendLine(Label("| Модуль | Статус | Находок | Время |", "| Check | Status | Findings | Time |"));
        sb.AppendLine("|---|---|---|---|");
        foreach (var check in result.Checks)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"| {Text(check.Title)} | {Text(check.StatusText)} | {check.Findings.Count} | {check.Duration.TotalSeconds:F1} {Label("с", "s")} |");
        }

        foreach (var check in result.Checks)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"### {Text(check.Title)} — {Text(check.StatusText)}");
            if (!string.IsNullOrWhiteSpace(check.Subtitle)) sb.AppendLine(CultureInfo.InvariantCulture, $"> {Text(check.Subtitle)}");
            if (check.Error is not null) sb.AppendLine(CultureInfo.InvariantCulture, $"> {Label("Ошибка", "Error")}: {check.Error}");
            if (check.Metrics.Count > 0)
            {
                sb.AppendLine();
                foreach (var metric in check.Metrics)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- **{Text(metric.Label)}:** {Text(metric.Value)}{(metric.Hint is null ? "" : $" — {Text(metric.Hint)}")}");
                }
            }
            if (check.Findings.Count > 0)
            {
                sb.AppendLine();
                foreach (var finding in check.Findings.OrderByDescending(f => f.Severity))
                {
                    var badge = finding.Severity switch
                    {
                        Severity.Critical => "🔴 critical",
                        Severity.Warning => "🟠 warning",
                        Severity.Notice => "🟡 notice",
                        _ => "⚪ info",
                    };
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- {badge} **{Text(finding.Title)}**{(string.IsNullOrWhiteSpace(finding.Detail) ? "" : $" — {Text(finding.Detail)}")}");
                    if (!string.IsNullOrWhiteSpace(finding.Evidence))
                        sb.AppendLine(CultureInfo.InvariantCulture, $"  ```{Environment.NewLine}  {finding.Evidence}{Environment.NewLine}  ```");
                }
            }
        }

        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine(Label("Сформировано NetworkChecker. Методика: обнаружение VPN и прокси на Windows.", "Generated by NetworkChecker. Indicators are heuristic and do not establish browser routing."));
        return sb.ToString();
    }
}
