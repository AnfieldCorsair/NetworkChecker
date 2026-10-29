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

    public static string ToMarkdown(CheckRunResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# NetworkChecker — отчёт о проверке");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Вердикт:** {result.Verdict.Headline} ({result.Verdict.Level}, {result.Verdict.Score}/100)");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Начато:** {result.StartedAt:dd.MM.yyyy HH:mm:ss zzz}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Длительность:** {result.Duration.TotalSeconds:F1} с");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Внешний IP:** {result.IpConsensus.Summary}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **ОС:** {result.Environment.OsDescription}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Приватный режим:** {(result.Environment.PrivacyMode ? "включён (IP/имена маскированы)" : "выключен")}");
        sb.AppendLine();
        sb.AppendLine("## Сводка");
        sb.AppendLine();
        sb.AppendLine(result.Verdict.Summary);
        if (result.Verdict.Reasons.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("### Причины");
            foreach (var reason in result.Verdict.Reasons) sb.AppendLine(CultureInfo.InvariantCulture, $"- {reason}");
        }

        sb.AppendLine();
        sb.AppendLine("## Модули");
        sb.AppendLine();
        sb.AppendLine("| Модуль | Статус | Находок | Время |");
        sb.AppendLine("|---|---|---|---|");
        foreach (var check in result.Checks)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"| {check.Title} | {check.StatusText} | {check.Findings.Count} | {check.Duration.TotalSeconds:F1} с |");
        }

        foreach (var check in result.Checks)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"### {check.Title} — {check.StatusText}");
            if (!string.IsNullOrWhiteSpace(check.Subtitle)) sb.AppendLine(CultureInfo.InvariantCulture, $"> {check.Subtitle}");
            if (check.Error is not null) sb.AppendLine(CultureInfo.InvariantCulture, $"> Ошибка: {check.Error}");
            if (check.Metrics.Count > 0)
            {
                sb.AppendLine();
                foreach (var metric in check.Metrics)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- **{metric.Label}:** {metric.Value}{(metric.Hint is null ? "" : $" — {metric.Hint}")}");
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
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- {badge} **{finding.Title}**{(string.IsNullOrWhiteSpace(finding.Detail) ? "" : $" — {finding.Detail}")}");
                    if (!string.IsNullOrWhiteSpace(finding.Evidence))
                        sb.AppendLine(CultureInfo.InvariantCulture, $"  ```{Environment.NewLine}  {finding.Evidence}{Environment.NewLine}  ```");
                }
            }
        }

        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine("Сформировано NetworkChecker. Методика: обнаружение VPN и прокси на Windows.");
        return sb.ToString();
    }
}
