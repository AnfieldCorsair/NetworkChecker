using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using RKNHardering.Core.Models;

namespace RKNHardering.Core.Export;

/// <summary>Экспорт результата в Markdown/JSON — паритет с formatters из Android-версии.</summary>
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
        sb.AppendLine("# RKNHardering PC — отчёт о проверке");
        sb.AppendLine();
        sb.AppendLine($"- **Вердикт:** {result.Verdict.Headline} ({result.Verdict.Level}, {result.Verdict.Score}/100)");
        sb.AppendLine($"- **Начато:** {result.StartedAt:dd.MM.yyyy HH:mm:ss zzz}");
        sb.AppendLine($"- **Длительность:** {result.Duration.TotalSeconds:F1} с");
        sb.AppendLine($"- **Внешний IP:** {result.IpConsensus.Summary}");
        sb.AppendLine($"- **ОС:** {result.Environment.OsDescription}");
        sb.AppendLine($"- **Приватный режим:** {(result.Environment.PrivacyMode ? "включён (IP/имена маскированы)" : "выключен")}");
        sb.AppendLine();
        sb.AppendLine("## Сводка");
        sb.AppendLine();
        sb.AppendLine(result.Verdict.Summary);
        if (result.Verdict.Reasons.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("### Причины");
            foreach (var reason in result.Verdict.Reasons) sb.AppendLine($"- {reason}");
        }

        sb.AppendLine();
        sb.AppendLine("## Модули");
        sb.AppendLine();
        sb.AppendLine("| Модуль | Статус | Находок | Время |");
        sb.AppendLine("|---|---|---|---|");
        foreach (var check in result.Checks)
        {
            sb.AppendLine($"| {check.Title} | {check.StatusText} | {check.Findings.Count} | {check.Duration.TotalSeconds:F1} с |");
        }

        foreach (var check in result.Checks)
        {
            sb.AppendLine();
            sb.AppendLine($"### {check.Title} — {check.StatusText}");
            if (!string.IsNullOrWhiteSpace(check.Subtitle)) sb.AppendLine($"> {check.Subtitle}");
            if (check.Error is not null) sb.AppendLine($"> Ошибка: {check.Error}");
            if (check.Metrics.Count > 0)
            {
                sb.AppendLine();
                foreach (var metric in check.Metrics)
                {
                    sb.AppendLine($"- **{metric.Label}:** {metric.Value}{(metric.Hint is null ? "" : $" — {metric.Hint}")}");
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
                    sb.AppendLine($"- {badge} **{finding.Title}**{(string.IsNullOrWhiteSpace(finding.Detail) ? "" : $" — {finding.Detail}")}");
                    if (!string.IsNullOrWhiteSpace(finding.Evidence))
                        sb.AppendLine($"  ```{Environment.NewLine}  {finding.Evidence}{Environment.NewLine}  ```");
                }
            }
        }

        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine("Сформировано RKNHardering PC. Методика: обнаружение VPN/прокси (порт RKNHardering).");
        return sb.ToString();
    }
}
