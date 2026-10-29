using System.Globalization;
using System.Net;
using System.Text;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Plain;

namespace NetworkChecker.Export.Formats;

/// <summary>
/// Один HTML-файл — весь отчёт. Стили и данные внутри, внешних ссылок и скриптов нет:
/// файл открывается в любом браузере, его можно отправить письмом или приложить к обращению.
/// </summary>
public static class HtmlExporter
{
    private static readonly CultureInfo Culture = CultureInfo.InvariantCulture;

    public static byte[] Build(CheckRunResult result)
    {
        var explanation = PlainLanguage.ForVerdict(result.Verdict, result.Checks);
        var accent = result.Verdict.Level switch
        {
            RiskLevel.Clean => "#2FA36B",
            RiskLevel.NeedsReview => "#D79B18",
            _ => "#D8483F",
        };

        var html = new StringBuilder();
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html lang=\"ru\">");
        html.AppendLine("<head>");
        html.AppendLine("<meta charset=\"utf-8\">");
        html.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        html.Append("<title>NetworkChecker · ").Append(E(result.Verdict.Headline)).AppendLine("</title>");
        html.AppendLine("<style>");
        html.AppendLine(Styles);
        html.AppendLine("</style>");
        html.AppendLine("</head>");
        html.AppendLine("<body>");
        html.AppendLine("<main>");

        // --- Шапка ---
        html.AppendLine("<header class=\"top\">");
        html.AppendLine("<div class=\"brand\">NetworkChecker</div>");
        html.Append("<div class=\"sub\">отчёт о проверке · ")
            .Append(E(result.StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm", Culture)))
            .AppendLine("</div>");
        html.AppendLine("</header>");

        // --- Вердикт ---
        html.Append("<section class=\"verdict\" style=\"border-left-color:").Append(accent).AppendLine("\">");
        html.Append("<div class=\"score\" style=\"color:").Append(accent).Append("\">")
            .Append(result.Verdict.Score.ToString(Culture)).AppendLine("<small>/100</small></div>");
        html.Append("<div class=\"verdict-body\">");
        html.Append("<h1>").Append(E(result.Verdict.Headline)).AppendLine("</h1>");
        html.Append("<p class=\"lead\">").Append(E(result.Verdict.Summary)).AppendLine("</p>");
        html.Append("<p class=\"plain\">").Append(E(explanation.WhatItMeans)).AppendLine("</p>");
        html.Append("</div>");
        html.AppendLine("</section>");

        // --- Что значимо ---
        if (result.Verdict.Reasons.Count > 0)
        {
            html.AppendLine("<section>");
            html.AppendLine("<h2>Что повлияло на вывод</h2>");
            html.AppendLine("<ul class=\"reasons\">");
            foreach (var reason in result.Verdict.Reasons)
                html.Append("<li>").Append(E(reason)).AppendLine("</li>");
            html.AppendLine("</ul>");
            html.AppendLine("</section>");
        }

        // --- Простыми словами ---
        html.AppendLine("<section>");
        html.AppendLine("<h2>Коротко по фактам</h2>");
        html.AppendLine("<div class=\"facts\">");
        foreach (var fact in PlainFacts.Build(result))
        {
            var tone = fact.Tone switch
            {
                "good" => "ok",
                "warn" => "warn",
                _ => "bad",
            };
            html.Append("<div class=\"fact ").Append(tone).AppendLine("\">");
            html.Append("<div class=\"q\">").Append(E(fact.Question)).AppendLine("</div>");
            html.Append("<div class=\"a\">").Append(E(fact.Answer)).AppendLine("</div>");
            if (!string.IsNullOrWhiteSpace(fact.Hint))
                html.Append("<div class=\"h\">").Append(E(fact.Hint!)).AppendLine("</div>");
            html.AppendLine("</div>");
        }
        html.AppendLine("</div>");
        html.Append("<p class=\"overall\"><strong>Общая картина:</strong> ").Append(E(PlainFacts.OverallConfiguration(result))).AppendLine("</p>");
        html.AppendLine("</section>");

        // --- Модули ---
        html.AppendLine("<section>");
        html.AppendLine("<h2>Модули проверки</h2>");
        html.AppendLine("<table>");
        html.AppendLine("<thead><tr><th>Модуль</th><th>Статус</th><th>Находок</th><th>Время</th></tr></thead>");
        html.AppendLine("<tbody>");
        foreach (var check in result.Checks)
        {
            html.Append("<tr><td><strong>").Append(E(check.Title)).Append("</strong><div class=\"muted\">")
                .Append(E(check.Subtitle)).AppendLine("</div></td>");
            html.Append("<td><span class=\"status ").Append(StatusClass(check.Status)).Append("\">")
                .Append(E(check.StatusText)).AppendLine("</span></td>");
            html.Append("<td>").Append(check.Findings.Count.ToString(Culture)).AppendLine("</td>");
            html.Append("<td class=\"muted\">").Append(check.Duration.TotalSeconds.ToString("F1", Culture)).AppendLine(" с</td></tr>");
        }
        html.AppendLine("</tbody></table>");
        html.AppendLine("</section>");

        // --- Находки ---
        var findings = result.Checks
            .SelectMany(c => c.Findings.Select(f => (Check: c.Title, Finding: f)))
            .OrderByDescending(x => x.Finding.Severity)
            .ToList();
        if (findings.Count > 0)
        {
            html.AppendLine("<section>");
            html.AppendLine("<h2>Находки</h2>");
            foreach (var (check, finding) in findings)
            {
                html.Append("<article class=\"finding ").Append(SeverityClass(finding.Severity)).AppendLine("\">");
                html.Append("<div class=\"finding-head\"><span class=\"sev\">").Append(E(SeverityText(finding.Severity)))
                    .Append("</span><strong>").Append(E(finding.Title)).AppendLine("</strong></div>");
                if (!string.IsNullOrWhiteSpace(finding.Detail))
                    html.Append("<p>").Append(E(finding.Detail)).AppendLine("</p>");
                if (!string.IsNullOrWhiteSpace(finding.Evidence))
                    html.Append("<pre>").Append(E(finding.Evidence!)).AppendLine("</pre>");
                html.Append("<div class=\"muted\">модуль: ").Append(E(check)).AppendLine("</div>");
                html.AppendLine("</article>");
            }
            html.AppendLine("</section>");
        }

        // --- Окружение ---
        var env = result.Environment;
        html.AppendLine("<section>");
        html.AppendLine("<h2>Окружение</h2>");
        html.AppendLine("<table class=\"kv\"><tbody>");
        AppendRow(html, "Операционная система", env.OsDescription);
        AppendRow(html, "Имя машины", env.MachineName);
        AppendRow(html, "Пользователь", env.UserName);
        AppendRow(html, "Права администратора", env.IsElevated ? "есть" : "нет");
        AppendRow(html, "Приватный режим", env.PrivacyMode ? "включён (IP и имена маскированы)" : "выключен");
        AppendRow(html, "IP-консенсус", result.IpConsensus.Summary);
        AppendRow(html, "Длительность", result.Duration.TotalSeconds.ToString("F1", Culture) + " с");
        html.AppendLine("</tbody></table>");
        html.AppendLine("</section>");

        html.AppendLine("<footer>");
        html.AppendLine("Отчёт сформирован NetworkChecker. Все данные собраны на этом компьютере, ничего не отправлялось на сервер.");
        html.AppendLine("</footer>");
        html.AppendLine("</main>");
        html.AppendLine("</body>");
        html.AppendLine("</html>");

        return Encoding.UTF8.GetBytes(html.ToString());
    }

    private static void AppendRow(StringBuilder html, string key, string? value)
    {
        html.Append("<tr><th>").Append(E(key)).Append("</th><td>").Append(E(value ?? "—")).AppendLine("</td></tr>");
    }

    private static string StatusClass(CheckStatus status) => status switch
    {
        CheckStatus.Clean => "ok",
        CheckStatus.NeedsReview => "warn",
        CheckStatus.Detected => "bad",
        CheckStatus.Skipped => "skip",
        _ => "err",
    };

    private static string SeverityClass(Severity severity) => severity switch
    {
        Severity.Critical => "bad",
        Severity.Warning => "warn",
        Severity.Notice => "notice",
        _ => "info",
    };

    private static string SeverityText(Severity severity) => severity switch
    {
        Severity.Critical => "КРИТИЧНО",
        Severity.Warning => "ВНИМАНИЕ",
        Severity.Notice => "ЗАМЕТКА",
        _ => "ИНФО",
    };

    /// <summary>HTML-экранирование: в отчёт попадают строки из системы (имена, маршруты, hosts).</summary>
    private static string E(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);

    private const string Styles = """
        :root { color-scheme: light dark; }
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 32px 16px;
            font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f6f7f9; color: #1b2230; line-height: 1.5;
        }
        main { max-width: 980px; margin: 0 auto; }
        .top { display: flex; align-items: baseline; gap: 12px; margin-bottom: 20px; }
        .brand { font-weight: 700; font-size: 18px; letter-spacing: .2px; }
        .sub { color: #6b7686; font-size: 13px; }
        section { background: #fff; border: 1px solid #e3e7ee; border-radius: 12px; padding: 20px 22px; margin-bottom: 18px; }
        h1 { font-size: 24px; margin: 0 0 8px; }
        h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .08em; color: #6b7686; margin: 0 0 14px; }
        p { margin: 0 0 8px; }
        .verdict { display: flex; gap: 22px; align-items: flex-start; border-left: 5px solid #888; }
        .score { font-size: 40px; font-weight: 700; line-height: 1; }
        .score small { font-size: 14px; font-weight: 500; color: #8a93a3; }
        .lead { font-size: 15px; }
        .plain { color: #4a5464; font-size: 14px; }
        .reasons { margin: 0; padding-left: 20px; }
        .reasons li { margin-bottom: 6px; }
        .facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
        .fact { border: 1px solid #e3e7ee; border-radius: 10px; padding: 12px 14px; background: #fbfcfe; }
        .fact.ok { border-left: 4px solid #2FA36B; }
        .fact.warn { border-left: 4px solid #D79B18; }
        .fact.bad { border-left: 4px solid #D8483F; }
        .fact .q { font-size: 11px; text-transform: uppercase; letter-spacing: .07em; color: #77808f; }
        .fact .a { font-size: 16px; font-weight: 600; margin: 2px 0; }
        .fact .h { font-size: 12.5px; color: #5d6779; }
        .overall { margin-top: 14px; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #eceff3; vertical-align: top; }
        thead th { font-size: 11px; text-transform: uppercase; letter-spacing: .07em; color: #77808f; border-bottom: 1px solid #dfe4ec; }
        tbody tr:last-child td { border-bottom: none; }
        table.kv th { width: 42%; color: #5d6779; font-weight: 500; }
        .muted { color: #77808f; font-size: 12.5px; }
        .status { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; }
        .status.ok { background: rgba(47,163,107,.12); color: #237a50; }
        .status.warn { background: rgba(215,155,24,.14); color: #8f6508; }
        .status.bad { background: rgba(216,72,63,.12); color: #a52f28; }
        .status.skip, .status.err { background: rgba(120,132,150,.14); color: #5d6779; }
        .finding { border: 1px solid #e3e7ee; border-left-width: 4px; border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; }
        .finding.bad { border-left-color: #D8483F; }
        .finding.warn { border-left-color: #D79B18; }
        .finding.notice { border-left-color: #D7B018; }
        .finding.info { border-left-color: #8d97a8; }
        .finding-head { display: flex; gap: 10px; align-items: center; margin-bottom: 4px; }
        .sev { font-size: 10.5px; font-weight: 700; letter-spacing: .06em; color: #77808f; }
        pre {
            white-space: pre-wrap; word-break: break-word; background: #f3f5f9; border-radius: 8px;
            padding: 10px; font-size: 12.5px; margin: 8px 0; color: #33405a;
        }
        footer { color: #77808f; font-size: 12.5px; text-align: center; padding: 8px 0 24px; }
        @media print {
            body { background: #fff; padding: 0; }
            section { border: none; padding: 12px 0; page-break-inside: avoid; }
            .verdict { border-left-width: 4px; }
        }
        @media (prefers-color-scheme: dark) {
            body { background: #10151d; color: #e6eaf2; }
            section, .fact { background: #161d28; border-color: #26303f; }
            .fact { background: #131a24; }
            h2, .muted, .sub, footer { color: #9aa5b6; }
            .plain, table.kv th { color: #b9c2d1; }
            pre { background: #0d131b; color: #cfd7e4; }
            thead th { border-color: #26303f; }
            th, td { border-color: #222b38; }
        }
        """;
}
