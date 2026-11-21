using System.Globalization;
using System.Text;

namespace VpnChecker.Core.VpnAudit;

public sealed record SupportSpeedSample(
    double? DownloadMbps,
    double? UploadMbps,
    int? LatencyMs,
    string ProviderUsed);

public sealed record SupportNetworkSnapshot(
    string Phase,
    DateTimeOffset CapturedAt,
    string? Ip,
    string? Country,
    string? City,
    string? Isp,
    string? Asn,
    SupportSpeedSample? Speed = null,
    IReadOnlyList<string>? WebRtcSrflxIps = null);

public sealed record SupportTicketDraft(
    string Symptom,
    string ConnectionType,
    string ClientApp,
    string? UserComment = null,
    bool MaskHomeIp = true,
    SupportNetworkSnapshot? WithoutVpn = null,
    SupportNetworkSnapshot? WithVpn = null,
    VpnAuditReport? ActiveReport = null,
    RttBenchmarkResult? RttBenchmark = null,
    WindowsNetworkStackReport? OsStack = null,
    IReadOnlyList<string>? Symptoms = null);

/// <summary>
/// Формирует готовый диагностический пакет для техподдержки ВПН-сервиса:
/// 1) Компактное сообщение для Telegram-бота / чата поддержки (с мультивыбором проблем, авто-маскировкой ключей/UUID и срезом стека Windows, без привязки к одному конкретному узлу).
/// 2) Полный Markdown-файл с таблицей «Без ВПН (провайдер РФ)» vs «С ВПН».
/// </summary>
public static class SupportTicketBuilder
{
    public static IReadOnlyList<string> ResolveSymptoms(SupportTicketDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);

        if (draft.Symptoms is { Count: > 0 })
        {
            var cleaned = draft.Symptoms
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (cleaned.Count > 0)
            {
                return cleaned;
            }
        }

        return string.IsNullOrWhiteSpace(draft.Symptom)
            ? ["Не указана (см. замеры ниже)"]
            : [draft.Symptom.Trim()];
    }

    public static string BuildTelegramMessage(SupportTicketDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);

        var symptoms = ResolveSymptoms(draft);
        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"Здравствуйте! Прошу помочь с подключением ({DateTimeOffset.Now:dd.MM.yyyy HH:mm}).");
        sb.AppendLine();

        if (symptoms.Count == 1)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Проблема: {symptoms[0]}");
        }
        else
        {
            sb.AppendLine("• Проблемы с интернетом / ВПН:");
            foreach (var item in symptoms)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"  - {item}");
            }
        }

        sb.AppendLine(CultureInfo.InvariantCulture, $"• Тип сети: {draft.ConnectionType}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"• Клиент: {draft.ClientApp}");

        if (draft.WithoutVpn is { } w)
        {
            var loc = JoinNonEmpty(", ", w.City, w.Country);
            var isp = JoinNonEmpty(" ", w.Isp, w.Asn);
            sb.AppendLine();
            sb.AppendLine("1) Без ВПН (мой провайдер в РФ):");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Провайдер: {(string.IsNullOrWhiteSpace(isp) ? "не определён" : isp)}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Регион: {(string.IsNullOrWhiteSpace(loc) ? "—" : loc)}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• IP: {FormatIp(w.Ip, draft.MaskHomeIp)}");
            if (w.Speed?.DownloadMbps is not null)
            {
                var up = w.Speed.UploadMbps?.ToString("F1", CultureInfo.InvariantCulture) ?? "—";
                sb.AppendLine(CultureInfo.InvariantCulture, $"• Скорость без ВПН: ↓ {w.Speed.DownloadMbps:F1} Мбит/с | ↑ {up} Мбит/с");
            }
        }

        if (draft.WithVpn is { } v)
        {
            var loc = JoinNonEmpty(", ", v.City, v.Country);
            var isp = JoinNonEmpty(" ", v.Isp, v.Asn);
            var metaSuffix = JoinNonEmpty(", ", loc, isp);
            sb.AppendLine();
            sb.AppendLine("2) С включённым ВПН:");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Выходной IP: {FormatIp(v.Ip, false)}{(string.IsNullOrWhiteSpace(metaSuffix) ? string.Empty : $" ({metaSuffix})")}");
            if (v.Speed?.DownloadMbps is not null)
            {
                var up = v.Speed.UploadMbps?.ToString("F1", CultureInfo.InvariantCulture) ?? "—";
                sb.AppendLine(CultureInfo.InvariantCulture, $"• Скорость с ВПН: ↓ {v.Speed.DownloadMbps:F1} Мбит/с | ↑ {up} Мбит/с");
            }

            if (v.WebRtcSrflxIps is not null)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"• Утечка IP (WebRTC): {EvaluateWebRtcSummary(draft.WithoutVpn, draft.WithVpn)}");
            }
        }

        if (draft.OsStack is { } os)
        {
            sb.AppendLine();
            sb.AppendLine("Сетевой стек ОС Windows:");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• {FormatOsStackLine(os)}");
        }

        if (!string.IsNullOrWhiteSpace(draft.UserComment))
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"Комментарий: {VpnConfigAuditor.MaskSensitiveText(draft.UserComment.Trim())}");
        }

        return sb.ToString().TrimEnd();
    }

    public static string BuildFullMarkdownReport(SupportTicketDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);

        var symptoms = ResolveSymptoms(draft);
        var downWithout = draft.WithoutVpn?.Speed?.DownloadMbps is { } d1
            ? string.Create(CultureInfo.InvariantCulture, $"{d1:F1} Мбит/с")
            : "—";
        var downWith = draft.WithVpn?.Speed?.DownloadMbps is { } d2
            ? string.Create(CultureInfo.InvariantCulture, $"{d2:F1} Мбит/с")
            : "—";
        var upWithout = draft.WithoutVpn?.Speed?.UploadMbps is { } u1
            ? string.Create(CultureInfo.InvariantCulture, $"{u1:F1} Мбит/с")
            : "—";
        var upWith = draft.WithVpn?.Speed?.UploadMbps is { } u2
            ? string.Create(CultureInfo.InvariantCulture, $"{u2:F1} Мбит/с")
            : "—";

        var sb = new StringBuilder();
        sb.AppendLine("# Диагностический пакет для техподдержки ВПН (VPN_Checker)");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Дата сбора:** {DateTimeOffset.UtcNow:O}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Проблемы:** {string.Join("; ", symptoms)}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Тип сети:** {draft.ConnectionType}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Клиент:** {draft.ClientApp}");
        sb.AppendLine();
        sb.AppendLine("## Сравнение «Без ВПН» vs «С ВПН»");
        sb.AppendLine();
        sb.AppendLine("| Показатель | Без ВПН (РФ-провайдер) | С ВПН (туннель) |");
        sb.AppendLine("|---|---|---|");
        sb.AppendLine(CultureInfo.InvariantCulture, $"| IP | {FormatIp(draft.WithoutVpn?.Ip, draft.MaskHomeIp)} | {FormatIp(draft.WithVpn?.Ip, false)} |");
        sb.AppendLine(CultureInfo.InvariantCulture, $"| Провайдер / ASN | {draft.WithoutVpn?.Isp ?? "—"} {draft.WithoutVpn?.Asn ?? ""} | {draft.WithVpn?.Isp ?? "—"} {draft.WithVpn?.Asn ?? ""} |");
        sb.AppendLine(CultureInfo.InvariantCulture, $"| Download | {downWithout} | {downWith} |");
        sb.AppendLine(CultureInfo.InvariantCulture, $"| Upload | {upWithout} | {upWith} |");

        if (draft.OsStack is { } os)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"**Стек ОС Windows:** {FormatOsStackLine(os)}");
        }

        if (draft.WithVpn?.WebRtcSrflxIps is not null)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"**Утечка WebRTC:** {EvaluateWebRtcSummary(draft.WithoutVpn, draft.WithVpn)}");
        }

        if (!string.IsNullOrWhiteSpace(draft.UserComment))
        {
            sb.AppendLine();
            sb.AppendLine("## Комментарий пользователя");
            sb.AppendLine();
            sb.AppendLine(VpnConfigAuditor.MaskSensitiveText(draft.UserComment.Trim()));
        }

        return sb.ToString().TrimEnd();
    }

    private static string FormatOsStackLine(WindowsNetworkStackReport os)
    {
        var tun = os.HasActiveTunAdapter ? $"TUN активен ({os.ActiveTunName})" : "TUN выключен (системный прокси / без ВПН)";
        var dns = os.HasPlainIspDnsOutsideTun ? "риск SMHNR DNS на физ. адаптере" : "DNS защищён";
        var v6 = os.HasGlobalIpv6OutsideTun ? "обнаружен глобальный IPv6 вне TUN" : "глобальный IPv6 вне TUN не найден";
        return $"{tun} · {dns} · {v6}";
    }

    private static string JoinNonEmpty(string separator, string? first, string? second)
    {
        if (string.IsNullOrWhiteSpace(first)) return second?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(second)) return first.Trim();
        return $"{first.Trim()}{separator}{second.Trim()}";
    }

    private static string EvaluateWebRtcSummary(SupportNetworkSnapshot? withoutVpn, SupportNetworkSnapshot? withVpn)
    {
        if (withVpn?.WebRtcSrflxIps is null) return "проверка не выполнялась";
        if (!string.IsNullOrWhiteSpace(withoutVpn?.Ip) &&
            withVpn.WebRtcSrflxIps.Contains(withoutVpn.Ip, StringComparer.Ordinal) &&
            !string.Equals(withoutVpn.Ip, withVpn.Ip, StringComparison.Ordinal))
        {
            return "КРИТИЧНО: обнаружена утечка реального домашнего IP через WebRTC!";
        }
        return "утечек реального IP не обнаружено";
    }

    private static string FormatIp(string? ip, bool mask)
    {
        if (string.IsNullOrWhiteSpace(ip)) return "не определён";
        if (!mask) return ip;
        var parts = ip.Split('.');
        return parts.Length == 4 ? $"{parts[0]}.{parts[1]}.xxx.xxx" : "••••:••••";
    }
}
