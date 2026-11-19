using System.Globalization;
using System.Text;

namespace NetworkChecker.Core.VpnAudit;

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
    RttBenchmarkResult? RttBenchmark = null);

/// <summary>
/// Формирует готовый диагностический пакет для техподдержки ВПН-сервиса:
/// 1) Компактное сообщение для Telegram-бота / чата поддержки (с авто-маскировкой ключей/UUID).
/// 2) Полный Markdown-файл с таблицей «Без ВПН (провайдер РФ)» vs «С ВПН».
/// </summary>
public static class SupportTicketBuilder
{
    public static string BuildTelegramMessage(SupportTicketDraft draft)
    {
        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"Здравствуйте! Прошу помочь с подключением ({DateTimeOffset.Now:dd.MM.yyyy HH:mm}).");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"• Проблема: {draft.Symptom}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"• Тип сети: {draft.ConnectionType}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"• Клиент: {draft.ClientApp}");

        if (draft.WithoutVpn is { } w)
        {
            var loc = string.Join(", ", new[] { w.City, w.Country }.Where(s => !string.IsNullOrWhiteSpace(s)));
            var isp = string.Join(" ", new[] { w.Isp, w.Asn }.Where(s => !string.IsNullOrWhiteSpace(s)));
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
            var loc = string.Join(", ", new[] { v.City, v.Country }.Where(s => !string.IsNullOrWhiteSpace(s)));
            var isp = string.Join(" ", new[] { v.Isp, v.Asn }.Where(s => !string.IsNullOrWhiteSpace(s)));
            sb.AppendLine();
            sb.AppendLine("2) С включённым ВПН:");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Выходной IP: {FormatIp(v.Ip, false)} ({loc}, {isp})");
            if (v.Speed?.DownloadMbps is not null)
            {
                var up = v.Speed.UploadMbps?.ToString("F1", CultureInfo.InvariantCulture) ?? "—";
                sb.AppendLine(CultureInfo.InvariantCulture, $"• Скорость с ВПН: ↓ {v.Speed.DownloadMbps:F1} Мбит/с | ↑ {up} Мбит/с");
            }
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Утечка IP (WebRTC): {EvaluateWebRtcSummary(draft.WithoutVpn, draft.WithVpn)}");
        }

        if (draft.ActiveReport is { Profile.Protocol: not VpnProtocol.Unknown } rep)
        {
            var p = rep.Profile;
            var portText = p.ServerPort?.ToString(CultureInfo.InvariantCulture) ?? "—";
            sb.AppendLine();
            sb.AppendLine("3) Параметры профиля (ключи скрыты):");
            sb.AppendLine(CultureInfo.InvariantCulture, $"• Узел: {p.Name} · {p.ProtocolLabel} ({p.Transport}) · {p.ServerHost ?? "—"}:{portText}");
            if (!string.IsNullOrWhiteSpace(p.Tls.Sni))
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"• Маскировка: {p.Tls.Mode.ToUpperInvariant()} · SNI={p.Tls.Sni} · fp={p.Tls.Fingerprint ?? "—"}");
            }
        }

        if (draft.RttBenchmark is { } rtt)
        {
            var avgText = rtt.AvgMs?.ToString(CultureInfo.InvariantCulture) ?? "—";
            var p95Text = rtt.P95Ms?.ToString(CultureInfo.InvariantCulture) ?? "—";
            var jitterText = rtt.JitterMs?.ToString(CultureInfo.InvariantCulture) ?? "—";
            sb.AppendLine(CultureInfo.InvariantCulture, $"• TCP RTT ({rtt.Host}:{rtt.Port}): avg {avgText} мс / p95 {p95Text} мс / jitter {jitterText} мс / потери {rtt.LossPct}%");
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
        sb.AppendLine("# Диагностический пакет для техподдержки ВПН (NetworkChecker)");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Дата сбора:** {DateTimeOffset.UtcNow:O}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- **Симптом:** {draft.Symptom}");
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
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"**Утечка WebRTC:** {EvaluateWebRtcSummary(draft.WithoutVpn, draft.WithVpn)}");
        return sb.ToString().TrimEnd();
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
