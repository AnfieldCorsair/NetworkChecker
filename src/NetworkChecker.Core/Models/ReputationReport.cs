namespace NetworkChecker.Core.Models;

/// <summary>Цвет строки репутации в интерфейсе.</summary>
public enum ReputationTone
{
    Neutral = 0,
    Good = 1,
    Warn = 2,
    Bad = 3,
    Unknown = 4,
}

/// <summary>Почему отчёт репутации может быть пустым: это не «чистый адрес».</summary>
public enum ReputationReportState
{
    Ok = 0,
    Offline = 1,
    Disabled = 2,
    NoData = 3,
}

/// <summary>Один источник репутации: что спросили и что ответили.</summary>
public sealed record ReputationSource(
    string Group,
    string Name,
    string Status,
    string? Detail,
    ReputationTone Tone,
    string? Link);

/// <summary>
/// Метка региона Google. Зонд ходит без cookies и без аккаунта, поэтому показывает
/// только сетевую часть классификации Google, а не решение для конкретного профиля.
/// </summary>
public sealed record GoogleRegionInfo(
    string? Region,
    string? GeoCountry,
    bool? RuMarked,
    bool? RegionDiffersFromGeo,
    bool? AiStudioRedirect,
    string? AiStudioStatus,
    string? AiStudioFinalUri,
    string? YouTubeStatus,
    string? Note);

/// <summary>
/// Итог блока «Репутация в целом». Индекс риска условный: это не вероятность VPN,
/// не мнение Google и не предсказание капчи.
/// </summary>
public sealed record ReputationReport(
    DateTimeOffset At,
    string? Ip,
    ReputationReportState State,
    bool RiskAvailable,
    int Risk,
    string Headline,
    string Summary,
    IReadOnlyList<ReputationSource> Sources,
    GoogleRegionInfo Google,
    IReadOnlyList<string> Caveats)
{
    public bool HasData => State == ReputationReportState.Ok && Sources.Count > 0;

    public static ReputationReport Disabled(string reason, bool offline)
    {
        var info = new GoogleRegionInfo(null, null, null, null, null,
            offline ? "не проверялось: офлайн-режим" : "не проверялось: проверка выключена",
            null, "не проверялось", null);
        return new ReputationReport(
            DateTimeOffset.Now,
            null,
            offline ? ReputationReportState.Offline : ReputationReportState.Disabled,
            false,
            0,
            offline ? "Проверка репутации не выполнялась" : "Проверка репутации выключена",
            reason,
            [new ReputationSource("Общее", "Внешние запросы", offline ? "офлайн-режим" : "выключено", reason,
                ReputationTone.Unknown, null)],
            info,
            [.. DefaultCaveats()]);
    }

    /// <summary>Общие оговорки, которые показывает и UI, и экспорт.</summary>
    public static IReadOnlyList<string> DefaultCaveats() =>
    [
        "Нахождение в спам-базе говорит о почтовой или сетевой репутации адреса, а не об использовании VPN.",
        "PBL (коды 127.0.0.10 и .11) — обычные динамические диапазоны провайдера, это не спам и не нарушение.",
        "Spamhaus не отвечает на запросы через публичные резолверы вроде 8.8.8.8 и 1.1.1.1: такие зоны показаны как «нет данных». Для надёжности нужен бесплатный DQS-ключ.",
        "У Google нет публичного API «доверия к IP» и вероятности капчи: reCAPTCHA v3 считается для конкретного сайта, а Postmaster Tools v2 не отдаёт репутацию IP.",
        "Метка GL зависит ещё и от аккаунта, cookies, языка и прошлой активности. Наш зонд без cookies видит только сетевую часть классификации.",
        "Редирект Google AI Studio бывает и из-за возраста аккаунта, платёжного профиля и политик Workspace — не только из-за региона.",
        "Отсутствие метки в базе не означает «доверенный адрес»: резидентные прокси и новые VPN-сервисы часто выглядят чистыми.",
        "Проверка отправляет внешний IP сторонним сервисам; API-ключи хранятся локально в settings.json и не попадают в отчёты и логи.",
    ];
}
