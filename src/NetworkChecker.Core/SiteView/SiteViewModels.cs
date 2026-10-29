namespace NetworkChecker.Core.SiteView;

/// <summary>Оценка того, как выглядит факт для сайта: нейтрально, обычно, подозрительно, плохо.</summary>
public enum SiteViewTone
{
    Neutral,
    Good,
    Warn,
    Bad,
}

/// <summary>Строка «визитной карточки»: что именно сервер запишет о посетителе.</summary>
public sealed record SiteViewRow(string Label, string Value, string? Hint, SiteViewTone Tone);

/// <summary>Вывод, который делает сайт (или его антибот) на основе одного или нескольких фактов.</summary>
public sealed record SiteViewSignal(string Title, string Detail, SiteViewTone Tone, int Points);

/// <summary>Сырой запрос: ровно то, что уходит на сервер.</summary>
public sealed record SiteViewRequest(string Line, IReadOnlyList<KeyValuePair<string, string>> Headers);

/// <summary>
/// Данные, которые сервер узнаёт о посетителе по одному HTTP-запросу.
/// Источник — GeoIP-база, которая отвечает про внешний адрес.
/// </summary>
public sealed record SiteGeo(
    string? Ip,
    string? Country,
    string? City,
    string? Region,
    string? Company,
    string? Asn,
    string? Timezone,
    bool? Hosting,
    bool? Proxy,
    string? Isp);

/// <summary>
/// То, что видно только на стороне пользователя: системный часовой пояс, язык, клиент.
/// Сайт узнаёт это из заголовков (язык, клиент) и из JS (часовой пояс), поэтому пары
/// «адрес ↔ система» и сравниваются.
/// </summary>
public sealed record SiteLocalProfile(
    string TimeZoneId,
    TimeSpan UtcOffset,
    string CultureName,
    string OsName,
    string UserAgent);

/// <summary>Итог осмотра: что сайт видит и насколько это похоже на VPN.</summary>
public sealed record SiteViewReport(
    DateTimeOffset At,
    string? Ip,
    IReadOnlyList<SiteViewRow> Rows,
    IReadOnlyList<SiteViewSignal> Signals,
    SiteViewRequest Request,
    int Exposure,
    string Headline,
    string Summary,
    string? Error,
    bool Offline)
{
    /// <summary>Есть ли данные о внешнем адресе (иначе показаны только локальные факты).</summary>
    public bool HasGeo => !string.IsNullOrWhiteSpace(Ip);

    public static SiteViewReport Empty(string error, bool offline) => new(
        DateTimeOffset.Now,
        null,
        [],
        [],
        new SiteViewRequest("GET / HTTP/1.1", []),
        0,
        "Сайт пока ничего о вас не знает",
        "Нет данных о внешнем адресе: включён офлайн-режим или GeoIP-сервисы не ответили. Локальные факты — часовой пояс, язык, клиент — показаны ниже.",
        error,
        offline);
}

/// <summary>Осмотр «глазами сайта»: внешний адрес + локальный профиль.</summary>
public interface ISiteEyeService
{
    Task<SiteViewReport> InspectAsync(CancellationToken ct = default);
}
