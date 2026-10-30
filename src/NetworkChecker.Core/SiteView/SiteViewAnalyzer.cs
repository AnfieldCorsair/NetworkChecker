using System.Globalization;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.SiteView;

/// <summary>
/// Собирает «визитную карточку посетителя» так, как её видит сервер российского сайта:
/// адрес, география, тип сети, часовой пояс, язык, клиент. Ничего не запрашивает сам —
/// на вход только уже полученные данные, поэтому логику можно проверять тестами целиком.
/// </summary>
public static class SiteViewAnalyzer
{
    /// <summary>Порог «похоже на VPN» по накопленным признакам.</summary>
    public const int VpnLikeThreshold = 50;

    /// <summary>Порог «есть что записать в профиль».</summary>
    public const int ReviewThreshold = 20;

    /// <summary>Разница часовых поясов, после которой сайт считает данные несогласованными.</summary>
    public const double TimeZoneSuspicionHours = 2;

    public static SiteViewReport Build(
        SiteGeo? geo,
        SiteLocalProfile local,
        DateTimeOffset at,
        string? error = null,
        bool offline = false,
        Func<string, TimeZoneInfo?>? resolveTimeZone = null)
    {
        ArgumentNullException.ThrowIfNull(local);

        var request = BuildRequest("api.ipapi.is", local);
        if (geo is null || string.IsNullOrWhiteSpace(geo.Ip))
        {
            var localOnly = LocalRows(local, localOffsetDiffHours: null).ToList();
            return new SiteViewReport(
                at,
                null,
                localOnly,
                [],
                request,
                0,
                "Нет данных о внешнем адресе",
                "Внешний адрес не получен: включён офлайн-режим или GeoIP-сервисы не ответили. Ниже — только то, "
                + "что вообще не зависит от интернета: часовой пояс, язык и клиент.",
                error,
                offline);
        }

        var resolve = resolveTimeZone ?? DefaultResolve;
        var ipOffset = ResolveOffset(geo.Timezone, at, resolve);

        var rows = new List<SiteViewRow> { GeoRow(geo) };
        var ipZoneText = ipOffset is null
            ? "неизвестен"
            : $"{geo.Timezone} ({FormatOffset(ipOffset.Value)})";
        rows.AddRange(GeoDetails(geo, ipZoneText));
        rows.AddRange(LocalRows(local, OffsetDiff(ipOffset, local.UtcOffset)));
        rows.Add(ClientRow(local));

        var signals = BuildSignals(geo, local, ipOffset);
        var exposure = Math.Clamp(signals.Sum(s => s.Points), 0, 100);
        var headline = exposure >= VpnLikeThreshold ? "Есть признаки, совместимые с VPN"
            : exposure >= ReviewThreshold ? "Есть что записать в профиль"
            : "Сильных признаков не найдено";

        return new SiteViewReport(
            at,
            geo.Ip!.Trim(),
            rows,
            signals,
            request,
            exposure,
            headline,
            BuildSummary(geo, signalCount: signals.Count, exposure),
            error,
            offline);
    }

    /// <summary>
    /// Заголовки, которые действительно уходят в запросе от приложения.
    /// Формат — как в HTTP/1.1, чтобы было видно, что сервер получает буквально.
    /// </summary>
    public static SiteViewRequest BuildRequest(string host, SiteLocalProfile local)
    {
        ArgumentNullException.ThrowIfNull(local);

        var headers = new List<KeyValuePair<string, string>>
        {
            new("Host", host),
            new("User-Agent", local.UserAgent),
            new("Accept", "application/json, text/plain, */*"),
            new("Accept-Encoding", "gzip, deflate, br"),
            new("Connection", "keep-alive"),
        };
        return new SiteViewRequest("GET / HTTP/1.1", headers);
    }

    /// <summary>Смещение в виде UTC+3 / UTC−7 (минус — типографский, чтобы не путать с дефисом).</summary>
    public static string FormatOffset(TimeSpan offset)
    {
        var total = (int)offset.TotalMinutes;
        var sign = total < 0 ? "\u2212" : "+";
        var abs = Math.Abs(total);
        var hours = (abs / 60).ToString(CultureInfo.InvariantCulture);
        return abs % 60 == 0
            ? $"UTC{sign}{hours}"
            : $"UTC{sign}{hours}:{(abs % 60).ToString("00", CultureInfo.InvariantCulture)}";
    }

    private static SiteViewRow GeoRow(SiteGeo geo) => new(
        "IP-адрес",
        geo.Ip!.Trim(),
        "Сервис видит адрес, с которого пришёл запрос. Он может отличаться от адреса браузера.",
        SiteViewTone.Neutral);

    private static IEnumerable<SiteViewRow> GeoDetails(SiteGeo geo, string ipZoneText)
    {
        var country = geo.Country is null ? "неизвестна" : $"{GeoCountries.Name(geo.Country)} ({geo.Country})";
        var place = string.Join(" · ", new[] { country, geo.Region, geo.City }.Where(p => !string.IsNullOrWhiteSpace(p)));
        yield return new SiteViewRow("География по IP", place,
            "Оценка GeoIP может отличаться от реального местоположения и базы конкретного сайта.", SiteViewTone.Neutral);

        var provider = new[] { geo.Company, geo.Isp }.FirstOrDefault(p => !string.IsNullOrWhiteSpace(p));
        yield return new SiteViewRow("Провайдер и ASN",
            string.Join(" · ", new[] { provider, geo.Asn }.Where(p => !string.IsNullOrWhiteSpace(p))) is { Length: > 0 } text
                ? text
                : "нет данных",
            "Данные зависят от GeoIP-базы и могут ошибаться.",
            SiteViewTone.Neutral);

        yield return new SiteViewRow("Тип сети", geo.Hosting switch
        {
            true => "дата-центр (хостинг)",
            false => "не помечен как хостинг",
            null => "нет данных",
        }, geo.Hosting switch
        {
            true => "Сервис классифицирует адрес как хостинг; это не доказывает VPN.",
            false => "Сервис не пометил адрес как хостинг; это не устанавливает тип сети.",
            null => "База GeoIP не дала признак hosting.",
        }, geo.Hosting switch { true => SiteViewTone.Bad, _ => SiteViewTone.Neutral });

        yield return new SiteViewRow("Метки в базах", geo.Proxy switch
        {
            true => "VPN / прокси / Tor",
            false => "не помечен сервисом",
            null => "нет данных",
        }, geo.Proxy switch
        {
            true => "Сервис пометил адрес; другие базы и решения сайтов могут отличаться, возможна ошибка.",
            false => "Этот GeoIP-сервис не пометил адрес как прокси; другие базы могут отличаться.",
            null => "Признак proxy от сервиса не пришёл.",
        }, geo.Proxy switch { true => SiteViewTone.Bad, _ => SiteViewTone.Neutral });

        yield return new SiteViewRow("Часовой пояс адреса", ipZoneText,
            "По GeoIP; сайт может сравнивать с данными браузера, если они доступны.", SiteViewTone.Neutral);
    }

    private static IEnumerable<SiteViewRow> LocalRows(SiteLocalProfile local, double? localOffsetDiffHours)
    {
        var sameZone = localOffsetDiffHours is null || localOffsetDiffHours.Value == 0;
        yield return new SiteViewRow("Ваш часовой пояс",
            $"{local.TimeZoneId} ({FormatOffset(local.UtcOffset)})",
            localOffsetDiffHours is null
                ? "Системное значение; браузер может раскрыть другой часовой пояс через JS."
                : sameZone
                    ? "Системный пояс совпадает с поясом по IP; браузер может сообщать другое."
                    : $"Расходится с адресом на {FormatHours(localOffsetDiffHours.Value)} — сайт может заметить расхождение, если браузер сообщит этот пояс.",
            localOffsetDiffHours is null ? SiteViewTone.Neutral : sameZone ? SiteViewTone.Good : SiteViewTone.Warn);

        yield return new SiteViewRow("Язык системы", local.CultureName,
            "Язык системы; язык, который отправляет браузер, может отличаться.",
            SiteViewTone.Neutral);

        yield return new SiteViewRow("Операционная система", local.OsName,
            "Определена локально. Браузер может раскрывать сведения об ОС, но не обязательно в полном виде.", SiteViewTone.Neutral);
    }

    private static SiteViewRow ClientRow(SiteLocalProfile local) => new(
        "Клиент запроса",
        local.UserAgent,
        local.UserAgent.Contains("Mozilla", StringComparison.OrdinalIgnoreCase)
            ? "Похож на браузерный."
            : "Так выглядит запрос программы, а не браузера: настоящий добавил бы Accept-Language, cookie и отпечаток JS.",
        SiteViewTone.Neutral);

    private static List<SiteViewSignal> BuildSignals(SiteGeo geo, SiteLocalProfile local, TimeSpan? ipOffset)
    {
        var signals = new List<SiteViewSignal>();

        if (geo.Proxy == true)
        {
            signals.Add(new SiteViewSignal(
                "Адрес помечен как VPN/прокси/Tor",
                "Некоторые антибот-системы используют такие метки: возможны капчи, региональные ограничения и "
                + "блокировка части функций — даже если вы просто сидите за корпоративным шлюзом.",
                SiteViewTone.Bad, 30));
        }

        if (geo.Hosting == true)
        {
            signals.Add(new SiteViewSignal(
                "Адрес принадлежит дата-центру",
                "Это может быть сервер, корпоративная сеть или VPN; классификация может ошибаться.",
                SiteViewTone.Bad, 25));
        }

        var isRussianCountry = geo.Country?.Equals("RU", StringComparison.OrdinalIgnoreCase) == true;
        if (geo.Country is not null && !isRussianCountry)
        {
            signals.Add(new SiteViewSignal(
                "Зарубежный IP-адрес",
                $"GeoIP определяет страну как {GeoCountries.Name(geo.Country)}. Сайты могут использовать другие базы. Часть сервисов "
                + "предложит другой язык, другую версию сайта или попросит подтвердить номер.",
                SiteViewTone.Warn, 20));
        }

        if (ipOffset is not null)
        {
            var diff = OffsetDiff(ipOffset, local.UtcOffset) ?? 0;
            if (diff > TimeZoneSuspicionHours)
            {
                signals.Add(new SiteViewSignal(
                    "Часовой пояс не сходится со страной адреса",
                    $"Адрес «в {FormatOffset(ipOffset.Value)}», а система — в {FormatOffset(local.UtcOffset)}. "
                    + "Некоторые сайты могут сравнивать эти величины; расхождение не доказывает VPN.",
                    SiteViewTone.Warn, 15));
            }
        }

        var culture = local.CultureName;
        var cultureIsRu = culture.StartsWith("ru", StringComparison.OrdinalIgnoreCase);
        var russianSpeakingRegion = geo.Country is not null && new[] { "KZ", "UA", "BY", "KG", "UZ", "TJ", "AM", "AZ", "MD", "TM", "GE" }.Contains(geo.Country, StringComparer.OrdinalIgnoreCase);
        if (cultureIsRu && russianSpeakingRegion)
        {
            signals.Add(new SiteViewSignal(
                "Русский язык и зарубежный IP: региональное примечание",
                "Русский язык распространён в этой стране; такое сочетание само по себе не признак VPN. Некоторые сайты могут объединять страны региона, но правила каждого сервиса различаются. Украина и Грузия не относятся к СНГ; здесь они учтены только как страны, где встречается русский язык.",
                SiteViewTone.Neutral, 0));
        }
        else if (geo.Country is not null && cultureIsRu != isRussianCountry)
        {
            signals.Add(new SiteViewSignal(
                "Язык и страна адреса не совпадают",
                cultureIsRu
                    ? $"Язык системы — {culture}, адрес — {GeoCountries.Name(geo.Country)}. Такое сочетание встречается по множеству причин и не доказывает VPN."
                    : $"Язык системы — {culture}, адрес — российский. Это не доказывает использование прокси.",
                SiteViewTone.Warn, 10));
        }

        if (!local.UserAgent.Contains("Mozilla", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(new SiteViewSignal(
                "Запрос не похож на браузерный",
                "Наш клиент отправляет собственный User-Agent и не передаёт Accept-Language. Браузер добавил бы ещё "
                + "cookie, язык и отпечаток JS — фактические данные браузера нужно проверять отдельно.",
                SiteViewTone.Warn, 5));
        }

        return signals;
    }

    private static string BuildSummary(SiteGeo geo, int signalCount, int exposure)
    {
        var country = geo.Country is null ? "неизвестной стране" : GeoCountries.Name(geo.Country);
        return $"География по IP: {country}; сигналов: {signalCount}, условный балл: {exposure}/100. "
            + "Это не вероятность VPN и не оценка конкретного сайта. Данные GeoIP могут быть неполными или ошибочными; "
            + "язык и часовой пояс взяты из системы, а не из браузера. Капча и ограничения зависят от самого сайта.";
    }

    private static double? OffsetDiff(TimeSpan? ipOffset, TimeSpan localOffset)
    {
        if (ipOffset is null) return null;
        return Math.Abs((ipOffset.Value - localOffset).TotalHours);
    }

    private static TimeSpan? ResolveOffset(string? timeZoneId, DateTimeOffset at, Func<string, TimeZoneInfo?> resolve)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId)) return null;
        var zone = resolve(timeZoneId);
        return zone?.GetUtcOffset(at);
    }

    private static TimeZoneInfo? DefaultResolve(string id)
    {
        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(id);
        }
        catch (TimeZoneNotFoundException)
        {
            // GeoIP обычно отдаёт IANA. На Windows может потребоваться преобразование в Windows ID.
            if (OperatingSystem.IsWindows() && TimeZoneInfo.TryConvertIanaIdToWindowsId(id, out var windowsId))
            {
                try { return TimeZoneInfo.FindSystemTimeZoneById(windowsId); }
                catch (TimeZoneNotFoundException) { return null; }
                catch (InvalidTimeZoneException) { return null; }
            }
            return null;
        }
        catch (InvalidTimeZoneException)
        {
            return null;
        }
    }

    private static string FormatHours(double hours) =>
        hours % 1 == 0
            ? hours.ToString("0", CultureInfo.InvariantCulture) + " ч"
            : hours.ToString("0.##", CultureInfo.InvariantCulture) + " ч";
}
