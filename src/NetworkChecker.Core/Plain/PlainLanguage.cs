using NetworkChecker.Core.Models;

namespace NetworkChecker.Core.Plain;

/// <summary>Объяснение «человеческим языком»: что проверяли, что это значит и что делать.</summary>
public sealed record PlainExplanation(string Headline, string WhatItMeans, string Advice)
{
    public string AllText => $"{Headline}. {WhatItMeans} {Advice}".Trim();
}

/// <summary>
/// Слой перевода технических результатов в понятные фразы.
/// Используется простым режимом интерфейса и отчётами, чтобы отчёт читал не только инженер.
/// Здесь нет обращения к сети и времени — только чистые функции, поэтому всё покрыто тестами.
/// </summary>
public static class PlainLanguage
{
    /// <summary>Короткая оценка «конфигурация в порядке или нет» для верхней карточки.</summary>
    public static PlainExplanation ForVerdict(VerdictResult verdict, IReadOnlyList<CheckResult> checks)
    {
        var failed = checks.Count(c => c.Status is CheckStatus.Failed or CheckStatus.Skipped);
        var tail = failed > 0
            ? $" Правда, {failed} проверок пропущены или не смогли отработать — часть картины неизвестна."
            : string.Empty;

        return verdict.Level switch
        {
            RiskLevel.Clean => new PlainExplanation(
                "Всё выглядит обычно",
                "В доступных данных не найдено признаков туннелей, прокси или программ обхода. " +
                "Эти проверки не дают полной гарантии." + tail,
                "Если интернет работает медленно или что-то не открывается, нужны дополнительные проверки; этот результат не исключает VPN."),

            RiskLevel.NeedsReview => new PlainExplanation(
                "Есть на что посмотреть",
                "Нашлись мелочи, которые по отдельности ничего не значат: например, необычный адрес выхода или " +
                "нестандартная настройка сети. Это не повод для паники, но и не идеально чистая картина." + tail,
                "Переключите тумблер «Подробно» и посмотрите, что помечено жёлтым. Если вы сами ничего не настраивали — " +
                "такие сигналы могут иметь разные причины, в том числе настройки провайдера или роутера."),

            RiskLevel.Detected => new PlainExplanation(
                "Похоже, трафик идёт через VPN или прокси",
                "Найдены сигналы, совместимые с VPN или прокси; отдельные признаки могут иметь и другие объяснения." + tail,
                "Если вы включали VPN сами — всё ожидаемо, беспокоиться не о чем. Если нет — откройте «Подробно» " +
                "и посмотрите, какая именно программа или настройка помечена красным; проверьте её назначение перед изменениями."),

            _ => new PlainExplanation(
                "Проверка не завершилась",
                "Не удалось собрать достаточно данных для вывода.",
                "Запустите проверку ещё раз. Если ошибка повторяется — посмотрите подробный режим: там указано, " +
                "какие проверки не отработали."),
        };
    }

    /// <summary>Простое описание модуля проверки.</summary>
    public static string WhatWeChecked(CheckCategory category) => category switch
    {
        CheckCategory.GeoIp => "Смотрели, как ваш интернет-адрес выглядит со стороны",
        CheckCategory.IpComparison => "Сравнивали адрес, который видят разные сервисы",
        CheckCategory.DirectSigns => "Искали включённые VPN, прокси и программы для обхода",
        CheckCategory.IndirectSigns => "Смотрели настройки сети: маршруты, DNS, размер пакетов",
        CheckCategory.Bypass => "Проверяли, не открыт ли на компьютере локальный прокси",
        CheckCategory.CallTransport => "Проверяли, ходит ли трафик напрямую или только через посредника",
        CheckCategory.CdnPulling => "Спрашивали у крупных сервисов, что они о вас видят",
        CheckCategory.DomainReachability => "Проверяли, открываются ли нужные сайты и на каком шаге ломается",
        CheckCategory.RttTriangulation => "Замеряли скорость отклика до российских и зарубежных сайтов",
        CheckCategory.IcmpSpoofing => "Проверяли, не подделывает ли провайдер ответы сети",
        _ => "Дополнительная проверка",
    };

    /// <summary>Простой статус модуля.</summary>
    public static string StatusInPlainWords(CheckStatus status) => status switch
    {
        CheckStatus.Clean => "Всё обычно",
        CheckStatus.NeedsReview => "Есть мелочи",
        CheckStatus.Detected => "Нашли признаки",
        CheckStatus.Skipped => "Не проверялось",
        CheckStatus.Failed => "Не удалось проверить",
        _ => "Неизвестно",
    };

    /// <summary>Что сделать, если модуль что-то нашёл.</summary>
    public static string AdviceFor(CheckResult check) => check.Status switch
    {
        CheckStatus.Detected => check.Category switch
        {
            CheckCategory.DirectSigns =>
                "Посмотрите в подробном режиме, что именно совпало: имя туннеля, настройка прокси или запущенная программа. " +
                "Самый быстрый способ проверить — выключить подозрительную программу и запустить проверку снова.",
            CheckCategory.Bypass =>
                "На компьютере отвечает локальный прокси — обычно это клиент VPN/обхода в трее. Закройте его и проверьте снова; " +
                "если порт остался открытым, программу пора обновить или удалить.",
            CheckCategory.GeoIp =>
                "Адрес выхода не похож на домашний: он либо за границей, либо принадлежит дата-центру. " +
                "Это нормально при включённом VPN и ненормально, если вы ничего не включали.",
            CheckCategory.IndirectSigns =>
                "В настройках сети есть что-то нестандартное: маршрут, DNS или размер пакетов. " +
                "Если вы не настраивали сеть руками — вероятно, так работает роутер или клиент VPN.",
            CheckCategory.CallTransport =>
                "Часть трафика идёт не тем путём, что остальной. Так бывает, когда прокси заворачивает только часть соединений.",
            CheckCategory.DomainReachability =>
                "Часть сайтов не открывается. Это может быть блокировка у провайдера — как раз то, для чего обычно и включают VPN.",
            CheckCategory.RttTriangulation =>
                "Ответы от российских сайтов идут дольше зарубежных: похоже, трафик выходит за границу и возвращается.",
            CheckCategory.IcmpSpoofing =>
                "Ответы сети выглядят подозрительно: адреса или задержки не сходятся. Стоит проверить на другом подключении.",
            _ => "Откройте подробный режим, чтобы увидеть детали этой проверки.",
        },
        CheckStatus.NeedsReview =>
            "Само по себе это ничего не значит — просто обратите внимание. Если хотите деталей, включите «Подробно».",
        CheckStatus.Failed =>
            "Проверка не смогла отработать: возможно, нет доступа к сети или нужных прав. Остальные проверки на это не влияют.",
        CheckStatus.Skipped =>
            "Проверка пропущена — например, из-за офлайн-режима или отсутствия нужных данных.",
        _ => "Ничего делать не нужно.",
    };

    /// <summary>Итог одной проверки в формате простого режима.</summary>
    public static PlainCheck ToPlain(CheckResult check) => new(
        Title: check.Title,
        WhatWeChecked: WhatWeChecked(check.Category),
        Status: StatusInPlainWords(check.Status),
        Colour: ColourOf(check.Status),
        Advice: check.Status is CheckStatus.Clean or CheckStatus.Skipped ? string.Empty : AdviceFor(check),
        FindingsCount: check.Findings.Count);

    private static string ColourOf(CheckStatus status) => status switch
    {
        CheckStatus.Clean => "green",
        CheckStatus.NeedsReview => "yellow",
        CheckStatus.Detected => "red",
        CheckStatus.Failed => "purple",
        _ => "grey",
    };
}

/// <summary>Готовая строка простого режима (сериализуется в отчёты как есть).</summary>
public sealed record PlainCheck(string Title, string WhatWeChecked, string Status, string Colour, string Advice, int FindingsCount);
