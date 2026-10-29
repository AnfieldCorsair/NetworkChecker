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
                "Обнаружены настройки VPN или прокси",
                "Обнаружены настройки прокси (в том числе переменные окружения процесса) или подключение VPN Windows. Это не подтверждает маршрут конкретного браузера." + tail,
                "Откройте «Подробно» " +
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
                "Проверьте, какая программа слушает локальный порт. Один ответ не доказывает использование прокси браузером.",
            CheckCategory.GeoIp =>
                "Внешняя база присвоила адресу метку или определила страну. Эти сведения могут быть неточными и не доказывают VPN.",
            CheckCategory.IndirectSigns =>
                "В настройках сети есть что-то нестандартное: маршрут, DNS или размер пакетов. " +
                "Если вы не настраивали сеть руками — вероятно, так работает роутер или клиент VPN.",
            CheckCategory.CallTransport =>
                "Сравните результаты UDP и HTTPS: различия могут быть связаны с NAT, маршрутами или настройками прокси.",
            CheckCategory.DomainReachability =>
                "Часть сайтов не открывается. Это может быть блокировка у провайдера — как раз то, для чего обычно и включают VPN.",
            CheckCategory.RttTriangulation =>
                "Задержки до групп сайтов различаются. Причину по одному RTT-измерению определить нельзя.",
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
