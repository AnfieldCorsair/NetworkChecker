using System.Globalization;
using RKNHardering.Core.Models;

namespace RKNHardering.Core.Plain;

/// <summary>Ответ на простой вопрос: «всё хорошо», «есть нюанс» или «плохо».</summary>
public sealed record PlainFact(string Question, string Answer, string Tone, string? Hint = null)
{
    public bool IsGood => Tone is "good";
    public bool IsWarn => Tone is "warn";
    public bool IsBad => Tone is "bad";
}

/// <summary>
/// Пять понятных ответов для простого режима: интернет-адрес, VPN, прокси, программы обхода, отклик сети.
/// Чистая функция от результата прогона — поэтому покрывается тестами без сети.
/// </summary>
public static class PlainFacts
{
    public static IReadOnlyList<PlainFact> Build(CheckRunResult result)
    {
        var facts = new List<PlainFact>
        {
            AddressFact(result),
            VpnFact(result),
            ProxyFact(result),
            AppsFact(result),
            ResponseFact(result),
        };
        return facts;
    }

    private static PlainFact AddressFact(CheckRunResult result)
    {
        var geo = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.GeoIp);
        var country = geo?.Metrics.FirstOrDefault(m => m.Label == "Страна")?.Value;
        var ip = result.IpConsensus.ConsensusIp;

        if (geo is null || geo.Status is CheckStatus.Skipped or CheckStatus.Failed || string.IsNullOrWhiteSpace(ip))
            return new PlainFact("Интернет-адрес", "не удалось узнать", "warn",
                "Скорее всего нет доступа к внешним сервисам или включён офлайн-режим.");

        var foreign = geo.Findings.Any(f => f.Title.Contains("не российский", StringComparison.OrdinalIgnoreCase));
        var hosting = geo.Findings.Any(f => f.Title.Contains("хостинг", StringComparison.OrdinalIgnoreCase));
        var proxy = geo.Findings.Any(f => f.Title.Contains("proxy", StringComparison.OrdinalIgnoreCase) ||
                                          f.Title.Contains("VPN/Tor", StringComparison.OrdinalIgnoreCase));

        var where = country is null ? "страна неизвестна" : $"адрес из региона {country}";
        if (proxy)
            return new PlainFact("Интернет-адрес", $"{ip} · {where}", "bad",
                "Сервисы считают этот адрес выходом VPN/прокси.");
        if (hosting)
            return new PlainFact("Интернет-адрес", $"{ip} · {where}", "warn",
                "Адрес принадлежит дата-центру, а не домашнему провайдеру — так бывает при VPN.");
        if (foreign)
            return new PlainFact("Интернет-адрес", $"{ip} · {where}", "warn",
                "Адрес не российский. Если вы не включали VPN — стоит посмотреть подробности.");
        return new PlainFact("Интернет-адрес", $"{ip} · {where}", "good", "Обычный домашний адрес.");
    }

    private static PlainFact VpnFact(CheckRunResult result)
    {
        var direct = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.DirectSigns);
        var indirect = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.IndirectSigns);
        if (direct is null && indirect is null)
            return new PlainFact("VPN или туннель", "не проверялось", "warn");

        var tunnels = direct?.Findings
            .Where(f => f.Title.Contains("туннель", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("VPN-подключение", StringComparison.OrdinalIgnoreCase))
            .ToList() ?? [];

        if (tunnels.Count > 0)
            return new PlainFact("VPN или туннель", "включён", "bad", string.Join("; ", tunnels.Select(t => t.Title)));

        if (indirect is not null && indirect.Status == CheckStatus.Detected)
            return new PlainFact("VPN или туннель", "похоже, включён", "bad",
                "В настройках сети есть признаки перенаправления трафика.");

        return new PlainFact("VPN или туннель", "не найден", "good", "Активных туннелей в системе нет.");
    }

    private static PlainFact ProxyFact(CheckRunResult result)
    {
        var direct = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.DirectSigns);
        var bypass = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.Bypass);

        var systemProxy = direct?.Findings.FirstOrDefault(f =>
            f.Title.Contains("Системный прокси включён", StringComparison.OrdinalIgnoreCase));
        if (systemProxy is not null)
            return new PlainFact("Прокси в системе", "настроен", "bad", systemProxy.Evidence ?? systemProxy.Detail);

        var localProxy = bypass?.Findings.FirstOrDefault(f =>
            f.Title.Contains("Локальный прокси", StringComparison.OrdinalIgnoreCase));
        if (localProxy is not null)
            return new PlainFact("Локальный прокси", "работает", "bad", localProxy.Evidence ?? localProxy.Title);

        if (bypass is null && direct is null)
            return new PlainFact("Прокси в системе", "не проверялось", "warn");

        return new PlainFact("Прокси в системе", "не настроен", "good", "Ни системного, ни локального прокси нет.");
    }

    private static PlainFact AppsFact(CheckRunResult result)
    {
        var direct = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.DirectSigns);
        if (direct is null) return new PlainFact("Программы для обхода", "не проверялось", "warn");

        var running = direct.Findings.Where(f => f.Title.StartsWith("Запущен клиент", StringComparison.OrdinalIgnoreCase)).ToList();
        if (running.Count > 0)
            return new PlainFact("Программы для обхода", "запущены", "bad", string.Join("; ", running.Select(r => r.Title)));

        var installed = direct.Findings.FirstOrDefault(f => f.Title.StartsWith("Установлены клиенты", StringComparison.OrdinalIgnoreCase));
        if (installed is not null)
            return new PlainFact("Программы для обхода", "установлены, но не запущены", "warn", installed.Title);

        return new PlainFact("Программы для обхода", "не найдены", "good",
            "Ни запущенных, ни установленных клиентов обхода не видно.");
    }

    private static PlainFact ResponseFact(CheckRunResult result)
    {
        var rtt = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.RttTriangulation);
        if (rtt is null || rtt.Metrics.Count == 0)
            return new PlainFact("Отклик сети", "не измерялся", "warn");

        var ru = rtt.Metrics.FirstOrDefault(m => m.Label.StartsWith("RU", StringComparison.OrdinalIgnoreCase))?.Value;
        var world = rtt.Metrics.FirstOrDefault(m => m.Label.StartsWith("Иностранные", StringComparison.OrdinalIgnoreCase))?.Value;
        var method = rtt.Metrics.FirstOrDefault(m => m.Label == "Метод измерения")?.Value;

        if (ru is null || world is null)
            return new PlainFact("Отклик сети", "недостаточно данных", "warn");

        var tone = rtt.Status == CheckStatus.Detected ? "bad" : rtt.Status == CheckStatus.Clean ? "good" : "warn";
        var hint = rtt.Status == CheckStatus.Detected
            ? "Российские сайты отвечают заметно медленнее зарубежных — трафик, похоже, идёт в обход."
            : "Отклик обычный для прямого подключения.";
        if (!string.IsNullOrWhiteSpace(method))
            hint += $" Замер: {method}.";

        return new PlainFact("Отклик сети", $"Россия {ru} · мир {world}", tone, hint);
    }

    /// <summary>Короткая строка «конфигурация обычная/странная» для заголовка простого режима.</summary>
    public static string OverallConfiguration(CheckRunResult result)
    {
        var bad = result.Checks.Count(c => c.Status == CheckStatus.Detected);
        var warn = result.Checks.Count(c => c.Status == CheckStatus.NeedsReview);
        var failed = result.Checks.Count(c => c.Status == CheckStatus.Failed);

        var text = bad switch
        {
            0 when warn == 0 => "Конфигурация обычная",
            0 => "Конфигурация в целом обычная, есть мелочи",
            <= 2 => "В конфигурации есть отклонения",
            _ => "Конфигурация сильно отличается от обычной",
        };
        if (failed > 0) text += $" · {failed} проверок не отработали";
        return text;
    }

    internal static string Format(double value) => value.ToString("F0", CultureInfo.InvariantCulture);
}
