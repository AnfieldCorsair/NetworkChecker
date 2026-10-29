namespace NetworkChecker.Core.Models;

/// <summary>
/// Консервативная проекция для приватной записи/экспорта: никаких произвольных строк
/// проб, IP, путей, имён интерфейсов и прокси. Не является гарантией анонимности.
/// </summary>
public static class PrivateRunProjection
{
    public static CheckRunResult Create(CheckRunResult source) => new()
    {
        Id = source.Id,
        StartedAt = source.StartedAt,
        FinishedAt = source.FinishedAt,
        Checks = source.Checks.Select(c => new CheckResult
        {
            Category = c.Category,
            Title = SafeTitle(c.Category),
            Status = c.Status,
            Weight = c.Weight,
            StartedAt = c.StartedAt,
            Duration = c.Duration,
            Error = c.Error is null ? null : "Подробности ошибки скрыты",
            Findings = c.Findings.Select(f => new Finding
            {
                Title = "Подробности скрыты приватным режимом",
                Severity = f.Severity,
                Kind = f.Kind,
            }).ToArray(),
        }).ToArray(),
        IpConsensus = new IpConsensus(),
        Environment = new EnvironmentSnapshot { OsDescription = "Скрыто", MachineName = "•••", UserName = "•••", PrivacyMode = true },
        Verdict = new VerdictResult
        {
            Level = source.Verdict.Level,
            Score = source.Verdict.Score,
            ScoreAvailable = source.Verdict.ScoreAvailable,
            Headline = source.Verdict.Level switch
            {
                RiskLevel.Detected => "Обнаружены настройки VPN или прокси",
                RiskLevel.NeedsReview => "Требуется проверка",
                _ => "Признаков обхода не обнаружено",
            },
            Summary = "Приватный отчёт: подробности скрыты. Индекс условный, не вероятность; маршрут браузера не проверялся.",
            TriggeredCategories = source.Verdict.TriggeredCategories.ToArray(),
        },
    };

    private static string SafeTitle(CheckCategory category) => category switch
    {
        CheckCategory.GeoIp => "GeoIP и репутация IP",
        CheckCategory.IpComparison => "Сравнение IP-источников",
        CheckCategory.DirectSigns => "Прямые признаки",
        CheckCategory.IndirectSigns => "Косвенные признаки",
        CheckCategory.Bypass => "Локальный обход",
        CheckCategory.CallTransport => "UDP / STUN-транспорт",
        CheckCategory.CdnPulling => "CDN и redirector",
        CheckCategory.DomainReachability => "Доступность доменов",
        CheckCategory.RttTriangulation => "RTT-триангуляция (β)",
        CheckCategory.IcmpSpoofing => "ICMP-спуфинг (β)",
        _ => "Дополнительная проверка",
    };
}
