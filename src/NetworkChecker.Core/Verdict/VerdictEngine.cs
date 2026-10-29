using NetworkChecker.Core.Models;

namespace NetworkChecker.Core.Verdict;

/// <summary>
/// Итоговый вердикт. Логика повторяет идею VerdictEngine из Android-версии:
/// эвристическая оценка: один критический признак тоже может дать «Обнаружено».
/// Это не подтверждает перехват или активный обход.
/// </summary>
public static class VerdictEngine
{
    private static readonly Dictionary<CheckCategory, double> SeverityFactor = new()
    {
        [CheckCategory.DirectSigns] = 1.0,
        [CheckCategory.Bypass] = 1.0,
        [CheckCategory.GeoIp] = 0.7,
        [CheckCategory.IndirectSigns] = 0.6,
        [CheckCategory.CallTransport] = 0.5,
        [CheckCategory.RttTriangulation] = 0.4,
        [CheckCategory.IcmpSpoofing] = 0.4,
        [CheckCategory.DomainReachability] = 0.25,
        [CheckCategory.CdnPulling] = 0.2,
    };

    public static VerdictResult Build(IReadOnlyList<CheckResult> checks, IpConsensus consensus)
    {
        var weighted = checks.Where(c => c.Weight > 0).ToList();
        var reasons = new List<string>();
        var triggered = new List<CheckCategory>();

        var raw = 0.0;
        var maxRaw = 0.0;
        foreach (var check in weighted)
        {
            var factor = SeverityFactor.GetValueOrDefault(check.Category, 0.3);
            maxRaw += check.Weight * factor;
            var severityScore = ScoreOf(check);
            raw += check.Weight * factor * severityScore;
            if (severityScore >= 0.55) triggered.Add(check.Category);
        }

        var score = maxRaw <= 0 ? 0 : (int)Math.Round(Math.Clamp(raw / maxRaw, 0, 1) * 100);

        // --- жёсткие правила -----------------------------------------------------
        var direct = checks.FirstOrDefault(c => c.Category == CheckCategory.DirectSigns);
        var geo = checks.FirstOrDefault(c => c.Category == CheckCategory.GeoIp);
        var bypass = checks.FirstOrDefault(c => c.Category == CheckCategory.Bypass);

        var directCritical = direct is not null &&
                             direct.Findings.Any(f => f.Severity == Severity.Critical);
        var geoFlagged = geo is not null && geo.Status == CheckStatus.Detected;
        var bypassCritical = bypass is not null && bypass.Findings.Any(f => f.Severity == Severity.Critical);

        foreach (var check in weighted.OrderByDescending(c => c.HighestSeverity).ThenByDescending(c => c.Weight))
        {
            foreach (var finding in check.Findings.Where(f => f.Severity >= Severity.Warning).Take(2))
            {
                if (reasons.Count >= 6) break;
                reasons.Add($"{check.Title}: {finding.Title}");
            }
        }

        if (consensus.IsSplit)
        {
            reasons.Add("Источники видят разные внешние IP — трафик расщеплён между маршрутами.");
            score = Math.Max(score, 55);
        }

        RiskLevel level;
        string headline;
        string summary;

        if (directCritical && (geoFlagged || bypassCritical || consensus.IsSplit))
        {
            level = RiskLevel.Detected;
            score = Math.Max(score, 80);
            headline = "Обнаружены признаки возможного обхода";
            summary = "Обнаружены несколько сигналов, совместимых с туннелем или прокси; они не доказывают активный обход.";
        }
        else if (directCritical || bypassCritical || (geoFlagged && consensus.IsSplit) || score >= 60)
        {
            level = RiskLevel.Detected;
            score = Math.Max(score, 60);
            headline = bypassCritical && !directCritical
                ? "Обнаружены локальные средства обхода"
                : "Обнаружены признаки обхода блокировок";
            summary = directCritical
                ? "Найдены признаки, совместимые с туннелем или прокси; они не доказывают перехват."
                : "Совокупность сигналов требует проверки; она не доказывает активный обход.";
        }
        else if (score >= 25 || triggered.Count > 0 || consensus.IsSplit)
        {
            level = RiskLevel.NeedsReview;
            score = Math.Max(score, 30);
            headline = "Требуется проверка";
            summary = "Есть отдельные сигналы, но для вывода «обход активен» не хватает подтверждения.";
        }
        else
        {
            level = RiskLevel.Clean;
            headline = "Признаков обхода не обнаружено";
            summary = "Ни прямые, ни косвенные проверки не нашли следов туннеля, прокси или подмены.";
        }

        var failed = checks.Count(c => c.Status == CheckStatus.Failed);
        if (failed > 0)
        {
            summary += $" Часть модулей не отработала ({failed}) — вердикт неполный.";
        }

        // Честность важнее красивой цифры: если половина веса модулей не проверялась,
        // «Признаков не обнаружено» — неправда. Такой прогон не может быть чище «требует проверки».
        var skippedWeight = weighted.Where(c => c.Status is CheckStatus.Skipped or CheckStatus.Failed).Sum(c => c.Weight);
        var totalWeight = weighted.Sum(c => c.Weight);
        var skippedShare = totalWeight == 0 ? 0 : skippedWeight / (double)totalWeight;

        if (skippedShare >= 0.5 && level == RiskLevel.Clean)
        {
            level = RiskLevel.NeedsReview;
            score = Math.Max(score, 25);
            headline = "Проверка неполная";
            summary = "Не выполнена как минимум половина суммарного веса модулей (пропуски или ошибки) — " +
                      "судить о конфигурации по такому прогону нельзя.";
            reasons.Insert(0, $"Не проверялось или завершилось ошибкой модулей с весом {skippedWeight} из {totalWeight}.");
        }

        return new VerdictResult
        {
            Level = level,
            Score = Math.Clamp(score, 0, 100),
            Headline = headline,
            Summary = summary,
            Reasons = reasons,
            TriggeredCategories = triggered,
        };
    }

    private static double ScoreOf(CheckResult check) => check.Status switch
    {
        CheckStatus.Detected => check.Findings.Any(f => f.Severity == Severity.Critical) ? 1.0 : 0.8,
        CheckStatus.NeedsReview => 0.45,
        CheckStatus.Clean => 0.0,
        _ => 0.0,
    };
}
