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
            if (check.Status is CheckStatus.Failed or CheckStatus.Skipped) continue;
            maxRaw += check.Weight * factor;
            var severityScore = ScoreOf(check);
            raw += check.Weight * factor * severityScore;
            if (severityScore >= 0.55) triggered.Add(check.Category);
        }

        var score = maxRaw <= 0 ? 0 : (int)Math.Round(Math.Clamp(raw / maxRaw, 0, 1) * 100);

        // --- жёсткие правила -----------------------------------------------------
        // Только структурированные факты конфигурации, полученные выполненным модулем,
        // дают статус Detected. Маркер процесса, открытый порт, GeoIP и beta-пробы
        // не доказывают применение VPN/прокси конкретным браузером.
        var strong = checks.Where(c => c.Category == CheckCategory.DirectSigns &&
            c.Status is CheckStatus.Clean or CheckStatus.NeedsReview or CheckStatus.Detected)
            .SelectMany(c => c.Findings)
            .Where(f => f.Kind is EvidenceKind.ConfiguredProxy or EvidenceKind.ConnectedWindowsVpn)
            .ToList();

        foreach (var check in weighted.Where(c => c.Status is not CheckStatus.Failed and not CheckStatus.Skipped)
                     .OrderByDescending(c => c.HighestSeverity).ThenByDescending(c => c.Weight))
        {
            foreach (var finding in check.Findings.Where(f => f.Severity >= Severity.Warning).Take(2))
            {
                if (reasons.Count >= 6) break;
                reasons.Add($"{check.Title}: {finding.Title}");
            }
        }
        if (consensus.IsSplit)
            reasons.Add("Источники видят разные внешние IP одного семейства; причина не установлена.");

        RiskLevel level;
        string headline;
        string summary;
        if (strong.Count > 0)
        {
            level = RiskLevel.Detected;
            headline = "Обнаружены настройки VPN или прокси";
            summary = "Обнаружены настройки прокси (WinINET, WinHTTP или окружение) либо подключение VPN Windows. " +
                      "Это не доказывает, что конкретный браузер или сайт использует этот путь.";
        }
        else if (score >= 25 || triggered.Count > 0 || consensus.IsSplit ||
                 checks.Any(c => c.Weight > 0 && c.Status == CheckStatus.NeedsReview))
        {
            level = RiskLevel.NeedsReview;
            headline = "Требуется проверка";
            summary = "Есть неоднозначные сигналы. Они могут иметь другие объяснения и не доказывают VPN, прокси или перехват.";
        }
        else
        {
            level = RiskLevel.Clean;
            headline = "Признаков обхода не обнаружено";
            summary = "В доступных данных не найдены значимые признаки. Это не исключает VPN или прокси.";
        }

        summary += " Индекс условный, не вероятность; влияние на браузер отдельно не проверялось.";

        var failed = checks.Count(c => c.Status == CheckStatus.Failed);
        if (failed > 0)
        {
            summary += $" Часть модулей не отработала ({failed}) — вердикт неполный.";
        }

        // Честность важнее красивой цифры: если половина веса модулей не проверялась,
        // «Признаков не обнаружено» — неправда. Такой прогон не может быть чище «требует проверки».
        var skippedWeight = weighted.Where(c => c.Status is CheckStatus.Skipped or CheckStatus.Failed).Sum(c => c.Weight);
        var totalWeight = weighted.Sum(c => c.Weight);
        var skippedShare = totalWeight == 0 ? 1 : skippedWeight / (double)totalWeight;

        if (skippedShare >= 0.5 && level == RiskLevel.Clean)
        {
            level = RiskLevel.NeedsReview;
            headline = "Проверка неполная";
            summary = "Не выполнена как минимум половина суммарного веса модулей (пропуски или ошибки) — " +
                      "судить о конфигурации по такому прогону нельзя. Индекс условный, не вероятность.";
            reasons.Insert(0, $"Не проверялось или завершилось ошибкой модулей с весом {skippedWeight} из {totalWeight}.");
        }

        return new VerdictResult
        {
            Level = level,
            Score = Math.Clamp(score, 0, 100),
            ScoreAvailable = maxRaw > 0,
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
