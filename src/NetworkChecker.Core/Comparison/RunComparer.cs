using System.Globalization;
using NetworkChecker.Core.Models;

namespace NetworkChecker.Core.Comparison;

/// <summary>Направление изменения между двумя прогонами.</summary>
public enum ChangeDirection
{
    /// <summary>Стало меньше сигналов.</summary>
    Better,
    /// <summary>Ничего не изменилось.</summary>
    Same,
    /// <summary>Стало больше сигналов.</summary>
    Worse,
    /// <summary>Сравнивать нечего: модуль появился, исчез или не запускался.</summary>
    Unknown,
}

/// <summary>Изменение одного модуля между прогонами.</summary>
public sealed record CheckChange
{
    public required string Title { get; init; }
    public required CheckStatus Before { get; init; }
    public required CheckStatus After { get; init; }
    public required IReadOnlyList<string> Appeared { get; init; }
    public required IReadOnlyList<string> Disappeared { get; init; }
    public required ChangeDirection Direction { get; init; }
    public bool Changed => Before != After || Appeared.Count > 0 || Disappeared.Count > 0;
}

/// <summary>Итог сравнения двух прогонов.</summary>
public sealed record RunComparison
{
    public required CheckRunResult Before { get; init; }
    public required CheckRunResult After { get; init; }
    public required IReadOnlyList<CheckChange> Changes { get; init; }
    public required ChangeDirection Direction { get; init; }
    public required string Summary { get; init; }

    public int ScoreBefore => Before.Verdict.Score;
    public int ScoreAfter => After.Verdict.Score;
    public int ScoreDelta => ScoreAfter - ScoreBefore;
    public string HeadlineBefore => Before.Verdict.Headline;
    public string HeadlineAfter => After.Verdict.Headline;
    public IReadOnlyList<CheckChange> MeaningfulChanges => Changes.Where(c => c.Changed).ToList();
    public TimeSpan Elapsed => After.StartedAt - Before.StartedAt;
}

/// <summary>
/// Сравнение двух прогонов: что изменилось в конфигурации между проверками.
/// Полезно, когда пользователь что-то включил или выключил и хочет увидеть эффект.
/// </summary>
public static class RunComparer
{
    public static RunComparison Compare(CheckRunResult before, CheckRunResult after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var changes = new List<CheckChange>();
        var titles = before.Checks.Select(c => c.Title)
            .Concat(after.Checks.Select(c => c.Title))
            .Distinct(StringComparer.Ordinal);

        foreach (var title in titles)
        {
            var old = before.Checks.FirstOrDefault(c => c.Title == title);
            var current = after.Checks.FirstOrDefault(c => c.Title == title);

            if (old is null || current is null)
            {
                changes.Add(new CheckChange
                {
                    Title = title,
                    Before = old?.Status ?? CheckStatus.Skipped,
                    After = current?.Status ?? CheckStatus.Skipped,
                    Appeared = [],
                    Disappeared = [],
                    Direction = ChangeDirection.Unknown,
                });
                continue;
            }

            var oldFindings = old.Findings.Select(f => f.Title).ToHashSet(StringComparer.Ordinal);
            var newFindings = current.Findings.Select(f => f.Title).ToHashSet(StringComparer.Ordinal);
            var appeared = newFindings.Except(oldFindings, StringComparer.Ordinal).ToList();
            var disappeared = oldFindings.Except(newFindings, StringComparer.Ordinal).ToList();

            var oldSignals = old.Findings.Where(f => f.Severity >= Severity.Warning).Select(f => f.Title).ToHashSet(StringComparer.Ordinal);
            var newSignals = current.Findings.Where(f => f.Severity >= Severity.Warning).Select(f => f.Title).ToHashSet(StringComparer.Ordinal);
            changes.Add(new CheckChange
            {
                Title = title,
                Before = old.Status,
                After = current.Status,
                Appeared = appeared,
                Disappeared = disappeared,
                Direction = DirectionOf(old.Status, current.Status,
                    newSignals.Except(oldSignals, StringComparer.Ordinal).Count(),
                    oldSignals.Except(newSignals, StringComparer.Ordinal).Count()),
            });
        }

        var delta = after.Verdict.Score - before.Verdict.Score;
        var worse = changes.Count(c => c.Direction == ChangeDirection.Worse);
        var better = changes.Count(c => c.Direction == ChangeDirection.Better);
        var unknown = changes.Count(c => c.Direction == ChangeDirection.Unknown);

        var scoresComparable = before.Verdict.ScoreAvailable && after.Verdict.ScoreAvailable;
        var direction = worse > better ? ChangeDirection.Worse
            : better > worse ? ChangeDirection.Better
            : worse == 0 && better == 0 && unknown > 0 ? ChangeDirection.Unknown
            : scoresComparable && Math.Abs(delta) >= 5 ? (delta > 0 ? ChangeDirection.Worse : ChangeDirection.Better)
            : ChangeDirection.Same;

        return new RunComparison
        {
            Before = before,
            After = after,
            Changes = changes.OrderByDescending(c => c.Direction == ChangeDirection.Worse)
                .ThenByDescending(c => c.Direction == ChangeDirection.Better)
                .ThenBy(c => c.Title, StringComparer.Ordinal)
                .ToList(),
            Direction = direction,
            Summary = BuildSummary(scoresComparable ? delta : null, worse, better, unknown),
        };
    }

    private static ChangeDirection DirectionOf(CheckStatus before, CheckStatus after, int appeared, int disappeared)
    {
        // Пропущенный или упавший модуль — это не «стало лучше/хуже», это отсутствие данных.
        // Иначе отключение сети в офлайн-режиме выглядело бы как «риск снизился».
        if (IsNoData(before) || IsNoData(after)) return ChangeDirection.Unknown;

        var oldRisk = Risk(before);
        var newRisk = Risk(after);
        if (newRisk > oldRisk || appeared > 0) return ChangeDirection.Worse;
        if (newRisk < oldRisk || disappeared > 0) return ChangeDirection.Better;
        return ChangeDirection.Same;
    }

    private static bool IsNoData(CheckStatus status) => status is CheckStatus.Skipped or CheckStatus.Failed;

    /// <summary>Числовая оценка «плохости» статуса — только для сравнения, не для вердикта.</summary>
    private static int Risk(CheckStatus status) => status switch
    {
        CheckStatus.Clean => 0,
        CheckStatus.NeedsReview => 2,
        CheckStatus.Detected => 3,
        _ => 0,
    };

    private static string BuildSummary(int? delta, int worse, int better, int unknown)
    {
        var speed = delta switch
        {
            > 0 => $"условный индекс вырос на {delta.Value.ToString(CultureInfo.InvariantCulture)}",
            < 0 => $"условный индекс снизился на {Math.Abs(delta.Value).ToString(CultureInfo.InvariantCulture)}",
            0 => "условный индекс не изменился",
            _ => "индекс одного из прогонов недоступен",
        };

        if (worse == 0 && better == 0 && unknown > 0)
        {
            return $"Сравнивать нечего: {unknown.ToString(CultureInfo.InvariantCulture)} модулей работали только " +
                   "в одном из прогонов (офлайн-режим или недоступные источники).";
        }

        if (worse == 0 && better == 0) return $"По сопоставимым статусам изменений не обнаружено: {speed}.";
        if (worse > 0 && better == 0) return $"Больше сигналов: {speed}, модулей с увеличением — {worse.ToString(CultureInfo.InvariantCulture)}. Это не оценка безопасности.";
        if (better > 0 && worse == 0) return $"Меньше сигналов: {speed}, модулей с уменьшением — {better.ToString(CultureInfo.InvariantCulture)}. Это не оценка безопасности.";
        return $"Смешанные изменения: {speed}, больше сигналов {worse.ToString(CultureInfo.InvariantCulture)}, меньше {better.ToString(CultureInfo.InvariantCulture)}.";
    }
}
