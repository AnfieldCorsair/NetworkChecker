namespace NetworkChecker.Core.Models;

/// <summary>Итоговый вердикт методики.</summary>
public sealed class VerdictResult
{
    public required RiskLevel Level { get; init; }
    /// <summary>Условный индекс сигналов 0–100; не вероятность и не измерение точности.</summary>
    public required int Score { get; init; }
    public bool ScoreAvailable { get; init; } = true;
    public string ScoreText => ScoreAvailable ? $"{Score} / 100" : "не рассчитан";
    public required string Headline { get; init; }
    public required string Summary { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<CheckCategory> TriggeredCategories { get; init; } = Array.Empty<CheckCategory>();

    public string LevelText => Level switch
    {
        RiskLevel.Clean => "Чисто",
        RiskLevel.NeedsReview => "Требует проверки",
        RiskLevel.Detected => "Настройки обнаружены",
        _ => "—",
    };
}
