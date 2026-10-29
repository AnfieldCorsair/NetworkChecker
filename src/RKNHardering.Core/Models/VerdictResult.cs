using RKNHardering.Core.Models;

namespace RKNHardering.Core.Models;

/// <summary>Итоговый вердикт методики.</summary>
public sealed class VerdictResult
{
    public required RiskLevel Level { get; init; }
    /// <summary>0–100, насколько набор сигналов похож на активный обход блокировок.</summary>
    public required int Score { get; init; }
    public required string Headline { get; init; }
    public required string Summary { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<CheckCategory> TriggeredCategories { get; init; } = Array.Empty<CheckCategory>();

    public string LevelText => Level switch
    {
        RiskLevel.Clean => "Чисто",
        RiskLevel.NeedsReview => "Требует проверки",
        RiskLevel.Detected => "Обнаружен обход",
        _ => "—",
    };
}
