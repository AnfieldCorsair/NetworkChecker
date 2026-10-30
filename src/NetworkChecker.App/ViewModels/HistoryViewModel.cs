using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Comparison;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Data;
using NetworkChecker.Data.Entities;

namespace NetworkChecker.App.ViewModels;

public sealed class HistoryRowViewModel(RunRecord record)
{
    public RunRecord Record { get; } = record;
    public string When { get; } = record.StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture);
    public string Headline { get; } = Localizer.T(record.Headline);
    public string ScoreText { get; } = ScoreTextOf(record);

    private static string ScoreTextOf(RunRecord record)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(record.ChecksJson);
            var hasData = doc.RootElement.EnumerateArray().Any(c =>
                c.TryGetProperty("weight", out var w) && w.GetInt32() > 0 &&
                c.TryGetProperty("status", out var status) && status.GetInt32() is not (int)CheckStatus.Skipped and not (int)CheckStatus.Failed);
            return hasData ? $"{record.Score}/100" : "—";
        }
        catch (System.Text.Json.JsonException) { return "—"; }
    }
    public string IpText { get; } = Masking.Ip(record.ExternalIp);
    public string DurationText { get; } = $"{record.DurationMs / 1000.0:F1} {(Localizer.Culture == "en-US" ? "s" : "с")}";
    public string Color { get; } = record.RiskLevel switch
    {
        0 => "#35C48A",
        1 => "#F5C542",
        _ => "#F0524C",
    };
    public Avalonia.Media.IBrush ColorBrush => Ui.Brush(Color);

    public string LevelText { get; } = Localizer.T(record.RiskLevel switch
    {
        0 => "Чисто",
        1 => "Проверка",
        _ => "Обнаружено",
    });
}

/// <summary>Строка сравнения прогонов: что стало с одним модулем.</summary>
public sealed class ComparisonRowViewModel(CheckChange change)
{
    private readonly CheckChange _change = change;

    public string Title { get; } = Localizer.T(change.Title);
    public string BeforeText { get; } = StatusTextOf(change.Before);
    public string AfterText { get; } = StatusTextOf(change.After);
    public string DirectionText { get; } = Localizer.T(change.Direction switch
    {
        ChangeDirection.Worse => "больше сигналов",
        ChangeDirection.Better => "меньше сигналов",
        ChangeDirection.Same => "без изменений",
        _ => "несопоставимо",
    });

    public string DirectionColor { get; } = change.Direction switch
    {
        ChangeDirection.Worse => "#F0524C",
        ChangeDirection.Better => "#35C48A",
        ChangeDirection.Same => "#5C7A99",
        _ => "#8A93A3",
    };

    public Avalonia.Media.IBrush DirectionBrush => Ui.Brush(DirectionColor);

    public string DetailText
    {
        get
        {
            var parts = new List<string>();
            if (_change.Appeared.Count > 0) parts.Add(Localizer.T("появилось: ") + string.Join("; ", _change.Appeared.Select(Localizer.T)));
            if (_change.Disappeared.Count > 0) parts.Add(Localizer.T("исчезло: ") + string.Join("; ", _change.Disappeared.Select(Localizer.T)));
            return string.Join(" · ", parts);
        }
    }

    public bool HasDetail => DetailText.Length > 0;

    private static string StatusTextOf(CheckStatus status) => Localizer.T(status switch
    {
        CheckStatus.Clean => "чисто",
        CheckStatus.NeedsReview => "требует проверки",
        CheckStatus.Detected => "обнаружено",
        CheckStatus.Skipped => "пропущено",
        CheckStatus.Failed => "ошибка",
        _ => "—",
    });
}

public sealed partial class HistoryViewModel : ViewModelBase
{
    private readonly HistoryRepository _history;

    public HistoryViewModel(HistoryRepository history, UiModeService mode)
    {
        Mode = mode;
        _history = history;
        _ = LoadAsync();
    }

    public UiModeService Mode { get; }

    public override string Title => global::NetworkChecker.App.Localization.Localizer.T("История");
    public override string Icon => global::NetworkChecker.App.Icons.Clock;
    public override string Description => global::NetworkChecker.App.Localization.Localizer.T("Локальные прогоны в SQLite");

    public ObservableCollection<HistoryRowViewModel> Runs { get; } = [];
    public ObservableCollection<CheckCardViewModel> DetailChecks { get; } = [];
    public ObservableCollection<string> DetailReasons { get; } = [];

    [ObservableProperty]
    public partial HistoryRowViewModel? Selected { get; set; }

    [ObservableProperty]
    public partial string Status { get; set; } = Localizer.T("История загружается...");

    [ObservableProperty]
    public partial string DetailHeadline { get; set; } = Localizer.T("Выберите прогон из списка");

    [ObservableProperty]
    public partial string DetailSummary { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool HasDetail { get; set; }

    public ObservableCollection<ComparisonRowViewModel> ComparisonRows { get; } = [];

    [ObservableProperty]
    public partial bool HasComparison { get; set; }

    [ObservableProperty]
    public partial string ComparisonSummary { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ComparisonHeadline { get; set; } = string.Empty;

    partial void OnSelectedChanged(HistoryRowViewModel? value)
    {
        if (value is null) return;
        _ = LoadDetailAsync(value.Record.Id);
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        await LoadAsync().ConfigureAwait(true);
    }

    private async Task LoadAsync()
    {
        try
        {
            var records = await _history.GetRecentAsync(100).ConfigureAwait(true);
            Runs.Clear();
            foreach (var record in records) Runs.Add(new HistoryRowViewModel(record));
            Status = records.Count == 0
                ? Localizer.T("Пока пусто: ни одна проверка не сохранена.")
                : Localizer.Culture == "en-US" ? $"Saved runs: {records.Count}" : $"Сохранено прогонов: {records.Count}";
        }
        catch (Exception ex)
        {
            Status = Localizer.T("Не удалось прочитать историю: ") + ex.GetBaseException().Message;
        }
    }

    private async Task LoadDetailAsync(Guid id)
    {
        var result = await _history.GetAsync(id).ConfigureAwait(true);
        if (result is null) return;
        DetailChecks.Clear();
        foreach (var check in result.Checks) DetailChecks.Add(new CheckCardViewModel(check));
        DetailReasons.Clear();
        foreach (var reason in result.Verdict.Reasons) DetailReasons.Add(Localizer.T(reason));
        DetailHeadline = $"{Localizer.T(result.Verdict.Headline)} · {result.Verdict.ScoreText}";
        DetailSummary = Localizer.VerdictSummary(result.Verdict.Summary);
        HasDetail = true;
    }

    /// <summary>
    /// Сравнивает выбранный прогон с предыдущим по времени. Список отсортирован от новых к старым,
    /// поэтому «предыдущий» — это следующий элемент в списке.
    /// </summary>
    [RelayCommand]
    private async Task CompareWithPreviousAsync()
    {
        if (Selected is null) return;
        var index = Runs.IndexOf(Selected);
        if (index < 0 || index + 1 >= Runs.Count)
        {
            ComparisonSummary = Localizer.T("Не с чем сравнивать: это самый старый сохранённый прогон.");
            ComparisonHeadline = Localizer.T("Сравнение недоступно");
            ComparisonRows.Clear();
            HasComparison = true;
            return;
        }

        var previous = Runs[index + 1];
        var after = await _history.GetAsync(Selected.Record.Id).ConfigureAwait(true);
        var before = await _history.GetAsync(previous.Record.Id).ConfigureAwait(true);
        if (after is null || before is null)
        {
            ComparisonSummary = Localizer.T("Не удалось прочитать один из прогонов.");
            HasComparison = true;
            return;
        }

        var comparison = RunComparer.Compare(before, after);
        ComparisonRows.Clear();
        foreach (var change in comparison.Changes) ComparisonRows.Add(new ComparisonRowViewModel(change));
        ComparisonHeadline = $"{comparison.Before.Verdict.ScoreText} → {comparison.After.Verdict.ScoreText}";
        ComparisonSummary = Localizer.Culture == "en-US"
            ? $"Compared with the run from {previous.When}. More signals: {comparison.Changes.Count(c => c.Direction == ChangeDirection.Worse)}; fewer: {comparison.Changes.Count(c => c.Direction == ChangeDirection.Better)}; not comparable: {comparison.Changes.Count(c => c.Direction == ChangeDirection.Unknown)}. Scores and partial runs may not be comparable."
            : comparison.Summary + $" Сравнение с прогоном от {previous.When}.";
        HasComparison = true;
    }

    [RelayCommand]
    private void CloseComparison()
    {
        HasComparison = false;
        ComparisonRows.Clear();
    }

    [RelayCommand]
    private async Task DeleteAsync(HistoryRowViewModel? row)
    {
        if (row is null) return;
        await _history.DeleteAsync(row.Record.Id).ConfigureAwait(true);
        Runs.Remove(row);
        Status = Localizer.Culture == "en-US" ? $"Deleted. Runs remaining: {Runs.Count}" : $"Удалено. Осталось прогонов: {Runs.Count}";
    }

    private void ResetComparison()
    {
        HasComparison = false;
        ComparisonRows.Clear();
    }

    [RelayCommand]
    private async Task ClearAsync()
    {
        await _history.ClearAsync().ConfigureAwait(true);
        Runs.Clear();
        DetailChecks.Clear();
        ResetComparison();
        HasDetail = false;
        DetailHeadline = Localizer.T("История очищена");
        DetailSummary = string.Empty;
        Status = Localizer.T("История очищена.");
    }
}
