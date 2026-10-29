using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Data;
using RKNHardering.Data.Entities;

namespace RKNHardering.App.ViewModels;

public sealed class HistoryRowViewModel(RunRecord record)
{
    public RunRecord Record { get; } = record;
    public string When { get; } = record.StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    public string Headline { get; } = record.Headline;
    public string ScoreText { get; } = $"{record.Score}/100";
    public string IpText { get; } = Masking.Ip(record.ExternalIp);
    public string DurationText { get; } = $"{record.DurationMs / 1000.0:F1} с";
    public string Color { get; } = record.RiskLevel switch
    {
        0 => "#35C48A",
        1 => "#F5C542",
        _ => "#F0524C",
    };
    public Avalonia.Media.IBrush ColorBrush => Ui.Brush(Color);

    public string LevelText { get; } = record.RiskLevel switch
    {
        0 => "Чисто",
        1 => "Проверка",
        _ => "Обнаружено",
    };
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

    public override string Title => "История";
    public override string Icon => global::RKNHardering.App.Icons.Clock;
    public override string Description => "Локальные прогоны в SQLite";

    public ObservableCollection<HistoryRowViewModel> Runs { get; } = new();
    public ObservableCollection<CheckCardViewModel> DetailChecks { get; } = new();
    public ObservableCollection<string> DetailReasons { get; } = new();

    [ObservableProperty] private HistoryRowViewModel? _selected;
    [ObservableProperty] private string _status = "История загружается...";
    [ObservableProperty] private string _detailHeadline = "Выберите прогон из списка";
    [ObservableProperty] private string _detailSummary = string.Empty;
    [ObservableProperty] private bool _hasDetail;

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
                ? "Пока пусто: ни одна проверка не сохранена."
                : $"Сохранено прогонов: {records.Count}";
        }
        catch (Exception ex)
        {
            Status = "Не удалось прочитать историю: " + ex.GetBaseException().Message;
        }
    }

    private async Task LoadDetailAsync(Guid id)
    {
        var result = await _history.GetAsync(id).ConfigureAwait(true);
        if (result is null) return;
        DetailChecks.Clear();
        foreach (var check in result.Checks) DetailChecks.Add(new CheckCardViewModel(check));
        DetailReasons.Clear();
        foreach (var reason in result.Verdict.Reasons) DetailReasons.Add(reason);
        DetailHeadline = $"{result.Verdict.Headline} · {result.Verdict.Score}/100";
        DetailSummary = result.Verdict.Summary;
        HasDetail = true;
    }

    [RelayCommand]
    private async Task DeleteAsync(HistoryRowViewModel? row)
    {
        if (row is null) return;
        await _history.DeleteAsync(row.Record.Id).ConfigureAwait(true);
        Runs.Remove(row);
        Status = $"Удалено. Осталось прогонов: {Runs.Count}";
    }

    [RelayCommand]
    private async Task ClearAsync()
    {
        await _history.ClearAsync().ConfigureAwait(true);
        Runs.Clear();
        DetailChecks.Clear();
        HasDetail = false;
        DetailHeadline = "История очищена";
        DetailSummary = string.Empty;
        Status = "История очищена.";
    }
}
