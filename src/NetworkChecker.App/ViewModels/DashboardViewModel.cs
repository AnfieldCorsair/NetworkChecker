using System.Collections.ObjectModel;
using Avalonia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using NetworkChecker.App.Startup;
using NetworkChecker.Core;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Plain;
using NetworkChecker.Data;
using NetworkChecker.Export;

namespace NetworkChecker.App.ViewModels;

public sealed class MetricViewModel(Metric metric)
{
    public string Label { get; } = metric.Label;
    public string Value { get; } = metric.Value;
    public string? Hint { get; } = metric.Hint;
    public bool HasHint => !string.IsNullOrWhiteSpace(Hint);
}

public sealed class FindingViewModel(Finding finding)
{
    public string Title { get; } = finding.Title;
    public string Detail { get; } = finding.Detail;
    public string? Evidence { get; } = finding.Evidence;
    public bool HasEvidence => !string.IsNullOrWhiteSpace(Evidence);
    public bool HasDetail => !string.IsNullOrWhiteSpace(Detail);
    public string SeverityText => finding.Severity switch
    {
        Severity.Critical => "КРИТИЧНО",
        Severity.Warning => "ВНИМАНИЕ",
        Severity.Notice => "ЗАМЕТКА",
        _ => "ИНФО",
    };
    public Avalonia.Media.IBrush SeverityBrush => Ui.Brush(SeverityColor);

    public string SeverityColor => finding.Severity switch
    {
        Severity.Critical => "#F0524C",
        Severity.Warning => "#F2913D",
        Severity.Notice => "#F5C542",
        _ => "#5C7A99",
    };
}

public sealed partial class CheckCardViewModel : ObservableObject
{
    public CheckCardViewModel(CheckResult result)
    {
        Result = result;
        Metrics = new ObservableCollection<MetricViewModel>(result.Metrics.Select(m => new MetricViewModel(m)));
        Findings = new ObservableCollection<FindingViewModel>(
            result.Findings.OrderByDescending(f => f.Severity).Select(f => new FindingViewModel(f)));
        IsExpanded = result.Status is CheckStatus.Detected or CheckStatus.Failed;
    }

    public CheckResult Result { get; }
    public string Title => Result.Title;
    public string Subtitle => Result.Subtitle;
    public string StatusText => Result.StatusText;
    public string DurationText => $"{Result.Duration.TotalSeconds:F1} с";
    public string FindingsCountText => Result.Findings.Count == 0
        ? (Result.Status == CheckStatus.Skipped ? "не запускалась" : "находок нет")
        : $"находок: {Result.Findings.Count}";
    public ObservableCollection<MetricViewModel> Metrics { get; }
    public ObservableCollection<FindingViewModel> Findings { get; }
    public bool HasMetrics => Metrics.Count > 0;
    public bool HasFindings => Findings.Count > 0;
    public bool ShowEmptyText => Findings.Count == 0;
    public string EmptyText => Result.Status == CheckStatus.Skipped
        ? "Ещё не запускалась — нажмите «Запустить проверку»."
        : "Находок нет: модуль не выявил сигналов.";
    public string? Error => Result.Error;
    public bool HasError => !string.IsNullOrWhiteSpace(Error);

    public Avalonia.Media.IBrush StatusBrush => Ui.Brush(StatusColor);
    public Avalonia.Media.IBrush StatusSoftBrush => Ui.Brush(StatusColor, 0.14);

    public string StatusColor => Result.Status switch
    {
        CheckStatus.Clean => "#35C48A",
        CheckStatus.NeedsReview => "#F5C542",
        CheckStatus.Detected => "#F0524C",
        CheckStatus.Skipped => "#5C7A99",
        CheckStatus.Failed => "#B061D6",
        _ => "#5C7A99",
    };

    public string AccentOpacity => Result.Status == CheckStatus.Clean ? "0.9" : "1";

    [ObservableProperty]
    public partial bool IsExpanded { get; set; }

    [RelayCommand]
    private void Toggle() => IsExpanded = !IsExpanded;
}

public sealed class VerdictViewModel
{
    public VerdictViewModel(VerdictResult verdict, IpConsensus consensus, TimeSpan duration)
    {
        Headline = verdict.Headline;
        Summary = verdict.Summary;
        Score = verdict.Score;
        ScoreText = $"{verdict.Score} / 100";
        LevelText = verdict.LevelText;
        Reasons = new ObservableCollection<string>(verdict.Reasons);
        HasReasons = Reasons.Count > 0;
        IpText = consensus.Summary;
        Observations = new ObservableCollection<string>(consensus.Observations
            .Select(o => $"{o.Source}: {Masking.Ip(o.Ip)}{(o.Note is null ? "" : $" · {o.Note}")}")
            .Distinct());
        ObservedCount = consensus.Observations.Count;
        DurationText = $"{duration.TotalSeconds:F1} с";
        Color = verdict.Level switch
        {
            RiskLevel.Clean => "#35C48A",
            RiskLevel.NeedsReview => "#F5C542",
            _ => "#F0524C",
        };
        SoftColor = verdict.Level switch
        {
            RiskLevel.Clean => "#14301F",
            RiskLevel.NeedsReview => "#332B12",
            _ => "#3A1A1A",
        };
    }

    public string Headline { get; }
    public string Summary { get; }
    public int Score { get; }
    public string ScoreText { get; }
    public string LevelText { get; }
    public string Color { get; }
    public string SoftColor { get; }
    public Avalonia.Media.IBrush ColorBrush => Ui.Brush(Color);
    public Avalonia.Media.IBrush SoftBrush => Ui.Brush(SoftColor);
    public string IpText { get; }
    public int ObservedCount { get; }
    public string DurationText { get; }
    public ObservableCollection<string> Reasons { get; }
    public ObservableCollection<string> Observations { get; }
    public bool HasReasons { get; }
    public double ScoreWidth => Math.Clamp(Score, 0, 100) * 3.2;
}

/// <summary>Строка простого режима: вопрос и понятный ответ.</summary>
public sealed class FactViewModel(PlainFact fact)
{
    public string Question { get; } = fact.Question;
    public string Answer { get; } = fact.Answer;
    public string? Hint { get; } = fact.Hint;
    public bool HasHint => !string.IsNullOrWhiteSpace(Hint);
    public Avalonia.Media.IBrush DotBrush { get; } = Ui.Brush(fact.Tone switch
    {
        "good" => "#35C48A",
        "bad" => "#F0524C",
        _ => "#F5C542",
    });
}

/// <summary>Строка простого режима: модуль проверки человеческим языком.</summary>
public sealed class PlainCheckViewModel(PlainCheck check)
{
    public string Title { get; } = check.Title;
    public string WhatWeChecked { get; } = check.WhatWeChecked;
    public string Status { get; } = check.Status;
    public string Advice { get; } = check.Advice;
    public bool HasAdvice => !string.IsNullOrWhiteSpace(Advice);
    public Avalonia.Media.IBrush DotBrush { get; } = Ui.Brush(check.Colour switch
    {
        "green" => "#35C48A",
        "yellow" => "#F5C542",
        "red" => "#F0524C",
        "purple" => "#B061D6",
        _ => "#5C7A99",
    });
    public Avalonia.Media.IBrush StatusSoftBrush { get; } = Ui.Brush(check.Colour switch
    {
        "green" => "#35C48A",
        "yellow" => "#F5C542",
        "red" => "#F0524C",
        "purple" => "#B061D6",
        _ => "#5C7A99",
    }, 0.14);
}

public sealed partial class DashboardViewModel : ViewModelBase, IDisposable
{
    private readonly CheckRunner _runner;
    private readonly HistoryRepository _history;
    private readonly SettingsStore _settings;
    private readonly RknOptions _options;
    private readonly IFileDialogService _files;
    private readonly ILogger<DashboardViewModel> _logger;
    private CancellationTokenSource? _cts;
    private CheckRunResult? _lastResult;

    public DashboardViewModel(
        CheckRunner runner,
        HistoryRepository history,
        SettingsStore settings,
        RknOptions options,
        IFileDialogService files,
        UiModeService mode,
        ILogger<DashboardViewModel> logger)
    {
        Mode = mode;
        _runner = runner;
        _history = history;
        _settings = settings;
        _options = options;
        _files = files;
        _logger = logger;
        PrivacyMode = options.PrivacyMode;
        OfflineMode = options.OfflineMode;

        _runner.Progress += OnProgress;
        _runner.StatusText += (_, text) => StatusLine = text;

        Cards = new ObservableCollection<CheckCardViewModel>(
            _runner.Checks.Select(c => new CheckCardViewModel(new CheckResult
            {
                Category = c.Category,
                Title = c.Title,
                Subtitle = c.Subtitle,
                Status = CheckStatus.Skipped,
                Weight = c.Weight,
                Findings = [],
            })));

        ShowPlainDetails = true;
        StatusLine = "Готово к запуску. Проверок в наборе: " + _runner.Checks.Count;
        CheckCount = _runner.Checks.Count;
    }

    public override string Title => "Проверка";
    public override string Icon => global::NetworkChecker.App.Icons.ShieldCheck;
    public override string Description => "Обнаружение VPN и прокси по методике РКН";

    public UiModeService Mode { get; }

    public ObservableCollection<CheckCardViewModel> Cards { get; }
    public ObservableCollection<FactViewModel> Facts { get; } = [];
    public ObservableCollection<PlainCheckViewModel> PlainChecks { get; } = [];

    [ObservableProperty]
    public partial VerdictViewModel? Verdict { get; set; }

    [ObservableProperty]
    public partial bool IsRunning { get; set; }

    [ObservableProperty]
    public partial double Progress { get; set; }

    [ObservableProperty]
    public partial string StatusLine { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ProgressText { get; set; } = "0 / 0";

    [ObservableProperty]
    public partial int CheckCount { get; set; }

    [ObservableProperty]
    public partial string LastRunText { get; set; } = "прогонов ещё не было";

    [ObservableProperty]
    public partial bool PrivacyMode { get; set; }

    [ObservableProperty]
    public partial bool OfflineMode { get; set; }

    [ObservableProperty]
    public partial string SaveMessage { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool HasResult { get; set; }

    [ObservableProperty]
    public partial string PlainHeadline { get; set; } = "Проверка ещё не запускалась";

    [ObservableProperty]
    public partial string PlainMeaning { get; set; } = "Нажмите «Проверить компьютер» — приложение посмотрит настройки сети и объяснит простыми словами, всё ли обычно.";

    [ObservableProperty]
    public partial string PlainAdvice { get; set; } = "Проверка занимает около 10 секунд и ничего не меняет в системе.";

    [ObservableProperty]
    public partial string PlainConfiguration { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PlainAccent { get; set; } = "#5C7A99";

    [ObservableProperty]
    public partial Avalonia.Media.IBrush PlainAccentBrush { get; set; } = Ui.Brush("#5C7A99");

    [ObservableProperty]
    public partial Avalonia.Media.IBrush PlainSoftBrush { get; set; } = Ui.Brush("#5C7A99", 0.12);

    [ObservableProperty]
    public partial bool ShowPlainDetails { get; set; }

    public bool HasVerdict => Verdict is not null;

    partial void OnVerdictChanged(VerdictViewModel? value) => OnPropertyChanged(nameof(HasVerdict));

    partial void OnPrivacyModeChanged(bool value)
    {
        _options.PrivacyMode = value;
        Masking.Enabled = value;
        _settings.Save();
    }

    partial void OnOfflineModeChanged(bool value)
    {
        _options.OfflineMode = value;
        _settings.Save();
    }

    private void OnProgress(object? sender, CheckProgressEventArgs e)
    {
        Progress = e.Percent;
        ProgressText = $"{e.Completed} / {e.Total}";
        if (e.Result is null) return;
        var index = Cards.ToList().FindIndex(c => c.Result.Category == e.Result.Category);
        if (index >= 0) Cards[index] = new CheckCardViewModel(e.Result);
    }

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        _cts = new CancellationTokenSource();
        IsRunning = true;
        RunCommand.NotifyCanExecuteChanged();
        CancelCommand.NotifyCanExecuteChanged();
        Progress = 0;
        ProgressText = $"0 / {Cards.Count}";
        SaveMessage = string.Empty;
        foreach (var card in Cards.ToList())
        {
            card.IsExpanded = false;
        }

        try
        {
            var result = await Task.Run(() => _runner.RunAsync(_options, PrivacyMode, _cts.Token)).ConfigureAwait(true);
            _lastResult = result;
            Verdict = new VerdictViewModel(result.Verdict, result.IpConsensus, result.Duration);
            HasResult = true;
            ExportReportCommand.NotifyCanExecuteChanged();
            UpdatePlainView(result);
            Progress = 100;
            LastRunText = $"последний прогон: {result.FinishedAt:dd.MM.yyyy HH:mm:ss}";
            StatusLine = result.Verdict.Headline;
            if (_options.SaveHistory)
            {
                try { await _history.SaveAsync(result).ConfigureAwait(true); }
                catch (Exception ex) { _logger.LogWarning(ex, "Не удалось сохранить прогон в историю"); }
            }
        }
        catch (OperationCanceledException)
        {
            StatusLine = "Проверка отменена пользователем";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка прогона");
            StatusLine = "Ошибка: " + ex.GetBaseException().Message;
        }
        finally
        {
            IsRunning = false;
            RunCommand.NotifyCanExecuteChanged();
            CancelCommand.NotifyCanExecuteChanged();
            _cts?.Dispose();
            _cts = null;
        }
    }

    /// <summary>
    /// Показывает готовый прогон (например, выбранный в истории) без повторного запуска проверок.
    /// </summary>
    /// <summary>Последний прогон — для повторного экспорта и предпросмотра отчёта.</summary>
    public CheckRunResult? LastResult => _lastResult;

    public void LoadRun(CheckRunResult result)
    {
        _lastResult = result;
        Verdict = new VerdictViewModel(result.Verdict, result.IpConsensus, result.Duration);
        HasResult = true;
        ExportReportCommand.NotifyCanExecuteChanged();
        UpdatePlainView(result);
        Progress = 100;
        LastRunText = $"последний прогон: {result.FinishedAt:dd.MM.yyyy HH:mm:ss}";
        StatusLine = result.Verdict.Headline;
    }

    private void UpdatePlainView(CheckRunResult result)
    {
        var explanation = PlainLanguage.ForVerdict(result.Verdict, result.Checks);
        PlainHeadline = explanation.Headline;
        PlainMeaning = explanation.WhatItMeans;
        PlainAdvice = explanation.Advice;
        PlainConfiguration = PlainFacts.OverallConfiguration(result);
        PlainAccent = result.Verdict.Level switch
        {
            RiskLevel.Clean => "#35C48A",
            RiskLevel.NeedsReview => "#F5C542",
            _ => "#F0524C",
        };
        PlainAccentBrush = Ui.Brush(PlainAccent);
        PlainSoftBrush = Ui.Brush(PlainAccent, 0.12);

        Facts.Clear();
        foreach (var fact in PlainFacts.Build(result)) Facts.Add(new FactViewModel(fact));

        PlainChecks.Clear();
        foreach (var check in result.Checks.Select(PlainLanguage.ToPlain)) PlainChecks.Add(new PlainCheckViewModel(check));
    }

    private bool CanRun() => !IsRunning;

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private void Cancel() => _cts?.Cancel();

    private bool CanCancel() => IsRunning;

    /// <summary>Доступные форматы отчёта (PDF, Word, Excel, CSV, Markdown, JSON).</summary>
    public IReadOnlyList<ExportFormatOption> ExportFormats { get; } = ExportFormatOption.All;

    [ObservableProperty]
    public partial ExportFormatOption SelectedFormat { get; set; } = ExportFormatOption.All[0];

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportReportAsync()
    {
        if (_lastResult is null) return;
        try
        {
            var file = ReportExporter.Build(SelectedFormat.Format, _lastResult);
            var path = await _files.SaveBytesAsync(file.FileName, file.Content, SelectedFormat.Extension, file.Description)
                .ConfigureAwait(true);
            SaveMessage = path is null ? string.Empty : $"Отчёт сохранён: {path}";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка экспорта отчёта");
            SaveMessage = "Не удалось сохранить отчёт: " + ex.GetBaseException().Message;
        }
    }

    private bool CanExport() => _lastResult is not null;

    [RelayCommand]
    private void TogglePlainDetails() => ShowPlainDetails = !ShowPlainDetails;

    /// <summary>Переключить на подробный режим (кнопка «Нужны детали»).</summary>
    [RelayCommand]
    private void GoPro() => Mode.IsSimple = false;

    [RelayCommand]
    private async Task CopySummaryAsync()
    {
        if (_lastResult is null || Application.Current?.ApplicationLifetime is null) return;
        var window = (Application.Current.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        var clipboard = window?.Clipboard;
        if (clipboard is null) return;
        var text = $"{_lastResult.Verdict.Headline} · {_lastResult.Verdict.Score}/100\n" +
                   string.Join("\n", _lastResult.Checks.Select(c => $"{c.Title}: {c.StatusText}")) +
                   $"\nВнешний IP: {_lastResult.IpConsensus.Summary}";
        await Avalonia.Input.Platform.ClipboardExtensions.SetTextAsync(clipboard, text).ConfigureAwait(true);
        SaveMessage = "Сводка скопирована в буфер обмена";
    }

    /// <summary>Освобождает незавершённый прогон (например, при закрытии окна во время проверки).</summary>
    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}
