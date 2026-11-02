using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Reputation;

namespace NetworkChecker.App.ViewModels;

/// <summary>Одна строка таблицы источников репутации.</summary>
public sealed class ReputationRowViewModel(ReputationSource source)
{
    public string Group { get; } = Localizer.T(source.Group);
    public string Name { get; } = Localizer.T(source.Name);
    public string Status { get; } = Localizer.T(source.Status);
    public string Detail { get; } = source.Detail is null ? string.Empty : Localizer.T(source.Detail);
    public bool HasDetail => Detail.Length > 0;
    public Avalonia.Media.IBrush DotBrush { get; } = Ui.Brush(ColorOf(source.Tone));

    private static string ColorOf(ReputationTone tone) => tone switch
    {
        ReputationTone.Good => "#35C48A",
        ReputationTone.Warn => "#F5C542",
        ReputationTone.Bad => "#F0524C",
        ReputationTone.Unknown => "#8A8F98",
        _ => "#5C7A99",
    };
}

/// <summary>
/// Вкладка «Репутация»: что думают об этом адресе спам-базы и репутационные сервисы,
/// и какую метку региона поставил Google (GL на YouTube + доступность AI Studio).
/// Никаких скрытых запросов: проверка запускается только по кнопке или общим прогоном.
/// </summary>
public sealed partial class ReputationViewModel : ViewModelBase, IDisposable
{
    private readonly ReputationService _service;
    private readonly ILogger<ReputationViewModel> _logger;
    private CancellationTokenSource? _cts;
    private Task _pending = Task.CompletedTask;
    private bool _loaded;

    public ReputationViewModel(ReputationService service, RknOptions options, ILogger<ReputationViewModel> logger)
    {
        _service = service;
        _logger = logger;
        CurrentOptions = options;
    }

    public override string Title => Localizer.T("Репутация");
    public override string Icon => global::NetworkChecker.App.Icons.Globe;
    public override string Description => Localizer.T("Спам-базы, жалобы и метка Google");

    public ObservableCollection<ReputationRowViewModel> Sources { get; } = [];
    public ObservableCollection<string> Caveats { get; } = [];

    public Task PendingTask => _pending;

    [ObservableProperty] public partial string Headline { get; set; } = Localizer.T("Ещё не проверяли");
    [ObservableProperty] public partial string Summary { get; set; } = Localizer.T("Нажмите «Проверить репутацию», чтобы запросить базы и метку Google.");
    [ObservableProperty] public partial string RiskText { get; set; } = "—";
    [ObservableProperty] public partial string IpText { get; set; } = Localizer.T("адрес ещё не получен");
    [ObservableProperty] public partial string GlText { get; set; } = "—";
    [ObservableProperty] public partial string GeoText { get; set; } = "—";
    [ObservableProperty] public partial string RuText { get; set; } = "—";
    [ObservableProperty] public partial string AiStudioText { get; set; } = "—";
    [ObservableProperty] public partial string StatusLine { get; set; } = Localizer.T("Готово к проверке");
    [ObservableProperty] public partial string UpdatedText { get; set; } = Localizer.T("проверок ещё не было");
    [ObservableProperty] public partial Avalonia.Media.IBrush AccentBrush { get; set; } = Ui.Brush("#5C7A99");
    [ObservableProperty] public partial Avalonia.Media.IBrush AccentSoftBrush { get; set; } = Ui.Brush("#5C7A99", 0.12);
    [ObservableProperty] public partial bool HasData { get; set; }
    [ObservableProperty] public partial bool IsBusy { get; set; }
    [ObservableProperty] public partial bool HasError { get; set; }
    [ObservableProperty] public partial string? ErrorText { get; set; }

    /// <summary>Показываем последний готовый отчёт без новых сетевых запросов.</summary>
    public void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        if (_service.Last is { } cached) Apply(cached);
    }

    [RelayCommand]
    private async Task RefreshAsync(CancellationToken ct)
    {
        if (IsBusy) return;
        _cts?.Dispose();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        IsBusy = true;
        HasError = false;
        ErrorText = null;
        StatusLine = Localizer.T("Опрашиваем базы и читаем метку Google…");
        try
        {
            var report = await _service.InspectAsync(CurrentOptions, force: true, token).ConfigureAwait(true);
            Apply(report);
        }
        catch (OperationCanceledException)
        {
            StatusLine = Localizer.T("Проверка отменена");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Не удалось собрать репутацию IP");
            StatusLine = Localizer.T("Не получилось");
            ErrorText = ex.GetBaseException().Message;
            HasError = true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Настройки прогона: тот же объект, что используют остальные экраны.</summary>
    public RknOptions CurrentOptions { get; }

    private void Apply(ReputationReport report)
    {
        Sources.Clear();
        foreach (var source in report.Sources) Sources.Add(new ReputationRowViewModel(source));
        Caveats.Clear();
        foreach (var caveat in report.Caveats) Caveats.Add(Localizer.T(caveat));

        Headline = Localizer.T(report.Headline);
        Summary = Localizer.T(report.Summary);
        RiskText = report.RiskAvailable ? report.Risk.ToString(CultureInfo.InvariantCulture) : "—";
        IpText = report.Ip ?? Localizer.T("нет данных");
        GlText = report.Google.Region ?? Localizer.T("нет данных");
        GeoText = report.Google.GeoCountry ?? Localizer.T("нет данных");
        RuText = report.Google.RuMarked switch
        {
            true => Localizer.T("да"),
            false => Localizer.T("нет"),
            _ => Localizer.T("нет данных"),
        };
        AiStudioText = report.Google.AiStudioStatus is { } aiStatus
            ? Localizer.T(aiStatus)
            : Localizer.T("нет данных");
        HasData = report.HasData;
        UpdatedText = report.At.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        StatusLine = report.State switch
        {
            ReputationReportState.Offline => Localizer.T("Офлайн-режим: внешние запросы не выполнялись"),
            ReputationReportState.Disabled => Localizer.T("Проверка выключена в настройках"),
            ReputationReportState.NoData => Localizer.T("Источники не вернули данных"),
            _ => Localizer.T("Готово"),
        };

        var accent = report.RiskAvailable && report.Risk >= 60 ? "#F0524C"
            : report.RiskAvailable && report.Risk > 0 ? "#F5C542"
            : "#35C48A";
        AccentBrush = Ui.Brush(accent);
        AccentSoftBrush = Ui.Brush(accent, 0.12);
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}
