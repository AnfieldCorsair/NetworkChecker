using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.SiteView;

namespace NetworkChecker.App.ViewModels;

/// <summary>Строка визитной карточки: подпись, значение, пояснение и цветной маркер.</summary>
public sealed class SiteRowViewModel(SiteViewRow row)
{
    public string Label { get; } = Localizer.T(row.Label);
    public string Value { get; } = Localizer.T(row.Value);
    public string Hint { get; } = row.Hint is null ? string.Empty : Localizer.T(row.Hint);
    public bool HasHint { get; } = !string.IsNullOrWhiteSpace(row.Hint);
    public string Tone { get; } = ToneKey(row.Tone);
    public Avalonia.Media.IBrush DotBrush { get; } = Ui.Brush(ColorOf(row.Tone));
    public bool IsBad { get; } = row.Tone == SiteViewTone.Bad;

    private static string ToneKey(SiteViewTone tone) => tone switch
    {
        SiteViewTone.Good => "good",
        SiteViewTone.Warn => "warn",
        SiteViewTone.Bad => "bad",
        _ => "neutral",
    };

    private static string ColorOf(SiteViewTone tone) => tone switch
    {
        SiteViewTone.Good => "#35C48A",
        SiteViewTone.Warn => "#F5C542",
        SiteViewTone.Bad => "#F0524C",
        _ => "#5C7A99",
    };
}

/// <summary>Вывод сайта: короткий заголовок, объяснение и «вес» признака.</summary>
public sealed class SiteSignalViewModel(SiteViewSignal signal)
{
    public string Title { get; } = Localizer.T(signal.Title);
    public string Detail { get; } = Localizer.T(signal.Detail);
    public string PointsText { get; } = signal.Points > 0 ? "+" + signal.Points.ToString(CultureInfo.InvariantCulture) : string.Empty;
    public bool HasPoints { get; } = signal.Points > 0;
    public Avalonia.Media.IBrush AccentBrush { get; } = Ui.Brush(signal.Tone switch
    {
        SiteViewTone.Bad => "#F0524C",
        SiteViewTone.Warn => "#F5C542",
        SiteViewTone.Good => "#35C48A",
        _ => "#5C7A99",
    });
}

/// <summary>Заголовок HTTP-запроса в том виде, в котором его получает сервер.</summary>
public sealed class HeaderRowViewModel(string name, string value)
{
    public string Name { get; } = name;
    public string Value { get; } = value;
}

/// <summary>
/// Экран «Глазами сайта»: что о вас узнаёт российский сайт (ВК, Яндекс, банк) с первого же запроса.
/// Данные берутся из ответа GeoIP-сервиса и из локальных настроек — на серверы сайтов ничего не уходит.
/// </summary>
public sealed partial class SiteViewModel : ViewModelBase, IDisposable
{
    private readonly ISiteEyeService _service;
    private readonly ILogger<SiteViewModel> _logger;
    private CancellationTokenSource? _cts;
    private Task _pending = Task.CompletedTask;
    private bool _loaded;

    public SiteViewModel(ISiteEyeService service, UiModeService mode, ILogger<SiteViewModel> logger)
    {
        _service = service;
        _logger = logger;
        Mode = mode;
        Mode.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName is nameof(UiModeService.IsSimple) or nameof(UiModeService.IsPro))
            {
                OnPropertyChanged(nameof(ShowRawRequest));
            }
        };
    }

    public UiModeService Mode { get; }

    public override string Title => global::NetworkChecker.App.Localization.Localizer.T("Глазами сайта");
    public override string Icon => global::NetworkChecker.App.Icons.Eye;
    public override string Description => global::NetworkChecker.App.Localization.Localizer.T("Что о вас узнаёт ВК или Яндекс");

    public ObservableCollection<SiteRowViewModel> Rows { get; } = [];
    public ObservableCollection<SiteSignalViewModel> Signals { get; } = [];
    public ObservableCollection<HeaderRowViewModel> Headers { get; } = [];

    /// <summary>Сырые заголовки — только в подробном режиме: обычному пользователю они не нужны.</summary>
    public bool ShowRawRequest => Mode.IsPro;

    public bool HasSignals => Signals.Count > 0;

    /// <summary>«Всё сходится» показываем только когда действительно есть что оценивать.</summary>
    public bool ShowNoSignals => HasReport && !HasSignals;

    [ObservableProperty]
    public partial string Headline { get; set; } = Localizer.T("Ещё не смотрели");

    [ObservableProperty]
    public partial string Summary { get; set; } = "Нажмите «Посмотреть», и приложение покажет, что о вас узнаёт сайт с первого запроса.";

    [ObservableProperty]
    public partial string ExposureText { get; set; } = "—";

    [ObservableProperty]
    public partial string IpText { get; set; } = Localizer.T("адрес ещё не получен");

    [ObservableProperty]
    public partial Avalonia.Media.IBrush AccentBrush { get; set; } = Ui.Brush("#5C7A99");

    [ObservableProperty]
    public partial Avalonia.Media.IBrush AccentSoftBrush { get; set; } = Ui.Brush("#5C7A99", 0.12);

    [ObservableProperty]
    public partial string RequestLine { get; set; } = "GET / HTTP/1.1";

    [ObservableProperty]
    public partial string StatusLine { get; set; } = "Готово к запуску";

    [ObservableProperty]
    public partial string? ErrorText { get; set; }

    [ObservableProperty]
    public partial bool HasError { get; set; }

    [ObservableProperty]
    public partial bool HasReport { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string UpdatedText { get; set; } = "прогонов ещё не было";

    /// <summary>Задача текущего осмотра: нужна тестам и снятию скриншотов, чтобы дождаться результата.</summary>
    public Task PendingTask => _pending;

    /// <summary>Первый вход на вкладку сам запускает осмотр — лишний клик никому не нужен.</summary>
    public void EnsureLoaded()
    {
        if (_loaded || IsBusy) return;
        _loaded = true;
        _pending = RefreshAsync(CancellationToken.None);
    }

    [RelayCommand]
    private async Task RefreshAsync(CancellationToken ct)
    {
        if (IsBusy) return;

        _cts?.Dispose();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;

        IsBusy = true;
        StatusLine = Localizer.T("Спрашиваем GeoIP-сервис, каким вас видит интернет…");
        ErrorText = null;
        HasError = false;

        try
        {
            var report = await _service.InspectAsync(token).ConfigureAwait(true);
            Apply(report);
        }
        catch (OperationCanceledException)
        {
            StatusLine = Localizer.T("Осмотр отменён");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Не удалось собрать данные «глазами сайта»");
            StatusLine = Localizer.T("Не получилось");
            ErrorText = ex.GetBaseException().Message;
            HasError = true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void Apply(SiteViewReport report)
    {
        Rows.Clear();
        foreach (var row in report.Rows) Rows.Add(new SiteRowViewModel(row));

        Signals.Clear();
        foreach (var signal in report.Signals) Signals.Add(new SiteSignalViewModel(signal));
        OnPropertyChanged(nameof(HasSignals));
        OnPropertyChanged(nameof(ShowNoSignals));

        Headers.Clear();
        foreach (var header in report.Request.Headers) Headers.Add(new HeaderRowViewModel(header.Key, header.Value));
        RequestLine = report.Request.Line;

        Headline = Localizer.T(report.Headline);
        Summary = Localizer.Culture != "en-US" ? report.Summary
            : report.HasGeo
                ? $"Signals: {report.Signals.Count}; heuristic score: {report.Exposure}/100. This is not a VPN probability or a particular website's assessment. GeoIP can be incomplete or inaccurate; language and time zone are system values, not browser values. Captchas and restrictions depend on the website."
                : "The public IP was not obtained: offline mode may be enabled or GeoIP services may be unavailable. Only local time zone, language and client information are shown.";
        ExposureText = report.HasGeo ? report.Exposure.ToString(CultureInfo.InvariantCulture) : "—";
        IpText = report.HasGeo ? report.Ip! : "адрес ещё не получен";
        ErrorText = report.Error;
        HasError = !string.IsNullOrWhiteSpace(report.Error);
        HasReport = true;
        OnPropertyChanged(nameof(ShowNoSignals));

        var accent = report.Exposure >= SiteViewAnalyzer.VpnLikeThreshold ? "#F0524C"
            : report.Exposure >= SiteViewAnalyzer.ReviewThreshold ? "#F5C542"
            : "#35C48A";
        AccentBrush = Ui.Brush(accent);
        AccentSoftBrush = Ui.Brush(accent, 0.12);

        UpdatedText = report.At.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        StatusLine = report.Offline
            ? Localizer.T("Офлайн-режим: показаны только локальные факты")
            : report.HasGeo ? Localizer.T("Готово") : Localizer.T("Внешний адрес получить не удалось");
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}
