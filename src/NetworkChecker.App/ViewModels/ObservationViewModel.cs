using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Principal;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Observation;

namespace NetworkChecker.App.ViewModels;

public sealed record ObservationRow(string Time, string Source, string Kind, string Detail);

/// <summary>Наблюдение по явному запросу, результаты не сохраняются в историю.</summary>
public sealed partial class ObservationViewModel(IObservationService service) : ViewModelBase, IDisposable
{
    private CancellationTokenSource? _cts;
    public override string Title => Localizer.T("Наблюдение");
    public override string Description => Localizer.T("Изменения WFP и сетевые события ETW");
    public override string Icon => global::NetworkChecker.App.Icons.Eye;
    public ObservableCollection<ObservationRow> Events { get; } = [];
    public bool IsElevated { get; } = GetElevation();
    public bool CanRestart => OperatingSystem.IsWindows() && !IsElevated;
    public string RightsText => IsElevated ? Localizer.T("Запущено с правами администратора") : Localizer.T("Права администратора не подтверждены");

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private bool _consented;
    [ObservableProperty] private string _status = Localizer.T("Наблюдение не запущено");
    [ObservableProperty] private string _wfpStatus = "—";
    [ObservableProperty] private string _etwStatus = "—";

    partial void OnConsentedChanged(bool value) => StartCommand.NotifyCanExecuteChanged();
    partial void OnIsRunningChanged(bool value)
    {
        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
    }
    private bool CanStart() => Consented && !IsRunning;
    private bool CanStop() => IsRunning;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        IsRunning = true;
        Events.Clear();
        WfpStatus = EtwStatus = Localizer.T("Запуск…");
        Status = Localizer.T("Наблюдение выполняется, не более 60 секунд…");
        _cts = new CancellationTokenSource();
        try
        {
            var token = _cts.Token;
            var report = await Task.Run(() => service.ObserveAsync(TimeSpan.FromSeconds(60), token), CancellationToken.None).ConfigureAwait(true);
            WfpStatus = FormatPart(report.Wfp);
            EtwStatus = FormatPart(report.Etw);
            foreach (var e in report.Wfp.Events.Concat(report.Etw.Events).OrderBy(e => e.At))
                Events.Add(new ObservationRow(e.At.ToString("HH:mm:ss", CultureInfo.InvariantCulture), e.Source, Localizer.T(e.Kind), e.Detail));
            Status = report.Wfp.Available || report.Etw.Available
                ? Localizer.T("Наблюдение завершено; результаты не доказывают перехват.")
                : Localizer.T("Источники недоступны; отсутствие событий ничего не доказывает.");
        }
        catch (Exception ex)
        {
            Status = Localizer.T("Ошибка наблюдения: ") + ex.GetBaseException().Message;
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            IsRunning = false;
            Consented = false;
        }
    }

    private static string FormatPart(ObservationPart part) => $"{Localizer.T(part.Status)} · {part.Events.Count.ToString(CultureInfo.InvariantCulture)} · {Localizer.T("пропущено сверх лимита")}: {part.Dropped.ToString(CultureInfo.InvariantCulture)}";
    [RelayCommand(CanExecute = nameof(CanStop))] private void Stop() => _cts?.Cancel();
    public void Dispose() => _cts?.Cancel();

    private static bool GetElevation()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
