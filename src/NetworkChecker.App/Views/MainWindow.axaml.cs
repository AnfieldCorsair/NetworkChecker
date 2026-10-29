using Avalonia.Controls;
using NetworkChecker.App.ViewModels;

namespace NetworkChecker.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Opened += OnOpened;
        Closing += OnClosing;
        Closed += OnClosed;
    }

    private bool _closingAfterObservation;

    private void OnOpened(object? sender, EventArgs e)
    {
        // Нативную рамку сохраняем. На масштабированных экранах исходные 1400×900 DIP
        // могут оказаться больше рабочего пространства и увести заголовок за экран.
        if (!OperatingSystem.IsWindows()) return;
        var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
        if (screen is null) return;
        var placement = InitialWindowPlacement.Fit(screen.WorkingArea, screen.Scaling, Width, Height);
        MinWidth = Math.Min(MinWidth, placement.Width);
        MinHeight = Math.Min(MinHeight, placement.Height);
        Width = placement.Width;
        Height = placement.Height;
        Position = placement.Position;
    }

    private async void OnClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_closingAfterObservation || DataContext is not MainWindowViewModel main) return;
        var observation = main.Pages.OfType<ObservationViewModel>().FirstOrDefault();
        if (observation is not { IsRunning: true }) return;
        e.Cancel = true;
        observation.StopCommand.Execute(null);
        try
        {
            if (observation.StartCommand.ExecutionTask is { } task) await task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
        }
        catch (TimeoutException) { }
        finally
        {
            _closingAfterObservation = true;
            Close();
        }
    }

    /// <summary>Закрытие окна должно остановить незавершённый прогон, а не оставить его в фоне.</summary>
    private void OnClosed(object? sender, EventArgs e)
    {
        if (DataContext is MainWindowViewModel vm) vm.Dispose();
    }
}
