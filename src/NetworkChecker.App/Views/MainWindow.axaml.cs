using Avalonia;
using Avalonia.Controls;

namespace NetworkChecker.App.Views;

public partial class MainWindow : Window
{
    private bool _initialBoundsApplied;

    public MainWindow()
    {
        InitializeComponent();
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        if (_initialBoundsApplied || WindowState != WindowState.Normal)
        {
            return;
        }

        _initialBoundsApplied = true;
        FitAndCenterOnActiveScreen();
    }

    private void FitAndCenterOnActiveScreen()
    {
        var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
        if (screen is null)
        {
            return;
        }

        var scaling = screen.Scaling > 0 ? screen.Scaling : 1.0;
        var workArea = screen.WorkingArea;
        var logicalWorkWidth = workArea.Width / scaling;
        var logicalWorkHeight = workArea.Height / scaling;

        if (logicalWorkWidth <= 0 || logicalWorkHeight <= 0)
        {
            return;
        }

        // Адаптируем минимальные и стартовые размеры под текущее разрешение и DPI Windows (100% / 125% / 150%)
        var safeMinWidth = Math.Min(920.0, Math.Max(640.0, Math.Floor(logicalWorkWidth * 0.85)));
        var safeMinHeight = Math.Min(600.0, Math.Max(480.0, Math.Floor(logicalWorkHeight * 0.85)));
        MinWidth = safeMinWidth;
        MinHeight = safeMinHeight;

        var targetWidth = Math.Floor(Math.Clamp(Math.Min(1220.0, logicalWorkWidth * 0.92), safeMinWidth, logicalWorkWidth * 0.96));
        var targetHeight = Math.Floor(Math.Clamp(Math.Min(760.0, logicalWorkHeight * 0.90), safeMinHeight, logicalWorkHeight * 0.95));

        Width = targetWidth;
        Height = targetHeight;

        var pixelWidth = (int)Math.Round(targetWidth * scaling);
        var pixelHeight = (int)Math.Round(targetHeight * scaling);
        var centeredX = workArea.X + Math.Max(0, (workArea.Width - pixelWidth) / 2);
        var centeredY = workArea.Y + Math.Max(0, (workArea.Height - pixelHeight) / 2);

        Position = new PixelPoint(centeredX, centeredY);
    }
}
