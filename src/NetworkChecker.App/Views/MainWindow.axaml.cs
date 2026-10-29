using Avalonia.Controls;
using NetworkChecker.App.ViewModels;

namespace NetworkChecker.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Closed += OnClosed;
    }

    /// <summary>Закрытие окна должно остановить незавершённый прогон, а не оставить его в фоне.</summary>
    private void OnClosed(object? sender, EventArgs e)
    {
        if (DataContext is MainWindowViewModel vm) vm.Dispose();
    }
}
