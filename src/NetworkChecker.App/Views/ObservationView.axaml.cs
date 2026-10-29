using System.ComponentModel;
using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using NetworkChecker.App.Localization;

namespace NetworkChecker.App.Views;

public partial class ObservationView : UserControl
{
    public ObservationView() => InitializeComponent();

    private void RestartAsAdmin(object? sender, RoutedEventArgs e)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Executable path unavailable.");
            var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
            var args = Environment.GetCommandLineArgs();
            var isDotnet = Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase);
            foreach (var arg in args.Skip(isDotnet ? 0 : 1)) start.ArgumentList.Add(arg);
            using var process = Process.Start(start);
            if (process is null) throw new InvalidOperationException("Unable to start elevated process.");
            if (TopLevel.GetTopLevel(this) is Window window) window.Close();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            RestartStatus.Text = Localizer.T("Повышение прав отменено.");
        }
        catch (Exception ex)
        {
            RestartStatus.Text = Localizer.T("Не удалось перезапустить: ") + ex.GetBaseException().Message;
        }
    }
}
