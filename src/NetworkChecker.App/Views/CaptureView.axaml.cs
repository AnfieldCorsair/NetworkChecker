using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using NetworkChecker.App.ViewModels;

namespace NetworkChecker.App.Views;

public partial class CaptureView : UserControl
{
    public CaptureView() => InitializeComponent();

    private async void OpenCapture(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not CaptureViewModel vm || vm.IsBusy) return;
        var top = TopLevel.GetTopLevel(this);
        if (top?.StorageProvider is null) return;
        try
        {
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Открыть файл захвата",
                AllowMultiple = false,
                FileTypeFilter = [new FilePickerFileType("PCAP / PCAPNG") { Patterns = ["*.pcap", "*.pcapng", "*.cap"] }],
            }).ConfigureAwait(true);
            if (files.Count == 0) return;
            await using var stream = await files[0].OpenReadAsync().ConfigureAwait(true);
            await vm.LoadAsync(stream).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            vm.Status = "Не удалось открыть файл: " + ex.Message;
        }
    }
}
