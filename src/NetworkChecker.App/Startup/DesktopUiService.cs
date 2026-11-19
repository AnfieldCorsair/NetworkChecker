using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;

namespace NetworkChecker.App.Startup;

public interface IDesktopUiService
{
    Task<bool> CopyTextAsync(string text);
    Task<string?> SaveTextFileAsync(string suggestedFileName, string content, string extension, string description);
}

public sealed class DesktopUiService : IDesktopUiService
{
    public async Task<bool> CopyTextAsync(string text)
    {
        var window = GetMainWindow();
        if (window?.Clipboard is null)
        {
            return false;
        }

        await window.Clipboard.SetTextAsync(text).ConfigureAwait(true);
        return true;
    }

    public async Task<string?> SaveTextFileAsync(
        string suggestedFileName,
        string content,
        string extension,
        string description)
    {
        var window = GetMainWindow();
        if (window?.StorageProvider is null)
        {
            return null;
        }

        var cleanExt = extension.TrimStart('.');
        var file = await window.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = suggestedFileName,
            DefaultExtension = cleanExt,
            FileTypeChoices =
            [
                new FilePickerFileType(description) { Patterns = [$"*.{cleanExt}"] },
            ],
        }).ConfigureAwait(true);

        if (file is null)
        {
            return null;
        }

        await using var stream = await file.OpenWriteAsync().ConfigureAwait(true);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(content).ConfigureAwait(true);
        return file.Path.LocalPath;
    }

    private static Avalonia.Controls.Window? GetMainWindow() =>
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
}
