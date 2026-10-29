using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;

namespace RKNHardering.App.Startup;

public interface IFileDialogService
{
    Task<string?> SaveTextAsync(string suggestedName, string content, string extension, string description);
}

public sealed class FileDialogService : IFileDialogService
{
    public async Task<string?> SaveTextAsync(string suggestedName, string content, string extension, string description)
    {
        var lifetime = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
        var window = lifetime?.MainWindow;
        if (window?.StorageProvider is null) return null;

        var file = await window.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = suggestedName,
            DefaultExtension = extension.TrimStart('.'),
            FileTypeChoices =
            [
                new FilePickerFileType(description) { Patterns = [$"*{extension}"] },
            ],
        }).ConfigureAwait(true);

        if (file is null) return null;
        await using var stream = await file.OpenWriteAsync().ConfigureAwait(true);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(content).ConfigureAwait(true);
        return file.Path.LocalPath;
    }
}
