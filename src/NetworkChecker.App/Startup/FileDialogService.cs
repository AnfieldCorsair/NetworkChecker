using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;

namespace NetworkChecker.App.Startup;

public interface IFileDialogService
{
    Task<string?> SaveTextAsync(string suggestedName, string content, string extension, string description);

    /// <summary>Сохранить произвольный файл (PDF, DOCX, XLSX, CSV…).</summary>
    Task<string?> SaveBytesAsync(string suggestedName, byte[] content, string extension, string description);
}

public sealed class FileDialogService : IFileDialogService
{
    public async Task<string?> SaveTextAsync(string suggestedName, string content, string extension, string description)
    {
        var target = await OpenAsync(suggestedName, extension, description).ConfigureAwait(true);
        if (target is null) return null;
        var (stream, path) = target.Value;
        await using (stream)
        {
            await using var writer = new StreamWriter(stream);
            await writer.WriteAsync(content).ConfigureAwait(true);
        }
        return path;
    }

    public async Task<string?> SaveBytesAsync(string suggestedName, byte[] content, string extension, string description)
    {
        var target = await OpenAsync(suggestedName, extension, description).ConfigureAwait(true);
        if (target is null) return null;
        var (stream, path) = target.Value;
        await using (stream)
        {
            await stream.WriteAsync(content).ConfigureAwait(true);
        }
        return path;
    }

    private static async Task<(Stream Stream, string Path)?> OpenAsync(string suggestedName, string extension, string description)
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
        var stream = await file.OpenWriteAsync().ConfigureAwait(true);
        return (stream, file.Path.LocalPath);
    }
}
