using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using NetworkChecker.App.Localization;
using NetworkChecker.Core.Capture;

namespace NetworkChecker.App.ViewModels;

/// <summary>Первый этап сниффера: локальный просмотр файлов захвата без записи и сетевой активности.</summary>
public sealed partial class CaptureViewModel : ViewModelBase
{
    public override string Title => Localizer.T("Сниффер");
    public override string Description => Localizer.T("Просмотр пакетного захвата");
    public override string Icon => global::NetworkChecker.App.Icons.Trace;
    public ObservableCollection<CapturePacket> Packets { get; } = [];

    [ObservableProperty] private CapturePacket? _selected;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _status = Localizer.T("Откройте файл PCAP или PCAPNG. Захват и фоновый мониторинг ещё не подключены.");

    public async Task LoadAsync(Stream stream, CancellationToken ct = default)
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[81920];
            int count;
            while ((count = await stream.ReadAsync(chunk, ct).ConfigureAwait(true)) > 0)
            {
                if (buffer.Length + count > CaptureReader.MaxFileBytes) throw new InvalidDataException("Файл больше 32 МиБ.");
                await buffer.WriteAsync(chunk.AsMemory(0, count), ct).ConfigureAwait(true);
            }
            var document = await Task.Run(() => CaptureReader.Read(buffer.ToArray()), ct).ConfigureAwait(true);
            Packets.Clear();
            foreach (var packet in document.Packets) Packets.Add(packet);
            Selected = Packets.FirstOrDefault();
            Status = Localizer.Culture == "en-US"
                ? $"{document.Format}: {Packets.Count} packets shown" +
                  (document.Limited ? " · limit of 2,000 reached" : "") +
                  (document.SkippedBlocks > 0 ? $" · other blocks skipped: {document.SkippedBlocks}" : "")
                : $"{document.Format}: показано {Packets.Count} пакетов" +
                  (document.Limited ? " · достигнут предел 2000" : "") +
                  (document.SkippedBlocks > 0 ? $" · пропущено других блоков: {document.SkippedBlocks}" : "");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            // Не оставляем результаты предыдущего файла под сообщением об ошибке нового.
            Packets.Clear();
            Selected = null;
            Status = Localizer.Culture == "en-US"
                ? "Could not open the capture file: " + Localizer.T(ex.Message)
                : "Не удалось открыть файл: " + ex.Message;
        }
        finally { IsBusy = false; }
    }
}
