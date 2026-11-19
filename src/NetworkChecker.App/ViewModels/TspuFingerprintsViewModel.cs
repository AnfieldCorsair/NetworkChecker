using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

public sealed record FingerprintDisplayItem(
    string StatusLabel,
    string ConfidenceText,
    string Title,
    string Mechanism,
    string Recommendation,
    string EvidenceText);

public sealed record TargetDisplayItem(
    string Label,
    string Host,
    string GroupLabel,
    string ResultText);

public sealed record CutoffDisplayItem(
    string StepLabel,
    string StatusText);

/// <summary>
/// Вкладка 3: Детектор отпечатков блокировок ТСПУ и провайдеров РФ.
/// </summary>
public sealed partial class TspuFingerprintsViewModel : ViewModelBase
{
    private readonly HttpClient _http;
    private readonly IDesktopUiService _ui;

    public TspuFingerprintsViewModel(HttpClient http, IDesktopUiService ui)
    {
        _http = http;
        _ui = ui;
    }

    public override string Title => "Отпечатки ТСПУ";
    public override string Subtitle => "Белые списки · 16 КБ · ECH";
    public override string Description => "Анализ реакций сети на домены «белых списков» (Яндекс/ВК/Госуслуги), ступенчатая проверка отсечки потока 16 КБ, L7 SNI и TLS ECH.";

    [ObservableProperty]
    public partial bool IsScanning { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Нажмите «Запустить анализ ТСПУ», чтобы проверить ваш канал напрямую с этого ПК.";

    public ObservableCollection<FingerprintDisplayItem> Fingerprints { get; } = [];
    public ObservableCollection<TargetDisplayItem> Targets { get; } = [];
    public ObservableCollection<CutoffDisplayItem> CutoffSteps { get; } = [];

    [RelayCommand]
    private async Task RunScanAsync(CancellationToken ct)
    {
        IsScanning = true;
        StatusText = "Идёт проверка матрицы доменов (РФ / глобальные / ECH) и отсечки 4–512 КБ...";
        try
        {
            var result = await BlockingFingerprintDetector.RunAsync(_http, ct).ConfigureAwait(true);

            Fingerprints.Clear();
            foreach (var fp in result.Fingerprints)
            {
                var status = fp.Status switch
                {
                    BlockingFingerprintStatus.Detected => "ОБНАРУЖЕНО",
                    BlockingFingerprintStatus.Suspected => "ПОДОЗРЕНИЕ",
                    BlockingFingerprintStatus.Clear => "ЧИСТО",
                    _ => "НЕЯСНО",
                };
                Fingerprints.Add(new FingerprintDisplayItem(
                    status,
                    string.Create(CultureInfo.InvariantCulture, $"{fp.Confidence}%"),
                    fp.Title,
                    fp.Mechanism,
                    fp.Recommendation,
                    string.Join(" · ", fp.Evidence)));
            }

            Targets.Clear();
            foreach (var t in result.Targets)
            {
                var groupLabel = t.Group switch
                {
                    "ru_whitelist" => "РФ Белый список",
                    "global_infra" => "Глобальная сеть",
                    "restricted_rf" => "Фильтр РФ",
                    "ech_cdn" => "TLS ECH",
                    _ => t.Group,
                };
                var resText = t.Ok
                    ? string.Create(CultureInfo.InvariantCulture, $"OK ({t.LatencyMs} мс)")
                    : $"СБОЙ: {t.Error ?? "таймаут"}";
                Targets.Add(new TargetDisplayItem(t.Label, t.Host, groupLabel, resText));
            }

            CutoffSteps.Clear();
            foreach (var s in result.CutoffSteps)
            {
                var targetKb = s.BytesTarget / 1024;
                var recvKb = s.BytesReceived / 1024.0;
                var text = s.Ok
                    ? string.Create(CultureInfo.InvariantCulture, $"OK · получено {recvKb:F1} КБ за {s.LatencyMs} мс")
                    : string.Create(CultureInfo.InvariantCulture, $"ОБРЫВ на {recvKb:F1} КБ ({s.Error ?? "таймаут"})");
                CutoffSteps.Add(new CutoffDisplayItem(
                    string.Create(CultureInfo.InvariantCulture, $"Шаг {targetKb} КБ"),
                    text));
            }

            var detectedCount = result.Fingerprints.Count(x => x.Status is BlockingFingerprintStatus.Detected or BlockingFingerprintStatus.Suspected);
            StatusText = string.Create(
                CultureInfo.InvariantCulture,
                $"Сканирование завершено ({result.ScannedAt.ToLocalTime():HH:mm:ss}) · выявлено паттернов: {detectedCount} из {result.Fingerprints.Count}.");
        }
        catch (OperationCanceledException)
        {
            StatusText = "Сканирование отменено.";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task CopySummaryAsync()
    {
        if (Fingerprints.Count == 0)
        {
            StatusText = "Сначала запустите анализ ТСПУ.";
            return;
        }

        var sb = new StringBuilder();
        sb.AppendLine("Отпечатки ТСПУ (NetworkChecker V2):");
        foreach (var fp in Fingerprints)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"- [{fp.StatusLabel} {fp.ConfidenceText}] {fp.Title} ({fp.EvidenceText})");
        }

        var ok = await _ui.CopyTextAsync(sb.ToString().TrimEnd()).ConfigureAwait(true);
        StatusText = ok ? "Сводка отпечатков ТСПУ скопирована в буфер обмена." : "Буфер обмена недоступен.";
    }
}
