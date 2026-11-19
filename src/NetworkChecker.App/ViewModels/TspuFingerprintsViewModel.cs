using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

public sealed partial class FingerprintDisplayItem : ObservableObject
{
    public FingerprintDisplayItem(
        string statusLabel,
        IBrush statusBrush,
        string confidenceText,
        string title,
        string mechanism,
        string recommendation,
        string evidenceText,
        bool isExpanded = false)
    {
        StatusLabel = statusLabel;
        StatusBrush = statusBrush;
        ConfidenceText = confidenceText;
        Title = title;
        Mechanism = mechanism;
        Recommendation = recommendation;
        EvidenceText = evidenceText;
        IsExpanded = isExpanded;
    }

    public string StatusLabel { get; }
    public IBrush StatusBrush { get; }
    public string ConfidenceText { get; }
    public string Title { get; }
    public string Mechanism { get; }
    public string Recommendation { get; }
    public string EvidenceText { get; }

    [ObservableProperty]
    public partial bool IsExpanded { get; set; }

    public string SpoilerButtonText => IsExpanded
        ? "▲ Скрыть технические замеры"
        : "▼ Показать технические замеры (тайминги, байты, коды)";

    partial void OnIsExpandedChanged(bool value)
    {
        OnPropertyChanged(nameof(SpoilerButtonText));
    }

    [RelayCommand]
    private void ToggleExpanded()
    {
        IsExpanded = !IsExpanded;
    }
}

public sealed record TargetDisplayItem(
    string Label,
    string Host,
    string GroupLabel,
    string ResultText,
    IBrush ResultBrush);

public sealed record CutoffDisplayItem(
    string StepLabel,
    string StatusText,
    IBrush StatusBrush);

/// <summary>
/// Вкладка 3: Детектор отпечатков блокировок ТСПУ, отсечки 16 КБ и DNS-спуфинга провайдеров РФ.
/// </summary>
public sealed partial class TspuFingerprintsViewModel : ViewModelBase
{
    private static readonly IBrush DangerBrush = new SolidColorBrush(Color.Parse("#F87171"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
    private static readonly IBrush CleanBrush = new SolidColorBrush(Color.Parse("#4ADE80"));
    private static readonly IBrush MutedBrush = new SolidColorBrush(Color.Parse("#9BAAC2"));

    private readonly HttpClient _http;
    private readonly IDesktopUiService _ui;

    public TspuFingerprintsViewModel(HttpClient http, IDesktopUiService ui)
    {
        _http = http;
        _ui = ui;
    }

    public override string Title => "Проверка блокировок (ТСПУ)";
    public override string Subtitle => "Лимит 16 КБ · Белые списки · DNS";
    public override string Description => "Проверяет ваш интернет-канал: есть ли на линии обрыв соединения после 16 КБ, подмена DNS провайдером или режим «белых списков».";
    public override string SimpleGuideText =>
        "Зачем это нужно: чтобы понять, почему не работает интернет или ВПН. Нажмите синюю кнопку «Запустить проверку линии» — программа за 5 секунд проверит, режет ли ваш провайдер зарубежные серверы на 16 килобайтах или подменяет адреса сайтов.";

    [ObservableProperty]
    public partial bool IsScanning { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Нажмите «Запустить проверку линии», чтобы узнать, какие ограничения действуют у вашего провайдера.";

    public ObservableCollection<FingerprintDisplayItem> Fingerprints { get; } = [];
    public ObservableCollection<TargetDisplayItem> Targets { get; } = [];
    public ObservableCollection<CutoffDisplayItem> CutoffSteps { get; } = [];

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName == nameof(ShowTechnicalDetails))
        {
            foreach (var item in Fingerprints)
            {
                item.IsExpanded = ShowTechnicalDetails;
            }
        }
    }

    [RelayCommand]
    private async Task RunScanAsync(CancellationToken ct)
    {
        IsScanning = true;
        StatusText = "Проверяем доступность российских и зарубежных сайтов, подмену DNS и скачивание пакетов от 4 до 512 КБ...";
        try
        {
            var result = await BlockingFingerprintDetector.RunAsync(_http, ct).ConfigureAwait(true);

            Fingerprints.Clear();
            foreach (var fp in result.Fingerprints)
            {
                var (status, brush) = fp.Status switch
                {
                    BlockingFingerprintStatus.Detected => ("ОБНАРУЖЕНО", DangerBrush),
                    BlockingFingerprintStatus.Suspected => ("ЕСТЬ ПРИЗНАКИ", WarnBrush),
                    BlockingFingerprintStatus.Clear => ("НЕ ОБНАРУЖЕНО", CleanBrush),
                    _ => ("НЕЯСНО", MutedBrush),
                };
                Fingerprints.Add(new FingerprintDisplayItem(
                    status,
                    brush,
                    string.Create(CultureInfo.InvariantCulture, $"Уверенность {fp.Confidence}%"),
                    fp.Title,
                    fp.Mechanism,
                    fp.Recommendation,
                    string.Join(" · ", fp.Evidence),
                    ShowTechnicalDetails));
            }

            Targets.Clear();
            foreach (var t in result.Targets)
            {
                var groupLabel = t.Group switch
                {
                    "ru_whitelist" => "Российский сайт",
                    "global_infra" => "Зарубежная сеть",
                    "restricted_rf" => "Под фильтром ТСПУ",
                    "ech_cdn" => "Cloudflare / ECH",
                    _ => t.Group,
                };
                var resText = t.Ok
                    ? string.Create(CultureInfo.InvariantCulture, $"ДОСТУПЕН ({t.LatencyMs} мс)")
                    : $"НЕ ОТКРЫЛСЯ ({t.Error ?? "таймаут"})";
                Targets.Add(new TargetDisplayItem(t.Label, t.Host, groupLabel, resText, t.Ok ? CleanBrush : DangerBrush));
            }

            CutoffSteps.Clear();
            foreach (var s in result.CutoffSteps)
            {
                var targetKb = s.BytesTarget / 1024;
                var recvKb = s.BytesReceived / 1024.0;
                var text = s.Ok
                    ? string.Create(CultureInfo.InvariantCulture, $"ПРОШЁЛ · скачано {recvKb:F1} КБ за {s.LatencyMs} мс")
                    : string.Create(CultureInfo.InvariantCulture, $"ОБРЫВ СВЯЗИ на {recvKb:F1} КБ ({s.Error ?? "таймаут"})");
                CutoffSteps.Add(new CutoffDisplayItem(
                    string.Create(CultureInfo.InvariantCulture, $"Пакет {targetKb} КБ"),
                    text,
                    s.Ok ? CleanBrush : DangerBrush));
            }

            var detectedCount = result.Fingerprints.Count(x => x.Status is BlockingFingerprintStatus.Detected or BlockingFingerprintStatus.Suspected);
            StatusText = detectedCount == 0
                ? string.Create(CultureInfo.InvariantCulture, $"Проверка завершена ({result.ScannedAt.ToLocalTime():HH:mm:ss}) · жёстких блокировок на линии не обнаружено.")
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Проверка завершена ({result.ScannedAt.ToLocalTime():HH:mm:ss}) · обнаружено ограничений на линии: {detectedCount} из {result.Fingerprints.Count}. Посмотрите рекомендации ниже.");
        }
        catch (OperationCanceledException)
        {
            StatusText = "Проверка отменена.";
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
            StatusText = "Сначала нажмите «Запустить проверку линии».";
            return;
        }

        var sb = new StringBuilder();
        sb.AppendLine("Проверка блокировок ТСПУ и DNS (Контур ВПН / NetworkChecker V2):");
        foreach (var fp in Fingerprints)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"- [{fp.StatusLabel} · {fp.ConfidenceText}] {fp.Title}: {fp.Recommendation}");
        }

        var ok = await _ui.CopyTextAsync(sb.ToString().TrimEnd()).ConfigureAwait(true);
        StatusText = ok ? "Результаты проверки скопированы в буфер обмена." : "Буфер обмена недоступен.";
    }
}
