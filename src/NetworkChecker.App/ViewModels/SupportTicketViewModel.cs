using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

/// <summary>
/// Вкладка 5: 2-шаговый генератор запроса в техподдержку ВПН («Без ВПН — РФ-провайдер» vs «С ВПН — туннель»).
/// </summary>
public sealed partial class SupportTicketViewModel : ViewModelBase
{
    private readonly HttpClient _http;
    private readonly ConfigAuditViewModel _configAudit;
    private readonly IDesktopUiService _ui;

    private SupportNetworkSnapshot? _withoutVpn;
    private SupportNetworkSnapshot? _withVpn;

    public SupportTicketViewModel(
        HttpClient http,
        ConfigAuditViewModel configAudit,
        IDesktopUiService ui)
    {
        _http = http;
        _configAudit = configAudit;
        _ui = ui;
        RebuildPreview();
    }

    public override string Title => "Техподдержка";
    public override string Subtitle => "Без ВПН vs С ВПН · .md";
    public override string Description => "Сбор 2 срезов сети (ваш РФ-провайдер без ВПН и выход через туннель), замер скорости и готовое сообщение для чата/бота поддержки с маскировкой ключей.";

    public IReadOnlyList<string> SymptomChoices { get; } =
    [
        "Сильно режет скорость (Download/Upload падает почти в ноль)",
        "Туннель подключается, но сайты/приложения не открываются",
        "Соединение обрывается через 10–30 секунд (подозрение на 16 КБ ТСПУ)",
        "Вообще не подключается (таймаут рукопожатия / сброс TCP)",
        "Работают только российские сайты (режим белых списков)",
    ];

    public IReadOnlyList<string> ConnectionChoices { get; } =
    [
        "Домашний проводной / Wi-Fi",
        "Мобильный интернет (4G/LTE)",
        "Корпоративная / публичная сеть",
    ];

    public IReadOnlyList<string> ClientChoices { get; } =
    [
        "v2rayN (Windows)",
        "Hiddify / Sing-box",
        "NekoRay / NekoBox",
        "Happ / Clash Verge",
        "AmneziaVPN / AmneziaWG",
    ];

    [ObservableProperty]
    public partial string SelectedSymptom { get; set; } = "Сильно режет скорость (Download/Upload падает почти в ноль)";

    [ObservableProperty]
    public partial string SelectedConnection { get; set; } = "Домашний проводной / Wi-Fi";

    [ObservableProperty]
    public partial string SelectedClient { get; set; } = "v2rayN (Windows)";

    [ObservableProperty]
    public partial string UserComment { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool MaskHomeIp { get; set; } = true;

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string WithoutVpnSummary { get; set; } = "Шаг 1 ещё не выполнен — отключите ВПН и нажмите «Снять срез Без ВПН».";

    [ObservableProperty]
    public partial string WithVpnSummary { get; set; } = "Шаг 2 ещё не выполнен — включите ВПН и нажмите «Снять срез С ВПН».";

    [ObservableProperty]
    public partial string TelegramPreview { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Данные профиля и последнего RTT-бенчмарка подтягиваются автоматически с маскировкой секретов.";

    partial void OnSelectedSymptomChanged(string value) => RebuildPreview();
    partial void OnSelectedConnectionChanged(string value) => RebuildPreview();
    partial void OnSelectedClientChanged(string value) => RebuildPreview();
    partial void OnUserCommentChanged(string value) => RebuildPreview();
    partial void OnMaskHomeIpChanged(bool value)
    {
        if (_withoutVpn is not null)
        {
            WithoutVpnSummary = FormatSnapshotSummary(_withoutVpn, value);
        }

        RebuildPreview();
    }

    [RelayCommand]
    private async Task CaptureWithoutVpnAsync(CancellationToken ct)
    {
        IsBusy = true;
        StatusText = "Шаг 1: определяем РФ-провайдера, ASN и скорость без ВПН...";
        try
        {
            _withoutVpn = await SupportNetworkProbe.CaptureAsync(_http, "without_vpn", runSpeedTest: true, ct).ConfigureAwait(true);
            WithoutVpnSummary = FormatSnapshotSummary(_withoutVpn, MaskHomeIp);
            RebuildPreview();
            StatusText = "Шаг 1 выполнен. Теперь включите ВПН и нажмите «Шаг 2: Срез С ВПН».";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task CaptureWithVpnAsync(CancellationToken ct)
    {
        IsBusy = true;
        StatusText = "Шаг 2: определяем выходной IP туннеля и скорость с ВПН...";
        try
        {
            _withVpn = await SupportNetworkProbe.CaptureAsync(_http, "with_vpn", runSpeedTest: true, ct).ConfigureAwait(true);
            WithVpnSummary = FormatSnapshotSummary(_withVpn, maskIp: false);
            RebuildPreview();
            StatusText = "Шаг 2 выполнен. Отчёт для техподдержки готов к копированию или сохранению.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void RefreshFromAudit()
    {
        RebuildPreview();
        StatusText = "Профиль и данные RTT обновлены из вкладки «Аудит и подписки».";
    }

    [RelayCommand]
    private async Task CopyTelegramAsync()
    {
        RebuildPreview();
        var ok = await _ui.CopyTextAsync(TelegramPreview).ConfigureAwait(true);
        StatusText = ok ? "Сообщение для Telegram-поддержки скопировано в буфер обмена." : "Буфер обмена недоступен.";
    }

    [RelayCommand]
    private async Task SaveMarkdownAsync()
    {
        var md = SupportTicketBuilder.BuildFullMarkdownReport(BuildDraft());
        var path = await _ui.SaveTextFileAsync("vpn-support-report.md", md, ".md", "Markdown-отчёт").ConfigureAwait(true);
        StatusText = path is not null ? $"Полный отчёт сохранён: {path}" : "Сохранение отменено.";
    }

    private SupportTicketDraft BuildDraft() => new(
        SelectedSymptom,
        SelectedConnection,
        SelectedClient,
        UserComment,
        MaskHomeIp,
        _withoutVpn,
        _withVpn,
        _configAudit.CurrentReport,
        _configAudit.LastRttResult);

    private void RebuildPreview()
    {
        TelegramPreview = SupportTicketBuilder.BuildTelegramMessage(BuildDraft());
    }

    private static string FormatSnapshotSummary(SupportNetworkSnapshot snap, bool maskIp)
    {
        var ip = string.IsNullOrWhiteSpace(snap.Ip) ? "не определён" : snap.Ip;
        if (maskIp && ip.Contains('.', StringComparison.Ordinal))
        {
            var parts = ip.Split('.');
            if (parts.Length == 4)
            {
                ip = $"{parts[0]}.{parts[1]}.xxx.xxx";
            }
        }

        var down = snap.Speed?.DownloadMbps is { } d ? string.Create(CultureInfo.InvariantCulture, $"{d:F1} Мбит/с") : "—";
        var up = snap.Speed?.UploadMbps is { } u ? string.Create(CultureInfo.InvariantCulture, $"{u:F1} Мбит/с") : "—";
        return $"IP: {ip} · {snap.Isp ?? "—"} {snap.Asn ?? string.Empty} · ↓ {down} / ↑ {up}";
    }
}
