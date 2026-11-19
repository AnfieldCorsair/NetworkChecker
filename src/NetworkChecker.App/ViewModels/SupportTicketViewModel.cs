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

    public override string Title => "Заявка в техподдержку";
    public override string Subtitle => "Готовый отчёт без паролей";
    public override string Description => "Собирает понятный технический отчёт для отправки в поддержку вашего ВПН-сервиса (при этом все ваши личные ключи и пароли автоматически скрываются).";
    public override string SimpleGuideText =>
        "Если ВПН плохо работает: 1) Выключите ВПН и нажмите «Снять замер БЕЗ ВПН». 2) Включите ВПН и нажмите «Снять замер С ВПН». 3) Нажмите «Скопировать готовый текст» и отправьте его в Telegram-бот или чат поддержки вашего ВПН.";

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
        "Домашний проводной интернет / Wi-Fi",
        "Мобильный интернет (4G / LTE)",
        "Рабочая / общественная сеть",
    ];

    public IReadOnlyList<string> ClientChoices { get; } =
    [
        "Happ (Windows / iOS / Android)",
        "v2rayN (Windows)",
        "Hiddify / Sing-box",
        "NekoRay / NekoBox",
        "AmneziaVPN / AmneziaWG",
    ];

    [ObservableProperty]
    public partial string SelectedSymptom { get; set; } = "Сильно режет скорость (Download/Upload падает почти в ноль)";

    [ObservableProperty]
    public partial string SelectedConnection { get; set; } = "Домашний проводной интернет / Wi-Fi";

    [ObservableProperty]
    public partial string SelectedClient { get; set; } = "Happ (Windows / iOS / Android)";

    [ObservableProperty]
    public partial string UserComment { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool MaskHomeIp { get; set; } = true;

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string WithoutVpnSummary { get; set; } = "Замер ещё не сделан — отключите ВПН и нажмите «Снять замер БЕЗ ВПН».";

    [ObservableProperty]
    public partial string WithVpnSummary { get; set; } = "Замер ещё не сделан — включите ВПН и нажмите «Снять замер С ВПН».";

    [ObservableProperty]
    public partial string TelegramPreview { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Все секретные ключи, пароли и ваш домашний IP автоматически скрыты звездочками — отчёт полностью безопасно отправлять в чат.";

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
        StatusText = "Шаг 1: определяем вашего интернет-провайдера и скорость линии без ВПН...";
        try
        {
            _withoutVpn = await SupportNetworkProbe.CaptureAsync(_http, "without_vpn", runSpeedTest: true, ct).ConfigureAwait(true);
            WithoutVpnSummary = FormatSnapshotSummary(_withoutVpn, MaskHomeIp);
            RebuildPreview();
            StatusText = "Шаг 1 готов! Теперь включите ваш ВПН и нажмите кнопку «Шаг 2: Снять замер С ВПН».";
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
        StatusText = "Шаг 2: проверяем выходной сервер ВПН и реальную скорость через туннель...";
        try
        {
            _withVpn = await SupportNetworkProbe.CaptureAsync(_http, "with_vpn", runSpeedTest: true, ct).ConfigureAwait(true);
            WithVpnSummary = FormatSnapshotSummary(_withVpn, maskIp: false);
            RebuildPreview();
            StatusText = "Оба замера готовы! Нажмите «Копировать текст» справа и отправьте сообщение в техподдержку.";
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
        StatusText = "Данные о вашей подписке и проверке сервера обновлены из Шага 1.";
    }

    [RelayCommand]
    private async Task CopyTelegramAsync()
    {
        RebuildPreview();
        var ok = await _ui.CopyTextAsync(TelegramPreview).ConfigureAwait(true);
        StatusText = ok ? "Готовое обращение скопировано! Просто вставьте его (Ctrl+V) в чат поддержки ВПН." : "Буфер обмена недоступен.";
    }

    [RelayCommand]
    private async Task SaveMarkdownAsync()
    {
        var md = SupportTicketBuilder.BuildFullMarkdownReport(BuildDraft());
        var path = await _ui.SaveTextFileAsync("vpn-support-report.md", md, ".md", "Markdown-отчёт").ConfigureAwait(true);
        StatusText = path is not null ? $"Полный отчёт сохранён в файл: {path}" : "Сохранение отменено.";
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
        _configAudit.LastRttResult,
        WindowsNetworkStackAuditor.AuditLiveOsStack());

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
        return $"IP: {ip} · Провайдер: {snap.Isp ?? "—"} {snap.Asn ?? string.Empty} · Скорость ↓ {down} / ↑ {up}";
    }
}
