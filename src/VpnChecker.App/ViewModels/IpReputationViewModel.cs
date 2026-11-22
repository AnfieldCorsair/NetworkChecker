using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VpnChecker.App.Startup;
using VpnChecker.Core.VpnAudit;

namespace VpnChecker.App.ViewModels;

public sealed record GoogleSignalDisplayItem(
    string SignalName,
    string StatusText,
    string Detail,
    IBrush StatusBrush);

public sealed record GeoProviderDisplayItem(
    string ProviderName,
    string Ip,
    string CountryDisplay,
    string AsnOrgDisplay,
    string HostingBadge,
    IBrush HostingBrush,
    string ProxyBadge,
    IBrush ProxyBrush,
    string StatusText);

public sealed partial class SubscriptionIpDisplayItem : ObservableObject
{
    public SubscriptionIpDisplayItem(
        string displayName,
        string protocolAndPort,
        string rawHost,
        string? resolvedIp,
        string hostAndResolvedIp,
        string countryDisplay,
        string asnOrgDisplay,
        string rdapDisplay,
        bool hasRdapInfo,
        IBrush rdapBrush,
        string hostingProxyBadges,
        string googleRuBleedBadge,
        IBrush googleRuBleedBrush,
        string cloud16KbBadge,
        IBrush cloud16KbBrush,
        string summaryNote,
        Func<SubscriptionIpDisplayItem, Task> onProbeLive)
    {
        ArgumentNullException.ThrowIfNull(onProbeLive);

        DisplayName = displayName;
        ProtocolAndPort = protocolAndPort;
        RawHost = rawHost;
        ResolvedIp = resolvedIp;
        HostAndResolvedIp = hostAndResolvedIp;
        CountryDisplay = countryDisplay;
        AsnOrgDisplay = asnOrgDisplay;
        RdapDisplay = rdapDisplay;
        HasRdapInfo = hasRdapInfo;
        RdapBrush = rdapBrush;
        HostingProxyBadges = hostingProxyBadges;
        GoogleRuBleedBadge = googleRuBleedBadge;
        GoogleRuBleedBrush = googleRuBleedBrush;
        Cloud16KbBadge = cloud16KbBadge;
        Cloud16KbBrush = cloud16KbBrush;
        SummaryNote = summaryNote;
        ProbeLiveNodeCommand = new AsyncRelayCommand(() => onProbeLive(this));
    }

    public string DisplayName { get; }

    public string ProtocolAndPort { get; }

    public string RawHost { get; }

    public string? ResolvedIp { get; }

    public string HostAndResolvedIp { get; }

    public string CountryDisplay { get; }

    public string AsnOrgDisplay { get; }

    public string RdapDisplay { get; }

    public bool HasRdapInfo { get; }

    public IBrush RdapBrush { get; }

    public string HostingProxyBadges { get; }

    public string GoogleRuBleedBadge { get; }

    public IBrush GoogleRuBleedBrush { get; }

    public string Cloud16KbBadge { get; }

    public IBrush Cloud16KbBrush { get; }

    public string SummaryNote { get; }

    public IAsyncRelayCommand ProbeLiveNodeCommand { get; }

    [ObservableProperty]
    public partial bool IsLiveVerified { get; set; }

    [ObservableProperty]
    public partial string LiveVerificationText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial IBrush LiveVerificationBrush { get; set; } = SolidColorBrush.Parse("#94A3B8");

    [ObservableProperty]
    public partial string LiveAiBadgesText { get; set; } = string.Empty;

    public void ApplyLiveGoogleVerdict(GoogleGeoVerdict verdict, string exitIp, bool exactIpMatch)
    {
        ArgumentNullException.ThrowIfNull(verdict);

        var scopeLabel = exactIpMatch ? $"IP {exitIp}" : $"подсеть /24 ({exitIp})";
        var aiStudioShort = verdict.AiStudioAccessible switch
        {
            true => "AI Studio: ПУСКАЕТ",
            false => "AI Studio: БЛОК",
            _ => "AI Studio: не подтв.",
        };
        var geminiShort = verdict.GeminiAccessible switch
        {
            true => string.IsNullOrWhiteSpace(verdict.GeminiCountryCode) ? "Gemini: ПУСКАЕТ" : $"Gemini: ПУСКАЕТ ({verdict.GeminiCountryCode})",
            false => string.IsNullOrWhiteSpace(verdict.GeminiCountryCode) ? "Gemini: БЛОК" : $"Gemini: БЛОК ({verdict.GeminiCountryCode})",
            _ => "Gemini: не подтв.",
        };
        var playShort = !string.IsNullOrWhiteSpace(verdict.GooglePlayCurrency)
            ? $"Play: {verdict.GooglePlayCurrency}"
            : "Play: —";

        LiveAiBadgesText = $"{aiStudioShort} · {geminiShort} · {playShort}";

        if (verdict.IsRuGeoPoisoned)
        {
            LiveVerificationText = verdict.AiStudioAccessible == true
                ? $"ЖИВОЙ ТЕСТ ({scopeLabel}): МЕТКА RU ЕСТЬ (но AI Studio пускает)"
                : $"ЖИВОЙ ТЕСТ ({scopeLabel}): МЕТКА RU ПОДТВЕРЖДЕНА";
            LiveVerificationBrush = SolidColorBrush.Parse("#F87171");
        }
        else if (verdict.HasGoogleCaptchaBlock || verdict.AiStudioAccessible == false || verdict.GeminiAccessible == false)
        {
            LiveVerificationText = $"ЖИВОЙ ТЕСТ ({scopeLabel}): Частичные ограничения / капча Google";
            LiveVerificationBrush = SolidColorBrush.Parse("#F59E0B");
        }
        else if (verdict.ProbeSucceeded)
        {
            LiveVerificationText = $"ЖИВОЙ ТЕСТ ({scopeLabel}): ЧИСТЫЙ ({verdict.DetectedGlCode ?? "OK"})";
            LiveVerificationBrush = SolidColorBrush.Parse("#34D399");
        }
        else
        {
            LiveVerificationText = $"ЖИВОЙ ТЕСТ ({scopeLabel}): Нет ответа Google";
            LiveVerificationBrush = SolidColorBrush.Parse("#94A3B8");
        }

        IsLiveVerified = true;
    }
}

/// <summary>
/// Вкладка 5: Репутация IP, консенсус 4 GeoIP-баз, 6-сигнальный живой детектор «прокажённой метки RU» у Google
/// с независимыми бейджами AI Studio / Gemini и пакетный аудит всех IP подписки через RIPE/RDAP WHOIS.
/// </summary>
public sealed partial class IpReputationViewModel : ViewModelBase
{
    private static readonly Uri AiStudioBrowserCheckUri = new("https://aistudio.google.com/prompts/new_chat");

    private readonly HttpClient _http;
    private readonly ConfigAuditViewModel _configAudit;
    private readonly IDesktopUiService _uiService;

    public IpReputationViewModel(
        HttpClient http,
        ConfigAuditViewModel configAudit,
        IDesktopUiService uiService)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(configAudit);
        ArgumentNullException.ThrowIfNull(uiService);

        _http = http;
        _configAudit = configAudit;
        _uiService = uiService;

        RoutingModeOptions =
        [
            "1. Активный интернет / TUN-адаптер (6 сигналов Google: YouTube, Premium, Play, Terms, Gemini, AI Studio)",
            "2. Авто-прокси запущенного клиента ВПН (Happ / v2rayN / Sing-box / NekoBox на 10808/10809/2080/7890)",
            "3. Ручная проверка любого IP или домена сервера (4 GeoIP-базы без переключения ВПН)",
        ];

        ManualTargetInput = configAudit.CurrentReport?.Profile.ServerHost ?? string.Empty;
        LoadInitialPlaceholders();
    }

    public override string Title => "Репутация IP и Google RU";

    public override string Subtitle => "Метка RU, AI Studio и все IP";

    public override string Description =>
        "Консенсус 4 GeoIP-баз, 6-сигнальный живой детектор метки RU у Google (YouTube, Play, Terms, Gemini, AI Studio) и пакетный RIPE/RDAP аудит всех IP подписки.";

    public override string SimpleGuideText =>
        "Слева нажмите «Проверить активный IP и Google RU» — программа проверит 6 независимых сигналов Google (YouTube GL, Premium, валюту Google Play, Terms/Search, Gemini и AI Studio) и покажет отдельно метку RU и доступ к AI Studio. Справа нажмите «Достать и проверить все IP из подписки», чтобы прогнать все серверы через RIPE/RDAP WHOIS и честно оценить риск подсетей.";

    public IReadOnlyList<string> RoutingModeOptions { get; }

    [ObservableProperty]
    public partial int SelectedRoutingModeIndex { get; set; }

    [ObservableProperty]
    public partial string ManualTargetInput { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool IsInspectingActive { get; set; }

    [ObservableProperty]
    public partial bool IsScanningSubscription { get; set; }

    [ObservableProperty]
    public partial string ActiveInspectionStatus { get; set; } =
        "Нажмите «Проверить активный IP и Google RU» для 6-сигнального теста через текущее подключение.";

    [ObservableProperty]
    public partial string DetectedExitIp { get; set; } = "—";

    [ObservableProperty]
    public partial string PhysicalGeoBadge { get; set; } = "Гео: ожидание";

    [ObservableProperty]
    public partial string DetectedAsnBadge { get; set; } = "ASN: ожидание";

    [ObservableProperty]
    public partial string MajorityHostingBadge { get; set; } = "Hosting (Majority Vote): —";

    [ObservableProperty]
    public partial IBrush MajorityHostingBrush { get; set; } = SolidColorBrush.Parse("#9CA9BE");

    [ObservableProperty]
    public partial string AnyProxyBadge { get; set; } = "Proxy / VPN (Any Vote): —";

    [ObservableProperty]
    public partial IBrush AnyProxyBrush { get; set; } = SolidColorBrush.Parse("#9CA9BE");

    [ObservableProperty]
    public partial string IpConsistencyBadge { get; set; } = "Совпадение IP (HTTP vs CDN): —";

    [ObservableProperty]
    public partial IBrush IpConsistencyBrush { get; set; } = SolidColorBrush.Parse("#9CA9BE");

    [ObservableProperty]
    public partial string GoogleVerdictTitle { get; set; } = "Ожидание проверки реакции Google (6 сигналов)";

    [ObservableProperty]
    public partial string GoogleVerdictSummary { get; set; } =
        "Проверяем независимо: метку RU (YouTube GL, Premium, валюта Google Play, Terms/Search) и отдельно фактический доступ к Google AI Studio и Gemini.";

    [ObservableProperty]
    public partial string GoogleVerdictEvidence { get; set; } =
        "Если сервер физически в Нидерландах или Германии, а YouTube/Play/Terms возвращают RU или RUB — подсеть «отравлена» меткой RU, даже если AI Studio ещё пускает.";

    [ObservableProperty]
    public partial string DetectedGlBadge { get; set; } = "YT: — · Play: — · Terms: —";

    [ObservableProperty]
    public partial string AiStudioBadgeText { get; set; } = "Google AI Studio: ожидание";

    [ObservableProperty]
    public partial IBrush AiStudioBadgeBrush { get; set; } = SolidColorBrush.Parse("#94A3B8");

    [ObservableProperty]
    public partial string GeminiBadgeText { get; set; } = "Google Gemini Web: ожидание";

    [ObservableProperty]
    public partial IBrush GeminiBadgeBrush { get; set; } = SolidColorBrush.Parse("#94A3B8");

    [ObservableProperty]
    public partial string AiDivergenceNotice { get; set; } = string.Empty;

    public bool HasAiDivergenceNotice => !string.IsNullOrWhiteSpace(AiDivergenceNotice);

    [ObservableProperty]
    public partial IBrush GoogleVerdictBorderBrush { get; set; } = SolidColorBrush.Parse("#2B3548");

    [ObservableProperty]
    public partial IBrush GoogleVerdictTitleBrush { get; set; } = SolidColorBrush.Parse("#93C5FD");

    [ObservableProperty]
    public partial string SubscriptionIpSummary { get; set; } =
        "Нажмите «Достать и проверить все IP из подписки», чтобы проверить все узлы через DNS + GeoIP + RIPE/RDAP WHOIS с честной 4-уровневой шкалой риска метки RU.";

    [ObservableProperty]
    public partial string CopyFeedback { get; set; } = string.Empty;

    public ObservableCollection<GoogleSignalDisplayItem> GoogleSignalItems { get; } = [];

    public ObservableCollection<GeoProviderDisplayItem> ProviderItems { get; } = [];

    public ObservableCollection<SubscriptionIpDisplayItem> SubscriptionIpItems { get; } = [];

    public IpReputationConsensusReport? LastActiveReport { get; private set; }

    public bool IsManualTargetVisible => ShowTechnicalDetails && SelectedRoutingModeIndex == 2;

    partial void OnAiDivergenceNoticeChanged(string value)
    {
        OnPropertyChanged(nameof(HasAiDivergenceNotice));
    }

    partial void OnSelectedRoutingModeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsManualTargetVisible));
        if (value == 2 && string.IsNullOrWhiteSpace(ManualTargetInput))
        {
            var host = _configAudit.CurrentReport?.Profile.ServerHost;
            if (!string.IsNullOrWhiteSpace(host))
            {
                ManualTargetInput = host;
            }
        }
    }

    protected override void OnPropertyChanged(PropertyChangedEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);
        base.OnPropertyChanged(e);
        if (e.PropertyName == nameof(ShowTechnicalDetails))
        {
            OnPropertyChanged(nameof(IsManualTargetVisible));
        }
    }

    [RelayCommand]
    private async Task OpenAiStudioInBrowserAsync()
    {
        var opened = await _uiService.OpenExternalUrlAsync(AiStudioBrowserCheckUri).ConfigureAwait(true);
        CopyFeedback = opened
            ? "Открыт aistudio.google.com в системном браузере для прямой проверки под вашей сессией."
            : "Не удалось открыть браузер автоматически — откройте https://aistudio.google.com/prompts/new_chat вручную.";
    }

    [RelayCommand]
    private void FillManualFromActiveNode()
    {
        var host = _configAudit.CurrentReport?.Profile.ServerHost;
        if (!string.IsNullOrWhiteSpace(host))
        {
            ManualTargetInput = host;
            SelectedRoutingModeIndex = 2;
            ActiveInspectionStatus = $"В поле ручной проверки подставлен адрес выбранного узла: {host}";
        }
        else
        {
            ActiveInspectionStatus = "На вкладке 1 ещё не загружен конфиг или подписка.";
        }
    }

    [RelayCommand]
    private async Task RunActiveInspectionAsync()
    {
        if (IsInspectingActive)
        {
            return;
        }

        IsInspectingActive = true;
        CopyFeedback = string.Empty;

        try
        {
            var mode = SelectedRoutingModeIndex switch
            {
                1 => IpReputationRoutingMode.AutoLocalVpnProxy,
                2 => IpReputationRoutingMode.ManualTargetIp,
                _ => IpReputationRoutingMode.DirectOrActiveTun,
            };

            ActiveInspectionStatus = mode switch
            {
                IpReputationRoutingMode.AutoLocalVpnProxy => "Ищем локальный порт ВПН-клиента (10809/10808/2080/7890) и опрашиваем 4 GeoIP-базы + 6 сигналов Google...",
                IpReputationRoutingMode.ManualTargetIp => $"Разрешаем '{ManualTargetInput}' и опрашиваем 4 GeoIP-базы по его репутации...",
                _ => "Опрашиваем 4 GeoIP-базы и 6 независимых сигналов Google (YouTube GL, Premium, Play, Terms, Gemini, AI Studio)...",
            };

            var report = await IpReputationProbe.RunActiveOrManualInspectionAsync(
                _http,
                mode,
                ManualTargetInput,
                CancellationToken.None).ConfigureAwait(true);

            LastActiveReport = report;
            ApplyConsensusReport(report);
            ApplyLiveReportToMatchingSubscriptionNodes(report, requestedNode: null);
        }
        catch (Exception ex) when (ex is ArgumentException or HttpRequestException or OperationCanceledException or SocketException)
        {
            ActiveInspectionStatus = $"Ошибка при проверке репутации IP: {ex.Message}";
        }
        finally
        {
            IsInspectingActive = false;
        }
    }

    private async Task ProbeSubscriptionNodeLiveAsync(SubscriptionIpDisplayItem node)
    {
        if (IsInspectingActive)
        {
            return;
        }

        IsInspectingActive = true;
        CopyFeedback = string.Empty;

        try
        {
            // Всегда проверяем через живой канал (если выбран режим «Ручной IP», временно используем активный TUN)
            var mode = SelectedRoutingModeIndex == 1
                ? IpReputationRoutingMode.AutoLocalVpnProxy
                : IpReputationRoutingMode.DirectOrActiveTun;

            ActiveInspectionStatus = $"Живой 6-сигнальный прогон Google для «{node.DisplayName}» ({node.ResolvedIp ?? node.RawHost})...";

            var report = await IpReputationProbe.RunActiveOrManualInspectionAsync(
                _http,
                mode,
                manualIpOrHost: null,
                CancellationToken.None).ConfigureAwait(true);

            LastActiveReport = report;
            ApplyConsensusReport(report);
            ApplyLiveReportToMatchingSubscriptionNodes(report, requestedNode: node);
        }
        catch (Exception ex) when (ex is ArgumentException or HttpRequestException or OperationCanceledException or SocketException)
        {
            ActiveInspectionStatus = $"Ошибка живого прогона узла: {ex.Message}";
        }
        finally
        {
            IsInspectingActive = false;
        }
    }

    private void ApplyLiveReportToMatchingSubscriptionNodes(
        IpReputationConsensusReport report,
        SubscriptionIpDisplayItem? requestedNode)
    {
        if (!report.GoogleVerdict.ProbeExecuted || string.IsNullOrWhiteSpace(report.ConsensusIp))
        {
            return;
        }

        var exitIp = report.ConsensusIp.Trim();
        var matchedRequested = false;
        var matchedAny = 0;

        foreach (var item in SubscriptionIpItems)
        {
            if (string.IsNullOrWhiteSpace(item.ResolvedIp))
            {
                continue;
            }

            var (isMatch, exactMatch) = MatchIpOrSlash24(exitIp, item.ResolvedIp);
            if (!isMatch)
            {
                continue;
            }

            item.ApplyLiveGoogleVerdict(report.GoogleVerdict, exitIp, exactMatch);
            matchedAny++;
            if (ReferenceEquals(item, requestedNode))
            {
                matchedRequested = true;
            }
        }

        if (requestedNode is not null && !matchedRequested)
        {
            var expectedIp = requestedNode.ResolvedIp ?? requestedNode.RawHost;
            ActiveInspectionStatus =
                $"Текущий выходной IP ({exitIp}) не совпадает с «{requestedNode.DisplayName}» ({expectedIp}). Переключитесь на этот сервер в Happ/v2rayN и нажмите «Проверить вживую» ещё раз.";
        }
        else if (matchedAny > 0)
        {
            ActiveInspectionStatus =
                $"{ActiveInspectionStatus} · Живой вердикт Google привязан к узлам подписки: {matchedAny}";
        }
    }

    private static (bool IsMatch, bool ExactMatch) MatchIpOrSlash24(string ipA, string ipB)
    {
        var a = ipA.Trim();
        var b = ipB.Trim();
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
        {
            return (true, true);
        }

        var partsA = a.Split('.');
        var partsB = b.Split('.');
        if (partsA.Length == 4 && partsB.Length == 4 &&
            string.Equals(partsA[0], partsB[0], StringComparison.Ordinal) &&
            string.Equals(partsA[1], partsB[1], StringComparison.Ordinal) &&
            string.Equals(partsA[2], partsB[2], StringComparison.Ordinal))
        {
            return (true, false);
        }

        return (false, false);
    }

    [RelayCommand]
    private async Task ScanSubscriptionIpsAsync()
    {
        if (IsScanningSubscription)
        {
            return;
        }

        var raw = _configAudit.RawConfig;
        if (string.IsNullOrWhiteSpace(raw))
        {
            SubscriptionIpSummary = "На вкладке 1 пусто: сначала загрузите подписку по ссылке или вставьте конфиг ВПН.";
            return;
        }

        IsScanningSubscription = true;
        CopyFeedback = string.Empty;

        try
        {
            var endpoints = IpReputationProbe.ExtractAllEndpointsFromConfig(raw);
            if (endpoints.Count == 0)
            {
                SubscriptionIpSummary = "Не удалось извлечь ни одного узла из текста на вкладке 1. Проверьте корректность ссылки или конфига.";
                return;
            }

            SubscriptionIpSummary = $"Найдено узлов: {endpoints.Count}. Выполняем DNS-резолв, пакетный GeoIP и проверку владельца подсетей в RIPE/RDAP WHOIS...";

            var rows = await IpReputationProbe.ScanSubscriptionIpsAsync(_http, raw, CancellationToken.None).ConfigureAwait(true);
            SubscriptionIpItems.Clear();

            var criticalOrHighCount = 0;
            var mediumDcCount = 0;
            var cleanIspCount = 0;
            var cloud16KbCount = 0;

            foreach (var row in rows)
            {
                switch (row.RiskTier)
                {
                    case RuBleedRiskTier.CriticalRu:
                    case RuBleedRiskTier.HighRisk:
                        criticalOrHighCount++;
                        break;
                    case RuBleedRiskTier.MediumDatacenterUnverified:
                        mediumDcCount++;
                        break;
                    case RuBleedRiskTier.LowCleanIsp:
                        cleanIspCount++;
                        break;
                }

                if (row.High16KbRisk)
                {
                    cloud16KbCount++;
                }

                var resolvedText = string.IsNullOrWhiteSpace(row.ResolvedIp) ? "Не разрешён" : row.ResolvedIp;
                var hostAndIp = string.Equals(row.RawHost, resolvedText, StringComparison.OrdinalIgnoreCase)
                    ? resolvedText
                    : $"{row.RawHost} → {resolvedText}";

                var hostingProxy = $"Hosting: {(row.IsHosting ? "ДА" : "НЕТ")} · Proxy/VPN: {(row.IsProxyOrVpn ? "ДА" : "НЕТ")}";
                var (ruBadge, ruBrush) = FormatRiskTierBadge(row.RiskTier);

                var cloudBadge = row.High16KbRisk
                    ? "ТСПУ 16 КБ: Риск облака"
                    : "ТСПУ 16 КБ: Норма";
                var cloudBrush = row.High16KbRisk
                    ? SolidColorBrush.Parse("#F59E0B")
                    : SolidColorBrush.Parse("#10B981");

                var countryLabel = string.IsNullOrWhiteSpace(row.CountryCode)
                    ? (row.CountryName ?? "—")
                    : $"{row.CountryCode} ({row.CountryName ?? row.CountryCode})";

                var asnOrgLabel = string.IsNullOrWhiteSpace(row.Asn) || row.Asn == "—"
                    ? (row.Isp ?? "—")
                    : $"{row.Asn} · {row.Isp}";

                var hasRdap = !string.IsNullOrWhiteSpace(row.RdapCountry) || !string.IsNullOrWhiteSpace(row.RdapOrgOrNetName);
                var rdapText = hasRdap
                    ? $"RIPE/RDAP: {row.RdapCountry ?? "—"} · {row.RdapOrgOrNetName ?? "—"}{(row.HasRuRdapFootprint ? " [РФ-СЛЕД!]" : string.Empty)}"
                    : string.Empty;
                var rdapBrush = row.HasRuRdapFootprint
                    ? SolidColorBrush.Parse("#F87171")
                    : SolidColorBrush.Parse("#94A3B8");

                SubscriptionIpItems.Add(new SubscriptionIpDisplayItem(
                    row.NodeName,
                    $"{row.ProtocolLabel} · :{row.Port}",
                    row.RawHost,
                    row.ResolvedIp,
                    hostAndIp,
                    countryLabel,
                    asnOrgLabel,
                    rdapText,
                    hasRdap,
                    rdapBrush,
                    hostingProxy,
                    ruBadge,
                    ruBrush,
                    cloudBadge,
                    cloudBrush,
                    $"{row.CleanlinessVerdict} — {row.TechnicalNotes}",
                    ProbeSubscriptionNodeLiveAsync));
            }

            if (LastActiveReport is not null)
            {
                ApplyLiveReportToMatchingSubscriptionNodes(LastActiveReport, requestedNode: null);
            }

            var uniqueIps = rows
                .Select(r => r.ResolvedIp)
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            SubscriptionIpSummary =
                $"Узлов: {rows.Count} (уник. IP: {uniqueIps}) · Критичный/Высокий риск RU: {criticalOrHighCount} · Дата-центры (нужен живой тест): {mediumDcCount} · Чистый ISP: {cleanIspCount} · Облака 16 КБ: {cloud16KbCount}";
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or SocketException)
        {
            SubscriptionIpSummary = $"Ошибка при пакетной проверке IP подписки: {ex.Message}";
        }
        finally
        {
            IsScanningSubscription = false;
        }
    }

    private static (string Badge, IBrush Brush) FormatRiskTierBadge(RuBleedRiskTier tier)
    {
        return tier switch
        {
            RuBleedRiskTier.CriticalRu => ("Риск метки RU: КРИТИЧНЫЙ (RIPE/РФ)", SolidColorBrush.Parse("#F87171")),
            RuBleedRiskTier.HighRisk => ("Риск метки RU: ВЫСОКИЙ (ASN/Proxy)", SolidColorBrush.Parse("#F59E0B")),
            RuBleedRiskTier.MediumDatacenterUnverified => ("Риск метки RU: СРЕДНИЙ · ДЦ (нужен живой тест)", SolidColorBrush.Parse("#FBBF24")),
            _ => ("Риск метки RU: Низкий (чистый ISP)", SolidColorBrush.Parse("#4ADE80")),
        };
    }

    [RelayCommand]
    private async Task CopyReputationReportAsync()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== VPN_Checker — ОТЧЁТ О РЕПУТАЦИИ IP, МЕТКЕ GOOGLE RU И AI STUDIO ===");

        if (LastActiveReport is not null)
        {
            var g = LastActiveReport.GoogleVerdict;
            sb.AppendLine(CultureInfo.InvariantCulture, $"Канал проверки: {g.RoutingChannelUsed}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Внешний IP: {LastActiveReport.ConsensusIp ?? "—"}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Физическое гео (консенсус): {LastActiveReport.ConsensusCountryCode ?? "—"} ({LastActiveReport.ConsensusCountryName ?? "—"})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Провайдер / ASN: {LastActiveReport.ConsensusAsn ?? "—"} · {LastActiveReport.ConsensusIsp ?? "—"}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Hosting / ДЦ (Majority Vote): {(LastActiveReport.MajorityHosting ? "ДА" : "НЕТ")} ({LastActiveReport.HostingPositiveCount}/{LastActiveReport.HostingKnownCount})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Proxy / VPN / Tor (Any Vote): {(LastActiveReport.AnyProxyOrVpn ? "ДА" : "НЕТ")} ({LastActiveReport.ProxyPositiveCount}/{LastActiveReport.ProxyKnownCount})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Совпадение IP (HTTP vs CDN): {(LastActiveReport.IpConsistencyOk ? "Совпадает" : "Расхождение IP!")}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Вердикт по метке RU: {g.VerdictTitle}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Независимые бейджи ИИ: {AiStudioBadgeText} | {GeminiBadgeText}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"YouTube GL: {g.YouTubeCountryCode ?? "—"} · Google Play: {g.GooglePlayCountry ?? "—"} ({g.GooglePlayCurrency ?? "—"}) · Terms/Search: {g.GoogleTermsCountry ?? g.GoogleSearchRegion ?? "—"}");
            if (g.SignalChecks is { Count: > 0 } signals)
            {
                foreach (var sig in signals)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"  - {sig.SignalName}: {sig.StatusText} ({sig.Detail})");
                }
            }
            if (!string.IsNullOrWhiteSpace(AiDivergenceNotice))
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"Расхождение AI Studio / RU: {AiDivergenceNotice}");
            }
            sb.AppendLine(CultureInfo.InvariantCulture, $"Пояснение: {g.VerdictSummary}");
        }

        if (SubscriptionIpItems.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"--- ВСЕ IP ИЗ ПОДПИСКИ ({SubscriptionIpItems.Count} узлов, RIPE/RDAP + GeoIP) ---");
            foreach (var item in SubscriptionIpItems)
            {
                var rdapPart = item.HasRdapInfo ? $" | {item.RdapDisplay}" : string.Empty;
                var livePart = item.IsLiveVerified ? $" | {item.LiveVerificationText} ({item.LiveAiBadgesText})" : string.Empty;
                sb.AppendLine(CultureInfo.InvariantCulture, $"• {item.DisplayName} [{item.ProtocolAndPort}] — {item.HostAndResolvedIp} | {item.CountryDisplay} | {item.AsnOrgDisplay}{rdapPart} | {item.GoogleRuBleedBadge}{livePart}");
            }
        }

        var ok = await _uiService.CopyTextAsync(sb.ToString().Trim()).ConfigureAwait(true);
        CopyFeedback = ok
            ? "Сводка по репутации IP, 6 сигналам Google и RIPE/RDAP скопирована в буфер обмена."
            : "Буфер обмена недоступен.";
    }

    private void ApplyConsensusReport(IpReputationConsensusReport report)
    {
        var okCount = report.Providers.Count(p => p.Ok);
        var g = report.GoogleVerdict;

        ActiveInspectionStatus = $"{g.RoutingChannelUsed} · Ответило GeoIP-баз: {okCount} из {report.Providers.Count}";
        DetectedExitIp = report.ConsensusIp ?? "Не определён";
        PhysicalGeoBadge = $"Физическое гео: {report.ConsensusCountryCode ?? "—"} ({report.ConsensusCountryName ?? "—"})";
        DetectedAsnBadge = string.IsNullOrWhiteSpace(report.ConsensusAsn)
            ? $"Провайдер: {report.ConsensusIsp ?? "—"}"
            : $"{report.ConsensusAsn} · {report.ConsensusIsp ?? "—"}";

        MajorityHostingBadge = $"Hosting / ДЦ (Majority >=50%): {(report.MajorityHosting ? "ДА" : "НЕТ")} ({report.HostingPositiveCount}/{report.HostingKnownCount})";
        MajorityHostingBrush = report.MajorityHosting
            ? SolidColorBrush.Parse("#F59E0B")
            : SolidColorBrush.Parse("#10B981");

        AnyProxyBadge = $"Proxy / VPN (Any Vote): {(report.AnyProxyOrVpn ? "ДА" : "НЕТ")} ({report.ProxyPositiveCount}/{report.ProxyKnownCount})";
        AnyProxyBrush = report.AnyProxyOrVpn
            ? SolidColorBrush.Parse("#F59E0B")
            : SolidColorBrush.Parse("#10B981");

        IpConsistencyBadge = report.IpConsistencyOk
            ? "HTTP vs CDN IP: Единый выходной IP"
            : "HTTP vs CDN IP: Разные IP (прокси-сплит)";
        IpConsistencyBrush = report.IpConsistencyOk
            ? SolidColorBrush.Parse("#10B981")
            : SolidColorBrush.Parse("#F59E0B");

        GoogleVerdictTitle = g.VerdictTitle;
        GoogleVerdictSummary = g.VerdictSummary;
        GoogleVerdictEvidence = g.TechnicalEvidence;

        var playShort = !string.IsNullOrWhiteSpace(g.GooglePlayCurrency)
            ? g.GooglePlayCurrency
            : (g.GooglePlayCountry ?? "—");
        var termsShort = g.GoogleTermsCountry ?? g.GoogleSearchRegion ?? "—";
        DetectedGlBadge = $"YT: {g.YouTubeCountryCode ?? "—"} · Play: {playShort} · Terms: {termsShort}";

        (AiStudioBadgeText, AiStudioBadgeBrush) = g.AiStudioAccessible switch
        {
            true => ("Google AI Studio: ПУСКАЕТ", SolidColorBrush.Parse("#34D399")),
            false => ("Google AI Studio: ЗАБЛОКИРОВАН", SolidColorBrush.Parse("#F87171")),
            _ => g.ProbeExecuted
                ? ("Google AI Studio: НЕ ПОДТВЕРЖДЕНО", SolidColorBrush.Parse("#FBBF24"))
                : ("Google AI Studio: не проверялся", SolidColorBrush.Parse("#94A3B8")),
        };

        var gemRegionSuffix = string.IsNullOrWhiteSpace(g.GeminiCountryCode)
            ? string.Empty
            : $" ({g.GeminiCountryCode})";
        (GeminiBadgeText, GeminiBadgeBrush) = g.GeminiAccessible switch
        {
            true => ($"Google Gemini Web: ПУСКАЕТ{gemRegionSuffix}", SolidColorBrush.Parse("#34D399")),
            false => ($"Google Gemini Web: ЗАБЛОКИРОВАН{gemRegionSuffix}", SolidColorBrush.Parse("#F87171")),
            _ => g.ProbeExecuted
                ? ("Google Gemini Web: НЕ ПОДТВЕРЖДЕНО", SolidColorBrush.Parse("#FBBF24"))
                : ("Google Gemini Web: не проверялся", SolidColorBrush.Parse("#94A3B8")),
        };

        if (g.AiAccessDivergesFromRuTag)
        {
            AiDivergenceNotice = g.AiStudioAccessible == true && g.GeminiAccessible != true
                ? "На подсети есть метка RU (YouTube/Play/Terms), но Google AI Studio сейчас пускает этот IP. У Google разные гео-таблицы для YouTube/Search и контура AI Studio — поэтому AI Studio может работать на части «отравленных» серверов, а Gemini/YouTube — нет."
                : "На подсети обнаружена метка RU (YouTube/Play/Terms), но живой контур Google AI (Gemini / AI Studio) сейчас пропускает этот IP благодаря отдельной гео-базе Google Cloud.";
        }
        else
        {
            AiDivergenceNotice = string.Empty;
        }

        GoogleSignalItems.Clear();
        if (g.SignalChecks is { Count: > 0 } signals)
        {
            foreach (var sig in signals)
            {
                var brush = sig.IsAlert
                    ? SolidColorBrush.Parse("#F87171")
                    : (sig.IsPass
                        ? SolidColorBrush.Parse("#34D399")
                        : (sig.StatusText.Contains("Не подтверждено", StringComparison.OrdinalIgnoreCase)
                            ? SolidColorBrush.Parse("#FBBF24")
                            : SolidColorBrush.Parse("#94A3B8")));
                GoogleSignalItems.Add(new GoogleSignalDisplayItem(sig.SignalName, sig.StatusText, sig.Detail, brush));
            }
        }

        if (g.IsRuGeoPoisoned)
        {
            GoogleVerdictBorderBrush = SolidColorBrush.Parse("#EF4444");
            GoogleVerdictTitleBrush = SolidColorBrush.Parse("#FCA5A5");
        }
        else if (g.HasGoogleCaptchaBlock ||
                 g.YouTubePremiumAvailable == false ||
                 g.GeminiAccessible == false ||
                 g.AiStudioAccessible == false)
        {
            GoogleVerdictBorderBrush = SolidColorBrush.Parse("#F59E0B");
            GoogleVerdictTitleBrush = SolidColorBrush.Parse("#FCD34D");
        }
        else if (g.ProbeSucceeded &&
                 !string.Equals(g.DetectedGlCode, "RU", StringComparison.OrdinalIgnoreCase))
        {
            GoogleVerdictBorderBrush = SolidColorBrush.Parse("#10B981");
            GoogleVerdictTitleBrush = SolidColorBrush.Parse("#6EE7B7");
        }
        else
        {
            GoogleVerdictBorderBrush = SolidColorBrush.Parse("#3B82F6");
            GoogleVerdictTitleBrush = SolidColorBrush.Parse("#93C5FD");
        }

        ProviderItems.Clear();
        foreach (var p in report.Providers)
        {
            var hostingBadge = !p.Ok || !p.IsHosting.HasValue
                ? "Hosting: —"
                : (p.IsHosting.Value ? "Hosting: ДА" : "Hosting: НЕТ");
            var hostingBrush = !p.Ok || !p.IsHosting.HasValue
                ? SolidColorBrush.Parse("#6B7894")
                : (p.IsHosting.Value ? SolidColorBrush.Parse("#F59E0B") : SolidColorBrush.Parse("#10B981"));

            var proxyBadge = !p.Ok || !p.IsProxyOrVpn.HasValue
                ? "Proxy/VPN: —"
                : (p.IsProxyOrVpn.Value ? "Proxy/VPN: ДА" : "Proxy/VPN: НЕТ");
            var proxyBrush = !p.Ok || !p.IsProxyOrVpn.HasValue
                ? SolidColorBrush.Parse("#6B7894")
                : (p.IsProxyOrVpn.Value ? SolidColorBrush.Parse("#F59E0B") : SolidColorBrush.Parse("#10B981"));

            var country = p.Ok
                ? (string.IsNullOrWhiteSpace(p.CountryName) ? (p.CountryCode ?? "—") : $"{p.CountryCode} · {p.CountryName}")
                : "Нет ответа";

            var asnOrg = p.Ok
                ? (string.IsNullOrWhiteSpace(p.Asn) ? (p.Isp ?? "—") : $"{p.Asn} · {p.Isp}")
                : (p.Error ?? "Таймаут");

            var status = p.Ok ? $"{p.ElapsedMs} мс" : "Ошибка";

            ProviderItems.Add(new GeoProviderDisplayItem(
                p.ProviderName,
                string.IsNullOrWhiteSpace(p.Ip) ? "—" : p.Ip,
                country,
                asnOrg,
                hostingBadge,
                hostingBrush,
                proxyBadge,
                proxyBrush,
                status));
        }
    }

    private void LoadInitialPlaceholders()
    {
        GoogleSignalItems.Clear();
        var muted = SolidColorBrush.Parse("#6B7894");
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("1. YouTube INNERTUBE_CONTEXT_GL", "Ожидание", "Реальный код страны YouTube с обходом EU-согласия", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("2. YouTube Premium", "Ожидание", "Проверка «недоступна в вашей стране» (признак метки RU)", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("3. Google Play (регион и валюта)", "Ожидание", "Проверка валюты (RUB vs EUR/USD) и доступности платных приложений", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("4. Google Terms / Search и /sorry/", "Ожидание", "Юрисдикция policies.google.com/terms, футер Search и капча 429", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("5. Google Gemini Web", "Ожидание", "Живой серверный маркер региона в HTML gemini.google.com (,2,1,200)", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("6. Google AI Studio", "Ожидание", "Проверка явных гео-блокировок aistudio.google.com (при редиректе на вход — статус «Не подтверждено»)", muted));

        ProviderItems.Clear();
        ProviderItems.Add(new GeoProviderDisplayItem("ipwho.is", "—", "Ожидание запуска", "Проверка ASN, ISP, флагов Hosting / Proxy / Tor", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
        ProviderItems.Add(new GeoProviderDisplayItem("ip-api.com", "—", "Ожидание запуска", "Проверка географии, провайдера и флагов hosting/proxy", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
        ProviderItems.Add(new GeoProviderDisplayItem("ipinfo.io", "—", "Ожидание запуска", "Проверка организации, ASN и принадлежности к облаку", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
        ProviderItems.Add(new GeoProviderDisplayItem("Cloudflare Trace", "—", "Ожидание запуска", "Сверка видимого IP и страны глазами CDN Cloudflare", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
    }
}
