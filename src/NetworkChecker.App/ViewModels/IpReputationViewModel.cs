using System.Collections.ObjectModel;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkChecker.App.Startup;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.ViewModels;

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

public sealed record SubscriptionIpDisplayItem(
    string DisplayName,
    string ProtocolAndPort,
    string HostAndResolvedIp,
    string CountryDisplay,
    string AsnOrgDisplay,
    string HostingProxyBadges,
    string GoogleRuBleedBadge,
    IBrush GoogleRuBleedBrush,
    string Cloud16KbBadge,
    IBrush Cloud16KbBrush,
    string SummaryNote);

/// <summary>
/// Вкладка 5: Репутация IP, консенсус 4 GeoIP-баз, детектор «прокажённой метки RU» у Google и пакетный сканер всех IP подписки.
/// </summary>
public sealed partial class IpReputationViewModel : ViewModelBase
{
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
            "1. Активный интернет / TUN-адаптер (проверка текущего выхода ОС и живой реакции Google/YouTube)",
            "2. Авто-прокси запущенного клиента ВПН (Happ / v2rayN / Sing-box / NekoBox на 10808/10809/2080/7890)",
            "3. Ручная проверка любого IP или домена сервера (4 GeoIP-базы без переключения ВПН)",
        ];

        ManualTargetInput = configAudit.CurrentReport?.Profile.ServerHost ?? string.Empty;
        LoadInitialPlaceholders();
    }

    public override string Title => "Репутация IP и Google RU";

    public override string Subtitle => "Метка RU у Google и все IP подписки";

    public override string Description =>
        "Консенсус 4 независимых GeoIP-баз, живой зонд «прокажённой метки RU» у Google / YouTube и пакетный аудит всех IP-адресов подписки.";

    public override string SimpleGuideText =>
        "Слева нажмите «Проверить активный IP и реакцию Google» — программа опросит 4 независимые GeoIP-базы (ipwho.is, ip-api.com, ipinfo.io, Cloudflare) и выполнит прямой запрос к YouTube/Google, чтобы проверить, не выдал ли Google вашему зарубежному серверу «прокажённую метку RU». Справа нажмите «Достать и проверить все IP из подписки», чтобы разом просканировать все серверы вашей подписки.";

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
        "Выберите режим маршрутизации и нажмите «Проверить активный IP и реакцию Google».";

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
    public partial string GoogleVerdictTitle { get; set; } = "Ожидание проверки реакции Google / YouTube";

    [ObservableProperty]
    public partial string GoogleVerdictSummary { get; set; } =
        "При проверке через активный интернет или локальный прокси ВПН программа извлекает код страны INNERTUBE_CONTEXT_GL напрямую из ответа YouTube и Google.";

    [ObservableProperty]
    public partial string GoogleVerdictEvidence { get; set; } =
        "Если физически сервер в Нидерландах или Германии, а Google возвращает GL=RU — значит подсеть «отравлена» российским гео-таргетингом.";

    [ObservableProperty]
    public partial string DetectedGlBadge { get; set; } = "YouTube GL: — · Google GL: —";

    [ObservableProperty]
    public partial IBrush GoogleVerdictBorderBrush { get; set; } = SolidColorBrush.Parse("#2B3548");

    [ObservableProperty]
    public partial IBrush GoogleVerdictTitleBrush { get; set; } = SolidColorBrush.Parse("#93C5FD");

    [ObservableProperty]
    public partial string SubscriptionIpSummary { get; set; } =
        "Нажмите «Достать и проверить все IP из подписки», чтобы извлечь все узлы из вкладки 1, разрешить домены в IP и проверить их репутацию.";

    [ObservableProperty]
    public partial string CopyFeedback { get; set; } = string.Empty;

    public ObservableCollection<GoogleSignalDisplayItem> GoogleSignalItems { get; } = [];

    public ObservableCollection<GeoProviderDisplayItem> ProviderItems { get; } = [];

    public ObservableCollection<SubscriptionIpDisplayItem> SubscriptionIpItems { get; } = [];

    public IpReputationConsensusReport? LastActiveReport { get; private set; }

    public bool IsManualTargetVisible => ShowTechnicalDetails && SelectedRoutingModeIndex == 2;

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

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);
        base.OnPropertyChanged(e);
        if (e.PropertyName == nameof(ShowTechnicalDetails))
        {
            OnPropertyChanged(nameof(IsManualTargetVisible));
        }
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
                IpReputationRoutingMode.AutoLocalVpnProxy => "Ищем локальный порт ВПН-клиента (10809/10808/2080/7890) и опрашиваем 4 GeoIP-базы + Google/YouTube...",
                IpReputationRoutingMode.ManualTargetIp => $"Разрешаем '{ManualTargetInput}' и опрашиваем 4 GeoIP-базы по его репутации...",
                _ => "Опрашиваем 4 GeoIP-базы (ipwho.is, ip-api, ipinfo, Cloudflare) и проверяем метку GL у Google/YouTube...",
            };

            var report = await IpReputationProbe.RunActiveOrManualInspectionAsync(
                _http,
                mode,
                ManualTargetInput,
                CancellationToken.None).ConfigureAwait(true);

            LastActiveReport = report;
            ApplyConsensusReport(report);
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

            SubscriptionIpSummary = $"Найдено узлов в подписке: {endpoints.Count}. Выполняем DNS-резолв доменов в реальные IP и пакетную проверку GeoIP / ASN...";

            var rows = await IpReputationProbe.ScanSubscriptionIpsAsync(_http, raw, CancellationToken.None).ConfigureAwait(true);
            SubscriptionIpItems.Clear();

            var ruRiskCount = 0;
            var cloud16KbCount = 0;
            var hostingCount = 0;

            foreach (var row in rows)
            {
                if (row.HighRuGoogleBleedRisk)
                {
                    ruRiskCount++;
                }

                if (row.High16KbRisk)
                {
                    cloud16KbCount++;
                }

                if (row.IsHosting)
                {
                    hostingCount++;
                }

                var resolvedText = string.IsNullOrWhiteSpace(row.ResolvedIp) ? "Не разрешён" : row.ResolvedIp;
                var hostAndIp = string.Equals(row.RawHost, resolvedText, StringComparison.OrdinalIgnoreCase)
                    ? resolvedText
                    : $"{row.RawHost} → {resolvedText}";

                var hostingProxy = $"Hosting: {(row.IsHosting ? "ДА" : "НЕТ")} · Proxy/VPN: {(row.IsProxyOrVpn ? "ДА" : "НЕТ")}";
                var ruBadge = row.HighRuGoogleBleedRisk
                    ? "Риск метки RU у Google: ВЫСОКИЙ"
                    : "Риск метки RU: Низкий";
                var ruBrush = row.HighRuGoogleBleedRisk
                    ? SolidColorBrush.Parse("#F59E0B")
                    : SolidColorBrush.Parse("#10B981");

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

                SubscriptionIpItems.Add(new SubscriptionIpDisplayItem(
                    row.NodeName,
                    $"{row.ProtocolLabel} · :{row.Port}",
                    hostAndIp,
                    countryLabel,
                    asnOrgLabel,
                    hostingProxy,
                    ruBadge,
                    ruBrush,
                    cloudBadge,
                    cloudBrush,
                    $"{row.CleanlinessVerdict} — {row.TechnicalNotes}"));
            }

            var uniqueIps = rows
                .Select(r => r.ResolvedIp)
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            SubscriptionIpSummary =
                $"Проверено узлов: {rows.Count} (уникальных IP: {uniqueIps}) · Дата-центры (Hosting): {hostingCount} · Высокий риск метки RU у Google: {ruRiskCount} · Популярные у ТСПУ 16 КБ облака: {cloud16KbCount}";
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

    [RelayCommand]
    private async Task CopyReputationReportAsync()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== КОНТУР ВПН (NetworkChecker V2) — ОТЧЁТ О РЕПУТАЦИИ IP И МЕТКЕ GOOGLE RU ===");

        if (LastActiveReport is not null)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"Канал проверки: {LastActiveReport.GoogleVerdict.RoutingChannelUsed}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Внешний IP: {LastActiveReport.ConsensusIp ?? "—"}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Физическое гео (консенсус): {LastActiveReport.ConsensusCountryCode ?? "—"} ({LastActiveReport.ConsensusCountryName ?? "—"})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Провайдер / ASN: {LastActiveReport.ConsensusAsn ?? "—"} · {LastActiveReport.ConsensusIsp ?? "—"}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Hosting / ДЦ (Majority Vote): {(LastActiveReport.MajorityHosting ? "ДА" : "НЕТ")} ({LastActiveReport.HostingPositiveCount}/{LastActiveReport.HostingKnownCount})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Proxy / VPN / Tor (Any Vote): {(LastActiveReport.AnyProxyOrVpn ? "ДА" : "НЕТ")} ({LastActiveReport.ProxyPositiveCount}/{LastActiveReport.ProxyKnownCount})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Совпадение IP (HTTP vs CDN): {(LastActiveReport.IpConsistencyOk ? "Совпадает" : "Расхождение IP!")}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Вердикт Google / YouTube: {LastActiveReport.GoogleVerdict.VerdictTitle}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"YouTube GL: {LastActiveReport.GoogleVerdict.YouTubeCountryCode ?? "—"} · Google GL: {LastActiveReport.GoogleVerdict.GoogleSearchRegion ?? "—"}");
            if (LastActiveReport.GoogleVerdict.SignalChecks is { Count: > 0 } signals)
            {
                foreach (var sig in signals)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"  - {sig.SignalName}: {sig.StatusText} ({sig.Detail})");
                }
            }
            sb.AppendLine(CultureInfo.InvariantCulture, $"Пояснение: {LastActiveReport.GoogleVerdict.VerdictSummary}");
        }

        if (SubscriptionIpItems.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"--- ВСЕ IP ИЗ ПОДПИСКИ ({SubscriptionIpItems.Count} узлов) ---");
            foreach (var item in SubscriptionIpItems)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"• {item.DisplayName} [{item.ProtocolAndPort}] — {item.HostAndResolvedIp} | {item.CountryDisplay} | {item.AsnOrgDisplay} | {item.GoogleRuBleedBadge}");
            }
        }

        var ok = await _uiService.CopyTextAsync(sb.ToString().Trim()).ConfigureAwait(true);
        CopyFeedback = ok
            ? "Сводка по репутации IP и метке Google RU скопирована в буфер обмена."
            : "Буфер обмена недоступен.";
    }

    private void ApplyConsensusReport(IpReputationConsensusReport report)
    {
        var okCount = report.Providers.Count(p => p.Ok);
        ActiveInspectionStatus = $"{report.GoogleVerdict.RoutingChannelUsed} · Ответило GeoIP-баз: {okCount} из {report.Providers.Count}";
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

        GoogleVerdictTitle = report.GoogleVerdict.VerdictTitle;
        GoogleVerdictSummary = report.GoogleVerdict.VerdictSummary;
        GoogleVerdictEvidence = report.GoogleVerdict.TechnicalEvidence;
        var ytPremShort = report.GoogleVerdict.YouTubePremiumAvailable switch
        {
            true => "Да",
            false => "Нет",
            _ => "—",
        };
        var geminiShort = report.GoogleVerdict.GeminiAccessible switch
        {
            true => "Да",
            false => "Нет",
            _ => "—",
        };
        DetectedGlBadge = $"YT GL: {report.GoogleVerdict.YouTubeCountryCode ?? "—"} · Premium: {ytPremShort} · Gemini: {geminiShort} · Search: {report.GoogleVerdict.GoogleSearchRegion ?? "—"}";

        GoogleSignalItems.Clear();
        if (report.GoogleVerdict.SignalChecks is { Count: > 0 } signals)
        {
            foreach (var sig in signals)
            {
                var brush = sig.IsAlert
                    ? SolidColorBrush.Parse("#F87171")
                    : (sig.IsPass ? SolidColorBrush.Parse("#34D399") : SolidColorBrush.Parse("#94A3B8"));
                GoogleSignalItems.Add(new GoogleSignalDisplayItem(sig.SignalName, sig.StatusText, sig.Detail, brush));
            }
        }

        if (report.GoogleVerdict.IsRuGeoPoisoned)
        {
            GoogleVerdictBorderBrush = SolidColorBrush.Parse("#EF4444");
            GoogleVerdictTitleBrush = SolidColorBrush.Parse("#FCA5A5");
        }
        else if (report.GoogleVerdict.HasGoogleCaptchaBlock ||
                 report.GoogleVerdict.YouTubePremiumAvailable == false ||
                 report.GoogleVerdict.GeminiAccessible == false)
        {
            GoogleVerdictBorderBrush = SolidColorBrush.Parse("#F59E0B");
            GoogleVerdictTitleBrush = SolidColorBrush.Parse("#FCD34D");
        }
        else if (report.GoogleVerdict.ProbeSucceeded &&
                 !string.Equals(report.GoogleVerdict.DetectedGlCode, "RU", StringComparison.OrdinalIgnoreCase))
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
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("1. YouTube INNERTUBE_CONTEXT_GL", "Ожидание", "Проверка реального кода страны YouTube с обходом EU-согласия", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("2. Доступность YouTube Premium", "Ожидание", "Проверка «недоступна в вашей стране» (признак метки RU)", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("3. Доступ к Google Gemini / AI", "Ожидание", "Проверка гео-блокировки /unsupported и HTTP 403 для РФ", muted));
        GoogleSignalItems.Add(new GoogleSignalDisplayItem("4. Google Search (регион и /sorry/)", "Ожидание", "Проверка футера страны в Google Search и капчи reCAPTCHA 429", muted));

        ProviderItems.Clear();
        ProviderItems.Add(new GeoProviderDisplayItem("ipwho.is", "—", "Ожидание запуска", "Проверка ASN, ISP, флагов Hosting / Proxy / Tor", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
        ProviderItems.Add(new GeoProviderDisplayItem("ip-api.com", "—", "Ожидание запуска", "Проверка географии, провайдера и флагов hosting/proxy", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
        ProviderItems.Add(new GeoProviderDisplayItem("ipinfo.io", "—", "Ожидание запуска", "Проверка организации, ASN и принадлежности к облаку", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
        ProviderItems.Add(new GeoProviderDisplayItem("Cloudflare Trace", "—", "Ожидание запуска", "Сверка видимого IP и страны глазами CDN Cloudflare", "Hosting: —", muted, "Proxy/VPN: —", muted, "Готов"));
    }
}
