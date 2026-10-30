using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;

namespace NetworkChecker.App.ViewModels;

public sealed record GuideItem(string Title, string Body, string Tag, string TagColor)
{
    public Avalonia.Media.IBrush TagBrush => Ui.Brush(TagColor);
    public Avalonia.Media.IBrush TagSoftBrush => Ui.Brush(TagColor, 0.15);
}

public sealed class GuideSection
{
    public required string Title { get; init; }
    public required string Icon { get; init; }
    public required string Summary { get; init; }
    public required ObservableCollection<GuideItem> Items { get; init; }
    public bool IsExpanded { get; set; } = true;
}

/// <summary>Вкладка-справочник: что именно делает каждый модуль и как читать результат.</summary>
public sealed partial class GuideViewModel : ViewModelBase
{
    public GuideViewModel()
    {
        if (global::NetworkChecker.App.Localization.Localizer.Culture == "en-US")
        {
            Sections = EnglishSections();
            return;
        }
        Sections =
        [
            new()
            {
                Title = "Как читать вердикт",
                Icon = global::NetworkChecker.App.Icons.ShieldCheck,
                Summary = "Итог собирает VerdictEngine: вес модуля × серьёзность находки, плюс жёсткие правила подтверждения.",
                Items =
                [
                    new("Чисто", "В доступных данных не найдено значимых признаков. Это не исключает VPN или прокси.", "уровень", "#35C48A"),
                    new("Требует проверки", "Есть сигналы (иностранный IP без hosting, транзитные скачки RTT, нестандартные записи hosts), но нет подтверждения прямыми признаками.", "уровень", "#F5C542"),
                    new("Настройки обнаружены", "Обнаружены настройки прокси или подключённый профиль VPN Windows. Маршрут конкретного браузера не проверяется.", "уровень", "#F0524C"),
                    new("Счёт 0–100", "Условный индекс по выполненным модулям; не вероятность и не оценка безопасности. При отсутствии данных не рассчитывается.", "механика", "#4EA1FF"),
                ],
            },
            new()
            {
                Title = "Прямые признаки",
                Icon = global::NetworkChecker.App.Icons.Shield,
                Summary = "Модуль DirectSigns: то, что видно в системе без сетевых запросов. Вес 30.",
                Items =
                [
                    new("Системный прокси", "Читаются ключи WinINET в HKCU\\...\\Internet Settings (ProxyEnable, ProxyServer, AutoConfigURL), машинные DefaultConnectionSettings и переменные HTTP_PROXY/ALL_PROXY.", "реестр", "#4EA1FF"),
                    new("TUN/TAP-адаптеры", "Через NetworkInterface ищутся интерфейсы типа Tunnel и имена вида tun/tap/wg/wintun/nordlynx/amnezia/clash-*. Активный туннель может иметь разные причины и не подтверждает маршрут браузера.", "сеть", "#4EA1FF"),
                    new("VPN-профили ОС", "Get-VpnConnection (все пользователи и текущий). Активное подключение = критичный сигнал, наличие профиля = контекст.", "PowerShell", "#B061D6"),
                    new("Запущенные клиенты", "Сверка имён процессов и путей с каталогом из 38 маркеров: WireGuard, OpenVPN, v2rayN, Xray, NekoRay, Clash, sing-box, Hiddify, Tor, GoodbyeDPI, zapret и др.", "каталог", "#4EA1FF"),
                    new("Установленные приложения", "Три ветки Uninstall в реестре (HKLM, WOW6432Node, HKCU). Факт установки — warning, а не приговор.", "реестр", "#4EA1FF"),
                    new("Kill switch", "Правила outbound-block в Windows Firewall, связанные с VPN-клиентом. Типичны для «защиты от утечек».", "файрвол", "#F2913D"),
                ],
            },
            new()
            {
                Title = "Косвенные признаки",
                Icon = global::NetworkChecker.App.Icons.Trace,
                Summary = "Модуль IndirectSigns: маршруты, DNS и MTU. Вес 20.",
                Items =
                [
                    new("Маршрут по умолчанию", "Get-NetRoute 0.0.0.0/0. Связь маршрута по умолчанию с интерфейсом не показывает маршрут конкретного приложения или сайта.", "маршруты", "#4EA1FF"),
                    new("Хостовые маршруты /32", "Маршруты на отдельные адреса — типовой приём tun2socks и v2rayN при выборочной маршрутизации.", "маршруты", "#4EA1FF"),
                    new("DNS на loopback", "Локальный DNS может использоваться обычными программами и сам по себе не доказывает туннель.", "DNS", "#4EA1FF"),
                    new("Split DNS (NRPT)", "Политики DnsPolicyConfig: часть доменов разрешается отдельным сервером — типично для корпоративных и VPN-профилей.", "DNS", "#4EA1FF"),
                    new("Нетипичный MTU", "MTU помогает изучить конфигурацию, но по одному значению нельзя установить программу.", "MTU", "#F2913D"),
                    new("Файл hosts", "Нестандартные записи (кроме localhost/::1) — перенаправление доменов для блокировки телеметрии или подмены резолвинга.", "hosts", "#5C7A99"),
                ],
            },
            new()
            {
                Title = "Локальный обход",
                Icon = global::NetworkChecker.App.Icons.Chip,
                Summary = "Модуль Bypass: сканирование loopback и управляющих API клиентов. Вес 30.",
                Items =
                [
                    new("Сканирование портов", "20 типовых портов (1080, 1087, 2080, 3128, 7890, 7897, 8080, 8888, 9050, 10808, 20170...). Каждый проверяется на SOCKS5-приветствие и CONNECT-ответ.", "порты", "#4EA1FF"),
                    new("Xray API", "HTTP-ответ на порту 10085 не доказывает Xray. Проверка Xray gRPC пока не реализована.", "API", "#4EA1FF"),
                    new("Clash/Mihomo API", "Ответ /version на портах 9090/9091 не позволяет надёжно определить программу.", "API", "#4EA1FF"),
                    new("Связка SOCKS5 + TUN", "Сочетание SOCKS5 и адаптера возможно в разных конфигурациях; использование браузером не проверяется.", "эвристика", "#F2913D"),
                ],
            },
            new()
            {
                Title = "Сетевые проверки",
                Icon = global::NetworkChecker.App.Icons.Globe,
                Summary = "GeoIP, сравнение IP-источников, UDP/STUN, домены, CDN, RTT и ICMP.",
                Items =
                [
                    new("GeoIP", "ipapi.is (основной), iplocate.io, ipinfo.io, myip.com. Hosting — majority vote, proxy/VPN/Tor — достаточно одного голоса. Иностранный IP без hosting даёт needsReview.", "вес 20", "#4EA1FF"),
                    new("Сравнение IP-источников", "Сравниваются только адреса одного семейства. Различия могут иметь разные причины; это не доказательство split tunneling.", "диагностика", "#5C7A99"),
                    new("UDP / STUN", "Различие адресов HTTPS и STUN может быть связано с NAT, маршрутами или прокси; утечка не доказана.", "вес 10", "#4EA1FF"),
                    new("Доступность доменов", "Цепочка DNS → TCP :443 → TLS для набора доменов. Показывает этап ошибки DNS, TCP или TLS; причина и блокировка по SNI не установлены.", "вес 10", "#4EA1FF"),
                    new("CDN и redirector", "cdn-cgi/trace и httpbin/headers: страна edge-узла и наличие прокси-заголовков (Via, X-Forwarded-For).", "вес 5", "#4EA1FF"),
                    new("RTT-триангуляция (β)", "Сравнение медиан задержки до групп узлов. Географию и тип маршрута по этим данным установить нельзя.", "вес 15", "#F2913D"),
                    new("ICMP-спуфинг (β)", "Сверка ICMP и TCP-ответов: разные адреса, «слишком близкий» ответ с малым TTL, ICMP есть при закрытом TCP.", "вес 10", "#F2913D"),
                ],
            },
            new()
            {
                Title = "Вкладка «Сеть»",
                Icon = global::NetworkChecker.App.Icons.Globe,
                Summary = "Три режима: база, диагностика, трассировка. Некоторые пробы обращаются к внешним сервисам.",
                Items =
                [
                    new("Овервью", "Адаптеры (тип, MTU, MAC, IP, шлюз, DNS), маршруты по умолчанию, системный прокси, внешний IP с ASN/ISP, UDP-выход через STUN.", "база", "#35C48A"),
                    new("Диагностика", "Пять пингов на хост (медиана, jitter, потери), проба MTU пути через ICMP с Don't Fragment, DNS-запросы к каждому системному резолверу и DoH, TLS-сертификаты трёх узлов.", "диагностика", "#4EA1FF"),
                    new("Трассировка", "ICMP traceroute по нарастающему TTL, до 20 хопов, с ASN и именем оператора через Team Cymru DNS. Таймауты и хопы не устанавливают точку выхода туннеля.", "трассировка", "#B061D6"),
                ],
            },
            new()
            {
                Title = "Вкладка «Глазами сайта»",
                Icon = global::NetworkChecker.App.Icons.Eye,
                Summary = "Условная модель доступных сайту сведений, не анализ конкретного сайта или браузера.",
                Items =
                [
                    new("Визитная карточка", "IP-адрес, страна и город по GeoIP, провайдер и ASN, тип сети (домашний провайдер или дата-центр), метки VPN/прокси в базах.", "что видно", "#4EA1FF"),
                    new("Часовой пояс и язык", "Модель сравнивает системные язык и часовой пояс с GeoIP. Настройки браузера могут отличаться; расхождение не доказывает VPN.", "сверка", "#F5C542"),
                    new("Шкала 0–100", "Сумма весов сигналов: метка VPN 30, дата-центр 25, иностранный адрес 20, расхождение поясов 15, язык 10, небраузерный клиент 5. Это условные веса, не вероятность и не методика конкретного сайта. Для русскоязычных стран региона язык отдельно не штрафуется.", "механика", "#F0524C"),
                    new("Сырой запрос", "Показан иллюстративный набор заголовков приложения, не перехваченный запрос браузера. Cookies и данные скриптов зависят от сайта и браузера.", "подробно", "#B061D6"),
                    new("Ничего не отправляется", "Запросы идут только к GeoIP-сервисам. На серверы ВК, Яндекса и банков приложение не ходит — это модель того, что они увидят.", "приватность", "#35C48A"),
                ],
            },
            new()
            {
                Title = "Сравнение с похожим приложением для Android",
                Icon = global::NetworkChecker.App.Icons.Book,
                Summary = "Сравнение с похожим Android-приложением RKNHardering: https://github.com/xtclovver/RKNHardering. Это источник вдохновения, а не форк; реализации и возможности отличаются.",
                Items =
                [
                    new("NetworkCapabilities → реестр WinINET", "Вместо ConnectivityManager читаются настройки прокси Windows и машинные параметры подключения.", "маппинг", "#5C7A99"),
                    new("VpnService → TUN-адаптеры", "Вместо dumpsys vpn_management используется перечисление сетевых интерфейсов и VPN-профилей ОС.", "маппинг", "#5C7A99"),
                    new("PackageManager → Uninstall-реестр", "Список установленных приложений строится по трём веткам Uninstall.", "маппинг", "#5C7A99"),
                    new("JNI-проверки → PowerShell/реестр", "NativeSigns (JNI) заменены на нативные Windows API: Get-NetRoute, Get-NetFirewallRule, Registry.", "маппинг", "#5C7A99"),
                    new("MCC/SIM/BeaconDB", "Не переносится: на ПК нет сотового модуля. Роль LocationSignals частично берёт на себя GeoIP.", "исключено", "#F2913D"),
                ],
            },
        ];
    }

    private static ObservableCollection<GuideSection> EnglishSections()
    {
        static GuideSection Section(string title, string icon, string summary, params GuideItem[] items) => new()
        {
            Title = title,
            Icon = icon,
            Summary = summary,
            Items = new(items),
        };
        const string blue = "#4EA1FF";
        return
        [
            Section("Understanding the verdict", global::NetworkChecker.App.Icons.ShieldCheck,
                "The result combines completed checks with conservative rules.",
                new("No indicators found", "Available data does not exclude a VPN or proxy.", "level", blue),
                new("Review needed", "Ambiguous observations can have several explanations.", "level", blue),
                new("Settings detected", "Proxy settings or a connected Windows VPN were found; the browser route was not checked.", "level", blue),
                new("Index 0–100", "An unvalidated relative index, not a probability or security score. It is unavailable without sufficient data.", "index", blue)),
            Section("Direct indicators", global::NetworkChecker.App.Icons.Shield,
                "Windows proxy settings, network interfaces, profiles, processes and services.",
                new("Proxy", "WinINET, WinHTTP, environment variables and PAC configuration may be inspected.", "system", blue),
                new("Tunnel interfaces", "An active tunnel interface does not prove a browser uses it.", "network", blue),
                new("VPN profiles and clients", "A connected Windows VPN is different from an installed client or an inactive profile.", "Windows", blue)),
            Section("Indirect indicators", global::NetworkChecker.App.Icons.Trace,
                "Routes, DNS, MTU and hosts entries provide context, not proof of a tunnel.",
                new("Routes and DNS", "Default routes, host routes, local DNS and NRPT policies can also be used by ordinary or corporate networks.", "network", blue),
                new("MTU and hosts", "Unusual values may have many causes and do not identify a specific application.", "context", blue)),
            Section("Local proxy checks", global::NetworkChecker.App.Icons.Chip,
                "Loopback ports and some local endpoints are probed.",
                new("SOCKS5 and HTTP CONNECT", "A response suggests a compatible local service, not that the browser uses it.", "ports", blue),
                new("Client APIs", "A response on port 10085 or /version is not sufficient to identify a particular client. Xray gRPC is not implemented.", "API", blue)),
            Section("Network checks", global::NetworkChecker.App.Icons.Globe,
                "GeoIP, IP comparison, STUN, reachability, CDN, RTT and ICMP.",
                new("IP and GeoIP", "Only addresses of the same family are compared. Databases can be incomplete or wrong; a mismatch does not prove a leak.", "IP", blue),
                new("DNS, TCP and TLS", "The checks show the stage that failed, not its cause or proof of filtering. Certificate validation failures have multiple possible causes.", "reachability", blue),
                new("RTT and ICMP", "Latency and differing replies cannot establish a route's geography or prove spoofing on their own.", "beta", blue)),
            Section("Network page", global::NetworkChecker.App.Icons.Globe,
                "Overview, diagnostics and traceroute. Some probes contact external services.",
                new("Overview", "Interfaces, routes, proxy settings and available external IP information.", "overview", blue),
                new("Diagnostics", "Latency, path MTU, DNS and TLS checks; unavailable probes do not establish a cause.", "diagnostics", blue),
                new("Traceroute", "TTL hops and ASN information from Team Cymru. It is not a geographic map; timeouts do not prove an outage.", "trace", blue)),
            Section("Website perspective", global::NetworkChecker.App.Icons.Eye,
                "A simplified model, not the actual view or decision of a website.",
                new("Data and assumptions", "GeoIP comes from an external service; language and time zone are system settings, not necessarily browser settings.", "model", blue),
                new("Score", "The weighted score is heuristic, not a probability or a website's real algorithm.", "index", blue),
                new("Illustrative request", "The displayed headers are an example, not an intercepted browser request. No request is sent to VK or Yandex.", "privacy", blue)),
            Section("Packet viewer and observation", global::NetworkChecker.App.Icons.Eye,
                "The PCAP viewer and the experimental Windows observation are separate features.",
                new("Packet viewer", "Opens local PCAP and supported PCAPNG blocks. Live capture and monitoring are not implemented. Capture files may contain secrets.", "viewer", blue),
                new("WFP / ETW", "Starts only on request. Results are limited, do not prove interception and do not affect the verdict.", "experimental", blue)),
        ];
    }

    public override string Title => global::NetworkChecker.App.Localization.Localizer.T("Справка");
    public override string Icon => global::NetworkChecker.App.Icons.Book;
    public override string Description => global::NetworkChecker.App.Localization.Localizer.T("Что делает каждый модуль");

    public ObservableCollection<GuideSection> Sections { get; }

    [RelayCommand]
    private void ToggleSection(GuideSection? section)
    {
        if (section is null) return;
        section.IsExpanded = !section.IsExpanded;
        var index = Sections.IndexOf(section);
        if (index >= 0) Sections[index] = section;
    }
}
