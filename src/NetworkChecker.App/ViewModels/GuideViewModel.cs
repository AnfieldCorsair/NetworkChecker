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
        Sections =
        [
            new()
            {
                Title = "Как читать вердикт",
                Icon = global::NetworkChecker.App.Icons.ShieldCheck,
                Summary = "Итог собирает VerdictEngine: вес модуля × серьёзность находки, плюс жёсткие правила подтверждения.",
                Items =
                [
                    new("Чисто", "Ни прямых, ни косвенных признаков обхода не найдено. Отдельные заметки могут быть — они informational.", "уровень", "#35C48A"),
                    new("Требует проверки", "Есть сигналы (иностранный IP без hosting, транзитные скачки RTT, нестандартные записи hosts), но нет подтверждения прямыми признаками.", "уровень", "#F5C542"),
                    new("Обнаружен обход", "Либо сработали прямые признаки (туннель, системный прокси, запущенный клиент), либо прямой признак подтверждён сетевыми данными.", "уровень", "#F0524C"),
                    new("Счёт 0–100", "Нормированная сумма весов модулей. Вес: прямые признаки 30, локальный обход 30, GeoIP 20, косвенные 20, RTT/ICMP 15/10, домены 10, CDN 5.", "механика", "#4EA1FF"),
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
                    new("TUN/TAP-адаптеры", "Через NetworkInterface ищутся интерфейсы типа Tunnel и имена вида tun/tap/wg/wintun/nordlynx/amnezia/clash-*. Активный туннель — критичный сигнал.", "сеть", "#4EA1FF"),
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
                    new("Маршрут по умолчанию", "Get-NetRoute 0.0.0.0/0. Если default route смотрит в туннельный интерфейс — перехватывается весь трафик.", "маршруты", "#4EA1FF"),
                    new("Хостовые маршруты /32", "Маршруты на отдельные адреса — типовой приём tun2socks и v2rayN при выборочной маршрутизации.", "маршруты", "#4EA1FF"),
                    new("DNS на loopback", "127.0.0.1 в качестве резолвера — признак локального DNS-туннеля или прокси-резолвера.", "DNS", "#4EA1FF"),
                    new("Split DNS (NRPT)", "Политики DnsPolicyConfig: часть доменов разрешается отдельным сервером — типично для корпоративных и VPN-профилей.", "DNS", "#4EA1FF"),
                    new("Нетипичный MTU", "Туннели с MTU 1280/1300/9000 вместо 1500/1420 выдают конкретный клиент или конфигурацию.", "MTU", "#F2913D"),
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
                    new("Сканирование портов", "21 типовой порт (1080, 1087, 2080, 3128, 7890, 7897, 8080, 8888, 9050, 10808, 20170...). Каждый проверяется на SOCKS5-приветствие и CONNECT-ответ.", "порты", "#4EA1FF"),
                    new("Xray API", "Порт 10085 — стандартный gRPC/REST-эндпоинт Xray-core. Ответ = клиент запущен.", "API", "#4EA1FF"),
                    new("Clash/Mihomo API", "Порты 9090/9091, эндпоинт /version. Открытый external controller означает запущенный Clash.", "API", "#4EA1FF"),
                    new("Связка SOCKS5 + TUN", "Комбинация локального SOCKS5 и туннельного адаптера — схема tun2socks.", "эвристика", "#F2913D"),
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
                    new("Сравнение IP-источников", "HTTP-источники против STUN. Расхождение адресов = split tunneling или прокси только для TCP. Диагностика, вес 0.", "диагностика", "#5C7A99"),
                    new("UDP / STUN", "Binding-запрос к STUN-серверам. Если TCP-адрес и UDP-адрес разные — прокси перехватывает только TCP (утечка).", "вес 10", "#4EA1FF"),
                    new("Доступность доменов", "Цепочка DNS → TCP :443 → TLS для набора доменов. Показывает, где именно ломается доступ: DNS, TCP или SNI.", "вес 10", "#4EA1FF"),
                    new("CDN и redirector", "cdn-cgi/trace и httpbin/headers: страна edge-узла и наличие прокси-заголовков (Via, X-Forwarded-For).", "вес 5", "#4EA1FF"),
                    new("RTT-триангуляция (β)", "Медиана задержки до RU-хостов против иностранных. Если до российских адресов дальше на 60+ мс — трафик выходит за границу и возвращается.", "вес 15", "#F2913D"),
                    new("ICMP-спуфинг (β)", "Сверка ICMP и TCP-ответов: разные адреса, «слишком близкий» ответ с малым TTL, ICMP есть при закрытом TCP.", "вес 10", "#F2913D"),
                ],
            },
            new()
            {
                Title = "Вкладка «Сеть»",
                Icon = global::NetworkChecker.App.Icons.Globe,
                Summary = "Три режима: база, диагностика, трассировка. Ничего не отправляется на сервер.",
                Items =
                [
                    new("Овервью", "Адаптеры (тип, MTU, MAC, IP, шлюз, DNS), маршруты по умолчанию, системный прокси, внешний IP с ASN/ISP, UDP-выход через STUN.", "база", "#35C48A"),
                    new("Диагностика", "Пять пингов на хост (медиана, jitter, потери), проба MTU пути через ICMP с Don't Fragment, DNS-запросы к каждому системному резолверу и DoH, TLS-сертификаты трёх узлов.", "диагностика", "#4EA1FF"),
                    new("Трассировка", "ICMP traceroute по нарастающему TTL, до 20 хопов, с ASN и именем оператора через Team Cymru DNS. Первый «дальний» хоп выдаёт точку выхода туннеля.", "трассировка", "#B061D6"),
                ],
            },
            new()
            {
                Title = "Вкладка «Глазами сайта»",
                Icon = global::NetworkChecker.App.Icons.Eye,
                Summary = "Что о вас узнаёт ВК, Яндекс или банк с первого запроса — и почему включается капча.",
                Items =
                [
                    new("Визитная карточка", "IP-адрес, страна и город по GeoIP, провайдер и ASN, тип сети (домашний провайдер или дата-центр), метки VPN/прокси в базах.", "что видно", "#4EA1FF"),
                    new("Часовой пояс и язык", "Сайт сверяет часовой пояс адреса с вашим системным, а язык — со страной адреса. Расхождение больше 2 часов — типичный признак VPN.", "сверка", "#F5C542"),
                    new("Шкала 0–100", "Сумма весов сигналов: метка VPN 30, дата-центр 25, иностранный адрес 20, расхождение поясов 15, язык 10, небраузерный клиент 5. Это условные веса, не вероятность и не методика конкретного сайта. Для русскоязычных стран региона язык отдельно не штрафуется.", "механика", "#F0524C"),
                    new("Сырой запрос", "В подробном режиме видно, какие ровно заголовки уходят на сервер. Настоящий браузер добавляет к ним cookie, язык и отпечаток JS.", "подробно", "#B061D6"),
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

    public override string Title => "Справка";
    public override string Icon => global::NetworkChecker.App.Icons.Book;
    public override string Description => "Что делает каждый модуль";

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
