namespace NetworkChecker.Core.Options;

/// <summary>
/// Известные причины ложных срабатываний, перечисленные в опубликованной (но официально не
/// подтверждённой) методике выявления средств обхода и в открытых исследованиях.
/// Каталог не доказывает и не опровергает использование VPN: он добавляет контекст к находкам.
/// </summary>
public static class FalsePositiveCatalog
{
    public sealed record Entry(string Name, string[] Markers, string Note);

    public static IReadOnlyList<Entry> Entries { get; } =
    [
        new("Корпоративный VPN и удалённый доступ",
            ["anyconnect", "globalprotect", "forticlient", "pulse secure", "check point vpn", "sonicwall", "junos pulse", "cisco vpn"],
            "Корпоративный туннель и Always On VPN дают те же признаки, что и средство обхода; методика предлагает белые списки и историю подключений."),
        new("Защитное ПО с сетевым фильтром",
            ["kaspersky", "eset", "bitdefender", "avast", "avira", "norton", "mcafee", "comodo"],
            "Антивирусы и DPI-фильтры могут создавать локальный DNS, прокси и виртуальный адаптер."),
        new("Виртуализация и контейнеры",
            ["hyper-v", "vethernet", "docker", "wsl", "vmware", "virtualbox", "vbox", "npcap", "tap-windows", "loopback adapter"],
            "WSL2, Hyper-V, Docker, VirtualBox и TAP-драйверы создают виртуальные адаптеры, маршруты и нестандартный MTU."),
        new("Сетевые службы ОС",
            ["internet connection sharing", "mobile hotspot", "ras", "remote access", "directaccess"],
            "Службы Windows и общий доступ к интернету тоже меняют маршруты и DNS."),
    ];

    /// <summary>Пояснение для конкретного маркера, если он похож на известный ложный сигнал.</summary>
    public static string? Match(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        foreach (var entry in Entries)
        {
            foreach (var marker in entry.Markers)
            {
                if (text.Contains(marker, StringComparison.OrdinalIgnoreCase)) return entry.Note;
            }
        }
        return null;
    }

    /// <summary>Общие оговорки методики: почему одного признака недостаточно.</summary>
    public static IReadOnlyList<string> ContextNotes { get; } =
    [
        "VPN, поднятый на роутере или выше по пути, не оставляет следов на этом компьютере: локальные проверки будут чистыми при иностранном адресе выхода.",
        "Резидентные прокси используют адреса обычных домашних провайдеров и не попадают в репутационные базы VPN.",
        "Split tunneling направляет через туннель только часть трафика; проверка одной активной сети может ничего не показать.",
        "Корпоративный VPN, антивирусный сетевой фильтр, Docker, WSL2, Hyper-V и VirtualBox создают интерфейсы, маршруты, DNS и MTU, похожие на обход.",
        "CDN и глобальные сервисы искажают географию по IP без всякого обхода; GeoIP-базы расходятся и устаревают.",
        "Новые VPN-сервисы появляются быстрее, чем обновляются списки IP и сигнатуры; отсутствие метки не означает чистый адрес.",
        "NAT, балансировка и anycast-резолверы объясняют расхождение адресов без прокси или туннеля.",
    ];

    /// <summary>Одна строка для экранов: «это не доказательство».</summary>
    public static string GeneralNote =>
        "Один локальный признак не доказывает обход: возможны корпоративный VPN, защитное ПО, виртуализация, " +
        "туннель на роутере, резидентный прокси, split tunneling и ошибки GeoIP.";
}
