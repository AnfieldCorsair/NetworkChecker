namespace RKNHardering.Core.Models;

/// <summary>Уровень серьёзности отдельной находки.</summary>
public enum Severity
{
    /// <summary>Информация, не влияет на вердикт.</summary>
    Info = 0,
    /// <summary>Косвенный признак, требует внимания.</summary>
    Notice = 1,
    /// <summary>Прямой признак обхода блокировок.</summary>
    Warning = 2,
    /// <summary>Однозначный признак (TUN + прокси + иностранный IP и т. п.).</summary>
    Critical = 3,
}

/// <summary>Статус отдельной проверки.</summary>
public enum CheckStatus
{
    /// <summary>Признаки не обнаружены.</summary>
    Clean = 0,
    /// <summary>Есть косвенные данные, методика требует ручной интерпретации.</summary>
    NeedsReview = 1,
    /// <summary>Признак обнаружен.</summary>
    Detected = 2,
    /// <summary>Проверка невозможна в текущем окружении.</summary>
    Skipped = 3,
    /// <summary>Ошибка выполнения.</summary>
    Failed = 4,
}

/// <summary>Идентификаторы модулей проверки (паритет с Android-версией).</summary>
public enum CheckCategory
{
    GeoIp = 0,
    IpComparison = 1,
    DirectSigns = 2,
    IndirectSigns = 3,
    Bypass = 4,
    CallTransport = 5,
    CdnPulling = 6,
    DomainReachability = 7,
    RttTriangulation = 8,
    IcmpSpoofing = 9,
}

/// <summary>Итоговый вердикт.</summary>
public enum RiskLevel
{
    /// <summary>Признаков обхода не найдено.</summary>
    Clean = 0,
    /// <summary>Есть шум, который методика РКН трактует как «требует проверки».</summary>
    NeedsReview = 1,
    /// <summary>Набор сигналов указывает на активный туннель/прокси.</summary>
    Detected = 2,
}

/// <summary>Тип сетевого интерфейса с точки зрения методики обнаружения.</summary>
public enum AdapterKind
{
    Ethernet = 0,
    Wifi = 1,
    Cellular = 2,
    Tunnel = 3,
    Loopback = 4,
    Virtual = 5,
    Unknown = 6,
}
