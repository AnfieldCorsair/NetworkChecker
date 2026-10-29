namespace NetworkChecker.Core.Models;

/// <summary>Уровень серьёзности отдельной находки.</summary>
public enum Severity
{
    /// <summary>Информация, не влияет на вердикт.</summary>
    Info = 0,
    /// <summary>Косвенный признак, требует внимания.</summary>
    Notice = 1,
    /// <summary>Сильный сигнал, требует интерпретации.</summary>
    Warning = 2,
    /// <summary>Высокая важность находки, но не безусловное доказательство.</summary>
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
    /// <summary>Есть неоднозначные сигналы или недостаточно данных.</summary>
    NeedsReview = 1,
    /// <summary>Подтверждён факт настроенного прокси или подключенного Windows VPN; маршрут браузера отдельно не проверен.</summary>
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
