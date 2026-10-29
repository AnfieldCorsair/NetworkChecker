using Avalonia;

namespace NetworkChecker.App.Localization;

/// <summary>Экспериментальный перевод оболочки. Язык системы и CurrentUICulture не изменяются.</summary>
public static class Localizer
{
    private static readonly Dictionary<string, string> English = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Проверка"] = "Check",
        ["Сеть"] = "Network",
        ["Глазами сайта"] = "Website view",
        ["История"] = "History",
        ["Справка"] = "Guide",
        ["Настройки"] = "Settings",
        ["Обнаружение VPN и прокси по методике РКН"] = "VPN and proxy indicators",
        ["База, диагностика и трассировка"] = "Overview, diagnostics and trace",
        ["Что о вас узнаёт ВК или Яндекс"] = "What a website might learn",
        ["Локальные прогоны в SQLite"] = "Local runs in SQLite",
        ["Что делает каждый модуль"] = "What each module does",
        ["Таймауты, цели проверок, приватность"] = "Timeouts, targets and privacy",
        ["Просто"] = "Simple",
        ["Подробно"] = "Detailed",
        ["Овервью"] = "Overview",
        ["Диагностика"] = "Diagnostics",
        ["Трассировка"] = "Trace",
        ["Цель"] = "Target",
        ["Трассировать"] = "Trace route",
        ["Стоп"] = "Stop",
        ["СХЕМА МАРШРУТА"] = "ROUTE DIAGRAM",
        ["Узел"] = "Hop",
        ["Лучший RTT"] = "Best RTT",
        ["Оператор"] = "Network operator",
        ["Обновить обзор"] = "Refresh overview",
        ["Порядок ответивших узлов, не географическая карта. Цвет группирует ASN; одинаковые цвета возможны и у разных ASN. Серый — ASN неизвестен. Отсутствие ответа не доказывает обрыв."] =
            "Responding hops in order, not a geographic map. Color groups ASNs; different ASNs can share a color. Gray means unknown ASN. A timeout does not prove an outage.",
    };

    public static string Culture { get; private set; } = "ru-RU";
    public static string Translate(string text, string? culture) =>
        culture?.StartsWith("en", StringComparison.OrdinalIgnoreCase) == true && English.TryGetValue(text, out var value) ? value : text;
    public static string T(string text) => Translate(text, Culture);

    public static void Configure(string? culture)
    {
        Culture = culture?.StartsWith("en", StringComparison.OrdinalIgnoreCase) == true ? "en-US" : "ru-RU";
        if (Application.Current is not { } app) return;
        foreach (var pair in Resources)
            app.Resources[pair.Key] = T(pair.Value);
    }

    private static readonly IReadOnlyDictionary<string, string> Resources = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["LocSimple"] = "Просто",
        ["LocDetailed"] = "Подробно",
        ["LocOverview"] = "Овервью",
        ["LocDiagnostics"] = "Диагностика",
        ["LocTrace"] = "Трассировка",
        ["LocTarget"] = "Цель",
        ["LocTraceAction"] = "Трассировать",
        ["LocStop"] = "Стоп",
        ["LocGraph"] = "СХЕМА МАРШРУТА",
        ["LocHop"] = "Узел",
        ["LocRtt"] = "Лучший RTT",
        ["LocOperator"] = "Оператор",
        ["LocRefresh"] = "Обновить обзор",
        ["LocGraphHint"] = "Порядок ответивших узлов, не географическая карта. Цвет группирует ASN; одинаковые цвета возможны и у разных ASN. Серый — ASN неизвестен. Отсутствие ответа не доказывает обрыв.",
    };
}
