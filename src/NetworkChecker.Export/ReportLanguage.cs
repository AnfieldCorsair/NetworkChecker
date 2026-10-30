namespace NetworkChecker.Export;

/// <summary>Report wording selected explicitly for one export; never changes system culture.</summary>
internal sealed class ReportLanguage(string? language, Func<string, string>? translate)
{
    public bool English { get; } = language?.StartsWith("en", StringComparison.OrdinalIgnoreCase) == true;

    public string Text(string text)
    {
        if (!English) return text;
        if (Labels.TryGetValue(text, out var translated)) return translated;
        return translate?.Invoke(text) ?? text;
    }

    public string Choose(string russian, string english) => English ? english : russian;

    private static readonly Dictionary<string, string> Labels = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Итог"] = "Summary",
        ["NetworkChecker — отчёт о проверке"] = "NetworkChecker — diagnostic report",
        ["Отчёт NetworkChecker"] = "NetworkChecker report",
        ["Вердикт"] = "Verdict",
        ["Уровень"] = "Level",
        ["Условный индекс"] = "Heuristic index",
        ["Что это значит"] = "What this means",
        ["Что делать"] = "What to do",
        ["Кратко"] = "Summary",
        ["Внешний IP"] = "Public IP",
        ["Наблюдений по IP"] = "IP observations",
        ["Начало"] = "Started",
        ["Длительность"] = "Duration",
        ["ОС"] = "OS",
        ["Компьютер"] = "Computer",
        ["Приватный режим"] = "Privacy mode",
        ["включён"] = "enabled",
        ["выключен"] = "disabled",
        ["Причины"] = "Reasons",
        ["Проверки"] = "Checks",
        ["Модуль"] = "Check",
        ["Проверка"] = "Check",
        ["Что проверяли"] = "What was checked",
        ["Статус"] = "Status",
        ["Простыми словами"] = "Plain language",
        ["Находок"] = "Findings",
        ["Время, с"] = "Time, s",
        ["Вес в вердикте"] = "Verdict weight",
        ["Находки"] = "Findings",
        ["Находка"] = "Finding",
        ["Подробности"] = "Details",
        ["Доказательство"] = "Evidence",
        ["критично"] = "critical",
        ["внимание"] = "warning",
        ["заметка"] = "notice",
        ["инфо"] = "info",
        ["КРИТИЧНО"] = "CRITICAL",
        ["ВНИМАНИЕ"] = "WARNING",
        ["ЗАМЕТКА"] = "NOTICE",
        ["ИНФО"] = "INFO",
        ["Находок нет"] = "No findings",
        ["IP-наблюдения"] = "IP observations",
        ["Источник"] = "Source",
        ["Страна"] = "Country",
        ["Примечание"] = "Note",
        ["не RU"] = "not RU",
        ["нет данных"] = "no data",
        ["Наблюдений нет"] = "No observations",
        ["Почему такой вывод"] = "Reasons for the verdict",
        ["Коротко по проверкам"] = "Checks at a glance",
        ["Служебное"] = "Environment",
        ["Наблюдения по внешнему IP"] = "Public IP observations",
        ["приватный режим"] = "privacy mode",
        ["полные данные"] = "full data",
        ["Окружение"] = "Environment",
        ["Операционная система"] = "Operating system",
        ["Имя машины"] = "Computer name",
        ["Пользователь"] = "User",
        ["Права администратора"] = "Administrator rights",
        ["есть"] = "yes",
        ["нет"] = "no",
        ["включён (IP и имена маскированы)"] = "enabled (IP and names masked)",
        ["IP-консенсус"] = "IP consensus",
        ["Что повлияло на вывод"] = "Factors in the verdict",
        ["Коротко по фактам"] = "Facts at a glance",
        ["Общая картина"] = "Overall picture",
        ["Модули проверки"] = "Checks",
    };
}
