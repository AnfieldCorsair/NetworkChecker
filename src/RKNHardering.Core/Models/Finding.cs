namespace RKNHardering.Core.Models;

/// <summary>Одна находка внутри результата проверки.</summary>
public sealed record Finding
{
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public string Detail { get; init; } = string.Empty;
    /// <summary>Сырые данные/доказательство: имя интерфейса, порт, IP, строка вывода.</summary>
    public string? Evidence { get; init; }

    public static Finding Info(string title, string detail = "", string? evidence = null) =>
        new() { Severity = Severity.Info, Title = title, Detail = detail, Evidence = evidence };

    public static Finding Notice(string title, string detail = "", string? evidence = null) =>
        new() { Severity = Severity.Notice, Title = title, Detail = detail, Evidence = evidence };

    public static Finding Warning(string title, string detail = "", string? evidence = null) =>
        new() { Severity = Severity.Warning, Title = title, Detail = detail, Evidence = evidence };

    public static Finding Critical(string title, string detail = "", string? evidence = null) =>
        new() { Severity = Severity.Critical, Title = title, Detail = detail, Evidence = evidence };
}
