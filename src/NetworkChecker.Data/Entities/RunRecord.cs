namespace NetworkChecker.Data.Entities;

/// <summary>Сохранённый прогон проверки.</summary>
public sealed class RunRecord
{
    public Guid Id { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset FinishedAt { get; set; }
    public int DurationMs { get; set; }
    public int RiskLevel { get; set; }
    public int Score { get; set; }
    public string Headline { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string? ExternalIp { get; set; }
    public string? Country { get; set; }
    public bool PrivacyMode { get; set; }
    public string OsDescription { get; set; } = string.Empty;
    public string ChecksJson { get; set; } = "[]";
    public string ReasonsJson { get; set; } = "[]";
    public string IpObservationsJson { get; set; } = "[]";
    public string EnvironmentJson { get; set; } = "{}";
}

/// <summary>Запись журнала событий приложения (диагностика).</summary>
public sealed class LogRecord
{
    public long Id { get; set; }
    public DateTimeOffset At { get; set; }
    public string Level { get; set; } = "Info";
    public string Message { get; set; } = string.Empty;
    public string? Detail { get; set; }
}
