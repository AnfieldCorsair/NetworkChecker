namespace NetworkChecker.Core.Models;

/// <summary>Пара «подпись — значение» для плиток метрик в UI.</summary>
public sealed record Metric(string Label, string Value, string? Hint = null);

/// <summary>Результат работы одного модуля проверки.</summary>
public sealed class CheckResult
{
    public required CheckCategory Category { get; init; }
    public required string Title { get; init; }
    public string Subtitle { get; init; } = string.Empty;
    public required CheckStatus Status { get; init; }
    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();
    public IReadOnlyList<Metric> Metrics { get; init; } = Array.Empty<Metric>();
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public TimeSpan Duration { get; init; }
    public string? Error { get; init; }

    /// <summary>Вес модуля в итоговом вердикте (0 — не влияет, только диагностика).</summary>
    public int Weight { get; init; }

    public int HighestSeverity => Findings.Count == 0 ? -1 : Findings.Max(f => (int)f.Severity);
    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);
    public int NoticeCount => Findings.Count(f => f.Severity == Severity.Notice);

    public string StatusText => Status switch
    {
        CheckStatus.Clean => "Чисто",
        CheckStatus.NeedsReview => "Требует проверки",
        CheckStatus.Detected => "Обнаружено",
        CheckStatus.Skipped => "Пропущено",
        CheckStatus.Failed => "Ошибка",
        _ => "—",
    };

    public static CheckResult Failed(CheckCategory category, string title, string error, TimeSpan duration, int weight = 0) =>
        new()
        {
            Category = category,
            Title = title,
            Status = CheckStatus.Failed,
            Error = error,
            Duration = duration,
            Weight = weight,
        };
}

/// <summary>Одно наблюдение IP-адреса от конкретного источника.</summary>
public enum IpChannel { Unknown, Web, Udp }

public sealed record IpObservation(string Source, string Ip, bool? IsRussian, string? Note = null, IpChannel Channel = IpChannel.Unknown);

/// <summary>Кросс-модульный консенсус по внешнему IP.</summary>
public sealed class IpConsensus
{
    public string? ConsensusIp { get; init; }
    public IReadOnlyList<IpObservation> Observations { get; init; } = Array.Empty<IpObservation>();
    public int RussianVotes { get; init; }
    public int ForeignVotes { get; init; }
    public bool IsSplit { get; init; }          // разные адреса одного семейства; причины неизвестны
    public bool WithinChannelConflict { get; init; }
    public bool CrossChannelMismatch { get; init; }
    public bool HasConsensus => !string.IsNullOrWhiteSpace(ConsensusIp);

    public string Summary => ConsensusIp is null
        ? "нет данных"
        : IsSplit
            ? $"расхождение адресов одного семейства (выбранный адрес: {ConsensusIp})"
            : ConsensusIp;
}

/// <summary>Снимок окружения, на котором выполнялся прогон.</summary>
public sealed class EnvironmentSnapshot
{
    public required string OsDescription { get; init; }
    public string MachineName { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string AppVersion { get; init; } = string.Empty;
    public IReadOnlyList<Platform.AdapterInfo> Adapters { get; init; } = Array.Empty<Platform.AdapterInfo>();
    public Platform.ProxySettings Proxy { get; init; } = new();
    public bool PrivacyMode { get; init; }
    /// <summary>Запущено с правами администратора — часть данных и проверок доступна только так.</summary>
    public bool IsElevated { get; init; }
    /// <summary>Сборка Windows (например, 26100), если ОС — Windows.</summary>
    public string? WindowsBuild { get; init; }
}

/// <summary>Полный результат одного прогона.</summary>
public sealed class CheckRunResult
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset FinishedAt { get; init; }
    public required IReadOnlyList<CheckResult> Checks { get; init; }
    public required VerdictResult Verdict { get; init; }
    public IpConsensus IpConsensus { get; init; } = new();
    public required EnvironmentSnapshot Environment { get; init; }

    public TimeSpan Duration => FinishedAt - StartedAt;
}
