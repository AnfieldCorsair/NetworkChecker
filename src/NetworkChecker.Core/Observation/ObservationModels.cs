namespace NetworkChecker.Core.Observation;

/// <summary>Ограниченное наблюдение; не является доказательством перехвата.</summary>
public sealed record ObservationEvent(string Source, string Kind, string Detail, DateTimeOffset At);
public sealed record WfpFilterRecord(Guid Key, Guid Layer, Guid? Provider, string Action, bool Disabled, Guid? Callout);
public sealed record WfpSnapshot(IReadOnlyList<WfpFilterRecord> Filters, int Scanned, int Callouts, bool Truncated, string? Error);
public sealed record ObservationPart(string Source, bool Available, string Status, IReadOnlyList<ObservationEvent> Events, int Dropped)
{
    public WfpSnapshot? Snapshot { get; init; }
}
public sealed record ObservationReport(ObservationPart Wfp, ObservationPart Etw);

public interface IObservationService
{
    Task<ObservationReport> ObserveAsync(TimeSpan duration, CancellationToken cancellationToken);
}

/// <summary>Потокобезопасная ограниченная запись событий без сетевых адресов и содержимого пакетов.</summary>
public sealed class ObservationBuffer(int limit)
{
    private readonly Lock _lock = new();
    private readonly List<ObservationEvent> _events = [];
    private int _dropped;

    public void Add(ObservationEvent item)
    {
        lock (_lock)
        {
            if (_events.Count < Math.Max(0, limit)) _events.Add(item);
            else _dropped++;
        }
    }

    public (IReadOnlyList<ObservationEvent> Events, int Dropped) Snapshot()
    {
        lock (_lock) return (_events.ToArray(), _dropped);
    }
}
