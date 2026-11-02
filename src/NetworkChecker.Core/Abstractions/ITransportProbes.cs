namespace NetworkChecker.Core.Abstractions;

/// <summary>Результат UDP-пробы: пришёл ли хоть один датаграммный ответ.</summary>
public sealed record UdpProbeResult(bool ResponseReceived, TimeSpan Elapsed, string? Error);

/// <summary>Результат TLS-пробы с явно заданным SNI.</summary>
public sealed record TlsProbeOutcome(bool Success, TimeSpan Elapsed, string? Error);

/// <summary>
/// Сетевые примитивы для наблюдательного модуля транспорта. Вынесены в интерфейс,
/// чтобы логику проверки можно было тестировать без реальной сети.
/// </summary>
public interface ITransportProbes
{
    /// <summary>Разрешение имени системным резолвером.</summary>
    Task<IReadOnlyList<string>> ResolveSystemAsync(string name, CancellationToken ct = default);

    /// <summary>Разрешение имени через публичный DoH-эндпоинт (A-записи).</summary>
    Task<IReadOnlyList<string>> ResolveDohAsync(string name, TimeSpan timeout, CancellationToken ct = default);

    /// <summary>Отправка одного UDP-пакета и ожидание любого ответа в течение таймаута.</summary>
    Task<UdpProbeResult> UdpAsync(string host, int port, byte[] payload, TimeSpan timeout, CancellationToken ct = default);

    /// <summary>TLS-рукопожатие к узлу с указанным SNI (зонд, не браузер).</summary>
    Task<TlsProbeOutcome> TlsAsync(string host, string sni, TimeSpan timeout, CancellationToken ct = default);
}
