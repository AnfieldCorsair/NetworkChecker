namespace NetworkChecker.Core.Abstractions;

/// <summary>
/// Запрос к внешнему сервису репутации. Нужен отдельный контракт, потому что часть API
/// требует произвольных заголовков (Key, X-API-Key) и своего User-Agent, а базовый
/// <see cref="IHttpProbe"/> намеренно их не поддерживает.
/// </summary>
public sealed record ExternalProbeRequest(
    Uri Uri,
    TimeSpan Timeout,
    bool IgnoreProxy = false,
    IReadOnlyDictionary<string, string>? Headers = null,
    string? UserAgent = null);

/// <summary>Результат DNS-запроса A-записей для DNSBL (NXDOMAIN = Found:false).</summary>
public sealed record DnsLookupResult(bool Found, IReadOnlyList<string> Addresses, string? Error);

/// <summary>Внешние пробы для блока репутации и метки Google. Легко подменяется в тестах.</summary>
public interface IExternalProbe
{
    Task<HttpProbeResult> GetAsync(ExternalProbeRequest request, CancellationToken ct = default);

    /// <summary>Разрешить A-записи системным резолвером (для DNSBL-зон).</summary>
    Task<DnsLookupResult> ResolveAAsync(string name, CancellationToken ct = default);
}
