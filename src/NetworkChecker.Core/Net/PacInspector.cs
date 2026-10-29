using System.Text.RegularExpressions;

namespace NetworkChecker.Core.Net;

/// <summary>
/// Разбор PAC-файла (Proxy Auto-Config). Полноценный JS-движок здесь не нужен:
/// задача — понять, что скрипт вообще делает с трафиком, и вытащить адреса,
/// на которые он отправляет запросы. Этого достаточно, чтобы отличить
/// «корпоративный PAC» от «PAC локального клиента обхода».
/// </summary>
public static partial class PacInspector
{
    /// <summary>Один прокси-сервер, упомянутый в PAC.</summary>
    public readonly record struct PacProxy(string Kind, string Host, int Port)
    {
        public bool IsLoopback => Host is "127.0.0.1" or "localhost" or "::1" or "[::1]";
        public override string ToString() => $"{Kind} {Host}:{Port}";
    }

    /// <summary>Результат разбора PAC-скрипта.</summary>
    public sealed record PacAnalysis
    {
        public required bool LooksLikePac { get; init; }
        public required IReadOnlyList<PacProxy> Proxies { get; init; }
        public required bool AllowsDirect { get; init; }
        public required IReadOnlyList<string> Indicators { get; init; }

        public bool RoutesThroughProxy => Proxies.Count > 0;
        public bool HasLoopbackProxy => Proxies.Any(p => p.IsLoopback);

        public static PacAnalysis Empty { get; } = new()
        {
            LooksLikePac = false,
            Proxies = [],
            AllowsDirect = false,
            Indicators = [],
        };
    }

    // Директива PAC: «PROXY host:port», «SOCKS5 host:port», «HTTPS host:port».
    // Кавычка перед директивой не обязательна — в скрипте они встречаются в любом окружении.
    [GeneratedRegex(@"(?<kind>PROXY|SOCKS5|SOCKS4|SOCKS|HTTPS)\s+(?<host>\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)\s*:\s*(?<port>\d{1,5})", RegexOptions.IgnoreCase)]
    private static partial Regex ProxyDirectiveRegex();

    [GeneratedRegex(@"\bFindProxyForURL\b", RegexOptions.IgnoreCase)]
    private static partial Regex PacSignatureRegex();

    [GeneratedRegex(@"\bDIRECT\b", RegexOptions.IgnoreCase)]
    private static partial Regex DirectRegex();

    [GeneratedRegex(@"\bisInNet\s*\(|isResolvable\s*\(|dnsResolve\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex HelperRegex();

    public static PacAnalysis Parse(string? script)
    {
        if (string.IsNullOrWhiteSpace(script)) return PacAnalysis.Empty;

        var looksLikePac = PacSignatureRegex().IsMatch(script);
        var proxies = new List<PacProxy>();
        var indicators = new List<string>();

        foreach (Match match in ProxyDirectiveRegex().Matches(script))
        {
            var kind = match.Groups["kind"].Value.ToUpperInvariant();
            var host = match.Groups["host"].Value;
            if (!int.TryParse(match.Groups["port"].Value, out var port) || port is < 1 or > 65535) continue;
            var proxy = new PacProxy(kind, host, port);
            if (!proxies.Contains(proxy)) proxies.Add(proxy);
        }

        if (proxies.Count == 0 && !looksLikePac)
        {
            return new PacAnalysis
            {
                LooksLikePac = false,
                Proxies = [],
                AllowsDirect = false,
                Indicators = ["Ответ не похож на PAC-скрипт"],
            };
        }

        if (proxies.Count == 0)
            indicators.Add("PAC не задаёт прокси — возможно, только правила DIRECT");

        if (proxies.Any(p => p.IsLoopback))
            indicators.Add("PAC отправляет трафик на локальный порт (127.0.0.1) — так устроены клиенты обхода");

        if (proxies.Any(p => !p.IsLoopback))
            indicators.Add("PAC указывает на внешний прокси-сервер");

        if (HelperRegex().IsMatch(script))
            indicators.Add("PAC содержит правила по IP-подсетям — выборочная маршрутизация");

        if (DirectRegex().IsMatch(script))
            indicators.Add("PAC разрешает часть запросов напрямую (DIRECT)");

        return new PacAnalysis
        {
            LooksLikePac = looksLikePac,
            Proxies = proxies,
            AllowsDirect = DirectRegex().IsMatch(script),
            Indicators = indicators,
        };
    }
}
