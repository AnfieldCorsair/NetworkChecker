using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NetworkChecker.Core.VpnAudit;

public sealed record SubnetSniNeighbor(
    string IpAddress,
    string Domain,
    string TlsProtocol,
    string Alpn,
    bool CertChainValid,
    long HandshakeMs,
    string? CertIssuer,
    bool IsRealityReady,
    string SourceLabel = "Сосед подсети /24");

/// <summary>
/// Нативный многопоточный охотник и сканер SNI для конфигураций и подписок:
/// 1) Проверка всех доменов/SNI из текущей подписки или конфига на лучшую связку TLS 1.3 + ALPN h2 + минимальный пинг,
/// 2) Перебор базы белых доменов РФ и глобальных CDN, не блокируемых ТСПУ,
/// 3) Сканирование соседних IP в подсети /24 целевого VPS (для «родного» Reality SNI того же дата-центра).
/// </summary>
public static class SubnetSniScanner
{
    private static readonly char[] DomainSeparators = [',', ';', ' ', '\n', '\r'];

    public static IReadOnlyList<string> CuratedRfWhiteSniDomains { get; } =
    [
        "www.microsoft.com",
        "learn.microsoft.com",
        "www.apple.com",
        "www.amd.com",
        "www.nvidia.com",
        "cdn.jsdelivr.net",
        "www.cloudflare.com",
        "dl.google.com",
        "st.ozone.ru",
        "yastatic.net",
        "www.wildberries.ru",
        "vk.com",
    ];

    public static IReadOnlyList<string> ExtractSniDomainsFromConfig(string rawConfig)
    {
        if (string.IsNullOrWhiteSpace(rawConfig))
        {
            return [];
        }

        var profiles = VpnConfigParser.ParseSubscription(rawConfig);
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in profiles)
        {
            if (!string.IsNullOrWhiteSpace(p.Tls.Sni))
            {
                var sni = p.Tls.Sni.Trim().ToLowerInvariant();
                if (sni.Contains('.', StringComparison.Ordinal) && !IPAddress.TryParse(sni, out _))
                {
                    set.Add(sni);
                }
            }

            if (!string.IsNullOrWhiteSpace(p.ServerHost))
            {
                var host = p.ServerHost.Trim().ToLowerInvariant();
                if (host.Contains('.', StringComparison.Ordinal) && !IPAddress.TryParse(host, out _))
                {
                    set.Add(host);
                }
            }
        }

        return set.ToList();
    }

    public static IReadOnlyList<string> BuildSlash24Addresses(string targetIp, int maxCount = 64)
    {
        if (!IPAddress.TryParse(targetIp.Trim(), out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return [];
        }

        var bytes = ip.GetAddressBytes();
        if (IsPrivateIpv4(bytes))
        {
            return [];
        }

        var prefix = $"{bytes[0]}.{bytes[1]}.{bytes[2]}";
        var center = bytes[3];
        var candidates = new List<int>();

        for (var delta = 1; delta < 254 && candidates.Count < maxCount; delta++)
        {
            var low = center - delta;
            var high = center + delta;
            if (low >= 1 && low <= 254 && low != center)
            {
                candidates.Add(low);
            }
            if (high >= 1 && high <= 254 && high != center && candidates.Count < maxCount)
            {
                candidates.Add(high);
            }
        }

        return candidates.Select(last => $"{prefix}.{last}").ToList();
    }

    public static async Task<IReadOnlyList<SubnetSniNeighbor>> ScanSlash24Async(
        string targetIp,
        int maxHosts = 48,
        int concurrency = 16,
        int timeoutMs = 1800,
        CancellationToken cancellationToken = default)
    {
        var ips = BuildSlash24Addresses(targetIp, maxHosts);
        if (ips.Count == 0)
        {
            return [];
        }

        var bag = new ConcurrentBag<SubnetSniNeighbor>();
        using var gate = new SemaphoreSlim(Math.Clamp(concurrency, 1, 32));

        var tasks = ips.Select(async neighborIp =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var found = await ProbeHostForRealitySniAsync(neighborIp, timeoutMs, cancellationToken)
                    .ConfigureAwait(false);
                if (found is not null)
                {
                    bag.Add(found);
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);

        return bag
            .OrderByDescending(x => x.IsRealityReady)
            .ThenBy(x => x.HandshakeMs)
            .ToList();
    }

    /// <summary>
    /// Комбинированный перебор SNI по 3 источникам:
    /// 1) SNI и домены из текущей подписки/конфига,
    /// 2) База белых доменов РФ и глобальных CDN + пользовательские домены через запятую,
    /// 3) Соседи подсети /24 целевого VPS.
    /// </summary>
    public static async Task<IReadOnlyList<SubnetSniNeighbor>> HuntMultiSourceSniAsync(
        string rawConfig,
        string? targetVpsHost,
        bool includeSubscriptionSnis = true,
        bool includeRfWhitelist = true,
        bool includeSlash24 = true,
        string? customDomainsCsv = null,
        int timeoutMs = 1900,
        CancellationToken cancellationToken = default)
    {
        var bag = new ConcurrentBag<SubnetSniNeighbor>();
        var domainCandidates = new List<(string Domain, string SourceLabel)>();
        var seenDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (includeSubscriptionSnis)
        {
            foreach (var d in ExtractSniDomainsFromConfig(rawConfig))
            {
                if (seenDomains.Add(d))
                {
                    domainCandidates.Add((d, "Из вашей подписки"));
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(customDomainsCsv))
        {
            var parts = customDomainsCsv.Split(DomainSeparators, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var clean = part.Trim().ToLowerInvariant();
                if (clean.Contains('.', StringComparison.Ordinal) &&
                    !IPAddress.TryParse(clean, out _) &&
                    seenDomains.Add(clean))
                {
                    domainCandidates.Add((clean, "Свой домен"));
                }
            }
        }

        if (includeRfWhitelist)
        {
            foreach (var d in CuratedRfWhiteSniDomains)
            {
                if (seenDomains.Add(d))
                {
                    domainCandidates.Add((d, "Белый список РФ / CDN"));
                }
            }
        }

        using var gate = new SemaphoreSlim(12);
        var domainTasks = domainCandidates.Select(async candidate =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var probed = await ProbeDomainForRealitySniAsync(
                        candidate.Domain,
                        candidate.SourceLabel,
                        timeoutMs,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (probed is not null)
                {
                    bag.Add(probed);
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(domainTasks).ConfigureAwait(false);

        if (includeSlash24 && !string.IsNullOrWhiteSpace(targetVpsHost))
        {
            try
            {
                string? targetIpv4 = null;
                var trimmedHost = targetVpsHost.Trim();
                if (IPAddress.TryParse(trimmedHost, out var parsedIp) &&
                    parsedIp.AddressFamily == AddressFamily.InterNetwork)
                {
                    targetIpv4 = parsedIp.ToString();
                }
                else
                {
                    var addrs = await Dns.GetHostAddressesAsync(trimmedHost, cancellationToken).ConfigureAwait(false);
                    targetIpv4 = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();
                }

                if (!string.IsNullOrWhiteSpace(targetIpv4))
                {
                    var slash24 = await ScanSlash24Async(targetIpv4, maxHosts: 32, concurrency: 12, timeoutMs: timeoutMs, cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    foreach (var n in slash24)
                    {
                        bag.Add(n);
                    }
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
            {
                // ignore DNS/subnet errors if domain candidates already succeeded
            }
        }

        return bag
            .GroupBy(x => x.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.IsRealityReady).ThenBy(x => x.HandshakeMs).First())
            .OrderByDescending(x => x.IsRealityReady)
            .ThenBy(x => x.HandshakeMs)
            .ToList();
    }

    public static async Task<SubnetSniNeighbor?> ProbeDomainForRealitySniAsync(
        string domain,
        string sourceLabel = "Проверка домена",
        int timeoutMs = 1900,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var cleanDomain = domain.Trim().ToLowerInvariant();
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            var addresses = await Dns.GetHostAddressesAsync(cleanDomain, cts.Token).ConfigureAwait(false);
            var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                     ?? addresses.FirstOrDefault();
            if (ip is null)
            {
                return null;
            }

            using var tcp = new TcpClient();
            await tcp.ConnectAsync(ip, 443, cts.Token).ConfigureAwait(false);

            var chainValid = false;
            string? issuer = null;

#pragma warning disable CA5359
            using var ssl = new SslStream(tcp.GetStream(), false, (_, cert, _, errors) =>
            {
                chainValid = errors == SslPolicyErrors.None;
                issuer = cert?.Issuer;
                return true;
            });
#pragma warning restore CA5359

            var authOpts = new SslClientAuthenticationOptions
            {
                TargetHost = cleanDomain,
                EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
            };

            await ssl.AuthenticateAsClientAsync(authOpts, cts.Token).ConfigureAwait(false);
            sw.Stop();

            var isTls13 = ssl.SslProtocol == SslProtocols.Tls13;
            var alpn = ssl.NegotiatedApplicationProtocol == SslApplicationProtocol.Http2
                ? "h2"
                : ssl.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11
                    ? "http/1.1"
                    : "none";

            var realityReady = isTls13 && alpn == "h2" && chainValid;

            return new SubnetSniNeighbor(
                ip.ToString(),
                cleanDomain,
                ssl.SslProtocol.ToString(),
                alpn,
                chainValid,
                sw.ElapsedMilliseconds,
                issuer,
                realityReady,
                sourceLabel);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException or ArgumentException)
        {
            return null;
        }
    }

    public static async Task<SubnetSniNeighbor?> ProbeHostForRealitySniAsync(
        string ipAddress,
        int timeoutMs = 1800,
        CancellationToken cancellationToken = default)
    {
        // Шаг 1: Быстрое TCP-подключение на :443 и извлечение CN/SAN из сертификата по умолчанию
        string? discoveredDomain = null;
        try
        {
            using var tcp1 = new TcpClient();
            using var cts1 = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts1.CancelAfter(timeoutMs);

            await tcp1.ConnectAsync(ipAddress, 443, cts1.Token).ConfigureAwait(false);
            // Шаг 1 выполняется по сырому IP ради извлечения CN/SAN из сертификата по умолчанию; прикладные данные не отправляются.
#pragma warning disable CA5359
            using var ssl1 = new SslStream(tcp1.GetStream(), false, (_, _, _, _) => true);
#pragma warning restore CA5359
            var authOpts1 = new SslClientAuthenticationOptions
            {
                TargetHost = ipAddress,
                EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
            };
            await ssl1.AuthenticateAsClientAsync(authOpts1, cts1.Token).ConfigureAwait(false);

            if (ssl1.RemoteCertificate is not null)
            {
                using var cert2 = new X509Certificate2(ssl1.RemoteCertificate);
                discoveredDomain = ExtractCleanDomainFromCertificate(cert2);
            }
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException or CryptographicException or ArgumentException)
        {
            return null;
        }

        // Если сертификат не отдал домен, пробуем PTR
        if (string.IsNullOrWhiteSpace(discoveredDomain))
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(ipAddress, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(entry.HostName) &&
                    entry.HostName.Contains('.', StringComparison.Ordinal) &&
                    !IPAddress.TryParse(entry.HostName, out _))
                {
                    discoveredDomain = entry.HostName.TrimEnd('.').ToLowerInvariant();
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
            {
                // ignore PTR failure
            }
        }

        if (string.IsNullOrWhiteSpace(discoveredDomain))
        {
            return null;
        }

        // Шаг 2: Полноценная валидация TLS 1.3 + ALPN h2 + валидность цепочки с именем SNI = discoveredDomain
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp2 = new TcpClient();
            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts2.CancelAfter(timeoutMs);

            await tcp2.ConnectAsync(ipAddress, 443, cts2.Token).ConfigureAwait(false);
            var chainValid = false;
            string? issuer = null;

            // Шаг 2 фиксирует результат проверки цепочки доверия в chainValid без отправки прикладных данных.
#pragma warning disable CA5359
            using var ssl2 = new SslStream(tcp2.GetStream(), false, (_, cert, _, errors) =>
            {
                chainValid = errors == SslPolicyErrors.None;
                issuer = cert?.Issuer;
                return true;
            });
#pragma warning restore CA5359

            var authOpts2 = new SslClientAuthenticationOptions
            {
                TargetHost = discoveredDomain,
                EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
            };

            await ssl2.AuthenticateAsClientAsync(authOpts2, cts2.Token).ConfigureAwait(false);
            sw.Stop();

            var isTls13 = ssl2.SslProtocol == SslProtocols.Tls13;
            var alpn = ssl2.NegotiatedApplicationProtocol == SslApplicationProtocol.Http2
                ? "h2"
                : ssl2.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11
                    ? "http/1.1"
                    : "none";

            var realityReady = isTls13 && alpn == "h2" && chainValid;

            return new SubnetSniNeighbor(
                ipAddress,
                discoveredDomain,
                ssl2.SslProtocol.ToString(),
                alpn,
                chainValid,
                sw.ElapsedMilliseconds,
                issuer,
                realityReady,
                "Сосед подсети /24");
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException or ArgumentException)
        {
            return null;
        }
    }

    private static string? ExtractCleanDomainFromCertificate(X509Certificate2 cert)
    {
        var simpleName = cert.GetNameInfo(X509NameType.DnsFromAlternativeName, false);
        if (string.IsNullOrWhiteSpace(simpleName))
        {
            simpleName = cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        if (string.IsNullOrWhiteSpace(simpleName))
        {
            return null;
        }

        var cleaned = simpleName.Trim().ToLowerInvariant();
        if (cleaned.StartsWith("*.", StringComparison.Ordinal))
        {
            cleaned = cleaned[2..];
        }

        if (!cleaned.Contains('.', StringComparison.Ordinal) ||
            cleaned.Contains(' ', StringComparison.Ordinal) ||
            IPAddress.TryParse(cleaned, out _))
        {
            return null;
        }

        return cleaned;
    }

    private static bool IsPrivateIpv4(byte[] b)
    {
        if (b.Length != 4) return true;
        if (b[0] is 0 or 10 or 127) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
        if (b[0] >= 224) return true;
        return false;
    }
}
