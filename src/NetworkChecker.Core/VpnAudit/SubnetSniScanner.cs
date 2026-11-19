using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetworkChecker.Core.VpnAudit;

public sealed record RawTlsServerHelloResult(
    bool HandshakeReceived,
    bool IsTls13,
    bool IsHelloRetryRequest,
    ushort CipherSuite,
    string? NegotiatedAlpn);

public sealed record SubnetSniNeighbor(
    string IpAddress,
    string Domain,
    string TlsProtocol,
    string Alpn,
    bool CertChainValid,
    long HandshakeMs,
    string? CertIssuer,
    bool IsRealityReady,
    string SourceLabel = "Сосед подсети /24",
    string? VerdictReason = null);

/// <summary>
/// Нативный многопоточный охотник и сканер SNI для конфигураций и подписок:
/// 1) Проверка всех доменов/SNI из текущей подписки или конфига на связку TLS 1.3 + ALPN h2 + валидный сертификат + пинг,
/// 2) Перебор базы белых доменов РФ и глобальных CDN, не блокируемых ТСПУ,
/// 3) Сканирование соседних IP в подсети /24 целевого VPS (для «родного» Reality SNI того же дата-центра).
/// Включает прямой RFC 8446 ClientHello зонд TLS 1.3 поверх TCP, чтобы корректно определять TLS 1.3 даже на Windows 10 (где SChannel ограничен TLS 1.2).
/// </summary>
public static class SubnetSniScanner
{
    private static readonly char[] DomainSeparators = [',', ';', ' ', '\n', '\r'];
    private static readonly byte[] AlpnHttp11Bytes = "http/1.1"u8.ToArray();

    // RFC 8446 Section 4.1.3 — специальный ServerRandom, обозначающий HelloRetryRequest (существует только в TLS 1.3)
    private static readonly byte[] HelloRetryRequestRandom =
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];

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

        var prefix = string.Create(CultureInfo.InvariantCulture, $"{bytes[0]}.{bytes[1]}.{bytes[2]}");
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

        return candidates.Select(last => string.Create(CultureInfo.InvariantCulture, $"{prefix}.{last}")).ToList();
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
        int timeoutMs = 2400,
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

        using var gate = new SemaphoreSlim(10);
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
        int timeoutMs = 2400,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var cleanDomain = domain.Trim().ToLowerInvariant();
        try
        {
            using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            dnsCts.CancelAfter(timeoutMs);

            var addresses = await Dns.GetHostAddressesAsync(cleanDomain, dnsCts.Token).ConfigureAwait(false);
            var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                     ?? addresses.FirstOrDefault();
            if (ip is null)
            {
                return null;
            }

            return await ProbeEndpointWithSniAsync(ip, cleanDomain, sourceLabel, timeoutMs, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException or ArgumentException)
        {
            return null;
        }
    }

    public static async Task<SubnetSniNeighbor?> ProbeHostForRealitySniAsync(
        string ipAddress,
        int timeoutMs = 2200,
        CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(ipAddress.Trim(), out var parsedIp))
        {
            return null;
        }

        // Шаг 1: Быстрое TCP-подключение на :443 и извлечение CN/SAN из сертификата по умолчанию
        string? discoveredDomain = null;
        try
        {
            using var tcp1 = new TcpClient(parsedIp.AddressFamily);
            using var cts1 = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts1.CancelAfter(timeoutMs);

            await tcp1.ConnectAsync(parsedIp, 443, cts1.Token).ConfigureAwait(false);
#pragma warning disable CA5359
            using var ssl1 = new SslStream(tcp1.GetStream(), false, (_, _, _, _) => true);
#pragma warning restore CA5359
            var authOpts1 = new SslClientAuthenticationOptions
            {
                TargetHost = ipAddress,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
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

        return await ProbeEndpointWithSniAsync(parsedIp, discoveredDomain, "Сосед подсети /24", timeoutMs, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<SubnetSniNeighbor?> ProbeEndpointWithSniAsync(
        IPAddress ip,
        string targetDomain,
        string sourceLabel,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            using var tcp = new TcpClient(ip.AddressFamily);
            await tcp.ConnectAsync(ip, 443, cts.Token).ConfigureAwait(false);

            var chainValid = false;
            string? issuer = null;

            // Диагностический зонд: прикладные данные не отправляются; игнорируем только недоступность CRL/OCSP за ТСПУ/ВПН.
#pragma warning disable CA5359
            using var ssl = new SslStream(tcp.GetStream(), false, (_, cert, chain, errors) =>
            {
                chainValid = EvaluateCertificateTrust(chain, errors);
                issuer = cert?.Issuer;
                return true;
            });
#pragma warning restore CA5359

            var authOpts = new SslClientAuthenticationOptions
            {
                TargetHost = targetDomain,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
            };

            await ssl.AuthenticateAsClientAsync(authOpts, cts.Token).ConfigureAwait(false);
            sw.Stop();

            var isTls13 = ssl.SslProtocol == SslProtocols.Tls13;
            var tlsLabel = isTls13
                ? "TLS 1.3"
                : ssl.SslProtocol == SslProtocols.Tls12
                    ? "TLS 1.2"
                    : ssl.SslProtocol.ToString();

            var alpn = ssl.NegotiatedApplicationProtocol == SslApplicationProtocol.Http2
                ? "h2"
                : ssl.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11
                    ? "http/1.1"
                    : "none";

            // На Windows 10 системный SChannel часто откатывается на TLS 1.2 даже для TLS 1.3 серверов.
            // Выполняем прямой RFC 8446 ClientHello зонд поверх TCP, чтобы точно подтвердить поддержку TLS 1.3 сервером.
            if (!isTls13)
            {
                var rawTls13 = await ProbeRawTls13Async(ip, targetDomain, Math.Min(timeoutMs, 1800), cancellationToken)
                    .ConfigureAwait(false);
                if (rawTls13 is { IsTls13: true })
                {
                    isTls13 = true;
                    tlsLabel = "TLS 1.3";
                }
            }

            var realityReady = isTls13 && string.Equals(alpn, "h2", StringComparison.OrdinalIgnoreCase) && chainValid;
            var verdictReason = BuildVerdictReason(isTls13, alpn, chainValid, tlsLabel);

            return new SubnetSniNeighbor(
                ip.ToString(),
                targetDomain,
                tlsLabel,
                alpn,
                chainValid,
                sw.ElapsedMilliseconds,
                issuer,
                realityReady,
                sourceLabel,
                verdictReason);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException or ArgumentException)
        {
            return null;
        }
    }

    public static bool EvaluateCertificateTrust(X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if ((errors & (SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0)
        {
            return false;
        }

        if (errors == SslPolicyErrors.RemoteCertificateChainErrors && chain is not null)
        {
            var statuses = chain.ChainStatus;
            if (statuses.Length == 0)
            {
                return true;
            }

            // За ТСПУ / ВПН серверы CRL/OCSP часто не отвечают, и SChannel выставляет RevocationStatusUnknown / OfflineRevocation.
            return statuses.All(s => s.Status is
                X509ChainStatusFlags.NoError or
                X509ChainStatusFlags.RevocationStatusUnknown or
                X509ChainStatusFlags.OfflineRevocation);
        }

        return false;
    }

    private static string BuildVerdictReason(bool isTls13, string alpn, bool chainValid, string tlsLabel)
    {
        if (isTls13 && string.Equals(alpn, "h2", StringComparison.OrdinalIgnoreCase) && chainValid)
        {
            return "ПОДХОДИТ ДЛЯ REALITY (TLS 1.3 + h2)";
        }

        if (isTls13 && !chainValid)
        {
            return "НЕ ПОДХОДИТ: ошибка сертификата (имя или цепочка)";
        }

        if (isTls13 && !string.Equals(alpn, "h2", StringComparison.OrdinalIgnoreCase))
        {
            return $"ЧАСТИЧНО: TLS 1.3 без h2 (ALPN: {alpn})";
        }

        return $"НЕ ПОДХОДИТ: сервер без TLS 1.3 ({tlsLabel})";
    }

    /// <summary>
    /// Отправляет сырой RFC 8446 TLS 1.3 ClientHello (с SNI, supported_versions=0x0304, ALPN=h2, x25519 key_share)
    /// и проверяет, отвечает ли сервер ServerHello с выбранной версией TLS 1.3 (0x0304).
    /// </summary>
    public static async Task<RawTlsServerHelloResult?> ProbeRawTls13Async(
        IPAddress ip,
        string sniDomain,
        int timeoutMs = 1800,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            using var tcp = new TcpClient(ip.AddressFamily);
            await tcp.ConnectAsync(ip, 443, cts.Token).ConfigureAwait(false);
            await using var stream = tcp.GetStream();

            var clientHello = BuildTls13ClientHello(sniDomain);
            await stream.WriteAsync(clientHello, cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);

            // Читаем заголовок TLS-записи (5 байт), затем тело записи
            var header = new byte[5];
            if (!await ReadExactAsync(stream, header, cts.Token).ConfigureAwait(false))
            {
                return null;
            }

            if (header[0] != 0x16)
            {
                return new RawTlsServerHelloResult(false, false, false, 0, null);
            }

            var recordLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
            if (recordLength == 0 || recordLength > 16384)
            {
                return null;
            }

            var fullRecord = new byte[5 + recordLength];
            Buffer.BlockCopy(header, 0, fullRecord, 0, 5);
            if (!await ReadExactAsync(stream, fullRecord.AsMemory(5, recordLength), cts.Token).ConfigureAwait(false))
            {
                return null;
            }

            return ParseTls13ServerHello(fullRecord);
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException or ArgumentException)
        {
            return null;
        }
    }

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], ct).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }
            total += read;
        }
        return true;
    }

    public static byte[] BuildTls13ClientHello(string sniDomain)
    {
        var hostBytes = Encoding.ASCII.GetBytes(sniDomain.Trim().ToLowerInvariant());

        // Собираем расширения
        var extensions = new List<byte>(256);

        // 1. server_name (0x0000)
        if (hostBytes.Length > 0 && hostBytes.Length <= 253)
        {
            var serverNameListLen = 3 + hostBytes.Length;
            WriteUInt16(extensions, 0x0000);
            WriteUInt16(extensions, (ushort)(2 + serverNameListLen));
            WriteUInt16(extensions, (ushort)serverNameListLen);
            extensions.Add(0x00); // host_name
            WriteUInt16(extensions, (ushort)hostBytes.Length);
            extensions.AddRange(hostBytes);
        }

        // 2. supported_groups (0x000A): x25519 (0x001D), secp256r1 (0x0017)
        WriteUInt16(extensions, 0x000A);
        WriteUInt16(extensions, 6);
        WriteUInt16(extensions, 4);
        WriteUInt16(extensions, 0x001D);
        WriteUInt16(extensions, 0x0017);

        // 3. ec_point_formats (0x000B): uncompressed (0x00)
        WriteUInt16(extensions, 0x000B);
        WriteUInt16(extensions, 2);
        extensions.Add(1);
        extensions.Add(0);

        // 4. signature_algorithms (0x000D)
        WriteUInt16(extensions, 0x000D);
        WriteUInt16(extensions, 14);
        WriteUInt16(extensions, 12);
        WriteUInt16(extensions, 0x0403); // ecdsa_secp256r1_sha256
        WriteUInt16(extensions, 0x0804); // rsa_pss_rsae_sha256
        WriteUInt16(extensions, 0x0401); // rsa_pkcs1_sha256
        WriteUInt16(extensions, 0x0503); // ecdsa_secp384r1_sha384
        WriteUInt16(extensions, 0x0805); // rsa_pss_rsae_sha384
        WriteUInt16(extensions, 0x0501); // rsa_pkcs1_sha384

        // 5. ALPN (0x0010): h2, http/1.1
        WriteUInt16(extensions, 0x0010);
        WriteUInt16(extensions, 14);
        WriteUInt16(extensions, 12);
        extensions.Add(2);
        extensions.Add((byte)'h');
        extensions.Add((byte)'2');
        extensions.Add(8);
        extensions.AddRange(AlpnHttp11Bytes);

        // 6. supported_versions (0x002B): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
        WriteUInt16(extensions, 0x002B);
        WriteUInt16(extensions, 5);
        extensions.Add(4);
        WriteUInt16(extensions, 0x0304);
        WriteUInt16(extensions, 0x0303);

        // 7. psk_key_exchange_modes (0x002D): psk_dhe_ke (0x01)
        WriteUInt16(extensions, 0x002D);
        WriteUInt16(extensions, 2);
        extensions.Add(1);
        extensions.Add(1);

        // 8. key_share (0x0033): X25519 (0x001D), 32-byte key
        var fakePubKey = new byte[32];
        RandomNumberGenerator.Fill(fakePubKey);
        fakePubKey[0] |= 1; // гарантируем ненулевую координату
        WriteUInt16(extensions, 0x0033);
        WriteUInt16(extensions, 38);
        WriteUInt16(extensions, 36);
        WriteUInt16(extensions, 0x001D);
        WriteUInt16(extensions, 32);
        extensions.AddRange(fakePubKey);

        // Тело ClientHello
        var body = new List<byte>(128 + extensions.Count);
        WriteUInt16(body, 0x0303); // legacy_version = TLS 1.2

        var random = new byte[32];
        RandomNumberGenerator.Fill(random);
        body.AddRange(random);

        // legacy_session_id = 32 bytes (RFC 8446 middlebox compatibility)
        var sessionId = new byte[32];
        RandomNumberGenerator.Fill(sessionId);
        body.Add(32);
        body.AddRange(sessionId);

        // Cipher suites (TLS 1.3 + TLS 1.2 ECDHE)
        WriteUInt16(body, 10);
        WriteUInt16(body, 0x1301); // TLS_AES_128_GCM_SHA256
        WriteUInt16(body, 0x1302); // TLS_AES_256_GCM_SHA384
        WriteUInt16(body, 0x1303); // TLS_CHACHA20_POLY1305_SHA256
        WriteUInt16(body, 0xC02F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        WriteUInt16(body, 0xC02B); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

        // Compression methods: null
        body.Add(1);
        body.Add(0);

        // Extensions length + bytes
        WriteUInt16(body, (ushort)extensions.Count);
        body.AddRange(extensions);

        // Handshake header (1 byte type + 3 bytes length)
        var handshakeLen = body.Count;
        var recordLen = 4 + handshakeLen;
        var packet = new List<byte>(5 + recordLen)
        {
            0x16, // ContentType: Handshake
            0x03,
            0x01, // Record legacy version: TLS 1.0
            (byte)(recordLen >> 8),
            (byte)(recordLen & 0xFF),
            0x01, // HandshakeType: ClientHello
            (byte)((handshakeLen >> 16) & 0xFF),
            (byte)((handshakeLen >> 8) & 0xFF),
            (byte)(handshakeLen & 0xFF),
        };
        packet.AddRange(body);
        return [.. packet];
    }

    public static RawTlsServerHelloResult ParseTls13ServerHello(ReadOnlySpan<byte> data)
    {
        if (data.Length < 9 || data[0] != 0x16)
        {
            return new RawTlsServerHelloResult(false, false, false, 0, null);
        }

        var recordLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(3, 2));
        var recordEnd = Math.Min(data.Length, 5 + recordLen);
        if (recordEnd < 9 || data[5] != 0x02) // 0x02 = ServerHello
        {
            return new RawTlsServerHelloResult(false, false, false, 0, null);
        }

        var hsLen = (data[6] << 16) | (data[7] << 8) | data[8];
        var hsEnd = Math.Min(recordEnd, 9 + hsLen);
        var pos = 9;

        // legacy_version (2) + random (32) + session_id_len (1)
        if (pos + 2 + 32 + 1 > hsEnd)
        {
            return new RawTlsServerHelloResult(false, false, false, 0, null);
        }

        pos += 2;
        var serverRandom = data.Slice(pos, 32);
        var isHrr = serverRandom.SequenceEqual(HelloRetryRequestRandom);
        pos += 32;

        var sessionIdLen = data[pos++];
        if (pos + sessionIdLen + 3 > hsEnd)
        {
            return new RawTlsServerHelloResult(false, false, false, 0, null);
        }

        pos += sessionIdLen;
        var cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
        pos += 2;
        pos += 1; // compression_method

        var isTls13 = isHrr || cipherSuite is 0x1301 or 0x1302 or 0x1303 or 0x1304 or 0x1305;
        string? alpn = null;

        if (pos + 2 <= hsEnd)
        {
            var extTotalLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
            pos += 2;
            var extEnd = Math.Min(hsEnd, pos + extTotalLen);

            while (pos + 4 <= extEnd)
            {
                var extType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
                var extLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos + 2, 2));
                pos += 4;
                if (pos + extLen > extEnd)
                {
                    break;
                }

                if (extType == 0x002B && extLen == 2)
                {
                    var selectedVersion = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
                    isTls13 = selectedVersion == 0x0304;
                }
                else if (extType == 0x0010 && extLen >= 4)
                {
                    var protoLen = data[pos + 2];
                    if (3 + protoLen <= extLen)
                    {
                        alpn = Encoding.ASCII.GetString(data.Slice(pos + 3, protoLen));
                    }
                }

                pos += extLen;
            }
        }

        return new RawTlsServerHelloResult(true, isTls13, isHrr, cipherSuite, alpn);
    }

    private static void WriteUInt16(List<byte> dst, ushort value)
    {
        dst.Add((byte)(value >> 8));
        dst.Add((byte)(value & 0xFF));
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
