using System.Diagnostics;
using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// Наблюдательный модуль «транспорт и DPI» (вес 0, в индекс не входит).
/// Закрывает пробелы, которые есть в сетевых методах обнаружения, но отсутствовали в
/// инструменте: whoami-DNS и сравнение с DoH, UDP/443 (QUIC), сравнение TLS с разным SNI.
/// Все выводы — наблюдения: отсутствие UDP-ответа не доказывает блокировку QUIC, а срыв
/// TLS с «триггерным» SNI может быть реакцией самого сервера. ECH и JA3/JA4 здесь
/// намеренно не реализованы: для них нужен настоящий браузерный TLS-стек.
/// </summary>
public sealed class TransportObservationCheck(IHttpProbe http, ITransportProbes probes) : ICheck
{
    private readonly IHttpProbe _http = http;
    private readonly ITransportProbes _probes = probes;

    public CheckCategory Category => CheckCategory.TransportObservation;
    public string Title => "Транспорт и DPI (β)";
    public string Subtitle => "DNS-утечки и подмена, UDP/443 (QUIC), сравнение SNI";
    public int Weight => 0;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (context.Options.OfflineMode)
        {
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("Офлайн-режим", "Внешние и транспортные пробы отключены.")],
                Duration = sw.Elapsed,
            };
        }

        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromSeconds(Math.Min(Math.Max(context.Options.RequestTimeoutSeconds, 2), 8));

        // --- 1. Whoami-DNS: адрес резолвера против адреса выхода -----------------
        var egress = await ReadEgressIpAsync(timeout, ct).ConfigureAwait(false);
        metrics.Add(new Metric("Внешний адрес для сравнения", egress is null ? "нет данных" : Masking.Ip(egress)));
        foreach (var domain in context.Options.DnsLeakTestDomains.Take(3))
        {
            ct.ThrowIfCancellationRequested();
            var resolverIps = await _probes.ResolveSystemAsync(domain, ct).ConfigureAwait(false);
            metrics.Add(new Metric($"Whoami · {domain}",
                resolverIps.Count == 0 ? "нет ответа" : string.Join(", ", resolverIps.Take(3).Select(Masking.Ip)),
                "whoami-имя отвечает адресом рекурсивного резолвера"));
            if (resolverIps.Count == 0 || egress is null) continue;

            if (resolverIps.Contains(egress, StringComparer.OrdinalIgnoreCase))
            {
                findings.Add(Finding.Info($"Резолвер совпадает с адресом выхода ({domain})",
                    "Для этого имени DNS и HTTP вышли через один адрес; это не исключает проксирование других приложений."));
            }
            else
            {
                findings.Add(Finding.Notice($"DNS-резолвер отличается от адреса выхода ({domain})",
                    "Расхождение характерно для DNS-утечки или раздельных маршрутов, но объясняется и anycast-резолвером, " +
                    "корпоративным DNS, CDN, split tunneling и кешированием. Само по себе оно не доказывает обход.",
                    string.Join(", ", resolverIps.Take(3).Select(Masking.Ip))));
            }
        }

        // --- 2. Сравнение системного DNS с DoH -----------------------------------
        foreach (var domain in context.Options.DnsCompareDomains.Take(2))
        {
            ct.ThrowIfCancellationRequested();
            var system = await _probes.ResolveSystemAsync(domain, ct).ConfigureAwait(false);
            var doh = await _probes.ResolveDohAsync(domain, timeout, ct).ConfigureAwait(false);
            metrics.Add(new Metric($"DNS · {domain}",
                $"система: {(system.Count == 0 ? "нет данных" : system.Count.ToString(CultureInfo.InvariantCulture))}, " +
                $"DoH: {(doh.Count == 0 ? "нет данных" : doh.Count.ToString(CultureInfo.InvariantCulture))}",
                "сравнение ответов на одно и то же имя"));
            if (system.Count == 0 || doh.Count == 0)
            {
                metrics.Add(new Metric($"DoH · {domain}", "нет данных", "отсутствие ответа не считается совпадением"));
                continue;
            }
            if (!system.Intersect(doh, StringComparer.OrdinalIgnoreCase).Any())
            {
                findings.Add(Finding.Notice($"Системный DNS и DoH вернули разные адреса для {domain}",
                    "Возможна политика split DNS, подмена ответа или балансировка CDN. Тест не проверяет DNSSEC " +
                    "и не устанавливает, какой ответ достоверен.",
                    $"система: {string.Join(", ", system.Take(3).Select(Masking.Ip))}; DoH: {string.Join(", ", doh.Take(3).Select(Masking.Ip))}"));
            }
            else
            {
                findings.Add(Finding.Info($"Ответы DNS и DoH пересекаются ({domain})",
                    "Совпадение не доказывает отсутствие подмены: зонд обращается к публичному резолверу, а не к доверенному."));
            }
        }

        // --- 3. UDP/443: наблюдательная QUIC-проба -------------------------------
        var payload = BuildQuicLikeDatagram();
        foreach (var host in context.Options.QuicProbeTargets.Take(2))
        {
            ct.ThrowIfCancellationRequested();
            var udp = await _probes.UdpAsync(host, 443, payload, timeout, ct).ConfigureAwait(false);
            metrics.Add(new Metric($"UDP/443 · {host}",
                udp.ResponseReceived
                    ? $"ответ за {udp.Elapsed.TotalMilliseconds.ToString("F0", CultureInfo.InvariantCulture)} мс"
                    : "ответа нет",
                udp.Error ?? "QUIC-подобный датаграмм 1200 байт; ответ не гарантирован протоколом"));
        }
        findings.Add(Finding.Info("UDP/443: молчание не равно блокировке QUIC",
            "У UDP нет обязательного ответа на произвольный датаграмм; ТСПУ может сбрасывать пакеты после " +
            "обнаружения QUIC-признака, но отсутствие ответа объясняется и фильтрацией, и конфигурацией сервера. " +
            "Измеряется только факт ответа, без вывода о типе DPI."));

        // --- 4. Сравнение TLS с контрольным и «триггерным» SNI ------------------
        var controlHost = string.IsNullOrWhiteSpace(context.Options.SniControlHost)
            ? "example.com"
            : context.Options.SniControlHost;
        var control = await _probes.TlsAsync(controlHost, controlHost, timeout, ct).ConfigureAwait(false);
        metrics.Add(new Metric($"TLS · контрольный SNI ({controlHost})",
            control.Success ? $"успех за {control.Elapsed.TotalMilliseconds.ToString("F0", CultureInfo.InvariantCulture)} мс" : "не завершилось",
            control.Error));
        foreach (var sni in context.Options.SniProbeNames.Take(3))
        {
            ct.ThrowIfCancellationRequested();
            var trigger = await _probes.TlsAsync(controlHost, sni, timeout, ct).ConfigureAwait(false);
            metrics.Add(new Metric($"TLS · SNI {sni}",
                trigger.Success ? $"успех за {trigger.Elapsed.TotalMilliseconds.ToString("F0", CultureInfo.InvariantCulture)} мс" : "не завершилось",
                trigger.Error ?? $"тот же узел {controlHost}, другое имя в ClientHello"));
            if (control.Success && !trigger.Success)
            {
                findings.Add(Finding.Notice($"TLS с SNI «{sni}» не завершился при успешном контрольном",
                    "Характерно для фильтрации по SNI, но сервер вправе отвергнуть неизвестное имя, а зонд отличается " +
                    "от браузера по TLS-отпечатку. Это наблюдение, а не доказательство работы DPI.",
                    trigger.Error ?? "причина не установлена"));
            }
        }
        if (!control.Success)
        {
            findings.Add(Finding.Info("Контрольное TLS-соединение не завершилось",
                "Без успешного контрольного зонда сравнение SNI не интерпретируется: данные неполные."));
        }

        findings.Add(Finding.Info("Чего этот модуль не измеряет",
            "ECH, JA3/JA4, пассивный TCP/IP fingerprint (MSS/TTL), WebRTC и отпечаток браузера требуют " +
            "настоящего браузерного стека или серверной точки наблюдения; приложение их не эмулирует."));

        var review = findings.Any(f => f.Severity >= Severity.Notice);
        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = review ? CheckStatus.NeedsReview : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }

    private async Task<string?> ReadEgressIpAsync(TimeSpan timeout, CancellationToken ct)
    {
        var response = await _http.GetAsync(new Uri("https://api.ipify.org?format=json"), timeout, ignoreProxy: false, ct)
            .ConfigureAwait(false);
        return response.Success && response.Body is not null ? GeoIpParser.Parse(response.Body)?.Ip : null;
    }

    /// <summary>
    /// Датаграмм с открытым полем версии QUIC и размером 1200 байт — по описанию триггера
    /// ТСПУ в измерении IMC'22. Это не валидный Initial: ответ от сервера не ожидается.
    /// </summary>
    private static byte[] BuildQuicLikeDatagram()
    {
        var payload = new byte[1200];
        payload[0] = 0xC0;   // long header
        payload[1] = 0x00;   // version 0x00000001
        payload[2] = 0x00;
        payload[3] = 0x00;
        payload[4] = 0x01;
        for (var i = 8; i < payload.Length; i++) payload[i] = (byte)((i * 31) % 251);
        return payload;
    }
}
