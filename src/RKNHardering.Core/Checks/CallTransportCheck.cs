using System.Diagnostics;
using System.Net;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;

namespace RKNHardering.Core.Checks;

/// <summary>
/// STUN/MTProto: доступность UDP-транспорта и внешний адрес по UDP.
/// Если TCP-путь проксирован, а UDP отвечает напрямую — это утечка, которую методика ловит.
/// </summary>
public sealed class CallTransportCheck : ICheck
{
    private readonly IHttpProbe _http;

    public CallTransportCheck(IHttpProbe http) => _http = http;

    public CheckCategory Category => CheckCategory.CallTransport;
    public string Title => "UDP / STUN-транспорт";
    public string Subtitle => "Доступность UDP и адрес выхода через STUN";
    public int Weight => 10;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromSeconds(context.Options.RequestTimeoutSeconds);

        var working = new List<(string Server, IPEndPoint Endpoint)>();
        foreach (var server in context.Options.StunServers)
        {
            ct.ThrowIfCancellationRequested();
            context.Progress($"STUN: {server}");
            var endpoint = await StunClient.BindAsync(server, timeout, ct).ConfigureAwait(false);
            if (endpoint is null) continue;
            working.Add((server, endpoint));
            context.CollectIp($"STUN · {server.Split(':')[0]}", endpoint.Address.ToString(), null, "UDP-выход");
        }

        metrics.Add(new Metric("STUN-серверов ответило", $"{working.Count} из {context.Options.StunServers.Count}"));
        if (working.Count > 0)
        {
            metrics.Add(new Metric("Внешний адрес (UDP)", Masking.Ip(working[0].Endpoint.Address.ToString()),
                "адрес, который видит NAT для UDP"));
        }

        if (working.Count == 0)
        {
            findings.Add(Finding.Warning("UDP полностью недоступен",
                "Ни один STUN-сервер не ответил. Так бывает при блокировке UDP оператором или при прокси, который заворачивает только TCP.",
                string.Join(", ", context.Options.StunServers)));
        }
        else
        {
            findings.Add(Finding.Info("UDP-транспорт работает",
                $"Ответили {working.Count} STUN-серверов. Голосовые вызовы и QUIC пойдут напрямую."));
        }

        // Порт в ответе STUN: если порт сильно отличается от 51820/4500/3478 — NAT не «симметричный», но это лишь информативно.
        if (working.Count > 1)
        {
            var addresses = working.Select(w => w.Endpoint.Address.ToString()).Distinct().Count();
            var ports = working.Select(w => w.Endpoint.Port).Distinct().Count();
            if (ports > 1)
            {
                findings.Add(Finding.Notice("STUN-серверы видят разные порты",
                    "Разные внешние порты для одного узла — симметричный NAT. Нормально для мобильных операторов, нетипично для домашнего Wi-Fi.",
                    string.Join(", ", working.Select(w => w.Server + "=" + w.Endpoint.Port))));
            }
            if (addresses > 1)
            {
                findings.Add(Finding.Warning("STUN-серверы видят разные адреса",
                    "UDP-трафик выходит через разные адреса — признак балансировки или цепочки узлов.",
                    string.Join(", ", working.Select(w => w.Endpoint.Address.ToString()))));
            }
        }

        // Сравнение UDP-адреса с HTTPS-адресом: расхождение = прокси только для TCP.
        var httpResult = await _http.GetAsync(new Uri("https://api.ipify.org?format=json"), timeout, ignoreProxy: false, ct).ConfigureAwait(false);
        var httpInfo = httpResult.Success && httpResult.Body is not null ? GeoIpParser.Parse(httpResult.Body) : null;
        if (httpInfo?.Ip is not null)
        {
            context.CollectIp("HTTPS (TCP) · ipify", httpInfo.Ip, null, "TCP-путь");
            metrics.Add(new Metric("Внешний адрес (TCP)", Masking.Ip(httpInfo.Ip), "адрес для HTTP(S)"));
            if (working.Count > 0)
            {
                var udpIp = working[0].Endpoint.Address.ToString();
                if (udpIp != httpInfo.Ip)
                {
                    findings.Add(Finding.Critical(
                        "TCP и UDP выходят через разные адреса",
                        "Классическая утечка: прокси перехватывает только TCP, UDP уходит напрямую с домашнего IP.",
                        $"UDP={Masking.Ip(udpIp)}, TCP={Masking.Ip(httpInfo.Ip)}"));
                }
            }
        }

        // MTProto-проба Telegram (доступность DC) — как индикатор прямого доступа.
        var mtprotoOk = await ProbeMtProtoAsync(ct).ConfigureAwait(false);
        metrics.Add(new Metric("Telegram DC (MTProto)", mtprotoOk ? "доступен" : "не ответил"));

        var detected = findings.Any(f => f.Severity == Severity.Critical);
        var review = findings.Any(f => f.Severity == Severity.Warning);

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = detected ? CheckStatus.Detected : review ? CheckStatus.NeedsReview : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }

    private static async Task<bool> ProbeMtProtoAsync(CancellationToken ct)
    {
        var result = await ConnectivityProbes.TcpConnectAsync("149.154.167.51", 443, TimeSpan.FromSeconds(4), ct).ConfigureAwait(false);
        return result.Success;
    }
}
