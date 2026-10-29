using System.Diagnostics;
using System.Net;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;

namespace RKNHardering.Core.Checks;

/// <summary>
/// DNS → TCP → TLS pipeline по набору доменов. Позволяет отличить блокировку DPI от
/// отсутствия маршрута и от подмены сертификата (MITM-прокси).
/// </summary>
public sealed class DomainReachabilityCheck : ICheck
{
    public DomainReachabilityCheck() { }

    public CheckCategory Category => CheckCategory.DomainReachability;
    public string Title => "Доступность доменов";
    public string Subtitle => "DNS → TCP → TLS: где именно ломается доступ";
    public int Weight => 10;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromSeconds(Math.Min(context.Options.RequestTimeoutSeconds, 6));

        var blockedDns = new List<string>();
        var blockedTcp = new List<string>();
        var blockedTls = new List<string>();
        var ok = new List<string>();
        var mitm = new List<string>();

        var tasks = context.Options.ReachabilityTargets.Select(async target =>
        {
            var addresses = await ConnectivityProbes.ResolveAsync(target, ct).ConfigureAwait(false);
            if (addresses.Count == 0) return (target, "dns", (string?)null, (TlsProbeResult?)null);

            var tcp = await ConnectivityProbes.TcpConnectAsync(target, 443, timeout, ct).ConfigureAwait(false);
            if (!tcp.Success) return (target, "tcp", tcp.Error, (TlsProbeResult?)null);

            var tls = await ConnectivityProbes.TlsHandshakeAsync(target, 443, timeout, ct).ConfigureAwait(false);
            return (target, tls.Success ? "ok" : "tls", tls.Error, (TlsProbeResult?)tls);
        }).ToArray();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        foreach (var (target, stage, error, tls) in results)
        {
            switch (stage)
            {
                case "dns":
                    blockedDns.Add(target);
                    findings.Add(Finding.Warning($"DNS не разрешает {target}",
                        "Имя не резолвится — блокировка на уровне DNS или провайдер-подмена.", error));
                    break;
                case "tcp":
                    blockedTcp.Add(target);
                    findings.Add(Finding.Notice($"TCP :443 недоступен для {target}",
                        "Имя резолвится, но соединение не устанавливается — характерно для DPI-блокировки по SNI/IP.", error));
                    break;
                case "tls":
                    blockedTls.Add(target);
                    findings.Add(Finding.Notice($"TLS-рукопожатие к {target} не состоялось",
                        "TCP открыт, но TLS не поднялся — возможен сброс по SNI (DPI) или MITM-прокси.", error));
                    break;
                default:
                    ok.Add(target);
                    if (tls?.Issuer is not null && IsSuspiciousIssuer(tls.Issuer, target))
                    {
                        mitm.Add(target);
                        findings.Add(Finding.Warning(
                            $"Подозрительный сертификат для {target}",
                            "Цепочка сертификата не похожа на публичный CA — признак перехвата TLS.",
                            $"{tls.Issuer} (до {tls.NotAfter:yyyy-MM-dd})"));
                    }
                    break;
            }
        }

        metrics.Add(new Metric("Доступно", $"{ok.Count}/{results.Length}", string.Join(", ", ok.Take(6))));
        if (blockedDns.Count > 0) metrics.Add(new Metric("Блокировка DNS", blockedDns.Count.ToString(), string.Join(", ", blockedDns)));
        if (blockedTcp.Count > 0) metrics.Add(new Metric("Блокировка TCP", blockedTcp.Count.ToString(), string.Join(", ", blockedTcp)));
        if (blockedTls.Count > 0) metrics.Add(new Metric("Блокировка TLS", blockedTls.Count.ToString(), string.Join(", ", blockedTls)));

        if (blockedDns.Count + blockedTcp.Count + blockedTls.Count == 0)
        {
            findings.Add(Finding.Info("Все проверенные домены доступны",
                "Ни DNS-, ни TCP-, ни TLS-блокировок не обнаружено. Если VPN активен, значит он не даёт заметного выигрыша по этим целям."));
        }

        var detected = mitm.Count > 0;
        var review = blockedDns.Count + blockedTcp.Count + blockedTls.Count > 0;

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

    private static bool IsSuspiciousIssuer(string issuer, string target)
    {
        string[] trustedHints =
        [
            "DigiCert", "Let's Encrypt", "GlobalSign", "Sectigo", "Google Trust", "Amazon", "Cloudflare",
            "Microsoft", "ISRG", "Thawte", "Entrust", "GoDaddy", "ZeroSSL", "Buypass", "HARICA", "Actalis",
            "Certum", "Comodo", "USERTrust", "GTS", "Apple", "Sectigo", "XRamp", "SecureTrust",
        ];
        if (trustedHints.Any(hint => issuer.Contains(hint, StringComparison.OrdinalIgnoreCase))) return false;
        return issuer.Contains("Kaspersky", StringComparison.OrdinalIgnoreCase)
               || issuer.Contains("ESET", StringComparison.OrdinalIgnoreCase)
               || issuer.Contains("Bitdefender", StringComparison.OrdinalIgnoreCase)
               || issuer.Contains("Avast", StringComparison.OrdinalIgnoreCase)
               || issuer.Contains("Zscaler", StringComparison.OrdinalIgnoreCase)
               || issuer.Contains("Fortinet", StringComparison.OrdinalIgnoreCase)
               || issuer.Contains("mitm", StringComparison.OrdinalIgnoreCase);
    }
}
