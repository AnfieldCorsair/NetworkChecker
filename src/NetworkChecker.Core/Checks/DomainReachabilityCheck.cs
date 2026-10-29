using System.Diagnostics;
using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

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
        if (context.Options.OfflineMode)
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("Офлайн-режим", "Внешние сетевые проверки отключены.")],
                Duration = sw.Elapsed,
            };
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromSeconds(Math.Min(context.Options.RequestTimeoutSeconds, 6));

        if (context.Options.ReachabilityTargets.Count == 0)
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("Нет целей для проверки")],
                Duration = sw.Elapsed
            };

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
                        "Имя не разрешилось. Возможны сбой DNS, ошибка имени, отсутствие сети или фильтрация; причину тест не устанавливает.", error));
                    break;
                case "tcp":
                    blockedTcp.Add(target);
                    findings.Add(Finding.Notice($"TCP :443 недоступен для {target}",
                        "Имя разрешилось, но TCP-соединение не установлено. Причин может быть несколько; SNI ещё не отправлялся.", error));
                    break;
                case "tls":
                    blockedTls.Add(target);
                    findings.Add(Finding.Notice($"TLS-рукопожатие к {target} не состоялось",
                        "TCP открыт, но TLS не поднялся — возможен сброс по SNI (DPI) или MITM-прокси.", error));
                    break;
                default:
                    ok.Add(target);
                    if (tls is { ChainValid: false })
                    {
                        mitm.Add(target);
                        findings.Add(Finding.Warning($"Сертификат {target} не прошёл проверку платформы",
                            "Причина может быть в имени, сроке или цепочке доверия. Это не доказывает перехват.",
                            $"{tls.Issuer} (до {tls.NotAfter:yyyy-MM-dd})"));
                    }
                    else if (tls?.Issuer is not null && IsSuspiciousIssuer(tls.Issuer))
                    {
                        mitm.Add(target);
                        findings.Add(Finding.Notice($"Издатель сертификата {target} похож на ПО безопасности",
                            "Возможно, используется проверка TLS защитным или корпоративным ПО; имя издателя не является доказательством.", tls.Issuer));
                    }
                    break;
            }
        }

        metrics.Add(new Metric("Доступно", $"{ok.Count}/{results.Length}", string.Join(", ", ok.Take(6))));
        if (blockedDns.Count > 0) metrics.Add(new Metric("Ошибки DNS", blockedDns.Count.ToString(CultureInfo.InvariantCulture), string.Join(", ", blockedDns)));
        if (blockedTcp.Count > 0) metrics.Add(new Metric("Ошибки TCP", blockedTcp.Count.ToString(CultureInfo.InvariantCulture), string.Join(", ", blockedTcp)));
        if (blockedTls.Count > 0) metrics.Add(new Metric("Ошибки TLS", blockedTls.Count.ToString(CultureInfo.InvariantCulture), string.Join(", ", blockedTls)));

        if (blockedDns.Count + blockedTcp.Count + blockedTls.Count == 0)
        {
            findings.Add(Finding.Info("Все проверенные домены доступны",
                "Соединения установлены. Это не определяет, какие маршруты использовались и есть ли фильтрация других целей."));
        }

        var review = mitm.Count + blockedDns.Count + blockedTcp.Count + blockedTls.Count > 0;

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

    private static bool IsSuspiciousIssuer(string issuer)
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
