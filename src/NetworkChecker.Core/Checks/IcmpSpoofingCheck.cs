using System.Diagnostics;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// ICMP-спуфинг оператора: если «заблокированный» внешний хост отвечает ICMP,
/// но TCP/TLS к нему не устанавливается — ответ подделан промежуточным узлом.
/// Дополнительно сверяются TTL и задержка ICMP против TCP.
/// </summary>
public sealed class IcmpSpoofingCheck : ICheck
{
    public CheckCategory Category => CheckCategory.IcmpSpoofing;
    public string Title => "ICMP-спуфинг (β)";
    public string Subtitle => "Поддельные ICMP-ответы и расхождение с TCP";
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

        foreach (var target in context.Options.IcmpSpoofTargets)
        {
            ct.ThrowIfCancellationRequested();
            context.Progress($"ICMP: {target}");

            var icmp = await PingTools.PingAsync(target, TimeSpan.FromSeconds(3), 128, 32, false, ct).ConfigureAwait(false);
            var tcp443 = await ConnectivityProbes.TcpConnectAsync(target, 443, TimeSpan.FromSeconds(4), ct).ConfigureAwait(false);
            var tls = tcp443.Success
                ? await ConnectivityProbes.TlsHandshakeAsync(target, 443, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false)
                : null;

            metrics.Add(new Metric($"ICMP {target}", icmp.Success ? $"{icmp.Roundtrip.TotalMilliseconds:F0} мс, TTL {icmp.Ttl}" : "нет ответа"));
            metrics.Add(new Metric($"TCP :443 {target}", tcp443.Success ? $"{tcp443.Elapsed.TotalMilliseconds:F0} мс" : tcp443.Error ?? "нет"));

            if (!icmp.Success && !tcp443.Success)
            {
                findings.Add(Finding.Info($"{target}: недоступен по ICMP и TCP",
                    "Похоже на обычную блокировку/недоступность, подмены не видно."));
                continue;
            }

            if (icmp.Success && !tcp443.Success)
            {
                findings.Add(Finding.Warning(
                    $"{target}: ICMP отвечает, TCP :443 — нет",
                    "Асимметрия характерна для фильтрации по порту, но также встречается при подделке ICMP-ответа промежуточным узлом.",
                    $"ICMP TTL {icmp.Ttl}, адрес ответа {Masking.Ip(icmp.Address)}"));
            }

            if (icmp.Success && tcp443.Success && icmp.Address is not null && tcp443.RemoteAddress is not null &&
                icmp.Address != tcp443.RemoteAddress)
            {
                findings.Add(Finding.Warning(
                    $"{target}: ICMP и TCP отвечают с разных адресов",
                    "Разница возможна из-за балансировки, DNS или маршрутов; она не доказывает подмену ICMP или перехват.",
                    $"ICMP {Masking.Ip(icmp.Address)} ≠ TCP {Masking.Ip(tcp443.RemoteAddress)}"));
            }

            if (tls is { Success: false } && icmp.Success && tcp443.Success)
            {
                findings.Add(Finding.Notice($"{target}: TCP открыт, TLS не поднялся",
                    "Возможен сброс TLS-рукопожатия по SNI.", tls.Error));
            }

            if (icmp.Success && icmp.Ttl is > 0 and < 40 && icmp.Roundtrip.TotalMilliseconds < 3)
            {
                findings.Add(Finding.Warning(
                    $"{target}: подозрительно «близкий» ответ",
                    "Малый TTL и задержка сами по себе не устанавливают расположение или подмену отвечающего узла.",
                    $"TTL {icmp.Ttl}, {icmp.Roundtrip.TotalMilliseconds:F1} мс"));
            }
        }

        if (findings.Count == 0)
        {
            findings.Add(Finding.Info("Аномалий ICMP не обнаружено"));
        }

        var review = findings.Any(f => f.Severity is Severity.Critical or Severity.Warning or Severity.Notice);
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
}
