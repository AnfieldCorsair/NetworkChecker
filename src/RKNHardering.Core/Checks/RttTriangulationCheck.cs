using System.Diagnostics;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;

namespace RKNHardering.Core.Checks;

/// <summary>
/// SNITCH (β): RTT-триангуляция. Если до RU-хостов задержка больше, чем до иностранных,
/// трафик, вероятно, выходит за пределы страны и возвращается — признак туннеля.
/// </summary>
public sealed class RttTriangulationCheck : ICheck
{
    private readonly PingTools _ping;

    public RttTriangulationCheck(PingTools ping) => _ping = ping;

    public CheckCategory Category => CheckCategory.RttTriangulation;
    public string Title => "RTT-триангуляция (β)";
    public string Subtitle => "Задержки до RU и иностранных узлов";
    public int Weight => 15;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();

        var ru = await SampleGroupAsync(context.Options.RttRussianHosts, context, ct).ConfigureAwait(false);
        var foreign = await SampleGroupAsync(context.Options.RttForeignHosts, context, ct).ConfigureAwait(false);

        if (ru.Samples == 0 || foreign.Samples == 0)
        {
            return new CheckResult
            {
                Category = Category, Title = Title, Subtitle = Subtitle, Weight = Weight,
                Status = CheckStatus.Skipped,
                Findings = [Finding.Info("ICMP недоступен",
                    "Не удалось собрать статистику по одной из групп хостов (ICMP может быть заблокирован).",
                    $"RU: {ru.Samples}, иностранные: {foreign.Samples}")],
                Metrics =
                [
                    new Metric("RU медиана", Format(ru.Median)),
                    new Metric("Иностранные медиана", Format(foreign.Median)),
                ],
                Duration = sw.Elapsed,
            };
        }

        var delta = ru.Median - foreign.Median;
        metrics.Add(new Metric("RU медиана", Format(ru.Median), string.Join(", ", ru.Hosts)));
        metrics.Add(new Metric("Иностранные медиана", Format(foreign.Median), string.Join(", ", foreign.Hosts)));
        metrics.Add(new Metric("Разница", $"{delta:+0;-0;0} мс", "RU минус иностранные"));
        metrics.Add(new Metric("Потери пакетов", $"RU {ru.Loss:F0}%, мир {foreign.Loss:F0}%"));
        var methods = Methods.Distinct().ToList();
        metrics.Add(new Metric("Метод измерения", string.Join(" + ", methods),
            methods.Contains("TCP") ? "ICMP заблокирован, часть замеров сделана по TCP :443" : "ICMP echo"));

        // Логика: при прямом подключении из РФ медиана до RU-хостов обычно заметно ниже или сравнима.
        if (delta > 60)
        {
            findings.Add(Finding.Warning(
                "RU-хосты отвечают медленнее иностранных",
                $"Разница {delta:F0} мс. Похоже, трафик к российским адресам уходит за границу и возвращается — типично для зарубежного туннеля.",
                $"RU {ru.Median:F0} мс против {foreign.Median:F0} мс"));
        }
        else if (Math.Abs(delta) <= 60)
        {
            findings.Add(Finding.Info("Задержки симметричны",
                "Разница в пределах нормы: нет признаков «дальнего» маршрута до российских адресов."));
        }
        else
        {
            findings.Add(Finding.Info("Российские хосты ближе",
                "Ожидаемая картина для прямого подключения из РФ."));
        }

        if (foreign.Loss > 30 && ru.Loss < 10)
        {
            findings.Add(Finding.Notice("Высокие потери до иностранных хостов",
                "Иногда это следствие блокировки ICMP на стороне провайдера, а не признак обхода.",
                $"мир {foreign.Loss:F0}%"));
        }

        if (ru.Jitter > 80 || foreign.Jitter > 80)
        {
            findings.Add(Finding.Notice("Высокий jitter",
                "Нестабильная задержка характерна для шифрованного туннеля с реорганизацией пакетов.",
                $"RU {ru.Jitter:F0} мс, мир {foreign.Jitter:F0} мс"));
        }

        var detected = findings.Any(f => f.Severity == Severity.Warning);

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = detected ? CheckStatus.Detected : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }

    private async Task<GroupStats> SampleGroupAsync(IReadOnlyList<string> hosts, CheckContext context, CancellationToken ct)
    {
        var all = new List<double>();
        var usedHosts = new List<string>();
        var attempts = 0;
        foreach (var host in hosts)
        {
            ct.ThrowIfCancellationRequested();
            context.Progress($"RTT: {host}");
            var (samples, method) = await _ping.SampleLatencyOrTcpAsync(host, 3, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            attempts += 5;
            if (samples.Count > 0) Methods.Add(method);
            if (samples.Count == 0) continue;
            usedHosts.Add(host);
            all.AddRange(samples.Select(s => s.TotalMilliseconds));
        }

        if (all.Count == 0) return new GroupStats(0, 0, 0, usedHosts, attempts);
        all.Sort();
        var median = all[all.Count / 2];
        var mean = all.Average();
        var jitter = Math.Sqrt(all.Average(v => Math.Pow(v - mean, 2)));
        var loss = attempts == 0 ? 0 : (attempts - all.Count) / (double)attempts * 100;
        return new GroupStats(all.Count, median, jitter, usedHosts, attempts) { Loss = loss };
    }

    private static string Format(double value) => value <= 0 ? "—" : $"{value:F0} мс";

    public List<string> Methods { get; } = new();

    private sealed record GroupStats(int Samples, double Median, double Jitter, List<string> Hosts, int Attempts)
    {
        public double Loss { get; init; }
    }
}
