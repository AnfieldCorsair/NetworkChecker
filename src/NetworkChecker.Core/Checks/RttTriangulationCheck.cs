using System.Diagnostics;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// RTT-триангуляция (β): сравнение задержек, не определяет географию маршрута.
/// </summary>
public sealed class RttTriangulationCheck : ICheck
{
    public CheckCategory Category => CheckCategory.RttTriangulation;
    public string Title => "RTT-триангуляция (β)";
    public string Subtitle => "Задержки до RU и иностранных узлов";
    public int Weight => 15;

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

        var methodsUsed = new List<string>();
        var ru = await SampleGroupAsync(context.Options.RttRussianHosts, context, methodsUsed, ct).ConfigureAwait(false);
        var foreign = await SampleGroupAsync(context.Options.RttForeignHosts, context, methodsUsed, ct).ConfigureAwait(false);

        if (ru.Samples == 0 || foreign.Samples == 0)
        {
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Weight = Weight,
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
        metrics.Add(new Metric("Успешных замеров", $"RU {ru.Samples}, мир {foreign.Samples}", "ICMP и TCP не дают общей оценки потерь пакетов"));
        var methods = methodsUsed.Distinct().ToList();
        metrics.Add(new Metric("Метод измерения", string.Join(" + ", methods),
            methods.Contains("TCP") ? "ICMP не ответил для части целей; использован TCP :443 или :80" : "ICMP echo"));

        // Логика: при прямом подключении из РФ медиана до RU-хостов обычно заметно ниже или сравнима.
        if (delta > 60)
        {
            findings.Add(Finding.Warning(
                "RU-хосты отвечают медленнее иностранных",
                $"Разница {delta:F0} мс. Это может быть связано с маршрутами, нагрузкой или расположением узлов; географию пути по RTT определить нельзя.",
                $"RU {ru.Median:F0} мс против {foreign.Median:F0} мс"));
        }
        else if (Math.Abs(delta) <= 60)
        {
            findings.Add(Finding.Info("Задержки симметричны",
                "Разница менее заданного порога не устанавливает географию маршрута."));
        }
        else
        {
            findings.Add(Finding.Info("Российские хосты ближе",
                "Такая разница сама по себе не устанавливает местоположение пользователя или тип подключения."));
        }

        var review = findings.Any(f => f.Severity is Severity.Warning or Severity.Notice);

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

    private static async Task<GroupStats> SampleGroupAsync(IReadOnlyList<string> hosts, CheckContext context, List<string> methodsUsed, CancellationToken ct)
    {
        var all = new List<double>();
        var usedHosts = new List<string>();
        foreach (var host in hosts)
        {
            ct.ThrowIfCancellationRequested();
            context.Progress($"RTT: {host}");
            var (samples, method) = await PingTools.SampleLatencyOrTcpAsync(host, 3, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            if (samples.Count > 0) methodsUsed.Add(method);
            if (samples.Count == 0) continue;
            usedHosts.Add(host);
            all.AddRange(samples.Select(s => s.TotalMilliseconds));
        }

        if (all.Count == 0) return new GroupStats(0, 0, usedHosts);
        all.Sort();
        var median = all[all.Count / 2];
        return new GroupStats(all.Count, median, usedHosts);
    }

    private static string Format(double value) => value <= 0 ? "—" : $"{value:F0} мс";

    private sealed record GroupStats(int Samples, double Median, List<string> Hosts);
}
