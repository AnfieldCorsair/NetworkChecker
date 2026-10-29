using System.Diagnostics;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;

namespace RKNHardering.Core.Checks;

/// <summary>
/// GeoIP + hosting/proxy-сигналы. Паритет с GeoIpChecker (Android):
/// несколько независимых провайдеров, majority vote по hosting, «хоть один» по proxy.
/// </summary>
public sealed class GeoIpCheck : ICheck
{
    private readonly IHttpProbe _http;

    public GeoIpCheck(IHttpProbe http) => _http = http;

    public CheckCategory Category => CheckCategory.GeoIp;
    public string Title => "GeoIP и репутация IP";
    public string Subtitle => "Страна, hosting, proxy/VPN/Tor по мнению внешних сервисов";
    public int Weight => 20;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromSeconds(context.Options.RequestTimeoutSeconds);

        if (context.Options.OfflineMode)
        {
            return new CheckResult
            {
                Category = Category,
                Title = Title,
                Subtitle = Subtitle,
                Status = CheckStatus.Skipped,
                Weight = Weight,
                Findings = [Finding.Info("Офлайн-режим", "Запросы к GeoIP-провайдерам отключены в настройках.")],
                Duration = sw.Elapsed,
            };
        }

        var results = new List<(string Provider, GeoIpParser.GeoInfo Info, TimeSpan Elapsed)>();
        foreach (var provider in context.Options.GeoIpProviders)
        {
            ct.ThrowIfCancellationRequested();
            context.Progress($"GeoIP: {new Uri(provider).Host}");
            var response = await _http.GetAsync(new Uri(provider), timeout, ignoreProxy: false, ct).ConfigureAwait(false);
            if (!response.Success || string.IsNullOrWhiteSpace(response.Body)) continue;
            var info = GeoIpParser.Parse(response.Body);
            if (info is null || string.IsNullOrWhiteSpace(info.Ip)) continue;
            results.Add((new Uri(provider).Host, info, response.Elapsed));
            context.CollectIp($"GeoIP · {new Uri(provider).Host}", info.Ip!, info.IsRussian,
                info.Country is null ? null : GeoCountries.Name(info.Country));
        }

        if (results.Count == 0)
        {
            return CheckResult.Failed(Category, Title, "Ни один GeoIP-провайдер не ответил данными", sw.Elapsed, Weight);
        }

        var primary = results[0];
        var country = primary.Info.Country ?? results.FirstOrDefault(r => r.Info.Country is not null).Info?.Country;
        var hostingVotes = results.Where(r => r.Info.Hosting == true).Count();
        var hostingTotal = results.Count(r => r.Info.Hosting is not null);
        var proxyHit = results.FirstOrDefault(r => r.Info.Proxy == true);
        var isHosting = hostingTotal > 0 && hostingVotes * 2 > hostingTotal;
        var isProxy = proxyHit.Info is not null;
        var foreign = country is not null && !country.Equals("RU", StringComparison.OrdinalIgnoreCase);

        metrics.Add(new Metric("Внешний IP", Masking.Ip(primary.Info.Ip), "как видят внешние сервисы"));
        metrics.Add(new Metric("Страна", $"{GeoCountries.Name(country)} ({country ?? "—"})", primary.Provider));
        if (primary.Info.Asn is not null) metrics.Add(new Metric("ASN", primary.Info.Asn, primary.Info.Org));
        if (primary.Info.Isp is not null) metrics.Add(new Metric("Провайдер", primary.Info.Isp, primary.Info.City));
        metrics.Add(new Metric("Hosting", hostingTotal == 0 ? "нет данных" : $"{hostingVotes}/{hostingTotal} голосов"));
        metrics.Add(new Metric("Провайдеров ответило", results.Count.ToString(), string.Join(", ", results.Select(r => r.Provider))));

        if (isHosting)
        {
            findings.Add(Finding.Warning(
                "IP принадлежит хостингу/дата-центру",
                "Большинство совместимых источников считают адрес hosting. Для домашнего подключения это нетипично.",
                $"{hostingVotes} из {hostingTotal} источников: hosting=true"));
        }

        if (isProxy)
        {
            findings.Add(Finding.Critical(
                "IP помечен как proxy/VPN/Tor",
                "Хотя бы один провайдер вернул признак proxy/VPN/Tor — это прямой сигнал методики РКН.",
                $"{proxyHit.Provider}: proxy=true"));
        }

        if (foreign)
        {
            findings.Add(isHosting || isProxy
                ? Finding.Notice("Внешний IP не российский", $"Страна выхода: {GeoCountries.Name(country)}.")
                : Finding.Notice("Внешний IP не российский, но без hosting/proxy",
                    "Методика относит такой случай к needsReview: иностранный адрес без явных признаков дата-центра."));
        }

        if (!foreign && !isHosting && !isProxy)
        {
            findings.Add(Finding.Info("Признаков не найдено", "Российский адрес, без hosting/proxy-меток."));
        }

        var distinctCountries = results.Select(r => r.Info.Country).Where(c => c is not null).Distinct().Count();
        if (distinctCountries > 1)
        {
            findings.Add(Finding.Notice(
                "Провайдеры расходятся в стране",
                "Разные GeoIP-базы вернули разные страны для одного IP — типично для anycast или цепочки прокси.",
                string.Join(", ", results.Select(r => $"{r.Provider}={r.Info.Country}"))));
        }

        // Методика: hosting/proxy — detected; иностранный адрес без них — needsReview.
        var status = isProxy || isHosting ? CheckStatus.Detected
            : foreign ? CheckStatus.NeedsReview
            : CheckStatus.Clean;

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = status,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }
}
