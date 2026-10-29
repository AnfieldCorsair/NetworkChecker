using System.Globalization;
using System.Runtime.InteropServices;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Options;

namespace NetworkChecker.Core.SiteView;

/// <summary>
/// Осматривает посетителя «глазами сайта»: спрашивает внешний адрес у GeoIP-сервиса
/// и добавляет то, что знает только эта машина (часовой пояс, язык, клиент).
/// </summary>
public sealed class SiteEyeService(IHttpProbe http, RknOptions options) : ISiteEyeService
{
    public async Task<SiteViewReport> InspectAsync(CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(http);

        var at = DateTimeOffset.Now;
        var local = LocalProfile(http.UserAgent);

        if (options.OfflineMode)
        {
            return SiteViewAnalyzer.Build(null, local, at,
                error: "Офлайн-режим: внешний адрес не запрашивался.", offline: true);
        }

        var timeout = TimeSpan.FromSeconds(Math.Max(2, options.RequestTimeoutSeconds));
        string? lastError = null;

        foreach (var provider in options.GeoIpProviders)
        {
            ct.ThrowIfCancellationRequested();
            if (!Uri.TryCreate(provider, UriKind.Absolute, out var uri)) continue;

            try
            {
                var response = await http.GetAsync(uri, timeout, ignoreProxy: false, ct).ConfigureAwait(false);
                if (!response.Success || string.IsNullOrWhiteSpace(response.Body))
                {
                    lastError = $"{uri.Host}: {response.Error ?? "пустой ответ"}";
                    continue;
                }

                var geo = SiteGeoParser.Parse(response.Body);
                if (geo is null || string.IsNullOrWhiteSpace(geo.Ip))
                {
                    lastError = $"{uri.Host}: ответ не удалось разобрать";
                    continue;
                }

                return SiteViewAnalyzer.Build(geo, local, at);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Один упавший сервис не должен ломать экран: пробуем следующий.
                lastError = $"{uri.Host}: {ex.GetBaseException().Message}";
            }
        }

        return SiteViewAnalyzer.Build(null, local, at,
            error: lastError ?? "Ни один GeoIP-сервис не ответил.");
    }

    /// <summary>Локальный профиль: то, что сайт узнаёт из заголовков и скриптов на странице.</summary>
    public static SiteLocalProfile LocalProfile(string userAgent)
    {
        var culture = CultureInfo.CurrentUICulture;
        var zone = TimeZoneInfo.Local;
        return new SiteLocalProfile(
            TimeZoneId: zone.Id,
            UtcOffset: zone.GetUtcOffset(DateTimeOffset.Now),
            CultureName: string.IsNullOrWhiteSpace(culture.Name) ? culture.TwoLetterISOLanguageName : culture.Name,
            OsName: DescribeOs(),
            UserAgent: string.IsNullOrWhiteSpace(userAgent) ? "NetworkChecker (неизвестная версия)" : userAgent);
    }

    private static string DescribeOs()
    {
        var description = RuntimeInformation.OSDescription;
        return string.IsNullOrWhiteSpace(description) ? Environment.OSVersion.VersionString : description.Trim();
    }
}
