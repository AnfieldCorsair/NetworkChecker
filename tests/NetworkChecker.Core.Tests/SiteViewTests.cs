using NetworkChecker.Core.Options;
using NetworkChecker.Core.SiteView;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Core.Tests;

/// <summary>
/// Экран «глазами сайта»: проверяем, что визитная карточка собирается верно и что
/// выводы не пугают пользователя зря — цена ложного «вы как под VPN» высокая.
/// </summary>
public class SiteViewAnalyzerTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 29, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Часовой пояс по идентификатору из GeoIP — фиксированный, чтобы тесты не зависели от базы ОС.</summary>
    private static TimeZoneInfo? Fixed(string id) => id switch
    {
        "Europe/Moscow" => TimeZoneInfo.CreateCustomTimeZone("Europe/Moscow", TimeSpan.FromHours(3), "МСК", "МСК"),
        "America/Los_Angeles" => TimeZoneInfo.CreateCustomTimeZone("America/Los_Angeles", TimeSpan.FromHours(-7), "LA", "LA"),
        "Asia/Novosibirsk" => TimeZoneInfo.CreateCustomTimeZone("Asia/Novosibirsk", TimeSpan.FromHours(7), "НСК", "НСК"),
        _ => null,
    };

    private static SiteLocalProfile Local(
        string zone = "Europe/Moscow",
        int offsetHours = 3,
        string culture = "ru-RU",
        string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetworkChecker") =>
        new(zone, TimeSpan.FromHours(offsetHours), culture, "Windows 11", userAgent);

    private static SiteGeo Geo(
        string ip = "5.5.5.5",
        string? country = "RU",
        string? timezone = "Europe/Moscow",
        bool? hosting = false,
        bool? proxy = false) =>
        new(ip, country, "Москва", "Москва", "Домашний провайдер", "AS12345", timezone, hosting, proxy, "Провайдер");

    [Fact]
    public void Datacenter_foreign_ip_looks_like_vpn()
    {
        var geo = Geo(ip: "35.230.92.167", country: "US", timezone: "America/Los_Angeles", hosting: true, proxy: true);

        var report = SiteViewAnalyzer.Build(geo, Local(culture: "ru-RU"), At, resolveTimeZone: Fixed);

        Assert.Equal("Есть признаки, совместимые с VPN", report.Headline);
        Assert.True(report.Exposure >= SiteViewAnalyzer.VpnLikeThreshold);
        Assert.Contains(report.Signals, s => s.Tone == SiteViewTone.Bad && s.Title.Contains("дата-центру"));
        Assert.Contains(report.Signals, s => s.Title.Contains("VPN/прокси/Tor"));
        Assert.Contains(report.Signals, s => s.Title.Contains("Зарубежный IP"));
        Assert.Contains(report.Signals, s => s.Title.Contains("Часовой пояс"));
        Assert.Contains("не вероятность", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Russian_home_ip_is_ordinary_visitor()
    {
        var report = SiteViewAnalyzer.Build(Geo(), Local(), At, resolveTimeZone: Fixed);

        Assert.Equal("Сильных признаков не найдено", report.Headline);
        Assert.True(report.Exposure < SiteViewAnalyzer.ReviewThreshold);
        Assert.DoesNotContain(report.Signals, s => s.Tone == SiteViewTone.Bad);
        Assert.Contains("не вероятность", report.Summary);
        Assert.Equal("домашний или мобильный провайдер", Row(report, "Тип сети").Value);
    }

    [Fact]
    public void Timezone_mismatch_is_noticed_even_for_russian_address()
    {
        var geo = Geo(timezone: "Asia/Novosibirsk");

        var report = SiteViewAnalyzer.Build(geo, Local(), At, resolveTimeZone: Fixed);

        Assert.Contains(report.Signals, s => s.Title.Contains("Часовой пояс не сходится"));
        Assert.Equal(SiteViewTone.Warn, Row(report, "Ваш часовой пояс").Tone);
    }

    [Fact]
    public void Matching_timezone_is_marked_good()
    {
        var report = SiteViewAnalyzer.Build(Geo(), Local(), At, resolveTimeZone: Fixed);

        Assert.Equal(SiteViewTone.Good, Row(report, "Ваш часовой пояс").Tone);
        Assert.DoesNotContain(report.Signals, s => s.Title.Contains("Часовой пояс"));
    }

    [Theory]
    [InlineData("KZ")]
    [InlineData("UA")]
    [InlineData("BY")]
    public void Russian_language_in_region_is_context_not_mismatch(string country)
    {
        var report = SiteViewAnalyzer.Build(Geo(country: country), Local(), At, resolveTimeZone: Fixed);
        Assert.Contains(report.Signals, s => s.Title.Contains("региональное примечание") && s.Points == 0);
        Assert.DoesNotContain(report.Signals, s => s.Title.Contains("Язык и страна адреса"));
        Assert.Contains(report.Signals, s => s.Title.Contains("Зарубежный IP"));
    }

    [Fact]
    public void Russian_address_with_foreign_language_disagrees()
    {
        var report = SiteViewAnalyzer.Build(Geo(), Local(culture: "en-US"), At, resolveTimeZone: Fixed);

        Assert.Contains(report.Signals, s => s.Title.Contains("Язык и страна адреса"));
    }

    [Fact]
    public void Browser_like_user_agent_does_not_add_noise()
    {
        var report = SiteViewAnalyzer.Build(Geo(timezone: "America/Los_Angeles", country: "US"), Local(), At,
            resolveTimeZone: Fixed);

        Assert.DoesNotContain(report.Signals, s => s.Title.Contains("не похож на браузерный"));
    }

    [Fact]
    public void App_user_agent_is_called_out()
    {
        var report = SiteViewAnalyzer.Build(Geo(), Local(userAgent: "NetworkChecker/1.1 (+Windows)"), At,
            resolveTimeZone: Fixed);

        Assert.Contains(report.Signals, s => s.Title.Contains("не похож на браузерный"));
    }

    [Fact]
    public void Missing_geo_leaves_only_local_facts()
    {
        var report = SiteViewAnalyzer.Build(null, Local(), At, error: "офлайн");

        Assert.False(report.HasGeo);
        Assert.Equal("Нет данных о внешнем адресе", report.Headline);
        Assert.Equal(0, report.Exposure);
        Assert.Equal("офлайн", report.Error);
        Assert.Contains(report.Rows, r => r.Label == "Ваш часовой пояс");
        Assert.Contains(report.Rows, r => r.Label == "Язык системы");
        Assert.DoesNotContain(report.Rows, r => r.Label == "География по IP");
        Assert.Empty(report.Signals);
    }

    [Fact]
    public void Offline_flag_is_preserved()
    {
        var report = SiteViewAnalyzer.Build(null, Local(), At, error: "нет сети", offline: true);

        Assert.True(report.Offline);
    }

    [Fact]
    public void Rows_always_start_with_the_ip()
    {
        var report = SiteViewAnalyzer.Build(Geo(), Local(), At, resolveTimeZone: Fixed);

        Assert.Equal("IP-адрес", report.Rows[0].Label);
        Assert.Equal("5.5.5.5", report.Rows[0].Value);
        Assert.Contains(report.Rows, r => r.Label == "Провайдер и ASN" && r.Value.Contains("AS12345", StringComparison.Ordinal));
        Assert.Contains(report.Rows, r => r.Label == "Клиент запроса");
    }

    [Fact]
    public void Unknown_timezone_does_not_break_the_report()
    {
        var geo = Geo(timezone: "Mars/Olympus");

        var report = SiteViewAnalyzer.Build(geo, Local(), At, resolveTimeZone: Fixed);

        Assert.Contains(report.Rows, r => r.Label == "Часовой пояс адреса" && r.Value == "неизвестен");
        Assert.DoesNotContain(report.Signals, s => s.Title.Contains("Часовой пояс не сходится"));
    }

    [Fact]
    public void Missing_hosting_flag_is_reported_as_unknown()
    {
        var report = SiteViewAnalyzer.Build(Geo(hosting: null, proxy: null), Local(), At, resolveTimeZone: Fixed);

        Assert.Equal("нет данных", Row(report, "Тип сети").Value);
        Assert.Equal("нет данных", Row(report, "Метки в базах").Value);
        Assert.DoesNotContain(report.Signals, s => s.Tone == SiteViewTone.Bad);
    }

    [Theory]
    [InlineData(3, "UTC+3")]
    [InlineData(-7, "UTC−7")]
    [InlineData(0, "UTC+0")]
    [InlineData(5.5, "UTC+5:30")]
    [InlineData(-3.5, "UTC−3:30")]
    public void Offsets_are_human_readable(double hours, string expected) =>
        Assert.Equal(expected, SiteViewAnalyzer.FormatOffset(TimeSpan.FromHours(hours)));

    [Fact]
    public void Request_shows_exactly_what_the_server_receives()
    {
        var request = SiteViewAnalyzer.BuildRequest("api.ipapi.is", Local(userAgent: "NetworkChecker/1.1 (+Windows)"));

        Assert.Equal("GET / HTTP/1.1", request.Line);
        Assert.Contains(request.Headers, h => h.Key == "Host" && h.Value == "api.ipapi.is");
        Assert.Contains(request.Headers, h => h.Key == "User-Agent" && h.Value == "NetworkChecker/1.1 (+Windows)");
        // Приложение не отправляет Accept-Language — и экран не должен делать вид, что отправляет.
        Assert.DoesNotContain(request.Headers, h => h.Key == "Accept-Language");
    }

    [Fact]
    public void Local_profile_requires_local_profile_argument()
    {
        Assert.Throws<ArgumentNullException>(() => SiteViewAnalyzer.Build(Geo(), null!, At));
        Assert.Throws<ArgumentNullException>(() => SiteViewAnalyzer.BuildRequest("host", null!));
    }

    private static SiteViewRow Row(SiteViewReport report, string label) =>
        report.Rows.Single(r => r.Label == label);
}

/// <summary>Разбор ответов разных GeoIP-сервисов в одну модель.</summary>
public class SiteGeoParserTests
{
    [Fact]
    public void Ipapi_is_payload_is_parsed()
    {
        const string json = """
        {"ip":"35.230.92.167","is_bogon":false,"company":"Google LLC","asn":"AS396982 Google LLC",
         "city":"The Dalles","region":"Oregon","country":"United States","lat":45.6,"lon":-121.2,
         "timezone":"America/Los_Angeles"}
        """;

        var geo = SiteGeoParser.Parse(json);

        Assert.NotNull(geo);
        Assert.Equal("35.230.92.167", geo.Ip);
        Assert.Equal("US", geo.Country);
        Assert.Equal("The Dalles", geo.City);
        Assert.Equal("Oregon", geo.Region);
        Assert.Equal("AS396982", geo.Asn);
        Assert.Equal("Google LLC", geo.Company);
        Assert.Equal("America/Los_Angeles", geo.Timezone);
        Assert.Null(geo.Hosting);
    }

    [Fact]
    public void Ipwho_is_nested_payload_is_parsed()
    {
        const string json = """
        {"ip":"8.8.8.8","success":true,"country":"United States","country_code":"US","region":"California",
         "city":"Mountain View","connection":{"asn":15169,"org":"Google LLC","isp":"Google"},
         "timezone":{"id":"America/Los_Angeles","abbr":"PDT","utc":"-07:00"}}
        """;

        var geo = SiteGeoParser.Parse(json);

        Assert.NotNull(geo);
        Assert.Equal("US", geo.Country);
        Assert.Equal("America/Los_Angeles", geo.Timezone);
        Assert.Equal("15169", geo.Asn);
        Assert.Equal("Google LLC", geo.Company);
        Assert.Equal("Google", geo.Isp);
    }

    [Fact]
    public void Two_ip_payload_is_parsed()
    {
        const string json = """
        {"ip":"95.24.1.1","country_code":"RU","country":"Russian federation","country_rus":"Россия",
         "region":"Москва","city":"Москва"}
        """;

        var geo = SiteGeoParser.Parse(json);

        Assert.NotNull(geo);
        Assert.Equal("RU", geo.Country);
        Assert.Equal("Москва", geo.City);
    }

    [Theory]
    [InlineData("""{"hosting":true}""")]
    [InlineData("""{"is_hosting":"yes"}""")]
    [InlineData("""{"vpn":1}""")]
    public void Flags_are_read_in_any_shape(string json)
    {
        var geo = SiteGeoParser.Parse($$"""{"ip":"1.2.3.4","country":"RU",{{json[1..^1]}}}""");

        Assert.NotNull(geo);
        Assert.True(geo.Hosting == true || geo.Proxy == true);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("не json")]
    [InlineData("[]")]
    [InlineData("""{"country":"RU"}""")]
    [InlineData("""{"ip":null}""")]
    public void Garbage_and_ip_less_answers_return_null(string? json) =>
        Assert.Null(SiteGeoParser.Parse(json));
}

/// <summary>Сервис: офлайн-режим, порядок провайдеров, аккуратный отказ.</summary>
public class SiteEyeServiceTests
{
    private const string GoodBody = """{"ip":"193.0.0.1","country":"RU","city":"Москва","timezone":"Europe/Moscow"}""";

    private static RknOptions Options(params string[] providers)
    {
        var options = Sample.Options();
        options.OfflineMode = false;
        options.RequestTimeoutSeconds = 3;
        options.GeoIpProviders = [.. providers];
        return options;
    }

    [Fact]
    public async Task Offline_mode_does_not_touch_the_network()
    {
        var http = new FakeHttpProbe().With("ipapi", GoodBody);
        var options = Options("https://api.ipapi.is/");
        options.OfflineMode = true;

        var report = await new SiteEyeService(http, options).InspectAsync();

        Assert.True(report.Offline);
        Assert.False(report.HasGeo);
        Assert.Empty(http.Requested);
    }

    [Fact]
    public async Task First_working_provider_wins()
    {
        var http = new FakeHttpProbe().With("ipapi", GoodBody);
        var options = Options("https://api.ipapi.is/", "https://www.iplocate.io/api/lookup");

        var report = await new SiteEyeService(http, options).InspectAsync();

        Assert.True(report.HasGeo);
        Assert.Equal("193.0.0.1", report.Ip);
        Assert.Single(http.Requested);
    }

    [Fact]
    public async Task Failing_provider_is_skipped()
    {
        var http = new FakeHttpProbe().With("ipapi", GoodBody);
        var options = Options("https://broken.example/geo", "https://api.ipapi.is/");

        var report = await new SiteEyeService(http, options).InspectAsync();

        Assert.True(report.HasGeo);
        Assert.Equal(2, http.Requested.Count);
    }

    [Fact]
    public async Task Unparsable_answer_falls_through_to_the_next_provider()
    {
        var http = new FakeHttpProbe()
            .With("broken", "<html>captcha</html>")
            .With("ipapi", GoodBody);
        var options = Options("https://broken.example/geo", "https://api.ipapi.is/");

        var report = await new SiteEyeService(http, options).InspectAsync();

        Assert.Equal("193.0.0.1", report.Ip);
    }

    [Fact]
    public async Task Nothing_answered_gives_honest_error()
    {
        var http = new FakeHttpProbe();
        var options = Options("https://broken.example/geo");

        var report = await new SiteEyeService(http, options).InspectAsync();

        Assert.False(report.HasGeo);
        Assert.False(string.IsNullOrWhiteSpace(report.Error));
        Assert.Contains("broken.example", report.Error);
        Assert.NotEmpty(report.Rows);
    }

    [Fact]
    public async Task Empty_provider_list_does_not_throw()
    {
        var report = await new SiteEyeService(new FakeHttpProbe(), Options()).InspectAsync();

        Assert.False(report.HasGeo);
        Assert.Equal("Нет данных о внешнем адресе", report.Headline);
    }

    [Fact]
    public async Task Cancellation_is_propagated()
    {
        var http = new FakeHttpProbe().With("ipapi", GoodBody);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SiteEyeService(http, Options("https://api.ipapi.is/")).InspectAsync(cts.Token));
    }

    [Fact]
    public void Local_profile_takes_user_agent_and_system_values()
    {
        var profile = SiteEyeService.LocalProfile("NetworkChecker/1.1");

        Assert.Equal("NetworkChecker/1.1", profile.UserAgent);
        Assert.False(string.IsNullOrWhiteSpace(profile.TimeZoneId));
        Assert.False(string.IsNullOrWhiteSpace(profile.CultureName));
        Assert.False(string.IsNullOrWhiteSpace(profile.OsName));
    }

    [Fact]
    public void Empty_user_agent_gets_a_readable_placeholder()
    {
        var profile = SiteEyeService.LocalProfile("   ");

        Assert.Contains("NetworkChecker", profile.UserAgent, StringComparison.Ordinal);
    }
}
