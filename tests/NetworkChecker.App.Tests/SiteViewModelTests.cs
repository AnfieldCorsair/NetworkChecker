using Avalonia.Headless.XUnit;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkChecker.App.ViewModels;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.SiteView;
using Xunit;

namespace NetworkChecker.App.Tests;

/// <summary>Заглушка сервиса осмотра: настоящая сеть в тестах не нужна.</summary>
internal sealed class FakeSiteEyeService(Func<SiteViewReport>? build = null) : ISiteEyeService
{
    public int Calls { get; private set; }
    public Exception? Throw { get; set; }

    public Task<SiteViewReport> InspectAsync(CancellationToken ct = default)
    {
        Calls++;
        if (Throw is not null) throw Throw;
        return Task.FromResult(build?.Invoke() ?? Report());
    }

    /// <summary>Обычное домашнее подключение: сигналов быть не должно.</summary>
    public static SiteViewReport Clean()
    {
        var local = new SiteLocalProfile("Europe/Moscow", TimeSpan.FromHours(3), "ru-RU", "Windows 11",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        var geo = new SiteGeo("95.24.1.1", "RU", "Москва", "Москва", "Ростелеком", "AS12389",
            "Europe/Moscow", Hosting: false, Proxy: false, Isp: "Ростелеком");
        return SiteViewAnalyzer.Build(geo, local, DateTimeOffset.Now);
    }

    /// <summary>Типичный «плохой» случай: зарубежный адрес дата-центра.</summary>
    public static SiteViewReport Report(bool offline = false, bool hasGeo = true)
    {
        var local = new SiteLocalProfile("Europe/Moscow", TimeSpan.FromHours(3), "ru-RU", "Windows 11",
            "NetworkChecker/1.1 (+Windows)");
        var geo = hasGeo
            ? new SiteGeo("35.230.92.167", "US", "The Dalles", "Oregon", "Google LLC", "AS396982",
                "America/Los_Angeles", Hosting: true, Proxy: true, Isp: "Google")
            : null;

        return SiteViewAnalyzer.Build(geo, local, DateTimeOffset.Now,
            error: hasGeo ? null : "Офлайн-режим: внешний адрес не запрашивался.", offline: offline);
    }
}

public class SiteViewModelTests
{
    private static SiteViewModel Build(FakeSiteEyeService service, UiModeService? mode = null) =>
        new(service, mode ?? new UiModeService(new UiOptions()), NullLogger<SiteViewModel>.Instance);

    [AvaloniaFact]
    public async Task Refresh_fills_rows_signals_and_score()
    {
        var vm = Build(new FakeSiteEyeService());

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.True(vm.HasReport);
        Assert.NotEmpty(vm.Rows);
        Assert.True(vm.HasSignals);
        Assert.Equal("Есть признаки, совместимые с VPN", vm.Headline);
        Assert.Equal("35.230.92.167", vm.IpText);
        Assert.NotNull(vm.ExposureText);
        Assert.False(vm.HasError);
        Assert.Equal("Готово", vm.StatusLine);
    }

    [AvaloniaFact]
    public async Task Offline_report_keeps_local_facts_and_shows_reason()
    {
        var vm = Build(new FakeSiteEyeService(() => FakeSiteEyeService.Report(offline: true, hasGeo: false)));

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.True(vm.HasError);
        Assert.Contains("Офлайн", vm.ErrorText);
        Assert.Contains("офлайн", vm.StatusLine, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("—", vm.ExposureText);
        Assert.Contains(vm.Rows, r => r.Label == "Ваш часовой пояс");
    }

    [AvaloniaFact]
    public async Task Nothing_to_summarise_before_the_first_look()
    {
        var vm = Build(new FakeSiteEyeService(FakeSiteEyeService.Clean));

        Assert.False(vm.HasReport);
        Assert.False(vm.ShowNoSignals);

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.True(vm.HasReport);
        Assert.True(vm.ShowNoSignals);
    }

    [AvaloniaFact]
    public async Task Pending_task_completes_the_look_started_by_navigation()
    {
        using var env = new TempEnv();
        var service = new FakeSiteEyeService();
        var main = TestHost.BuildMain(env, siteEye: service);

        main.NavigateCommand.Execute(main.NavItems[2]);
        var site = Assert.IsType<SiteViewModel>(main.CurrentPage);
        await site.PendingTask;
        Assert.True(site.HasReport);
        Assert.Equal(1, service.Calls);
    }

    [AvaloniaFact]
    public void Raw_request_is_hidden_in_simple_mode_and_shown_in_pro()
    {
        var mode = new UiModeService(new UiOptions());
        var vm = Build(new FakeSiteEyeService(), mode);

        mode.IsSimple = true;
        Assert.False(vm.ShowRawRequest);

        mode.IsPro = true;
        Assert.True(vm.ShowRawRequest);
    }

    [AvaloniaFact]
    public async Task Headers_of_the_real_request_are_visible_in_pro_mode()
    {
        var vm = Build(new FakeSiteEyeService());

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.Equal("GET / HTTP/1.1", vm.RequestLine);
        Assert.Contains(vm.Headers, h => h.Name == "User-Agent");
        Assert.Contains(vm.Headers, h => h.Name == "Host");
    }

    [AvaloniaFact]
    public async Task Service_crash_is_reported_not_thrown()
    {
        var service = new FakeSiteEyeService { Throw = new InvalidOperationException("сеть отвалилась") };
        var vm = Build(service);

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.True(vm.HasError);
        Assert.Contains("сеть отвалилась", vm.ErrorText);
        Assert.False(vm.IsBusy);
        Assert.Equal("Не получилось", vm.StatusLine);
    }

    [AvaloniaFact]
    public async Task Second_refresh_replaces_previous_data()
    {
        var bullets = 0;
        var service = new FakeSiteEyeService(() => FakeSiteEyeService.Report(hasGeo: bullets++ == 0));
        var vm = Build(service);

        await vm.RefreshCommand.ExecuteAsync(null);
        var firstCount = vm.Rows.Count;
        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.Equal(2, service.Calls);
        Assert.True(vm.Rows.Count < firstCount, "данные второго осмотра должны заменить первые");
    }

    [AvaloniaFact]
    public void Navigation_loads_site_screen_once()
    {
        using var env = new TempEnv();
        var service = new FakeSiteEyeService();
        var main = TestHost.BuildMain(env, siteEye: service);

        main.NavigateCommand.Execute(main.NavItems[2]);
        Assert.Equal("Глазами сайта", main.CurrentPage.Title);
        Assert.Equal(1, service.Calls);

        main.NavigateCommand.Execute(main.NavItems[1]);
        main.NavigateCommand.Execute(main.NavItems[2]);

        Assert.Equal(1, service.Calls);
    }

    [AvaloniaFact]
    public void Site_page_is_third_in_navigation()
    {
        using var env = new TempEnv();
        var main = TestHost.BuildMain(env, siteEye: new FakeSiteEyeService());

        Assert.Equal(7, main.NavItems.Count);
        Assert.Equal(["Проверка", "Сеть", "Глазами сайта", "История", "Справка", "Настройки", "Наблюдение"],
            main.NavItems.Select(n => n.Title));
        Assert.Contains("ВК", main.NavItems[2].Description, StringComparison.Ordinal);
    }
}
