using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using RKNHardering.App.Startup;
using RKNHardering.App.ViewModels;
using RKNHardering.Core;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Core.NetInfo;
using RKNHardering.Core.Options;
using RKNHardering.Data;
using RKNHardering.TestKit;

namespace RKNHardering.App.Tests;

/// <summary>
/// Собирает настоящие ViewModel'и приложения поверх фейковой платформы и временной папки данных.
/// Ничего не читает из ОС и не пишет в профиль пользователя.
/// </summary>
public static class TestHost
{
    public static MainWindowViewModel BuildMain(
        TempEnv env,
        IFileDialogService? files = null,
        RknOptions? options = null,
        IReadOnlyList<ICheck>? checks = null,
        FakePlatformProbe? platform = null,
        FakeHttpProbe? http = null)
    {
        var store = env.Store;
        var opts = options ?? Sample.Options();
        if (options is null) opts.SaveHistory = false;

        var mode = new UiModeService(store.Ui, store);
        platform ??= FakePlatformProbe.Clean();
        http ??= new FakeHttpProbe();
        var runner = new CheckRunner(checks ?? [FakeCheck.Detected(CheckCategory.DirectSigns, 30)], platform);
        var history = env.History();

        var dashboard = new DashboardViewModel(runner, history, store, opts, files ?? new FakeFileDialog(), mode,
            NullLogger<DashboardViewModel>.Instance);

        var dns = new DnsClientLite(http);
        var service = new NetworkInfoService(platform, http, new PingTools(), dns, new AsnLookup(dns),
            new TraceTool(new PingTools()));
        var network = new NetworkViewModel(service, opts, mode, NullLogger<NetworkViewModel>.Instance);

        var historyVm = new HistoryViewModel(history, mode);
        var guide = new GuideViewModel();
        var settings = new SettingsViewModel(store, opts, store.Ui, history, mode);

        return new MainWindowViewModel(dashboard, network, historyVm, guide, settings, mode);
    }
}
