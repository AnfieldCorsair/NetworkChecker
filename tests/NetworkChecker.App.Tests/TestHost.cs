using Microsoft.Extensions.Logging.Abstractions;
using NetworkChecker.App.Startup;
using NetworkChecker.App.ViewModels;
using NetworkChecker.Core;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;
using NetworkChecker.Core.NetInfo;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.SiteView;
using NetworkChecker.TestKit;

namespace NetworkChecker.App.Tests;

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
        FakeHttpProbe? http = null,
        ISiteEyeService? siteEye = null)
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
        var service = new NetworkInfoService(platform, http, dns);
        var network = new NetworkViewModel(service, opts, mode, NullLogger<NetworkViewModel>.Instance);

        var site = new SiteViewModel(siteEye ?? new SiteEyeService(http, opts), mode, NullLogger<SiteViewModel>.Instance);
        var historyVm = new HistoryViewModel(history, mode);
        var guide = new GuideViewModel();
        var settings = new SettingsViewModel(store, opts, store.Ui, history, mode);

        return new MainWindowViewModel(dashboard, network, site, historyVm, guide, settings, mode, new ObservationViewModel(new FakeObservationService()));
    }
}

public sealed class FakeObservationService : NetworkChecker.Core.Observation.IObservationService
{
    public Task<NetworkChecker.Core.Observation.ObservationReport> ObserveAsync(TimeSpan duration, CancellationToken cancellationToken)
    {
        var part = new NetworkChecker.Core.Observation.ObservationPart("test", true, "test", [], 0);
        return Task.FromResult(new NetworkChecker.Core.Observation.ObservationReport(part, part));
    }
}
