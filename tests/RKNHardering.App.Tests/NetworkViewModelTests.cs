using Avalonia.Headless.XUnit;
using Microsoft.Extensions.Logging.Abstractions;
using RKNHardering.App.ViewModels;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Core.NetInfo;
using RKNHardering.Core.Options;
using RKNHardering.TestKit;
using Xunit;

namespace RKNHardering.App.Tests;

public class NetworkViewModelTests
{
    private static NetworkViewModel Build(UiModeService mode, FakePlatformProbe? platform = null)
    {
        var opts = Sample.Options();
        opts.OfflineMode = true;
        platform ??= FakePlatformProbe.Clean();
        var http = new FakeHttpProbe();
        var dns = new DnsClientLite(http);
        var service = new NetworkInfoService(platform, http, new PingTools(), dns, new AsnLookup(dns), new TraceTool(new PingTools()));
        return new NetworkViewModel(service, opts, mode, NullLogger<NetworkViewModel>.Instance);
    }

    private static UiModeService Pro()
    {
        var mode = new UiModeService(new UiOptions { ProModeByDefault = true });
        return mode;
    }

    [AvaloniaFact]
    public void Tabs_are_visible_only_in_pro_mode()
    {
        var mode = Pro();
        var vm = Build(mode);
        Assert.True(vm.ShowTabs);

        mode.IsSimple = true;

        Assert.False(vm.ShowTabs);
        Assert.True(vm.ShowSimpleOverview);
        Assert.False(vm.ShowTechnicalOverview);
    }

    [AvaloniaFact]
    public void Mode_change_notifies_view_flags()
    {
        var mode = Pro();
        var vm = Build(mode);
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        mode.IsSimple = true;

        Assert.Contains(nameof(NetworkViewModel.ShowTabs), changed);
        Assert.Contains(nameof(NetworkViewModel.ShowSimpleOverview), changed);
        Assert.Contains(nameof(NetworkViewModel.ShowTechnicalOverview), changed);
    }

    [AvaloniaFact]
    public async Task Clean_network_reads_as_normal_in_plain_words()
    {
        var vm = Build(Pro());

        await vm.RefreshOverviewCommand.ExecuteAsync(null);

        Assert.NotEmpty(vm.SimpleFacts);
        // Офлайн-режим: внешний адрес неизвестен — это единственное «отличие», поэтому полоса жёлтая.
        Assert.StartsWith("Сеть работает обычно", vm.SimpleSummary);
        Assert.Equal("#F5C542", vm.SimpleTone);
        Assert.All(
            vm.SimpleFacts.Where(f => f.Label != "Адрес выхода"),
            f => Assert.True(f.IsGood, $"{f.Label} = {f.Value} ({f.Tone})"));
        Assert.NotEmpty(vm.Adapters);
        Assert.NotEmpty(vm.Overview);
        Assert.Contains(vm.Overview, r => r.Key == "Внешний IP");
    }

    [AvaloniaFact]
    public async Task Tunnelled_network_is_called_out_in_plain_words()
    {
        var vm = Build(Pro(), FakePlatformProbe.Tunneled());

        await vm.RefreshOverviewCommand.ExecuteAsync(null);

        var tunnelFact = vm.SimpleFacts.Single(f => f.Label == "VPN или туннель");
        Assert.True(tunnelFact.IsBad);
        Assert.Equal("включён", tunnelFact.Value);
        Assert.Contains("VPN", vm.SimpleSummary);
        Assert.Equal("#F0524C", vm.SimpleTone);
        Assert.Equal(tunnelFact.DotBrush.ToString(), vm.SimpleToneBrush.ToString());
    }

    [AvaloniaFact]
    public async Task Offline_mode_leaves_external_address_unknown()
    {
        var vm = Build(Pro());

        await vm.RefreshOverviewCommand.ExecuteAsync(null);

        Assert.Equal("—", vm.ExternalIp);
        var address = vm.SimpleFacts.Single(f => f.Label == "Адрес выхода");
        Assert.Equal("неизвестен", address.Value);
        Assert.False(address.IsGood);
    }

    [AvaloniaFact]
    public async Task Refresh_twice_does_not_duplicate_rows()
    {
        var vm = Build(Pro());

        await vm.RefreshOverviewCommand.ExecuteAsync(null);
        var firstCount = vm.Adapters.Count;
        await vm.RefreshOverviewCommand.ExecuteAsync(null);

        Assert.Equal(firstCount, vm.Adapters.Count);
        Assert.Equal(6, vm.SimpleFacts.Count);
    }

    [AvaloniaFact]
    public async Task Platform_failure_is_reported_not_thrown()
    {
        var mode = Pro();
        var opts = Sample.Options();
        opts.OfflineMode = true;
        var platform = new FakePlatformProbe { ThrowOn = new InvalidOperationException("нет доступа к адаптерам") };
        var http = new FakeHttpProbe();
        var dns = new DnsClientLite(http);
        var service = new NetworkInfoService(platform, http, new PingTools(), dns, new AsnLookup(dns), new TraceTool(new PingTools()));
        var vm = new NetworkViewModel(service, opts, mode, NullLogger<NetworkViewModel>.Instance);

        await vm.RefreshOverviewCommand.ExecuteAsync(null);

        Assert.StartsWith("Ошибка", vm.StatusLine);
        Assert.False(vm.IsLoadingOverview);
        Assert.True(vm.RefreshOverviewCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void Tab_selection_drives_panels()
    {
        var vm = Build(Pro());

        vm.SelectTabCommand.Execute("Диагностика");

        Assert.True(vm.ShowDiagnostics);
        Assert.False(vm.ShowOverview);
        Assert.False(vm.ShowTrace);
        Assert.Equal("Диагностика", vm.ActiveTab);

        vm.SelectTabCommand.Execute("   ");
        Assert.Equal("Диагностика", vm.ActiveTab);

        vm.SelectTabCommand.Execute("Трассировка");
        Assert.True(vm.ShowTrace);
        Assert.False(vm.ShowDiagnostics);
    }
}
