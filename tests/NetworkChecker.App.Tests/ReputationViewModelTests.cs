using Avalonia.Headless.XUnit;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkChecker.App.ViewModels;
using NetworkChecker.Core.Options;
using NetworkChecker.Core.Reputation;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.App.Tests;

/// <summary>Новая вкладка «Репутация»: привязки и отображение метки GL.</summary>
public class ReputationViewModelTests
{
    private static ReputationService Service()
    {
        var http = new FakeHttpProbe().With("api.ipapi.is", "{\"ip\":\"203.0.113.7\",\"country\":\"DE\"}");
        var external = new FakeExternalProbe()
            .With("m.youtube.com", "ytcfg.set({\"GL\":\"RU\"});")
            .WithRedirect("aistudio.google.com",
                "https://ai.google.dev/gemini-api/docs/available-regions", "region")
            .With("proxycheck.io", "{\"status\":\"ok\",\"203.0.113.7\":{\"proxy\":\"no\",\"risk\":0}}");
        return new ReputationService(http, external);
    }

    [AvaloniaFact]
    public async Task Refresh_shows_ru_label_and_ai_studio_redirect()
    {
        var options = new RknOptions { OfflineMode = false };
        var vm = new ReputationViewModel(Service(), options, NullLogger<ReputationViewModel>.Instance);

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.Equal("RU", vm.GlText);
        Assert.Equal("DE", vm.GeoText);
        Assert.True(vm.HasData);
        Assert.NotEmpty(vm.Sources);
        Assert.NotEmpty(vm.Caveats);
        Assert.Contains("RU", vm.Headline);
        Assert.NotEmpty(vm.Summary);
    }

    [AvaloniaFact]
    public void Ensure_loaded_does_not_start_network_requests()
    {
        var service = Service();
        var vm = new ReputationViewModel(service, new RknOptions(), NullLogger<ReputationViewModel>.Instance);

        vm.EnsureLoaded();

        Assert.False(vm.HasData);
        Assert.Empty(vm.Sources);
        Assert.Null(service.Last);
    }
}
