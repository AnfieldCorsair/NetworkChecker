using Microsoft.Extensions.DependencyInjection;
using NetworkChecker.App.ViewModels;
using NetworkChecker.Core.VpnAudit;

namespace NetworkChecker.App.Startup;

/// <summary>
/// Регистрация всех сервисов и 5 экранов NetworkChecker V2 (Контур ВПН) в DI-контейнере.
/// </summary>
public static class VpnAuditServiceCollectionExtensions
{
    public static IServiceCollection AddRefactoredVpnAudit(this IServiceCollection services)
    {
        services.AddSingleton(_ =>
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("NetworkChecker/2.0");
            return client;
        });

        services.AddSingleton<VpnEndpointProbe>();
        services.AddSingleton<SubscriptionService>(sp => new SubscriptionService(sp.GetRequiredService<HttpClient>()));
        services.AddSingleton<IDesktopUiService, DesktopUiService>();

        services.AddSingleton<ConfigAuditViewModel>();
        services.AddSingleton<DnsArchitectViewModel>();
        services.AddSingleton<TspuFingerprintsViewModel>();
        services.AddSingleton<WindowsStackSniViewModel>();
        services.AddSingleton<SupportTicketViewModel>();
        services.AddSingleton<MainWindowViewModel>();
        return services;
    }
}
