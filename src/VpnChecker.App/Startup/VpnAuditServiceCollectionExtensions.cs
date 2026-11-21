using System.Net;
using Microsoft.Extensions.DependencyInjection;
using VpnChecker.App.ViewModels;
using VpnChecker.Core.VpnAudit;

namespace VpnChecker.App.Startup;

/// <summary>
/// Регистрация всех сервисов и 6 экранов VPN_Checker в DI-контейнере.
/// </summary>
public static class VpnAuditServiceCollectionExtensions
{
    public static IServiceCollection AddVpnCheckerServices(this IServiceCollection services)
    {
        services.AddSingleton(_ =>
        {
            SocketsHttpHandler? handler = null;
            try
            {
                handler = new SocketsHttpHandler
                {
                    AutomaticDecompression = DecompressionMethods.All,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                };
                var client = new HttpClient(handler, disposeHandler: true)
                {
                    Timeout = TimeSpan.FromSeconds(12),
                };
                handler = null;
                client.DefaultRequestHeaders.UserAgent.ParseAdd("VPN_Checker/2.3");
                return client;
            }
            finally
            {
                handler?.Dispose();
            }
        });

        services.AddSingleton<VpnEndpointProbe>();
        services.AddSingleton<SubscriptionService>(sp => new SubscriptionService(sp.GetRequiredService<HttpClient>()));
        services.AddSingleton<IDesktopUiService, DesktopUiService>();

        services.AddSingleton<ConfigAuditViewModel>();
        services.AddSingleton<DnsArchitectViewModel>();
        services.AddSingleton<TspuFingerprintsViewModel>();
        services.AddSingleton<WindowsStackSniViewModel>();
        services.AddSingleton<IpReputationViewModel>();
        services.AddSingleton<SupportTicketViewModel>();
        services.AddSingleton<MainWindowViewModel>();
        return services;
    }
}
