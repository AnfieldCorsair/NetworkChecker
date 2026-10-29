using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RKNHardering.Core;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Checks;
using RKNHardering.Core.Net;
using RKNHardering.Core.NetInfo;
using RKNHardering.Core.Options;
using RKNHardering.Data;
using RKNHardering.Platform.Windows;
using RKNHardering.App.ViewModels;
using Serilog;

namespace RKNHardering.App.Startup;

/// <summary>Сборка приложения: Microsoft.Extensions.Hosting + DI, Serilog, проверки, EF Core.</summary>
public static class AppServices
{
    public static IHost Build(string[] args)
    {
        var settings = new SettingsStore();
        var options = settings.Load();

        Directory.CreateDirectory(Path.GetDirectoryName(settings.LogPath)!);
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(settings.LogPath, rollingInterval: RollingInterval.Day, retainedFileCountLimit: 7)
            .CreateLogger();

        var builder = Host.CreateApplicationBuilder(args);
        builder.Logging.ClearProviders();
        builder.Logging.AddSerilog(Log.Logger, dispose: true);

        var services = builder.Services;

        services.AddSingleton(settings);
        services.AddSingleton(options);
        services.AddSingleton(settings.Ui);

        services.AddSingleton<VpnClientCatalog>();
        services.AddSingleton<IPlatformProbe, WindowsPlatformProbe>();
        services.AddSingleton<IHttpProbe, HttpProbe>();
        services.AddSingleton<PingTools>();
        services.AddSingleton<TraceTool>();
        services.AddSingleton<DnsClientLite>();
        services.AddSingleton<AsnLookup>();
        services.AddSingleton<NetworkInfoService>();

        services.AddSingleton<ICheck, GeoIpCheck>();
        services.AddSingleton<ICheck, IpComparisonCheck>();
        services.AddSingleton<ICheck, DirectSignsCheck>();
        services.AddSingleton<ICheck, IndirectSignsCheck>();
        services.AddSingleton<ICheck, BypassCheck>();
        services.AddSingleton<ICheck, CallTransportCheck>();
        services.AddSingleton<ICheck, CdnPullingCheck>();
        services.AddSingleton<ICheck, DomainReachabilityCheck>();
        services.AddSingleton<ICheck, RttTriangulationCheck>();
        services.AddSingleton<ICheck, IcmpSpoofingCheck>();

        services.AddSingleton<CheckRunner>();

        services.AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={settings.DatabasePath}"));
        services.AddSingleton<HistoryRepository>();
        services.AddSingleton<IFileDialogService, FileDialogService>();

        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<NetworkViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<GuideViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<MainWindowViewModel>();

        return builder.Build();
    }

    public static async Task MigrateAsync(IHost host)
    {
        try
        {
            await using var db = await host.Services.GetRequiredService<IDbContextFactory<AppDbContext>>()
                .CreateDbContextAsync().ConfigureAwait(false);
            await db.Database.EnsureCreatedAsync().ConfigureAwait(false);
            Log.Information("База истории готова: {Path}", host.Services.GetRequiredService<SettingsStore>().DatabasePath);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Не удалось подготовить базу истории");
        }
    }
}
