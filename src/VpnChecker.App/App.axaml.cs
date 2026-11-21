using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using VpnChecker.App.Startup;
using VpnChecker.App.ViewModels;
using VpnChecker.App.Views;
using VpnChecker.Core.VpnAudit;

namespace VpnChecker.App;

public partial class App : Application
{
    private IServiceProvider? _services;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var collection = new ServiceCollection();
            collection.AddVpnCheckerServices();
            _services = collection.BuildServiceProvider();

            var mainWindow = new MainWindow
            {
                DataContext = _services.GetRequiredService<MainWindowViewModel>(),
            };

            desktop.MainWindow = mainWindow;
            desktop.ShutdownRequested += (_, _) =>
            {
                SubscriptionService.StopLocalSubscriptionServer();
                if (_services is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
