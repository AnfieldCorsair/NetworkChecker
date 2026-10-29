using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RKNHardering.App.Startup;
using RKNHardering.App.ViewModels;
using RKNHardering.App.Views;
using Serilog;

namespace RKNHardering.App;

public partial class App : Application
{
    public static IHost? Host { get; private set; }

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            Host ??= AppServices.Build(Array.Empty<string>());
            var migrate = AppServices.MigrateAsync(Host);
            migrate.GetAwaiter().GetResult();

            var window = new MainWindow
            {
                DataContext = Host.Services.GetRequiredService<MainWindowViewModel>(),
            };
            desktop.MainWindow = window;
            desktop.ShutdownRequested += (_, _) =>
            {
                try
                {
                    Host?.StopAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                    Log.CloseAndFlush();
                }
                catch { }
            };

            var ui = Host.Services.GetRequiredService<Core.Options.UiOptions>();
            ApplyTheme(ui.Theme);
        }

        base.OnFrameworkInitializationCompleted();
    }

    public static void ApplyTheme(string theme)
    {
        if (Current is null) return;
        Current.RequestedThemeVariant = theme switch
        {
            "Light" => ThemeVariant.Light,
            "System" => ThemeVariant.Default,
            _ => ThemeVariant.Dark,
        };
    }
}

/// <summary>Запуск десктопного приложения.</summary>
public static class AppEntry
{
    public static void Run(string[] args) => Program.BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
}
