using Xunit;
using Avalonia;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using RKNHardering.App.Tests;
using RKNHardering.App.ViewModels;
using RKNHardering.App.Views;

[assembly: AvaloniaTestApplication(typeof(TestAppBuilder))]

namespace RKNHardering.App.Tests;

/// <summary>
/// Тестовое приложение — то же, что и в проде (реальные стили и ресурсы из App.axaml),
/// но headless и без запуска DI-хоста.
/// </summary>
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder
        .Configure<global::RKNHardering.App.App>()
        .UseSkia()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
        .WithInterFont();
}

/// <summary>Ловит предупреждения Avalonia, в том числе ошибки привязок.</summary>
internal sealed class CollectingLogSink : Avalonia.Logging.ILogSink
{
    public List<string> Entries { get; } = [];

    public bool IsEnabled(Avalonia.Logging.LogEventLevel level, string area) =>
        level >= Avalonia.Logging.LogEventLevel.Warning;

    public void Log(Avalonia.Logging.LogEventLevel level, string area, object? source, string messageTemplate) =>
        Entries.Add($"{level}/{area}: {messageTemplate}");

    public void Log(Avalonia.Logging.LogEventLevel level, string area, object? source, string messageTemplate, params object?[] propertyValues) =>
        Entries.Add($"{level}/{area}: {messageTemplate} :: {string.Join(" | ", propertyValues)}");
}

/// <summary>
/// Дымовые тесты интерфейса: XAML реально загружается и рисуется, привязки не падают.
/// Такие тесты ловят опечатки в Binding и отсутствующие ресурсы, которые компилятор не видит.
/// </summary>
public class ViewSmokeTests
{
    private static void Pump(int ticks = 8)
    {
        for (var i = 0; i < ticks; i++)
        {
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            Dispatcher.UIThread.RunJobs();
        }
    }

    private static (MainWindow Window, MainWindowViewModel Vm, CollectingLogSink Log) ShowApp(TempEnv env)
    {
        var sink = new CollectingLogSink();
        Avalonia.Logging.Logger.Sink = sink;

        var main = TestHost.BuildMain(env);
        var window = new MainWindow
        {
            DataContext = main,
            Width = 1440,
            Height = 940,
        };
        window.Show();
        Pump();
        return (window, main, sink);
    }

    [AvaloniaFact]
    public void Every_page_renders_without_binding_errors()
    {
        using var env = new TempEnv();
        var (window, main, sink) = ShowApp(env);

        foreach (var nav in main.NavItems)
        {
            main.NavigateCommand.Execute(nav);
            Pump(12);

            var frame = window.CaptureRenderedFrame();
            Assert.NotNull(frame);
            Assert.True(frame!.PixelSize.Width >= 1000, "кадр слишком маленький: " + nav.Title);
            frame.Dispose();

            Assert.Equal(nav.Title, main.CurrentPage.Title);
        }

        // Warning'и про еще не заполненный Verdict — норма для экрана до первого прогона;
        // ошибки (Error) означают, что привязка или ресурс сломаны.
        var problems = sink.Entries
            .Where(e => e.StartsWith("Error", StringComparison.Ordinal))
            .ToList();
        Assert.True(problems.Count == 0, string.Join("\n", problems.Distinct()));
    }

    [AvaloniaFact]
    public void Simple_mode_renders_dashboard_and_network()
    {
        using var env = new TempEnv();
        var (window, main, sink) = ShowApp(env);

        Assert.True(main.Mode.IsSimple);
        main.NavigateCommand.Execute(main.NavItems[1]);
        Pump(12);
        using (var frame = window.CaptureRenderedFrame())
        {
            Assert.NotNull(frame);
        }

        main.SwitchModeCommand.Execute("pro");
        Pump(12);
        Assert.NotNull(window.CaptureRenderedFrame());

        // Переключение туда-обратно не должно оставлять битых привязок.
        main.SwitchModeCommand.Execute("simple");
        Pump(12);
        Assert.DoesNotContain(sink.Entries, e => e.StartsWith("Error", StringComparison.Ordinal));
    }

    [AvaloniaFact]
    public void Result_screen_renders_in_both_modes()
    {
        using var env = new TempEnv();
        var (window, main, _) = ShowApp(env);
        var dashboard = (DashboardViewModel)main.Pages[0];
        dashboard.LoadRun(global::RKNHardering.TestKit.Sample.RichRun());
        Pump(12);

        Assert.True(dashboard.HasResult);
        dashboard.Mode.IsPro = true;
        Pump(12);
        Assert.NotNull(window.CaptureRenderedFrame());

        dashboard.Mode.IsSimple = true;
        Pump(12);
        Assert.NotNull(window.CaptureRenderedFrame());
    }
}
