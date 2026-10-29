using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Media;
using Avalonia.Threading;
using NetworkChecker.App.Tests;
using NetworkChecker.App.ViewModels;
using NetworkChecker.App.Views;
using Xunit;

[assembly: AvaloniaTestApplication(typeof(TestAppBuilder))]

namespace NetworkChecker.App.Tests;

/// <summary>
/// Тестовое приложение — то же, что и в проде (реальные стили и ресурсы из App.axaml),
/// но headless и без запуска DI-хоста.
/// </summary>
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder
        .Configure<global::NetworkChecker.App.App>()
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
    public void Selectable_text_uses_global_wrapping_and_displays_multiple_lines()
    {
        var text = new SelectableTextBlock
        {
            Text = "Длинное описание проверки, которое должно полностью переноситься на несколько строк без сокращения.",
        };
        var window = new Window { Width = 180, Height = 240, Content = new Border { Width = 120, Child = text } };
        window.Show();
        Pump(12);
        Assert.Equal(TextWrapping.Wrap, text.TextWrapping);
        Assert.Equal(TextTrimming.None, text.TextTrimming);
        Assert.True(text.TextLayout.TextLines.Count > 1);
        Assert.True(text.Bounds.Height >= text.TextLayout.Height - 1);
        window.Close();
    }

    [AvaloniaFact]
    public void Narrow_window_can_scroll_to_wide_page_content()
    {
        using var env = new TempEnv();
        var (window, _, _) = ShowApp(env);
        window.Width = 760;
        window.Height = 520;
        Pump(12);
        var viewport = window.FindControl<ScrollViewer>("PageViewport");
        Assert.NotNull(viewport);
        Assert.True(viewport!.Extent.Width > viewport.Viewport.Width);
        viewport.Offset = new Vector(viewport.Extent.Width - viewport.Viewport.Width, 0);
        Pump();
        Assert.True(viewport.Offset.X > 0);
        window.Close();
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
    public void Trace_graph_renders_known_and_unknown_asns()
    {
        using var env = new TempEnv();
        var (window, main, sink) = ShowApp(env);
        main.Mode.IsPro = true;
        main.NavigateCommand.Execute(main.NavItems[1]);
        var network = (NetworkViewModel)main.Pages[1];
        network.SelectTabCommand.Execute("Трассировка");
        network.Hops.Add(new TraceHopViewModel(new NetworkChecker.Core.Net.TraceHop(1, "8.8.8.8", [TimeSpan.FromMilliseconds(10)], "15169", "Google")));
        network.Hops.Add(new TraceHopViewModel(new NetworkChecker.Core.Net.TraceHop(2, null, [], null, null)));
        Pump(12);
        using var frame = window.CaptureRenderedFrame();
        Assert.NotNull(frame);
        Assert.DoesNotContain(sink.Entries, e => e.StartsWith("Error", StringComparison.Ordinal));
    }

    [AvaloniaFact]
    public void Result_screen_renders_in_both_modes()
    {
        using var env = new TempEnv();
        var (window, main, _) = ShowApp(env);
        var dashboard = (DashboardViewModel)main.Pages[0];
        dashboard.LoadRun(global::NetworkChecker.TestKit.Sample.RichRun());
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
