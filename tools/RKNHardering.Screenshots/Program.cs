using Avalonia;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using RKNHardering.App;
using RKNHardering.App.Startup;
using RKNHardering.App.ViewModels;
using RKNHardering.App.Views;

namespace RKNHardering.Screenshots;

/// <summary>
/// Служебная утилита: рендерит реальные экраны Avalonia в PNG (headless + Skia).
/// Нужна для ревью UI без запуска на Windows.
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var output = args.Length > 0 ? args[0] : "screenshots";
        Directory.CreateDirectory(output);

        AppBuilder.Configure<global::RKNHardering.App.App>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .WithInterFont()
            .SetupWithoutStarting();

        // Чистая история: скриншоты не должны зависеть от прошлых прогонов.
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RKNHarderingPC");
        if (Directory.Exists(dataDir))
        {
            foreach (var file in Directory.GetFiles(dataDir, "history.db*"))
            {
                try { File.Delete(file); } catch { }
            }
        }

        var host = AppServices.Build(Array.Empty<string>());
        AppServices.MigrateAsync(host).GetAwaiter().GetResult();

        var main = host.Services.GetRequiredService<MainWindowViewModel>();
        var window = new MainWindow
        {
            DataContext = main,
            Width = 1440,
            Height = 940,
        };
        window.Show();
        Pump();

        var dashboard = host.Services.GetRequiredService<DashboardViewModel>();
        var network = host.Services.GetRequiredService<NetworkViewModel>();
        var mode = main.Mode;

        // 1. Простой режим: экран до запуска
        mode.IsSimple = true;
        Save(window, Path.Combine(output, "01-dashboard-simple-idle.png"));

        // 2. Реальный прогон проверки (сеть нужна; в офлайн-среде часть модулей уйдёт в Skipped)
        Console.WriteLine("Запуск проверки...");
        if (!AwaitWithPump(dashboard.RunCommand.ExecuteAsync(null), TimeSpan.FromSeconds(240)))
            Console.WriteLine("Проверка не завершилась за 240 с — снимаю текущее состояние.");

        for (var i = 0; i < 20; i++)
        {
            Pump();
            Thread.Sleep(120);
        }

        // 3. Простой режим: понятный результат
        Save(window, Path.Combine(output, "02-dashboard-simple-result.png"));

        // 4. Подробный режим: тот же прогон в технических деталях
        mode.IsPro = true;
        Pump(10);
        Save(window, Path.Combine(output, "03-dashboard-pro-result.png"));

        // 5. Сеть в простом режиме
        mode.IsSimple = true;
        main.NavigateCommand.Execute(main.NavItems[1]);
        AwaitWithPump(network.RefreshOverviewCommand.ExecuteAsync(null), TimeSpan.FromSeconds(90));
        Pump(10);
        Save(window, Path.Combine(output, "04-network-simple.png"));

        // 6. Сеть: овервью в подробном режиме
        mode.IsPro = true;
        network.SelectTabCommand.Execute("Овервью");
        AwaitWithPump(network.RefreshOverviewCommand.ExecuteAsync(null), TimeSpan.FromSeconds(90));
        Pump(10);
        Save(window, Path.Combine(output, "05-network-overview.png"));

        // 7. Сеть: диагностика
        network.SelectTabCommand.Execute("Диагностика");
        AwaitWithPump(network.RunDiagnosticsCommand.ExecuteAsync(null), TimeSpan.FromSeconds(180));
        Pump(8);
        Save(window, Path.Combine(output, "06-network-diagnostics.png"));

        // 8. Сеть: трассировка
        network.SelectTabCommand.Execute("Трассировка");
        AwaitWithPump(network.RunTraceCommand.ExecuteAsync(null), TimeSpan.FromSeconds(180));
        Pump(8);
        Save(window, Path.Combine(output, "07-network-trace.png"));

        // 9. История
        main.NavigateCommand.Execute(main.NavItems[2]);
        var history = host.Services.GetRequiredService<HistoryViewModel>();
        AwaitWithPump(history.RefreshCommand.ExecuteAsync(null), TimeSpan.FromSeconds(20));
        Pump(4);
        if (history.Runs.Count > 0) history.Selected = history.Runs[0];
        Pump(10);
        Save(window, Path.Combine(output, "08-history.png"));

        // 10. Справка
        main.NavigateCommand.Execute(main.NavItems[3]);
        Pump(8);
        Save(window, Path.Combine(output, "09-guide.png"));

        // 11. Настройки
        main.NavigateCommand.Execute(main.NavItems[4]);
        Pump(8);
        Save(window, Path.Combine(output, "10-settings.png"));

        Console.WriteLine("Готово: " + Path.GetFullPath(output));
        return 0;
    }

    /// <summary>
    /// Ожидание с прокачкой UI-очереди: ViewModel'и возвращаются в UI-поток,
    /// поэтому блокирующий Wait() на нём привёл бы к дедлоку.
    /// </summary>
    private static bool AwaitWithPump(Task task, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!task.IsCompleted && DateTime.UtcNow < deadline)
        {
            Dispatcher.UIThread.RunJobs();
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            Thread.Sleep(20);
        }
        Dispatcher.UIThread.RunJobs();
        return task.IsCompleted;
    }

    private static void Save(MainWindow window, string path)
    {
        Pump();
        // Даём компоновке доехать до финального кадра: длинные WrapPanel дорисовываются
        // не за один тик, поэтому прокручиваем рендер несколько раз.
        for (var i = 0; i < 12; i++)
        {
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(25);
        }
        _ = window.CaptureRenderedFrame();
        var frame = window.CaptureRenderedFrame();
        if (frame is null)
        {
            Console.WriteLine("Не удалось отрисовать кадр: " + path);
            return;
        }
        frame.Save(path, new PngBitmapEncoderOptions());
        Console.WriteLine("Сохранено: " + path);
    }

    private static void Pump(int ticks = 3)
    {
        for (var i = 0; i < ticks; i++)
        {
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            Dispatcher.UIThread.RunJobs();
        }
    }
}
