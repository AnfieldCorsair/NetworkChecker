using Avalonia;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Microsoft.Extensions.DependencyInjection;
using NetworkChecker.App.Startup;
using NetworkChecker.App.ViewModels;
using NetworkChecker.App.Views;

namespace NetworkChecker.Screenshots;

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

        AppBuilder.Configure<global::NetworkChecker.App.App>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .WithInterFont()
            .SetupWithoutStarting();

        // Чистая история: скриншоты не должны зависеть от прошлых прогонов.
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkChecker");
        if (Directory.Exists(dataDir))
        {
            foreach (var file in Directory.GetFiles(dataDir, "history.db*"))
            {
                try { File.Delete(file); } catch { }
            }
        }

        var host = AppServices.Build([]);
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

        // Отдельный демонстрационный кадр схемы: адреса документационные, ASN вымышленные.
        network.Hops.Clear();
        network.Hops.Add(new TraceHopViewModel(new NetworkChecker.Core.Net.TraceHop(1, "192.0.2.1", [TimeSpan.FromMilliseconds(12)], "64500", "Пример сети A")));
        network.Hops.Add(new TraceHopViewModel(new NetworkChecker.Core.Net.TraceHop(2, "192.0.2.2", [TimeSpan.FromMilliseconds(21)], "64500", "Пример сети A")));
        network.Hops.Add(new TraceHopViewModel(new NetworkChecker.Core.Net.TraceHop(3, null, [], null, null)));
        network.Hops.Add(new TraceHopViewModel(new NetworkChecker.Core.Net.TraceHop(4, "198.51.100.5", [TimeSpan.FromMilliseconds(38)], "64501", "Пример сети B")));
        network.TraceStatus = "ДЕМО · вымышленные хопы и ASN";
        Pump(8);
        Save(window, Path.Combine(output, "07b-network-trace-demo.png"));

        // 9. История
        main.NavigateCommand.Execute(main.NavItems[3]);
        var history = host.Services.GetRequiredService<HistoryViewModel>();
        AwaitWithPump(history.RefreshCommand.ExecuteAsync(null), TimeSpan.FromSeconds(20));
        Pump(4);
        if (history.Runs.Count > 0) history.Selected = history.Runs[0];
        Pump(10);
        Save(window, Path.Combine(output, "08-history.png"));

        // 10. История: сравнение с предыдущим прогоном.
        // Второй прогон делаем в офлайн-режиме — в сравнении появляются реальные различия.
        main.NavigateCommand.Execute(main.NavItems[0]);
        var runOptions = host.Services.GetRequiredService<NetworkChecker.Core.Options.RknOptions>();
        runOptions.OfflineMode = true;
        AwaitWithPump(dashboard.RunCommand.ExecuteAsync(null), TimeSpan.FromSeconds(120));
        runOptions.OfflineMode = false;
        Pump(6);

        main.NavigateCommand.Execute(main.NavItems[3]);
        AwaitWithPump(history.RefreshCommand.ExecuteAsync(null), TimeSpan.FromSeconds(20));
        Pump(4);
        if (history.Runs.Count > 0) history.Selected = history.Runs[0];
        Pump(8);
        AwaitWithPump(history.CompareWithPreviousCommand.ExecuteAsync(null), TimeSpan.FromSeconds(20));
        Pump(10);
        Save(window, Path.Combine(output, "09-history-compare.png"));
        history.CloseComparisonCommand.Execute(null);
        Pump(4);

        // 10. Глазами сайта — что о вас узнаёт ВК или Яндекс
        mode.IsPro = true;
        main.NavigateCommand.Execute(main.NavItems[2]);
        var site = host.Services.GetRequiredService<SiteViewModel>();
        AwaitWithPump(site.PendingTask, TimeSpan.FromSeconds(60));
        Pump(10);
        Save(window, Path.Combine(output, "10-site-view.png"));

        // 11. Справка
        main.NavigateCommand.Execute(main.NavItems[4]);
        Pump(8);
        Save(window, Path.Combine(output, "11-guide.png"));

        // 12. Настройки
        main.NavigateCommand.Execute(main.NavItems[5]);
        Pump(8);
        Save(window, Path.Combine(output, "12-settings.png"));

        // 12. Демонстрационные отчёты во всех форматах — чтобы формат можно было посмотреть глазами.
        var lastRun = dashboard.LastResult;
        if (lastRun is not null)
        {
            var samplesDir = Path.Combine(output, "..", "samples");
            Directory.CreateDirectory(samplesDir);
            foreach (var (format, title, _, _) in NetworkChecker.Export.ReportExporter.Catalog)
            {
                var file = NetworkChecker.Export.ReportExporter.Build(format, lastRun, "networkchecker-report");
                File.WriteAllBytes(Path.Combine(samplesDir, file.FileName), file.Content);
                Console.WriteLine($"Отчёт {title}: {file.FileName} ({file.Content.Length} байт)");
            }
            Console.WriteLine("Отчёты: " + Path.GetFullPath(samplesDir));
        }

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
