using Avalonia.Headless.XUnit;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using RKNHardering.App.Startup;
using RKNHardering.App.ViewModels;
using RKNHardering.Core;
using RKNHardering.Core.Models;
using RKNHardering.Core.Options;
using RKNHardering.Data;
using RKNHardering.TestKit;
using Xunit;

namespace RKNHardering.App.Tests;

/// <summary>Заглушка диалога сохранения: запоминает вызов, файлов не создаёт.</summary>
public sealed class FakeFileDialog : IFileDialogService
{
    public List<(string Name, int Size)> Saved { get; } = [];

    public Task<string?> SaveTextAsync(string suggestedName, string content, string extension, string description)
    {
        Saved.Add((suggestedName, content.Length));
        return Task.FromResult<string?>(@"C:\temp\" + suggestedName);
    }

    public Task<string?> SaveBytesAsync(string suggestedName, byte[] content, string extension, string description)
    {
        Saved.Add((suggestedName, content.Length));
        return Task.FromResult<string?>(@"C:\temp\" + suggestedName);
    }
}

public sealed class TempEnv : IDisposable
{
    public TempEnv()
    {
        Directory = Path.Combine(Path.GetTempPath(), "rkn-app-tests-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Directory);
    }

    public string Directory { get; }

    public SettingsStore Store => new(Directory);

    public HistoryRepository History()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite($"Data Source={Path.Combine(Directory, "history.db")}")
            .Options;
        var factory = new PooledDbContextFactory<AppDbContext>(options);
        using (var db = factory.CreateDbContext()) db.Database.EnsureCreated();
        return new HistoryRepository(factory);
    }

    public void Dispose()
    {
        try { System.IO.Directory.Delete(Directory, true); } catch { }
    }
}

public class UiModeServiceTests
{
    [Fact]
    public void Simple_is_default_and_persists_choice()
    {
        using var env = new TempEnv();
        var ui = new UiOptions();
        var store = env.Store;
        var mode = new UiModeService(ui, store);

        Assert.True(mode.IsSimple);
        Assert.False(mode.IsPro);

        mode.IsPro = true;

        Assert.False(mode.IsSimple);
        Assert.True(ui.ProModeByDefault);
        Assert.Equal("Подробно", mode.ModeText);
        Assert.True(env.Store.Load().PrivacyMode == false);
        // настройка действительно сохранена в файл
        Assert.True(File.Exists(Path.Combine(env.Directory, "settings.json")));
    }

    [Fact]
    public void Pro_by_default_is_respected()
    {
        var mode = new UiModeService(new UiOptions { ProModeByDefault = true });
        Assert.True(mode.IsPro);
        Assert.Equal("Подробно", mode.ModeText);
    }
}

public class MainWindowViewModelTests
{
    private static MainWindowViewModel Build(TempEnv env, FakeFileDialog? files = null, RknOptions? options = null) =>
        TestHost.BuildMain(env, files, options);

    [AvaloniaFact]
    public void Navigation_switches_pages_and_marks_selection()
    {
        using var env = new TempEnv();
        var main = Build(env);

        main.NavigateCommand.Execute(main.NavItems[2]);

        Assert.Equal("История", main.CurrentPage.Title);
        Assert.True(main.NavItems[2].IsSelected);
        Assert.False(main.NavItems[0].IsSelected);
        Assert.Equal(5, main.NavItems.Count);
    }

    [AvaloniaFact]
    public void Mode_toggle_switches_between_simple_and_pro()
    {
        using var env = new TempEnv();
        var main = Build(env);

        main.SwitchModeCommand.Execute("pro");
        Assert.True(main.Mode.IsPro);

        main.SwitchModeCommand.Execute("simple");
        Assert.True(main.Mode.IsSimple);

        main.SwitchModeCommand.Execute(null);
        Assert.True(main.Mode.IsSimple);
    }

    [AvaloniaFact]
    public async Task Run_fills_plain_and_technical_views()
    {
        using var env = new TempEnv();
        var main = Build(env);
        var dashboard = (DashboardViewModel)main.Pages[0];

        await dashboard.RunCommand.ExecuteAsync(null);

        Assert.True(dashboard.HasResult);
        Assert.NotNull(dashboard.Verdict);
        Assert.NotEmpty(dashboard.Facts);
        Assert.NotEmpty(dashboard.PlainChecks);
        Assert.NotEmpty(dashboard.PlainHeadline);
        Assert.DoesNotContain("Проверка ещё не запускалась", dashboard.PlainHeadline);
    }

    [AvaloniaFact]
    public async Task Export_writes_selected_format()
    {
        using var env = new TempEnv();
        var files = new FakeFileDialog();
        var main = Build(env, files);
        var dashboard = (DashboardViewModel)main.Pages[0];
        await dashboard.RunCommand.ExecuteAsync(null);

        dashboard.SelectedFormat = dashboard.ExportFormats.Single(f => f.Extension == ".pdf");
        await dashboard.ExportReportCommand.ExecuteAsync(null);

        var saved = Assert.Single(files.Saved);
        Assert.EndsWith(".pdf", saved.Name);
        Assert.True(saved.Size > 1000);
        Assert.Contains("сохранён", dashboard.SaveMessage);
    }

    [AvaloniaFact]
    public async Task Export_does_nothing_without_result()
    {
        using var env = new TempEnv();
        var files = new FakeFileDialog();
        var main = Build(env, files);
        var dashboard = (DashboardViewModel)main.Pages[0];

        Assert.False(dashboard.ExportReportCommand.CanExecute(null));
        await dashboard.ExportReportCommand.ExecuteAsync(null);

        Assert.Empty(files.Saved);
    }

    [AvaloniaFact]
    public async Task History_page_lists_saved_runs()
    {
        using var env = new TempEnv();
        var options = Sample.Options();
        options.SaveHistory = true;
        var main = Build(env, options: options);
        var dashboard = (DashboardViewModel)main.Pages[0];
        var history = (HistoryViewModel)main.Pages[2];

        await dashboard.RunCommand.ExecuteAsync(null);
        await history.RefreshCommand.ExecuteAsync(null);

        Assert.Single(history.Runs);
        history.Selected = history.Runs[0];
        Assert.True(history.HasDetail);
        Assert.NotEmpty(history.DetailChecks);
    }

    [AvaloniaFact]
    public void Settings_roundtrip_updates_options()
    {
        using var env = new TempEnv();
        var main = Build(env);
        var settings = (SettingsViewModel)main.Pages[4];

        settings.RequestTimeout = 17;
        settings.LocalProxyPorts = "1080, 8080, не-число, 70000";
        settings.GeoIpProviders = "https://a.test/\n\nhttps://b.test/";
        settings.SaveCommand.Execute(null);

        var store = env.Store;
        var loaded = store.Load();
        Assert.Equal(17, loaded.RequestTimeoutSeconds);
        Assert.Equal([1080, 8080], loaded.LocalProxyPorts);
        Assert.Equal(["https://a.test/", "https://b.test/"], loaded.GeoIpProviders);
    }

    [AvaloniaFact]
    public void Settings_reset_restores_defaults()
    {
        using var env = new TempEnv();
        var main = Build(env);
        var settings = (SettingsViewModel)main.Pages[4];
        settings.RequestTimeout = 44;
        settings.MaxParallelChecks = 11;

        settings.ResetToDefaultsCommand.Execute(null);

        Assert.Equal(8, settings.RequestTimeout);
        Assert.Equal(6, settings.MaxParallelChecks);
    }

    [AvaloniaFact]
    public void Guide_contains_sections_for_all_modules_and_modes()
    {
        var guide = new GuideViewModel();

        Assert.True(guide.Sections.Count >= 6);
        Assert.Contains(guide.Sections, s => s.Title.Contains("Прямые признаки"));
        Assert.Contains(guide.Sections, s => s.Title.Contains("Сеть"));
        Assert.All(guide.Sections, s => Assert.NotEmpty(s.Items));

        var section = guide.Sections[0];
        var wasExpanded = section.IsExpanded;
        guide.ToggleSectionCommand.Execute(section);
        Assert.NotEqual(wasExpanded, section.IsExpanded);
    }

    [Fact]
    public void Export_formats_catalog_is_complete()
    {
        Assert.Equal(6, ExportFormatOption.All.Count);
        Assert.Contains(ExportFormatOption.All, f => f.Extension == ".xlsx");
        Assert.All(ExportFormatOption.All, f => Assert.Contains("—", f.Display));
    }
}
