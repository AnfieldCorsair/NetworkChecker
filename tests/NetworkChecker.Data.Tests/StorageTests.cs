using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using NetworkChecker.TestKit;
using Xunit;

namespace NetworkChecker.Data.Tests;

/// <summary>Каждый тест работает в своей временной папке — реальные данные пользователя не трогаем.</summary>
public sealed class TempData : IDisposable
{
    public TempData()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "rkn-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public SettingsStore Store() => new(Path);

    public IDbContextFactory<AppDbContext> Factory()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            // Test databases must release SQLite file handles between operations on Windows.
            .UseSqlite(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
            {
                DataSource = System.IO.Path.Combine(Path, "history.db"),
                Pooling = false,
            }.ToString())
            .Options;
        var factory = new PooledDbContextFactory<AppDbContext>(options);
        using var db = factory.CreateDbContext();
        db.Database.EnsureCreated();
        return factory;
    }

    public HistoryRepository Repository() => new(Factory());

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch { }
    }
}

public class HistoryRepositoryTests
{
    [Fact]
    public async Task Saved_run_is_returned_with_same_verdict_and_checks()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        var run = Sample.RichRun();

        await repository.SaveAsync(run);
        var restored = await repository.GetAsync(run.Id);

        Assert.NotNull(restored);
        Assert.Equal(run.Verdict.Score, restored!.Verdict.Score);
        Assert.Equal(run.Verdict.Headline, restored.Verdict.Headline);
        Assert.Equal(run.Checks.Count, restored.Checks.Count);
        Assert.Equal(run.IpConsensus.ConsensusIp, restored.IpConsensus.ConsensusIp);
        Assert.Contains(restored.Verdict.Reasons, r => r.Contains("прокси"));
    }

    [Fact]
    public async Task Findings_survive_serialization()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        var run = Sample.RichRun();

        await repository.SaveAsync(run);
        var restored = await repository.GetAsync(run.Id);

        var bypass = restored!.Checks.Single(c => c.Category == Core.Models.CheckCategory.Bypass);
        var finding = bypass.Findings.Single();
        Assert.Equal("Локальный прокси на 127.0.0.1:1080", finding.Title);
        Assert.Equal(Core.Models.Severity.Critical, finding.Severity);
    }

    [Fact]
    public async Task Recent_returns_newest_first()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        // Сортировка идёт по времени начала прогона, а не по порядку вставки.
        var newer = WithStart(Sample.RichRun(), DateTimeOffset.Now);
        var older = WithStart(Sample.CleanRun(), DateTimeOffset.Now.AddHours(-3));

        await repository.SaveAsync(older);
        await repository.SaveAsync(newer);

        var recent = await repository.GetRecentAsync();

        Assert.Equal(2, recent.Count);
        Assert.Equal(newer.Id, recent[0].Id);
        Assert.Equal(older.Id, recent[1].Id);
        Assert.True(recent[0].StartedAt > recent[1].StartedAt);
    }

    private static Core.Models.CheckRunResult WithStart(Core.Models.CheckRunResult run, DateTimeOffset startedAt) =>
        new()
        {
            Id = run.Id,
            StartedAt = startedAt,
            FinishedAt = startedAt.AddSeconds(5),
            Checks = run.Checks,
            Verdict = run.Verdict,
            IpConsensus = run.IpConsensus,
            Environment = run.Environment,
        };

    [Fact]
    public async Task Delete_and_clear_work()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        var first = Sample.CleanRun();
        var second = Sample.RichRun();
        await repository.SaveAsync(first);
        await repository.SaveAsync(second);

        await repository.DeleteAsync(first.Id);
        Assert.Equal(1, await repository.CountAsync());

        await repository.ClearAsync();
        Assert.Equal(0, await repository.CountAsync());
        Assert.Empty(await repository.GetRecentAsync());
    }

    [Fact]
    public async Task Missing_run_returns_null()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        Assert.Null(await repository.GetAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Deleting_unknown_id_is_noop()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        await repository.SaveAsync(Sample.CleanRun());

        await repository.DeleteAsync(Guid.NewGuid());

        Assert.Equal(1, await repository.CountAsync());
    }

    [Fact]
    public async Task Privacy_mode_flag_is_stored()
    {
        using var temp = new TempData();
        var repository = temp.Repository();
        var baseRun = Sample.CleanRun();
        var masked = new Core.Models.CheckRunResult
        {
            StartedAt = baseRun.StartedAt,
            FinishedAt = baseRun.FinishedAt,
            Checks = baseRun.Checks,
            Verdict = baseRun.Verdict,
            IpConsensus = baseRun.IpConsensus,
            Environment = new Core.Models.EnvironmentSnapshot
            {
                OsDescription = baseRun.Environment.OsDescription,
                MachineName = "•••",
                UserName = "•••",
                PrivacyMode = true,
            },
        };

        await repository.SaveAsync(masked);
        var restored = await repository.GetAsync(masked.Id);

        Assert.True(restored!.Environment.PrivacyMode);
        Assert.Equal("•••", restored.Environment.MachineName);
        Assert.Null(restored.IpConsensus.ConsensusIp);
        Assert.Empty(restored.IpConsensus.Observations);
        Assert.Empty(restored.Environment.Adapters);
        // Inspect both SQLite database and WAL if present; all connections above are closed.
        var databasePath = System.IO.Path.Combine(temp.Path, "history.db");
        foreach (var path in new[] { databasePath, databasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            var bytes = await File.ReadAllBytesAsync(path);
            Assert.DoesNotContain(baseRun.IpConsensus.ConsensusIp!, System.Text.Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
        }
    }
}

public class SettingsStoreTests
{
    [Fact]
    public void Defaults_are_returned_when_file_missing()
    {
        using var temp = new TempData();
        var options = temp.Store().Load();

        Assert.Equal(8, options.RequestTimeoutSeconds);
        Assert.Contains(1080, options.LocalProxyPorts);
    }

    [Fact]
    public void Changes_are_persisted_and_reloaded()
    {
        using var temp = new TempData();
        var store = temp.Store();
        var options = store.Load();
        options.RequestTimeoutSeconds = 21;
        options.PrivacyMode = true;
        options.ReachabilityTargets = ["example.com", "test.local"];
        store.Ui.Theme = "Light";
        store.Ui.ProModeByDefault = true;
        store.Save();

        var reloaded = temp.Store();
        var loaded = reloaded.Load();

        Assert.Equal(21, loaded.RequestTimeoutSeconds);
        Assert.True(loaded.PrivacyMode);
        Assert.Equal(["example.com", "test.local"], loaded.ReachabilityTargets);
        Assert.Equal("Light", reloaded.Ui.Theme);
        Assert.True(reloaded.Ui.ProModeByDefault);
    }

    [Fact]
    public void Broken_file_falls_back_to_defaults()
    {
        using var temp = new TempData();
        File.WriteAllText(Path.Combine(temp.Path, "settings.json"), "{ это не json ");
        var store = temp.Store();

        var options = store.Load();

        Assert.Equal(8, options.RequestTimeoutSeconds);
    }

    [Fact]
    public void Paths_point_inside_data_directory()
    {
        using var temp = new TempData();
        var store = temp.Store();

        Assert.StartsWith(temp.Path, store.DatabasePath);
        Assert.EndsWith("history.db", store.DatabasePath);
        Assert.Contains("logs", store.LogPath);
    }
}

public class SettingsSaveStabilityTests
{
    [Fact]
    public void Failed_save_is_reported_and_temporary_file_is_removed()
    {
        using var temp = new TempData();
        var store = temp.Store();
        Directory.CreateDirectory(System.IO.Path.Combine(temp.Path, "settings.json"));
        Assert.False(store.Save());
        Assert.Empty(Directory.GetFiles(temp.Path, "*.tmp"));
    }

    [Fact]
    public void Repeated_save_replaces_complete_settings()
    {
        using var temp = new TempData();
        var store = temp.Store();
        store.Options.RequestTimeoutSeconds = 7;
        Assert.True(store.Save());
        store.Options.RequestTimeoutSeconds = 13;
        Assert.True(store.Save());
        var loaded = temp.Store();
        Assert.Equal(13, loaded.Load().RequestTimeoutSeconds);
        Assert.Empty(Directory.GetFiles(temp.Path, "*.tmp"));
    }
}
