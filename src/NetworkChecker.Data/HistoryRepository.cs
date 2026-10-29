using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using NetworkChecker.Core.Models;
using NetworkChecker.Data.Entities;

namespace NetworkChecker.Data;

/// <summary>Локальная история прогонов в SQLite. Сервер не нужен — всё лежит в %LOCALAPPDATA%.</summary>
public sealed class HistoryRepository(IDbContextFactory<AppDbContext> factory)
{
    private readonly IDbContextFactory<AppDbContext> _factory = factory;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task SaveAsync(CheckRunResult result, CancellationToken ct = default)
    {
        if (result.Environment.PrivacyMode) result = PrivateRunProjection.Create(result);
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var record = new RunRecord
        {
            Id = result.Id,
            StartedAt = result.StartedAt,
            FinishedAt = result.FinishedAt,
            DurationMs = (int)result.Duration.TotalMilliseconds,
            RiskLevel = (int)result.Verdict.Level,
            Score = result.Verdict.Score,
            Headline = result.Verdict.Headline,
            Summary = result.Verdict.Summary,
            ExternalIp = result.IpConsensus.ConsensusIp,
            Country = result.Checks.FirstOrDefault(c => c.Category == CheckCategory.GeoIp)?
                .Metrics.FirstOrDefault(m => m.Label == "Страна")?.Value,
            PrivacyMode = result.Environment.PrivacyMode,
            OsDescription = result.Environment.OsDescription,
            ChecksJson = JsonSerializer.Serialize(result.Checks, JsonOptions),
            ReasonsJson = JsonSerializer.Serialize(result.Verdict.Reasons, JsonOptions),
            IpObservationsJson = JsonSerializer.Serialize(result.IpConsensus, JsonOptions),
            EnvironmentJson = JsonSerializer.Serialize(result.Environment, JsonOptions),
        };
        db.Runs.Add(record);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RunRecord>> GetRecentAsync(int take = 50, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await db.Runs.AsNoTracking()
            .OrderByDescending(r => r.StartedAt)
            .Take(take)
            .ToListAsync(ct).ConfigureAwait(false);
    }

    public async Task<CheckRunResult?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var record = await db.Runs.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct).ConfigureAwait(false);
        if (record is null) return null;

        var checks = JsonSerializer.Deserialize<List<CheckResult>>(record.ChecksJson, JsonOptions) ?? [];
        var reasons = JsonSerializer.Deserialize<List<string>>(record.ReasonsJson, JsonOptions) ?? [];
        var consensus = JsonSerializer.Deserialize<IpConsensus>(record.IpObservationsJson, JsonOptions) ?? new IpConsensus();
        var environment = JsonSerializer.Deserialize<EnvironmentSnapshot>(record.EnvironmentJson, JsonOptions)
                          ?? new EnvironmentSnapshot { OsDescription = record.OsDescription };

        return new CheckRunResult
        {
            Id = record.Id,
            StartedAt = record.StartedAt,
            FinishedAt = record.FinishedAt,
            Checks = checks,
            IpConsensus = consensus,
            Environment = environment,
            Verdict = new VerdictResult
            {
                Level = (RiskLevel)record.RiskLevel,
                Score = record.Score,
                ScoreAvailable = checks.Any(c => c.Weight > 0 && c.Status is not CheckStatus.Skipped and not CheckStatus.Failed),
                Headline = record.Headline,
                Summary = record.Summary,
                Reasons = reasons,
            },
        };
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var record = await db.Runs.FirstOrDefaultAsync(r => r.Id == id, ct).ConfigureAwait(false);
        if (record is null) return;
        db.Runs.Remove(record);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task ClearAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await db.Runs.ExecuteDeleteAsync(ct).ConfigureAwait(false);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await db.Runs.CountAsync(ct).ConfigureAwait(false);
    }
}
