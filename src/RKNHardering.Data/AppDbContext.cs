using Microsoft.EntityFrameworkCore;
using RKNHardering.Data.Entities;

namespace RKNHardering.Data;

public sealed class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<RunRecord> Runs => Set<RunRecord>();
    public DbSet<LogRecord> Logs => Set<LogRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<RunRecord>(entity =>
        {
            entity.ToTable("runs");
            entity.HasKey(r => r.Id);
            entity.Property(r => r.Headline).HasMaxLength(200);
            entity.Property(r => r.Summary).HasMaxLength(1000);
            entity.Property(r => r.ExternalIp).HasMaxLength(64);
            entity.Property(r => r.Country).HasMaxLength(8);
            entity.Property(r => r.OsDescription).HasMaxLength(200);
            entity.Property(r => r.StartedAt).HasConversion(
                value => value.UtcTicks,
                value => new DateTimeOffset(value, TimeSpan.Zero));
            entity.Property(r => r.FinishedAt).HasConversion(
                value => value.UtcTicks,
                value => new DateTimeOffset(value, TimeSpan.Zero));
            entity.HasIndex(r => r.StartedAt);
        });

        modelBuilder.Entity<LogRecord>(entity =>
        {
            entity.ToTable("logs");
            entity.HasKey(l => l.Id);
            entity.Property(l => l.Message).HasMaxLength(500);
            entity.Property(l => l.At).HasConversion(
                value => value.UtcTicks,
                value => new DateTimeOffset(value, TimeSpan.Zero));
            entity.HasIndex(l => l.At);
        });
    }
}
