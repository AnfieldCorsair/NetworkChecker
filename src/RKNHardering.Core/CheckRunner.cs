using System.Diagnostics;
using RKNHardering.Core.Abstractions;
using RKNHardering.Core.Models;
using RKNHardering.Core.Net;
using RKNHardering.Core.Options;
using RKNHardering.Core.Platform;
using RKNHardering.Core.Verdict;

namespace RKNHardering.Core;

public sealed class CheckProgressEventArgs(int completed, int total, string title, CheckResult? result) : EventArgs
{
    public int Completed { get; } = completed;
    public int Total { get; } = total;
    public string Title { get; } = title;
    public CheckResult? Result { get; } = result;
    public double Percent => Total == 0 ? 0 : Completed * 100.0 / Total;
}

/// <summary>Оркестратор прогона: параллельный запуск модулей, консенсус IP, вердикт.</summary>
public sealed class CheckRunner
{
    private readonly IReadOnlyList<ICheck> _checks;
    private readonly IPlatformProbe _platform;

    public CheckRunner(IEnumerable<ICheck> checks, IPlatformProbe platform)
    {
        _checks = checks.ToArray();
        _platform = platform;
    }

    public IReadOnlyList<ICheck> Checks => _checks;

    public event EventHandler<CheckProgressEventArgs>? Progress;
    public event EventHandler<string>? StatusText;

    public async Task<CheckRunResult> RunAsync(RknOptions options, bool privacyMode, CancellationToken ct)
    {
        Masking.Enabled = privacyMode;
        var startedAt = DateTimeOffset.Now;

        var context = new CheckContext
        {
            Options = options,
            Report = message => StatusText?.Invoke(this, message),
        };

        using var gate = new SemaphoreSlim(Math.Max(1, options.MaxParallelChecks));
        var results = new List<CheckResult>();
        var completed = 0;
        var total = _checks.Count;
        var sync = new Lock();

        var tasks = _checks.Select(async check =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            var sw = Stopwatch.StartNew();
            CheckResult result;
            try
            {
                StatusText?.Invoke(this, $"{check.Title}: запуск");
                result = await check.RunAsync(context, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                result = CheckResult.Failed(check.Category, check.Title, ex.GetBaseException().Message, sw.Elapsed, check.Weight);
            }
            finally
            {
                gate.Release();
            }

            lock (sync)
            {
                results.Add(result);
                completed++;
                Progress?.Invoke(this, new CheckProgressEventArgs(completed, total, check.Title, result));
            }
        }).ToArray();

        await Task.WhenAll(tasks).ConfigureAwait(false);

        var ordered = _checks
            .Select(c => results.FirstOrDefault(r => r.Category == c.Category))
            .Where(r => r is not null)
            .Select(r => r!)
            .ToArray();

        var consensus = IpConsensusBuilder.Build(context.IpObservations);
        var verdict = VerdictEngine.Build(ordered, consensus);
        var env = await BuildEnvironmentAsync(privacyMode, ct).ConfigureAwait(false);

        return new CheckRunResult
        {
            StartedAt = startedAt,
            FinishedAt = DateTimeOffset.Now,
            Checks = ordered,
            Verdict = verdict,
            IpConsensus = consensus,
            Environment = env,
        };
    }

    private async Task<EnvironmentSnapshot> BuildEnvironmentAsync(bool privacyMode, CancellationToken ct)
    {
        OsInfo os;
        IReadOnlyList<AdapterInfo> adapters;
        ProxySettings proxy;
        try
        {
            os = await _platform.GetOsInfoAsync(ct).ConfigureAwait(false);
            adapters = await _platform.GetAdaptersAsync(ct).ConfigureAwait(false);
            proxy = await _platform.GetSystemProxyAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            os = new OsInfo { Description = Environment.OSVersion.VersionString };
            adapters = Array.Empty<AdapterInfo>();
            proxy = new ProxySettings();
        }

        return new EnvironmentSnapshot
        {
            OsDescription = os.Description,
            MachineName = privacyMode ? "•••" : Environment.MachineName,
            UserName = privacyMode ? "•••" : Environment.UserName,
            AppVersion = typeof(CheckRunner).Assembly.GetName().Version?.ToString() ?? "1.0.0",
            Adapters = adapters,
            Proxy = proxy,
            PrivacyMode = privacyMode,
        };
    }
}
