using System.Diagnostics;
using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Net;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// Локальные средства обхода: открытые порты прокси на loopback, SOCKS5/HTTP-прокси,
/// предположительные локальные API. Одного ответа недостаточно для установления программы.
/// Помимо настроенного списка проверяются типовые диапазоны из опубликованной методики
/// и порты, которые ОС сообщает как TCP LISTEN; параллелизм ограничен настройками прогона.
/// Аналог BypassChecker (Android).
/// </summary>
public sealed class BypassCheck(IHttpProbe http, Func<IReadOnlyList<int>>? listeningPorts = null) : ICheck
{
    private readonly IHttpProbe _http = http;
    private readonly Func<IReadOnlyList<int>>? _listeningPorts = listeningPorts;

    public CheckCategory Category => CheckCategory.Bypass;
    public string Title => "Локальный обход";
    public string Subtitle => "Прокси на 127.0.0.1, Xray/Clash API, tun2socks";
    public int Weight => 30;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var metrics = new List<Metric>();
        var timeout = TimeSpan.FromMilliseconds(700);

        var configured = LocalPortScanner.ConfiguredPorts(context.Options);
        IReadOnlyList<int> listening = context.Options.ScanListeningSockets
            ? ReadListeners(_listeningPorts)
            : Array.Empty<int>();
        var ports = LocalPortScanner.Merge(configured, listening, context.Options.MaxLocalProxyPorts);
        var fromListeners = listening.Except(configured).ToHashSet();

        using var gate = new SemaphoreSlim(Math.Clamp(context.Options.MaxParallelChecks, 1, 32));
        var probeTasks = ports.Select(async port =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var socks = await ConnectivityProbes.IsSocks5Async("127.0.0.1", port, timeout, ct).ConfigureAwait(false);
                if (socks) return (port, "SOCKS5", (string?)null);

                var http = await ConnectivityProbes.IsHttpProxyAsync("127.0.0.1", port, timeout, ct).ConfigureAwait(false);
                if (http) return (port, "HTTP-прокси", (string?)null);

                var banner = await ConnectivityProbes.ReadBannerAsync("127.0.0.1", port, timeout, ct).ConfigureAwait(false);
                return (port, banner is null ? "" : "сервис", banner);
            }
            finally
            {
                gate.Release();
            }
        }).ToArray();

        var results = await Task.WhenAll(probeTasks).ConfigureAwait(false);
        var openPorts = new List<(int Port, string Kind, string? Banner)>();
        foreach (var (port, kind, banner) in results)
        {
            if (kind is "") continue;
            openPorts.Add((port, kind, banner));
        }

        metrics.Add(new Metric("Портов проверено", ports.Count.ToString(CultureInfo.InvariantCulture),
            $"настройки: {configured.Count.ToString(CultureInfo.InvariantCulture)}, диапазоны включены"));
        metrics.Add(new Metric("Из системных LISTEN", fromListeners.Count.ToString(CultureInfo.InvariantCulture),
            context.Options.ScanListeningSockets ? "порты, о которых сообщила ОС" : "перечисление слушателей выключено"));
        metrics.Add(new Metric("Открыто на loopback", openPorts.Count.ToString(CultureInfo.InvariantCulture),
            openPorts.Count == 0 ? "не найдено" : string.Join(", ", openPorts.Select(p => p.Port))));

        foreach (var (port, kind, banner) in openPorts)
        {
            var origin = fromListeners.Contains(port)
                ? " Порт найден среди слушающих сокетов ОС, а не только в списке типовых значений."
                : " Порт из настроенного списка или диапазона методики.";
            if (kind == "сервис")
                findings.Add(Finding.Info($"Локальный сервис на 127.0.0.1:{port}",
                    "Сервис ответил, но его тип не подтверждён; это не свидетельство прокси." + origin, banner));
            else
                findings.Add(Finding.Warning($"Возможный локальный {kind} на 127.0.0.1:{port}",
                    "Ответ похож на ответ прокси. Открытый порт не означает, что браузер его использует." + origin));
        }

        // GET / не является проверкой Xray gRPC. Любой ответ — лишь факт сервиса.
        var xrayPort = await _http.GetAsync(new Uri("http://127.0.0.1:10085/"), timeout, ignoreProxy: true, ct).ConfigureAwait(false);
        if (xrayPort.StatusCode is 200 or 403 or 404 or 405)
            findings.Add(Finding.Info("Ответ локального сервиса на порту 10085",
                "Это не подтверждает Xray: специфичная gRPC-проверка пока не реализована."));

        foreach (var port in new[] { 9090, 9091 })
        {
            var response = await _http.GetAsync(new Uri($"http://127.0.0.1:{port}/version"), TimeSpan.FromSeconds(1), ignoreProxy: true, ct).ConfigureAwait(false);
            if (!response.Success || response.Body is null ||
                !response.Body.Contains("\"version\"", StringComparison.OrdinalIgnoreCase)) continue;
            findings.Add(Finding.Notice($"Ответ версии на локальном порту {port}",
                "Ответ похож на API контроллера, но поле version встречается и у других программ. Клиент не идентифицирован."));
            break;
        }

        if (openPorts.Count == 0)
            findings.Add(Finding.Info("Локальные сервисы на проверенных портах не ответили",
                "Это не исключает прокси на других портах, с другой привязкой или с другой настройкой."));

        var detected = findings.Any(f => f.Severity == Severity.Critical);
        var review = findings.Any(f => f.Severity is Severity.Notice or Severity.Warning);

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Status = detected ? CheckStatus.Detected : review ? CheckStatus.NeedsReview : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Duration = sw.Elapsed,
            Weight = Weight,
        };
    }

    /// <summary>
    /// Список слушателей ОС. Если источник не задан (тесты, ограниченное окружение),
    /// возвращается пустой список: это отсутствие данных, а не «портов нет».
    /// </summary>
    private static IReadOnlyList<int> ReadListeners(Func<IReadOnlyList<int>>? source)
    {
        if (source is null) return Array.Empty<int>();
        try
        {
            return source();
        }
        catch
        {
            return Array.Empty<int>();
        }
    }
}
