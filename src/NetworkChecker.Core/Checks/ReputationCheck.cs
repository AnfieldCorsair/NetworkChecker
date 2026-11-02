using System.Globalization;
using NetworkChecker.Core.Abstractions;
using NetworkChecker.Core.Models;
using NetworkChecker.Core.Reputation;

namespace NetworkChecker.Core.Checks;

/// <summary>
/// Адаптер блока репутации к общему прогону проверок. Вес 0: наблюдения попадают
/// в отчёт, но не влияют на индекс и правила «Обнаружено».
/// </summary>
public sealed class ReputationCheck(ReputationService service) : ICheck
{
    private readonly ReputationService _service = service;

    public CheckCategory Category => CheckCategory.Reputation;
    public string Title => "Репутация IP и метка Google";
    public string Subtitle => "Спам-базы, жалобы, риск-скоры, регион GL и доступность AI Studio";
    public int Weight => 0;

    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct)
    {
        var report = await _service.InspectAsync(context.Options, force: false, ct).ConfigureAwait(false);
        var findings = new List<Finding>();
        foreach (var source in report.Sources)
        {
            var title = $"{source.Name}: {source.Status}";
            var detail = source.Detail ?? string.Empty;
            findings.Add(source.Tone switch
            {
                ReputationTone.Bad => Finding.Warning(title, detail),
                ReputationTone.Warn => Finding.Notice(title, detail),
                _ => Finding.Info(title, detail),
            });
        }
        findings.Add(Finding.Info("Что этот блок не измеряет",
            "У Google нет публичного API доверия к IP: reCAPTCHA v3 считается для конкретного сайта, " +
            "Postmaster Tools v2 не отдаёт репутацию IP. Метка GL — только сетевая часть классификации, " +
            "а нахождение в спам-базе не доказывает использование VPN."));

        var review = findings.Any(f => f.Severity is Severity.Notice or Severity.Warning);
        var skipped = report.State is ReputationReportState.Offline or ReputationReportState.Disabled;

        var metrics = new List<Metric>
        {
            new("Условный индекс риска",
                report.RiskAvailable ? report.Risk.ToString(CultureInfo.InvariantCulture) : "нет данных",
                "не вероятность, не мнение Google и не прогноз капчи"),
            new("Регион GL (YouTube)", report.Google.Region ?? "нет данных", report.Google.YouTubeStatus),
            new("Страна по GeoIP", report.Google.GeoCountry ?? "нет данных", null),
            new("Google AI Studio", report.Google.AiStudioStatus ?? "нет данных", report.Google.AiStudioFinalUri),
        };

        return new CheckResult
        {
            Category = Category,
            Title = Title,
            Subtitle = Subtitle,
            Weight = Weight,
            Status = skipped ? CheckStatus.Skipped : review ? CheckStatus.NeedsReview : CheckStatus.Clean,
            Findings = findings,
            Metrics = metrics,
            Reputation = report,
        };
    }
}
