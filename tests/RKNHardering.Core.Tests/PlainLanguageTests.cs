using RKNHardering.Core.Models;
using RKNHardering.Core.Plain;
using RKNHardering.TestKit;
using Xunit;

namespace RKNHardering.Core.Tests;

public class PlainLanguageTests
{
    [Fact]
    public void Clean_verdict_explains_that_nothing_is_needed()
    {
        var run = Sample.CleanRun();
        var explanation = PlainLanguage.ForVerdict(run.Verdict, run.Checks);

        Assert.Contains("обычно", explanation.Headline, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("не в VPN", explanation.Advice);
        Assert.DoesNotContain("Ошибка", explanation.WhatItMeans);
    }

    [Fact]
    public void Detected_verdict_gives_actionable_advice()
    {
        var run = Sample.RichRun();
        var explanation = PlainLanguage.ForVerdict(run.Verdict, run.Checks);

        Assert.Contains("VPN", explanation.Headline);
        Assert.Contains("красн", explanation.Advice);
    }

    [Fact]
    public void Failed_checks_are_mentioned_in_plain_text()
    {
        var run = Sample.RichRun();
        var explanation = PlainLanguage.ForVerdict(run.Verdict, run.Checks);

        Assert.Contains("не смогли отработать", explanation.WhatItMeans);
    }

    [Theory]
    [InlineData(CheckStatus.Clean, "Всё обычно", "green")]
    [InlineData(CheckStatus.NeedsReview, "Есть мелочи", "yellow")]
    [InlineData(CheckStatus.Detected, "Нашли признаки", "red")]
    [InlineData(CheckStatus.Skipped, "Не проверялось", "grey")]
    [InlineData(CheckStatus.Failed, "Не удалось проверить", "purple")]
    public void Status_is_translated(CheckStatus status, string expected, string colour)
    {
        Assert.Equal(expected, PlainLanguage.StatusInPlainWords(status));
        var plain = PlainLanguage.ToPlain(Sample.Check(status: status));
        Assert.Equal(colour, plain.Colour);
        Assert.Equal(expected, plain.Status);
    }

    [Fact]
    public void Every_category_has_a_human_description()
    {
        foreach (var category in Enum.GetValues<CheckCategory>())
        {
            var text = PlainLanguage.WhatWeChecked(category);
            Assert.False(string.IsNullOrWhiteSpace(text));
            Assert.True(text.Length > 15, $"{category}: описание слишком короткое");
            // Никаких технических сокращений в простом тексте.
            Assert.DoesNotContain("Checker", text);
            Assert.DoesNotContain("Status", text);
        }
    }

    [Fact]
    public void Clean_and_skipped_checks_have_no_advice_noise()
    {
        Assert.Empty(PlainLanguage.ToPlain(Sample.Check(status: CheckStatus.Clean)).Advice);
        Assert.Empty(PlainLanguage.ToPlain(Sample.Check(status: CheckStatus.Skipped)).Advice);
        Assert.NotEmpty(PlainLanguage.ToPlain(Sample.Check(status: CheckStatus.Detected)).Advice);
    }

    [Fact]
    public void Detected_advice_is_category_specific()
    {
        var proxy = PlainLanguage.ToPlain(Sample.Check(CheckCategory.Bypass, status: CheckStatus.Detected));
        var geo = PlainLanguage.ToPlain(Sample.Check(CheckCategory.GeoIp, status: CheckStatus.Detected));
        var domains = PlainLanguage.ToPlain(Sample.Check(CheckCategory.DomainReachability, status: CheckStatus.Detected));

        Assert.Contains("прокси", proxy.Advice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("дата-центру", geo.Advice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("сайтов", domains.Advice, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(proxy.Advice, domains.Advice);
    }
}

public class PlainFactsTests
{
    [Fact]
    public void Rich_run_gives_five_facts_with_expected_tones()
    {
        var facts = PlainFacts.Build(Sample.RichRun());

        Assert.Equal(5, facts.Count);
        Assert.Contains(facts, f => f.Question == "Интернет-адрес" && f.IsWarn);
        Assert.Contains(facts, f => f.Question == "VPN или туннель" && f.IsBad);
        Assert.Contains(facts, f => f.Question == "Прокси в системе" && f.IsBad);
        Assert.Contains(facts, f => f.Question == "Программы для обхода" && f.IsWarn);
        Assert.Contains(facts, f => f.Question == "Отклик сети" && f.IsBad);
    }

    [Fact]
    public void Clean_run_marks_everything_good_or_neutral()
    {
        var facts = PlainFacts.Build(Sample.CleanRun());

        var vpn = facts.Single(f => f.Question == "VPN или туннель");
        Assert.True(vpn.IsGood);
        Assert.Equal("не найден", vpn.Answer);

        var proxy = facts.Single(f => f.Question == "Прокси в системе");
        Assert.True(proxy.IsGood);

        var address = facts.Single(f => f.Question == "Интернет-адрес");
        Assert.True(address.IsGood);
        Assert.Contains("198.51.100.10", address.Answer);
    }

    [Fact]
    public void Missing_checks_are_reported_as_not_checked()
    {
        var run = Sample.CleanRun();
        var onlyGeo = new CheckRunResult
        {
            StartedAt = run.StartedAt,
            FinishedAt = run.FinishedAt,
            Checks = [run.Checks.Single(c => c.Category == CheckCategory.GeoIp)],
            Verdict = run.Verdict,
            IpConsensus = run.IpConsensus,
            Environment = run.Environment,
        };

        var facts = PlainFacts.Build(onlyGeo);

        Assert.Equal("не проверялось", facts.Single(f => f.Question == "VPN или туннель").Answer);
        Assert.Equal("не проверялось", facts.Single(f => f.Question == "Программы для обхода").Answer);
    }

    [Theory]
    [InlineData(0, 0, 0, "Конфигурация обычная")]
    [InlineData(0, 2, 0, "есть мелочи")]
    [InlineData(1, 0, 0, "есть отклонения")]
    [InlineData(4, 0, 0, "сильно отличается")]
    public void Overall_configuration_wording(int detected, int review, int failed, string expectedPart)
    {
        var checks = new List<CheckResult>();
        for (var i = 0; i < detected; i++)
            checks.Add(Sample.Check(CheckCategory.GeoIp, status: CheckStatus.Detected));
        for (var i = 0; i < review; i++)
            checks.Add(Sample.Check(CheckCategory.CdnPulling, status: CheckStatus.NeedsReview));
        for (var i = 0; i < failed; i++)
            checks.Add(Sample.Check(CheckCategory.IcmpSpoofing, status: CheckStatus.Failed));

        var run = Sample.CleanRun();
        var result = new CheckRunResult
        {
            StartedAt = run.StartedAt,
            FinishedAt = run.FinishedAt,
            Checks = checks,
            Verdict = run.Verdict,
            IpConsensus = run.IpConsensus,
            Environment = run.Environment,
        };

        Assert.Contains(expectedPart, PlainFacts.OverallConfiguration(result), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Failed_modules_are_counted_in_configuration_text()
    {
        var run = Sample.RichRun();
        Assert.Contains("не отработали", PlainFacts.OverallConfiguration(run));
    }
}
