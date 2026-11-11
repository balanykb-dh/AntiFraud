namespace RenderService;

/// <summary>Rules first, then (optionally) Claude as a second opinion that may only raise the verdict.</summary>
public sealed class VerdictEngine
{
    private readonly BrandRegistry _brands;
    private readonly RuleEngine _rules;
    private readonly DomainAgeService _ages;
    private readonly LlmJudge _llm;

    public VerdictEngine(BrandRegistry brands, RuleEngine rules, DomainAgeService ages, LlmJudge llm)
    {
        _brands = brands;
        _rules = rules;
        _ages = ages;
        _llm = llm;
    }

    public async Task<CheckResult> EvaluateAsync(RenderResult render, bool useLlm, CancellationToken ct)
    {
        var requestedHost = DomainTools.HostOf(render.RequestedUrl) ?? "";
        var finalHost = DomainTools.HostOf(render.FinalUrl) ?? requestedHost;

        // Age of the link itself AND of where it landed; the youngest one counts. Checking only the final
        // host would let a fresh phishing domain hide behind a redirect to an old, legitimate site.
        DomainAge? age = null;
        if (!RuleEngine.IsUnreachable(render))
        {
            var domains = new[] { requestedHost, finalHost }
                .Where(h => h.Length > 0 && _brands.FindOfficial(h) is null && !DomainTools.IsFreeHosting(h))
                .Select(DomainTools.Registrable)
                .Distinct()
                .ToList();
            foreach (var domain in domains)
            {
                var found = await _ages.LookupAsync(domain, ct);
                if (found?.AgeDays is int days && (age?.AgeDays is not int youngest || days < youngest))
                {
                    age = found;
                }
                else if (age is null)
                {
                    age = found;
                }
            }
        }

        var rules = _rules.Evaluate(render, age);
        var result = new CheckResult
        {
            Verdict = rules.Verdict,
            Score = rules.Score,
            Brand = rules.Brand,
            Reasons = rules.Reasons,
            RuleVerdict = rules.Verdict,
            RuleScore = rules.Score,
            DomainAge = age,
            Render = render,
        };

        if (!useLlm || !_llm.Enabled || rules.Unreachable || rules.Official)
        {
            return result;
        }

        var opinion = await _llm.JudgeAsync(render, ct);
        result.Llm = opinion;
        if (opinion.Error is not null)
        {
            result.Reasons.Add("LLM недоступна: " + opinion.Error);
            return result;
        }

        if (opinion.IsPhishing)
        {
            if (opinion.Confidence >= 0.75)
            {
                result.Verdict = "phishing";
                result.Score = Math.Max(result.Score, (int)Math.Round(opinion.Confidence * 100));
            }
            else if (opinion.Confidence >= 0.5 && result.Verdict == "safe")
            {
                result.Verdict = "suspicious";
                result.Score = Math.Max(result.Score, RuleEngine.SuspiciousThreshold);
            }

            result.Brand ??= opinion.Brand;
            result.Reasons.Add($"LLM ({opinion.Confidence:0.00}): {opinion.Reason}");
        }
        else
        {
            result.Reasons.Add($"LLM не бачить фішингу ({opinion.Confidence:0.00}): {opinion.Reason}");
        }

        return result;
    }
}
