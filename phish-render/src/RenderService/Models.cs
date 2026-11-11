using System.Collections.Concurrent;

namespace RenderService;

/// <summary>
/// Body of POST /render. The url may be defanged: hxxps://olx-pay[.]site.
/// Referer: pretend the visit came from this page (fake shops show the clone only to visitors from ads).
/// PassWarning: click through a CDN "Suspected phishing" interstitial to capture the page behind it.
/// </summary>
public sealed record RenderRequest(
    string? Url, bool? Mobile, bool? FullPage, bool? IncludeHtml, bool? FollowCta, string? Referer = null, bool? PassWarning = null);

/// <summary>Body of POST /check: render + verdict.
/// LlmPool: "audit" counts LLM calls against LLM_AUDIT_DAILY_LIMIT, so brand audits never use up the main quota.</summary>
public sealed record CheckRequest(
    string? Url, bool? Mobile, bool? FollowCta, bool? UseLlm, string? Referer = null, bool? PassWarning = null,
    string? LlmPool = null);

public sealed record RenderOptions(
    bool Mobile, bool FullPage, bool IncludeHtml, bool FollowCta, string? Referer = null, bool PassWarning = false);

/// <summary>The page reached after clicking the main button of a lure page ("Отримати компенсацію").</summary>
public sealed class PageSnapshot
{
    public string? ClickedText { get; set; }
    public string? Url { get; set; }
    public string? Title { get; set; }
    public string? Text { get; set; }
    public bool HasPasswordInput { get; set; }
    public bool HasCardInput { get; set; }
    public List<FormInfo> Forms { get; set; } = new();
    public byte[]? ScreenshotJpeg { get; set; }
}

public sealed class LlmOpinion
{
    public bool IsPhishing { get; set; }
    public double Confidence { get; set; }
    public string? Brand { get; set; }
    public string? Reason { get; set; }
    public string? Model { get; set; }
    public int InputTokens { get; set; }
    public int OutputTokens { get; set; }
    public int ThinkingTokens { get; set; }
    public string? Error { get; set; }
}

/// <summary>Response of POST /check.</summary>
public sealed class CheckResult
{
    /// <summary>phishing | suspicious | safe | unreachable</summary>
    public string Verdict { get; set; } = "unreachable";
    public int Score { get; set; }
    public string? Brand { get; set; }
    public List<string> Reasons { get; set; } = new();

    /// <summary>Verdict of the rules alone, before the LLM opinion (for measuring what the LLM adds).</summary>
    public string RuleVerdict { get; set; } = "unreachable";
    public int RuleScore { get; set; }

    public LlmOpinion? Llm { get; set; }
    public DomainAge? DomainAge { get; set; }
    public RenderResult? Render { get; set; }
}

public sealed record BlockedRequest(string Url, string Reason);

public sealed class FormInfo
{
    public string? Action { get; set; }
    public string? Method { get; set; }
    public List<string> Inputs { get; set; } = new();
    public string? FrameUrl { get; set; }
}

/// <summary>What the in-page script reports for one frame.</summary>
public sealed class FrameFacts
{
    public List<FormInfo> Forms { get; set; } = new();
    public bool HasPassword { get; set; }
    public bool HasCard { get; set; }
    public string? Text { get; set; }
}

/// <summary>
/// Filled progressively while the page renders, so a hard timeout still returns
/// whatever was collected. Collections are concurrent because route handlers and
/// navigation events fire from Playwright's dispatcher while the render runs.
/// </summary>
public sealed class RenderResult
{
    private const int MaxBlockedListed = 50;
    private const int MaxNavigations = 30;

    private int _requestCount;
    private int _blockedCount;

    public string RequestedUrl { get; init; } = "";
    public string? FinalUrl { get; set; }
    public int? HttpStatus { get; set; }
    public string? Title { get; set; }
    public string? Error { get; set; }
    public long ElapsedMs { get; set; }

    /// <summary>Title of the "Suspected phishing" interstitial that was clicked through; the rest describes the page behind it.</summary>
    public string? PassedWarning { get; set; }

    /// <summary>HTTP redirects of the main document, oldest first (not including the final URL).</summary>
    public ConcurrentQueue<string> RedirectChain { get; } = new();

    /// <summary>Every URL the main frame landed on, including JavaScript redirects.</summary>
    public ConcurrentQueue<string> Navigations { get; } = new();

    public bool HasPasswordInput { get; set; }
    public bool HasCardInput { get; set; }
    public ConcurrentQueue<FormInfo> Forms { get; } = new();

    /// <summary>Visible text of the main frame, whitespace-collapsed, first 5000 chars.</summary>
    public string? Text { get; set; }

    public int RequestCount => _requestCount;
    public int BlockedCount => _blockedCount;
    public int AdsBlocked => _adsBlocked;
    public ConcurrentQueue<BlockedRequest> Blocked { get; } = new();

    /// <summary>Second step: the page after clicking the main call-to-action, if one was clicked.</summary>
    public PageSnapshot? CtaStep { get; set; }

    public string? Html { get; set; }

    /// <summary>JPEG screenshot; serialized as base64.</summary>
    public byte[]? ScreenshotJpeg { get; set; }

    private int _adsBlocked;

    internal int IncrementRequests() => Interlocked.Increment(ref _requestCount);

    internal void IncrementAdsBlocked() => Interlocked.Increment(ref _adsBlocked);

    internal void AddBlocked(string url, string reason)
    {
        if (Interlocked.Increment(ref _blockedCount) <= MaxBlockedListed)
        {
            Blocked.Enqueue(new BlockedRequest(Truncate(url, 300), reason));
        }
    }

    internal void AddNavigation(string url)
    {
        if (Volatile.Read(ref _navigationsFrozen) == 0 && Navigations.Count < MaxNavigations)
        {
            Navigations.Enqueue(Truncate(url, 2000));
        }
    }

    /// <summary>Stop recording: navigations caused by our own click on the call-to-action are not redirects.</summary>
    internal void FreezeNavigations() => Interlocked.Exchange(ref _navigationsFrozen, 1);

    private int _navigationsFrozen;

    internal static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
