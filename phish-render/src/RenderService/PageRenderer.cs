using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace RenderService;

public sealed partial class PageRenderer
{
    private const int MaxHtmlChars = 2_000_000;
    private const int MaxFramesInspected = 10;

    private static readonly JsonSerializerOptions FactsJson = new() { PropertyNameCaseInsensitive = true };

    private readonly BrowserHost _host;
    private readonly RenderSettings _settings;
    private readonly BrandRegistry _brands;
    private readonly ILogger<PageRenderer> _log;
    private readonly SemaphoreSlim _slots;

    public PageRenderer(BrowserHost host, RenderSettings settings, BrandRegistry brands, ILogger<PageRenderer> log)
    {
        _host = host;
        _settings = settings;
        _brands = brands;
        _log = log;
        _slots = new SemaphoreSlim(settings.MaxConcurrency, settings.MaxConcurrency);
    }

    /// <summary>Returns null when all render slots stayed busy for QUEUE_TIMEOUT_MS.</summary>
    public async Task<RenderResult?> TryRenderAsync(Uri target, RenderOptions options, CancellationToken ct)
    {
        if (!await _slots.WaitAsync(_settings.QueueTimeoutMs, ct))
        {
            return null;
        }

        try
        {
            return await RenderAsync(target, options);
        }
        finally
        {
            _slots.Release();
        }
    }

    private async Task<RenderResult> RenderAsync(Uri target, RenderOptions options)
    {
        var sw = Stopwatch.StartNew();
        var result = new RenderResult { RequestedUrl = target.AbsoluteUri };
        var guard = new EgressGuard();

        // Most reported phishing domains are already dead: answer those without opening a browser.
        var verdict = await guard.CheckHostAsync(target.IdnHost);
        if (verdict != HostVerdict.Allowed)
        {
            result.Error = verdict == HostVerdict.DnsFailed ? "dns_failed" : "blocked_internal_address";
            result.ElapsedMs = sw.ElapsedMilliseconds;
            return result;
        }

        IBrowserContext context;
        try
        {
            context = await NewContextAsync(options);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Could not open a browser context");
            result.Error = "browser_unavailable";
            result.ElapsedMs = sw.ElapsedMilliseconds;
            return result;
        }

        try
        {
            var work = RenderInContextAsync(context, target, options, guard, result);
            var finished = await Task.WhenAny(work, Task.Delay(_settings.HardTimeoutMs));
            if (finished == work)
            {
                await work;
            }
            else
            {
                result.Error ??= "hard_timeout";
                // The context is closed below, which makes the stuck call throw; observe it.
                _ = work.ContinueWith(static t => { _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Render failed for {Url}", target);
            result.Error ??= "render_failed: " + FirstLine(ex.Message);
        }
        finally
        {
            var close = context.CloseAsync();
            if (await Task.WhenAny(close, Task.Delay(TimeSpan.FromSeconds(10))) != close)
            {
                await _host.RecycleAsync();
            }
            else if (close.IsFaulted)
            {
                _ = close.Exception;
            }
        }

        result.ElapsedMs = sw.ElapsedMilliseconds;
        return result;
    }

    private async Task<IBrowserContext> NewContextAsync(RenderOptions options)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var browser = await _host.GetBrowserAsync();
                return await browser.NewContextAsync(BuildContextOptions(options.Mobile, _host.ChromeMajor));
            }
            catch (Exception ex) when (attempt == 1 && IsBrowserError(ex))
            {
                _log.LogWarning(ex, "New context failed, recycling Chromium and retrying once");
                await _host.RecycleAsync();
            }
        }
    }

    private async Task RenderInContextAsync(
        IBrowserContext context, Uri target, RenderOptions options, EgressGuard guard, RenderResult result)
    {
        context.SetDefaultTimeout(_settings.NavTimeoutMs);
        context.SetDefaultNavigationTimeout(_settings.NavTimeoutMs);
        await context.AddInitScriptAsync("Object.defineProperty(navigator, 'webdriver', { get: () => undefined });");
        await context.RouteAsync("**/*", route => GuardRouteAsync(route, guard, result));

        var page = await context.NewPageAsync();
        page.FrameNavigated += (_, frame) =>
        {
            if (frame.ParentFrame is null)
            {
                result.AddNavigation(frame.Url);
            }
        };

        IResponse? response = null;
        try
        {
            response = await page.GotoAsync(
                target.AbsoluteUri, new PageGotoOptions { WaitUntil = WaitUntilState.Load, Referer = options.Referer });
        }
        catch (TimeoutException)
        {
            // Slow page: keep going and capture whatever has rendered so far.
            result.Error = "navigation_timeout";
        }
        catch (PlaywrightException ex)
        {
            var netError = NetErrorRegex().Match(ex.Message);
            var replacedByJsRedirect =
                ex.Message.Contains("interrupted by another navigation", StringComparison.OrdinalIgnoreCase)
                || (netError.Success && netError.Value == "net::ERR_ABORTED");

            if (!replacedByJsRedirect)
            {
                // DNS error, refused connection, blocked redirect, download instead of a page...
                result.Error = netError.Success ? netError.Value : "navigation_failed: " + FirstLine(ex.Message);
                result.FinalUrl = page.Url;
                return;
            }

            // A JavaScript redirect replaced the page mid-load (typical for phishing): follow it.
            try
            {
                await page.WaitForLoadStateAsync(LoadState.Load);
            }
            catch (Exception e) when (IsBrowserError(e))
            {
                result.Error = "navigation_timeout";
            }
        }

        if (response is not null)
        {
            result.HttpStatus = response.Status;
            var chain = new List<string>();
            for (var r = response.Request.RedirectedFrom; r is not null; r = r.RedirectedFrom)
            {
                chain.Add(r.Url);
            }

            chain.Reverse();
            foreach (var url in chain)
            {
                result.RedirectChain.Enqueue(url);
            }
        }

        // Give JavaScript redirects and late-loading phishing forms a moment.
        if (_settings.SettleMs > 0)
        {
            try
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle, new PageWaitForLoadStateOptions { Timeout = _settings.SettleMs });
            }
            catch (Exception e) when (IsBrowserError(e))
            {
                // Pages with endless polling never go idle; that is fine.
            }
        }

        await Task.Delay(750);

        if (options.PassWarning)
        {
            await PassPhishingWarningAsync(page, result);
        }

        result.FinalUrl = page.Url;
        result.ScreenshotJpeg = await SafeAsync(() => page.ScreenshotAsync(Screenshot(options.FullPage)));
        result.Title = await SafeAsync(() => page.TitleAsync());

        var facts = await CollectFactsAsync(page);
        result.HasPasswordInput = facts.HasPassword;
        result.HasCardInput = facts.HasCard;
        result.Text = facts.Text;
        foreach (var form in facts.Forms)
        {
            result.Forms.Enqueue(form);
        }

        if (options.IncludeHtml)
        {
            var html = await SafeAsync(() => page.ContentAsync());
            result.Html = html is { Length: > MaxHtmlChars } ? html[..MaxHtmlChars] : html;
        }

        result.FinalUrl = page.Url;

        // Lure pages often show only a button ("Отримати компенсацію") and ask for the card on the next
        // screen. Click it once — never on official brand sites — and record the second page separately.
        var landedOnOfficial = _brands.FindOfficial(DomainTools.HostOf(page.Url)) is not null;
        if (options.FollowCta && !facts.HasCard && !facts.HasPassword && result.HttpStatus is null or < 400 && !landedOnOfficial)
        {
            await FollowCtaAsync(context, page, result);
        }
    }

    /// <summary>
    /// Cloudflare puts "Suspected Phishing" in front of reported sites. For a brand audit we need the page
    /// behind it (is it a copy of the brand's shop?), so wait for the Turnstile check and press "Ignore &amp; Proceed".
    /// Best effort: if the check never completes, the warning page stays as the result.
    /// </summary>
    private async Task PassPhishingWarningAsync(IPage page, RenderResult result)
    {
        const string bypassForm = "form[action*='/cdn-cgi/phish-bypass']";
        string? warningTitle;
        try
        {
            if (await page.Locator(bypassForm).CountAsync() == 0)
            {
                return;
            }

            warningTitle = await page.TitleAsync();
            await page.WaitForFunctionAsync(
                "() => { const i = document.querySelector(\"input[name='cf-turnstile-response']\"); return !i || i.value.length > 0; }",
                null,
                new PageWaitForFunctionOptions { Timeout = 15_000, PollingInterval = 500 });
        }
        catch (Exception e) when (IsBrowserError(e))
        {
            _log.LogInformation("Phishing warning on {Url}: check did not complete, keeping the warning page", page.Url);
            return;
        }

        try
        {
            var navigation = await page.RunAndWaitForNavigationAsync(
                async () =>
                {
                    var button = page.Locator($"{bypassForm} button, {bypassForm} input[type=submit]").First;
                    if (await button.CountAsync() == 0)
                    {
                        button = page.GetByText("Ignore & Proceed").First;
                    }

                    if (await button.CountAsync() > 0)
                    {
                        await button.ClickAsync(new LocatorClickOptions { Timeout = 5_000 });
                    }
                    else
                    {
                        await page.EvaluateAsync($"() => document.querySelector(\"{bypassForm}\").submit()");
                    }
                },
                new PageRunAndWaitForNavigationOptions { WaitUntil = WaitUntilState.Load, Timeout = 15_000 });

            try
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle, new PageWaitForLoadStateOptions { Timeout = Math.Max(1_000, _settings.SettleMs) });
            }
            catch (Exception e) when (IsBrowserError(e))
            {
                // Never went idle; capture what is there.
            }

            await Task.Delay(750);
            if (await page.Locator(bypassForm).CountAsync() > 0)
            {
                return; // Still the warning: the bypass was refused.
            }

            result.PassedWarning = warningTitle ?? "phishing warning";
            if (navigation is not null)
            {
                result.HttpStatus = navigation.Status;
            }
        }
        catch (Exception e) when (IsBrowserError(e))
        {
            _log.LogInformation("Phishing warning on {Url}: could not click through ({Error})", page.Url, FirstLine(e.Message));
        }
    }

    private async Task FollowCtaAsync(IBrowserContext context, IPage page, RenderResult result)
    {
        string? label;
        try
        {
            label = await page.EvaluateAsync<string?>(PageScripts.MarkCallToAction);
        }
        catch (Exception e) when (IsBrowserError(e))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(label))
        {
            return;
        }

        var step = new PageSnapshot { ClickedText = label };
        result.CtaStep = step;
        result.FreezeNavigations();

        IPage? popup = null;
        void OnNewPage(object? sender, IPage p) => popup = p;
        context.Page += OnNewPage;
        try
        {
            await page.ClickAsync("[data-pr-cta='1']", new PageClickOptions { Timeout = 5_000 });
            await Task.Delay(1_500);
        }
        catch (Exception e) when (IsBrowserError(e))
        {
            // The button may have navigated away mid-click; still look at where we ended up.
        }
        finally
        {
            context.Page -= OnNewPage;
        }

        var target = popup ?? page;
        try
        {
            await target.WaitForLoadStateAsync(LoadState.Load, new PageWaitForLoadStateOptions { Timeout = 10_000 });
            await target.WaitForLoadStateAsync(LoadState.NetworkIdle, new PageWaitForLoadStateOptions { Timeout = Math.Max(1_000, _settings.SettleMs) });
        }
        catch (Exception e) when (IsBrowserError(e))
        {
            // Never went idle; capture what is there.
        }

        await Task.Delay(500);

        step.Url = target.Url;
        step.ScreenshotJpeg = await SafeAsync(() => target.ScreenshotAsync(Screenshot(fullPage: false)));
        step.Title = await SafeAsync(() => target.TitleAsync());

        var facts = await CollectFactsAsync(target);
        step.HasPasswordInput = facts.HasPassword;
        step.HasCardInput = facts.HasCard;
        step.Text = facts.Text;
        step.Forms = facts.Forms;
    }

    private static PageScreenshotOptions Screenshot(bool fullPage) => new()
    {
        Type = ScreenshotType.Jpeg,
        Quality = 75,
        FullPage = fullPage,
        Timeout = 10_000,
    };

    private async Task GuardRouteAsync(IRoute route, EgressGuard guard, RenderResult result)
    {
        try
        {
            var request = route.Request;

            // Ads and trackers: irrelevant for phishing, and they triple the load time of normal sites.
            if (DomainTools.HostOf(request.Url) is { } requestHost && DomainTools.IsAdHost(requestHost))
            {
                result.IncrementAdsBlocked();
                await route.AbortAsync("blockedbyclient");
                return;
            }

            if (result.IncrementRequests() > _settings.MaxRequestsPerPage)
            {
                result.AddBlocked(request.Url, "too_many_requests");
                await route.AbortAsync("blockedbyclient");
                return;
            }

            if (request.ResourceType == "media")
            {
                await route.AbortAsync("blockedbyclient");
                return;
            }

            if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
            {
                result.AddBlocked(request.Url, "unparseable_url");
                await route.AbortAsync("blockedbyclient");
                return;
            }

            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                await route.ContinueAsync();
                return;
            }

            var verdict = await guard.CheckHostAsync(uri.IdnHost);
            if (verdict == HostVerdict.Allowed)
            {
                await route.ContinueAsync();
                return;
            }

            result.AddBlocked(request.Url, verdict == HostVerdict.DnsFailed ? "dns_failed" : "internal_address");
            await route.AbortAsync(verdict == HostVerdict.DnsFailed ? "namenotresolved" : "blockedbyclient");
        }
        catch (Exception)
        {
            // The context was closed while this request was in flight; nothing to route anymore.
        }
    }

    /// <summary>Forms, password/card flags from every frame (cap 10) and the main frame's visible text.</summary>
    private static async Task<FrameFacts> CollectFactsAsync(IPage page)
    {
        var merged = new FrameFacts();
        foreach (var frame in page.Frames.Take(MaxFramesInspected))
        {
            FrameFacts? facts;
            try
            {
                var json = await frame.EvaluateAsync<string>(PageScripts.CollectFacts);
                if (string.IsNullOrEmpty(json))
                {
                    continue;
                }

                facts = JsonSerializer.Deserialize<FrameFacts>(json, FactsJson);
            }
            catch (Exception ex) when (IsBrowserError(ex) || ex is JsonException)
            {
                continue;
            }

            if (facts is null)
            {
                continue;
            }

            merged.HasPassword |= facts.HasPassword;
            merged.HasCard |= facts.HasCard;
            foreach (var form in facts.Forms)
            {
                form.FrameUrl = frame.Url;
                merged.Forms.Add(form);
            }

            if (frame.ParentFrame is null)
            {
                merged.Text = facts.Text;
            }
        }

        return merged;
    }

    private static BrowserNewContextOptions BuildContextOptions(bool mobile, int chromeMajor)
    {
        // Victims open these links from Viber/Telegram on Android phones, and some kits
        // only show the phishing form to mobile visitors, so mobile is the default.
        var options = mobile
            ? new BrowserNewContextOptions
            {
                ViewportSize = new ViewportSize { Width = 412, Height = 915 },
                DeviceScaleFactor = 2,
                IsMobile = true,
                HasTouch = true,
                UserAgent = $"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chromeMajor}.0.0.0 Mobile Safari/537.36",
            }
            : new BrowserNewContextOptions
            {
                ViewportSize = new ViewportSize { Width = 1366, Height = 768 },
                UserAgent = $"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chromeMajor}.0.0.0 Safari/537.36",
            };

        options.Locale = "uk-UA";
        options.TimezoneId = "Europe/Kiev";
        options.AcceptDownloads = false;
        options.ServiceWorkers = ServiceWorkerPolicy.Block;
        options.IgnoreHTTPSErrors = true;
        return options;
    }

    private static async Task<T?> SafeAsync<T>(Func<Task<T>> action) where T : class
    {
        try
        {
            return await action();
        }
        catch (Exception e) when (IsBrowserError(e))
        {
            return null;
        }
    }

    /// <summary>
    /// Playwright for .NET reports browser failures as PlaywrightException,
    /// but timeouts as the standard System.TimeoutException.
    /// </summary>
    private static bool IsBrowserError(Exception e) => e is PlaywrightException or TimeoutException;

    private static string FirstLine(string message)
    {
        var line = message.Split('\n', 2)[0].Trim();
        return line.Length <= 200 ? line : line[..200];
    }

    [GeneratedRegex(@"net::ERR_[A-Z0-9_]+")]
    private static partial Regex NetErrorRegex();
}
