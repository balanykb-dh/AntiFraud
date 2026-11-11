using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using RenderService;

// Used once during `docker build`: downloads Chromium and its system libraries
// with exactly the version that matches the Microsoft.Playwright package.
if (args.Length > 0 && args[0] == "install-browsers")
{
    return Microsoft.Playwright.Program.Main(new[] { "install", "--with-deps", "chromium" });
}

var settings = RenderSettings.FromEnvironment();

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 16 * 1024);
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull);

builder.Services.AddHttpClient("rdap", c =>
{
    c.Timeout = TimeSpan.FromSeconds(10);
    c.DefaultRequestHeaders.UserAgent.ParseAdd("phish-render/1.0");
    c.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
    c.DefaultRequestHeaders.Accept.ParseAdd("application/json");
});
builder.Services.AddHttpClient("anthropic", c => c.Timeout = TimeSpan.FromSeconds(60));

builder.Services.AddSingleton(settings);
builder.Services.AddSingleton<BrandRegistry>();
builder.Services.AddSingleton<RuleEngine>();
builder.Services.AddSingleton<DomainAgeService>();
builder.Services.AddSingleton<LlmJudge>();
builder.Services.AddSingleton<VerdictEngine>();
builder.Services.AddSingleton<BrowserHost>();
builder.Services.AddSingleton<PageRenderer>();

var app = builder.Build();

// Fail loudly at startup (visible in `docker compose logs`) instead of on the first request.
app.Services.GetRequiredService<BrandRegistry>();
await app.Services.GetRequiredService<BrowserHost>().GetBrowserAsync();
app.Logger.LogInformation(
    "Render service ready: concurrency={Concurrency}, navTimeout={Nav}ms, hardTimeout={Hard}ms, llm={Llm}",
    settings.MaxConcurrency, settings.NavTimeoutMs, settings.HardTimeoutMs,
    string.IsNullOrWhiteSpace(settings.AnthropicApiKey) ? "off" : settings.LlmModel);

var expectedKey = Encoding.UTF8.GetBytes(settings.ApiKey);
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/render") || ctx.Request.Path.StartsWithSegments("/check"))
    {
        var given = Encoding.UTF8.GetBytes(ctx.Request.Headers["X-Api-Key"].ToString());
        if (!CryptographicOperations.FixedTimeEquals(given, expectedKey))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }
    }
    await next(ctx);
});

app.MapGet("/health", (BrowserHost host, LlmJudge llm) => Results.Ok(new
{
    status = host.IsConnected ? "ok" : "browser_down",
    browser = host.BrowserVersion,
    llm = llm.Enabled ? settings.LlmModel : "off",
    llmCallsToday = llm.CallsToday,
    llmDailyLimit = settings.LlmDailyLimit,
}));

app.MapPost("/render", async (RenderRequest req, PageRenderer renderer, ILogger<PageRenderer> log, CancellationToken ct) =>
{
    if (!UrlInput.TryNormalize(req.Url, out var target, out var error))
    {
        return Results.BadRequest(new { error });
    }

    if (!TryReferer(req.Referer, out var referer))
    {
        return Results.BadRequest(new { error = "referer must be an absolute http(s) URL" });
    }

    var options = new RenderOptions(
        req.Mobile ?? true, req.FullPage ?? false, req.IncludeHtml ?? false, req.FollowCta ?? false, referer, req.PassWarning ?? false);
    var result = await renderer.TryRenderAsync(target, options, ct);
    if (result is null)
    {
        return Results.Json(new { error = "busy" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    log.LogInformation(
        "render {Url} -> {Final} status={Status} error={Error} blocked={Blocked} {Ms}ms",
        result.RequestedUrl, result.FinalUrl, result.HttpStatus, result.Error, result.BlockedCount, result.ElapsedMs);
    return Results.Ok(result);
});

app.MapPost("/check", async (CheckRequest req, PageRenderer renderer, VerdictEngine verdicts, ILogger<VerdictEngine> log, CancellationToken ct) =>
{
    if (!UrlInput.TryNormalize(req.Url, out var target, out var error))
    {
        return Results.BadRequest(new { error });
    }

    if (!TryReferer(req.Referer, out var referer))
    {
        return Results.BadRequest(new { error = "referer must be an absolute http(s) URL" });
    }

    var options = new RenderOptions(
        req.Mobile ?? true, FullPage: false, IncludeHtml: false, FollowCta: req.FollowCta ?? true, referer, req.PassWarning ?? false);
    var render = await renderer.TryRenderAsync(target, options, ct);
    if (render is null)
    {
        return Results.Json(new { error = "busy" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    var check = await verdicts.EvaluateAsync(render, req.UseLlm ?? true, ct);
    log.LogInformation(
        "check {Url} -> {Verdict} score={Score} rules={RuleVerdict}/{RuleScore} brand={Brand} llm={Llm} {Ms}ms",
        render.RequestedUrl, check.Verdict, check.Score, check.RuleVerdict, check.RuleScore, check.Brand,
        check.Llm is null ? "-" : check.Llm.Error ?? $"{check.Llm.IsPhishing}/{check.Llm.Confidence:0.00}", render.ElapsedMs);
    return Results.Ok(check);
});

await app.RunAsync();
return 0;

static bool TryReferer(string? value, out string? referer)
{
    referer = null;
    if (string.IsNullOrWhiteSpace(value))
    {
        return true;
    }

    if (value.Length > 2000 || !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
        || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
    {
        return false;
    }

    referer = uri.AbsoluteUri;
    return true;
}
