using Microsoft.Playwright;

namespace RenderService;

/// <summary>
/// One shared Chromium process. Every render gets its own fresh incognito context,
/// so pages never share cookies, storage or cache. If Chromium dies, the next
/// request relaunches it.
/// </summary>
public sealed class BrowserHost : IAsyncDisposable
{
    private readonly ILogger<BrowserHost> _log;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private IPlaywright? _playwright;
    private IBrowser? _browser;

    public BrowserHost(ILogger<BrowserHost> log) => _log = log;

    public bool IsConnected => _browser?.IsConnected == true;
    public string? BrowserVersion => _browser?.Version;
    public int ChromeMajor { get; private set; } = 140;

    public async Task<IBrowser> GetBrowserAsync()
    {
        var current = _browser;
        if (current is { IsConnected: true })
        {
            return current;
        }

        await _lock.WaitAsync();
        try
        {
            if (_browser is { IsConnected: true })
            {
                return _browser;
            }

            if (_browser is not null)
            {
                _log.LogWarning("Chromium disconnected, relaunching");
                await CloseQuietlyAsync(_browser);
            }

            _playwright ??= await Playwright.CreateAsync();

            // "chromium" = full Chromium in new headless mode: closer to a real browser than the
            // stripped headless shell, so fewer phishing kits detect it and cloak.
            // BROWSER_CHANNEL=default in .env falls back to Playwright's default build.
            var channel = Environment.GetEnvironmentVariable("BROWSER_CHANNEL");
            if (string.IsNullOrWhiteSpace(channel))
            {
                channel = "chromium";
            }

            _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true,
                Channel = channel == "default" ? null : channel,
                Args = new[]
                {
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                },
            });

            if (int.TryParse(_browser.Version.Split('.')[0], out var major))
            {
                ChromeMajor = major;
            }

            _log.LogInformation("Chromium {Version} launched", _browser.Version);
            return _browser;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Drops the current browser; the next render launches a new one.</summary>
    public async Task RecycleAsync()
    {
        await _lock.WaitAsync();
        try
        {
            var old = _browser;
            _browser = null;
            if (old is not null)
            {
                _log.LogWarning("Recycling Chromium");
                await CloseQuietlyAsync(old);
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task CloseQuietlyAsync(IBrowser browser)
    {
        try
        {
            await Task.WhenAny(browser.CloseAsync(), Task.Delay(TimeSpan.FromSeconds(10)));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Chromium close failed");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_browser is not null)
        {
            await CloseQuietlyAsync(_browser);
        }

        _playwright?.Dispose();
    }
}
