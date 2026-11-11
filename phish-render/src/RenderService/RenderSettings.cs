namespace RenderService;

public sealed class RenderSettings
{
    public required string ApiKey { get; init; }
    public int MaxConcurrency { get; init; }
    public int NavTimeoutMs { get; init; }
    public int HardTimeoutMs { get; init; }
    public int QueueTimeoutMs { get; init; }
    public int SettleMs { get; init; }
    public int MaxRequestsPerPage { get; init; }

    /// <summary>Claude API key for the LLM second opinion. Empty = rules only.</summary>
    public string? AnthropicApiKey { get; init; }
    public string LlmModel { get; init; } = "claude-haiku-5-5";

    /// <summary>Hard cap on Claude calls per UTC day; beyond it verdicts fall back to rules only.</summary>
    public int LlmDailyLimit { get; init; } = 300;

    /// <summary>Separate daily cap for brand audits (requests with llmPool = "audit").</summary>
    public int LlmAuditDailyLimit { get; init; } = 2000;

    public static RenderSettings FromEnvironment()
    {
        var key = Environment.GetEnvironmentVariable("RENDER_API_KEY");
        if (string.IsNullOrWhiteSpace(key) || key.Length < 24)
        {
            throw new InvalidOperationException(
                "RENDER_API_KEY is missing or shorter than 24 characters. setup.sh writes one into .env.");
        }

        var model = Environment.GetEnvironmentVariable("LLM_MODEL");

        return new RenderSettings
        {
            ApiKey = key.Trim(),
            MaxConcurrency = Int("MAX_CONCURRENCY", 2, 1, 16),
            NavTimeoutMs = Int("NAV_TIMEOUT_MS", 20_000, 1_000, 120_000),
            HardTimeoutMs = Int("HARD_TIMEOUT_MS", 60_000, 5_000, 300_000),
            QueueTimeoutMs = Int("QUEUE_TIMEOUT_MS", 30_000, 0, 300_000),
            SettleMs = Int("SETTLE_MS", 4_000, 0, 30_000),
            MaxRequestsPerPage = Int("MAX_REQUESTS_PER_PAGE", 400, 10, 5_000),
            AnthropicApiKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY")?.Trim(),
            LlmModel = string.IsNullOrWhiteSpace(model) ? "claude-haiku-5-5" : model.Trim(),
            LlmDailyLimit = Int("LLM_DAILY_LIMIT", 300, 0, 100_000),
            LlmAuditDailyLimit = Int("LLM_AUDIT_DAILY_LIMIT", 2000, 0, 100_000),
        };
    }

    private static int Int(string name, int fallback, int min, int max) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var v) ? Math.Clamp(v, min, max) : fallback;
}
