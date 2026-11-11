using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text.Json;

namespace RenderService;

public sealed class DomainAge
{
    public string Domain { get; set; } = "";
    public DateTimeOffset? Registered { get; set; }
    public int? AgeDays { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Domain registration date via RDAP (the modern WHOIS). Fresh domains are the strongest phishing signal.
/// The IANA bootstrap file maps each TLD to its registry's RDAP server. Some ccTLDs (including .ua)
/// have no RDAP; those return Error = "rdap_not_available" and simply add no points.
/// </summary>
public sealed class DomainAgeService
{
    private const string BootstrapUrl = "https://data.iana.org/rdap/dns.json";

    private readonly IHttpClientFactory _http;
    private readonly ILogger<DomainAgeService> _log;
    private readonly SemaphoreSlim _bootstrapLock = new(1, 1);
    private readonly ConcurrentDictionary<string, DomainAge> _cache = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string>? _servers;
    private DateTimeOffset _serversLoadedAt;

    public DomainAgeService(IHttpClientFactory http, ILogger<DomainAgeService> log)
    {
        _http = http;
        _log = log;
    }

    public async Task<DomainAge?> LookupAsync(string host, CancellationToken ct)
    {
        var domain = DomainTools.Registrable(host);
        if (DomainTools.IsIpLiteral(domain) || !domain.Contains('.'))
        {
            return null;
        }

        if (_cache.TryGetValue(domain, out var cached))
        {
            return cached;
        }

        var servers = await GetServersAsync(ct);
        if (servers is null)
        {
            return new DomainAge { Domain = domain, Error = "rdap_bootstrap_failed" };
        }

        if (!servers.TryGetValue(DomainTools.Tld(domain), out var baseUrl))
        {
            return Remember(new DomainAge { Domain = domain, Error = "rdap_not_available" });
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var client = _http.CreateClient("rdap");
            using var response = await client.GetAsync($"{baseUrl.TrimEnd('/')}/domain/{domain}", cts.Token);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return Remember(new DomainAge { Domain = domain, Error = "not_found" });
            }

            if (!response.IsSuccessStatusCode)
            {
                return new DomainAge { Domain = domain, Error = $"http_{(int)response.StatusCode}" };
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token);
            var registered = FindRegistrationDate(doc.RootElement);
            if (registered is null)
            {
                return Remember(new DomainAge { Domain = domain, Error = "no_registration_date" });
            }

            var age = (int)Math.Max(0, (DateTimeOffset.UtcNow - registered.Value).TotalDays);
            return Remember(new DomainAge { Domain = domain, Registered = registered, AgeDays = age });
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            _log.LogDebug(ex, "RDAP lookup failed for {Domain}", domain);
            return new DomainAge { Domain = domain, Error = "rdap_failed" };
        }
    }

    private DomainAge Remember(DomainAge age)
    {
        if (_cache.Count > 20_000)
        {
            _cache.Clear();
        }

        _cache[age.Domain] = age;
        return age;
    }

    private static DateTimeOffset? FindRegistrationDate(JsonElement root)
    {
        if (!root.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var e in events.EnumerateArray())
        {
            if (e.TryGetProperty("eventAction", out var action)
                && action.ValueKind == JsonValueKind.String
                && action.GetString() == "registration"
                && e.TryGetProperty("eventDate", out var date)
                && date.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(date.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
            {
                return parsed;
            }
        }

        return null;
    }

    private async Task<Dictionary<string, string>?> GetServersAsync(CancellationToken ct)
    {
        if (_servers is not null && DateTimeOffset.UtcNow - _serversLoadedAt < TimeSpan.FromDays(1))
        {
            return _servers;
        }

        await _bootstrapLock.WaitAsync(ct);
        try
        {
            if (_servers is not null && DateTimeOffset.UtcNow - _serversLoadedAt < TimeSpan.FromDays(1))
            {
                return _servers;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            var client = _http.CreateClient("rdap");
            await using var stream = await client.GetStreamAsync(BootstrapUrl, cts.Token);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token);

            // { "services": [ [ ["com","net"], ["https://rdap.verisign.com/com/v1/"] ], ... ] }
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var service in doc.RootElement.GetProperty("services").EnumerateArray())
            {
                if (service.ValueKind != JsonValueKind.Array || service.GetArrayLength() < 2)
                {
                    continue;
                }

                var url = service[1].EnumerateArray()
                    .Select(u => u.GetString())
                    .FirstOrDefault(u => u is not null && u.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
                if (url is null)
                {
                    continue;
                }

                foreach (var tld in service[0].EnumerateArray())
                {
                    if (tld.GetString() is { Length: > 0 } t)
                    {
                        map[t] = url;
                    }
                }
            }

            _servers = map;
            _serversLoadedAt = DateTimeOffset.UtcNow;
            _log.LogInformation("RDAP bootstrap loaded: {Count} TLDs", map.Count);
            return _servers;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            _log.LogWarning(ex, "RDAP bootstrap download failed");
            return _servers;
        }
        finally
        {
            _bootstrapLock.Release();
        }
    }
}
