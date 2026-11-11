using System.Text.Json;

namespace RenderService;

public sealed class Brand
{
    public string Name { get; set; } = "";

    /// <summary>Official registrable domains; any subdomain of them counts as official.</summary>
    public List<string> Domains { get; set; } = new();

    /// <summary>Latin fragments that, found in a non-official hostname, point at impersonation.</summary>
    public List<string> HostKeywords { get; set; } = new();

    /// <summary>Lower-case phrases to look for in the title and visible text.</summary>
    public List<string> TextKeywords { get; set; } = new();
}

/// <summary>
/// Brands we protect, from brands.json next to the binary. Edit the JSON and rebuild to add brands.
/// </summary>
public sealed class BrandRegistry
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public IReadOnlyList<Brand> Brands { get; }

    public BrandRegistry(ILogger<BrandRegistry> log)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "brands.json");
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("brands.json is missing next to RenderService.dll", path);
        }

        var brands = JsonSerializer.Deserialize<List<Brand>>(File.ReadAllText(path), Json) ?? new List<Brand>();
        foreach (var b in brands)
        {
            b.Domains = b.Domains.Select(d => d.Trim().ToLowerInvariant()).Where(d => d.Length > 0).ToList();
            b.HostKeywords = b.HostKeywords.Select(k => k.Trim().ToLowerInvariant()).Where(k => k.Length > 0).ToList();
            b.TextKeywords = b.TextKeywords.Select(k => k.Trim().ToLowerInvariant()).Where(k => k.Length > 0).ToList();
        }

        Brands = brands;
        log.LogInformation("Loaded {Count} brands from {Path}", Brands.Count, path);
    }

    public Brand? FindOfficial(string? host)
    {
        // Shared hosting under a brand's domain (sites.google.com, storage.googleapis.com, forms.office.com,
        // s3.amazonaws.com...) is where anyone can publish, so it is never "official".
        if (string.IsNullOrEmpty(host) || DomainTools.IsFreeHosting(host))
        {
            return null;
        }

        return Brands.FirstOrDefault(b => b.Domains.Any(d => DomainTools.IsSameOrSubdomain(host, d)));
    }

    public Brand? FindInHost(string? host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        // "olx" matches anywhere ("olx-pay.site"); "=apple" matches only a whole token, so
        // "support-center-apple" is Apple but "pineapple-shop" is not.
        var h = host.ToLowerInvariant();
        var tokens = h.Split('.', '-', '_', '/');
        return Brands.FirstOrDefault(b => b.HostKeywords.Any(k =>
            k.StartsWith('=') ? tokens.Contains(k[1..]) : h.Contains(k, StringComparison.Ordinal)));
    }

    public Brand? FindInText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var t = text.ToLowerInvariant();
        return Brands.FirstOrDefault(b => b.TextKeywords.Any(k => t.Contains(k, StringComparison.Ordinal)));
    }
}
