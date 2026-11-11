using System.Diagnostics.CodeAnalysis;

namespace RenderService;

public static class UrlInput
{
    private const int MaxLength = 2048;

    public static bool TryNormalize(
        string? raw,
        [NotNullWhen(true)] out Uri? uri,
        [NotNullWhen(false)] out string? error)
    {
        uri = null;
        error = null;

        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "url is required";
            return false;
        }

        var s = Refang(raw);
        if (s.Length > MaxLength)
        {
            error = "url is too long";
            return false;
        }

        if (!Uri.TryCreate(s, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrEmpty(parsed.Host))
        {
            error = "only absolute http(s) urls are allowed";
            return false;
        }

        uri = parsed;
        return true;
    }

    /// <summary>
    /// Turns a defanged indicator back into a URL: hxxps://olx-pay[.]site -> https://olx-pay.site.
    /// A bare domain gets https:// because practically all current phishing runs on free TLS.
    /// </summary>
    public static string Refang(string raw)
    {
        var s = raw.Trim().Trim('"', '\'', '<', '>', '`');
        s = s.Replace("[.]", ".", StringComparison.Ordinal)
             .Replace("(.)", ".", StringComparison.Ordinal)
             .Replace("{.}", ".", StringComparison.Ordinal)
             .Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase)
             .Replace("[://]", "://", StringComparison.Ordinal)
             .Replace("[:]", ":", StringComparison.Ordinal);

        if (s.StartsWith("hxxps", StringComparison.OrdinalIgnoreCase))
        {
            s = "https" + s[5..];
        }
        else if (s.StartsWith("hxxp", StringComparison.OrdinalIgnoreCase))
        {
            s = "http" + s[4..];
        }

        if (!s.Contains("://", StringComparison.Ordinal))
        {
            s = "https://" + s;
        }

        return s;
    }
}
