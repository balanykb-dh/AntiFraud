using System.Net;
using System.Text.RegularExpressions;

namespace RenderService;

public static class DomainTools
{
    /// <summary>Second-level public suffixes we meet in practice (a small subset of the Public Suffix List).</summary>
    private static readonly HashSet<string> MultiPartSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.ua", "org.ua", "net.ua", "gov.ua", "edu.ua", "in.ua", "biz.ua", "co.ua", "pp.ua", "kiev.ua", "kyiv.ua",
        "lviv.ua", "od.ua", "dp.ua", "kh.ua", "zp.ua", "ck.ua", "cn.ua", "if.ua", "te.ua", "vn.ua", "zt.ua", "rv.ua",
        "co.uk", "org.uk", "com.pl", "net.pl", "com.br", "com.au", "co.jp", "com.tr", "com.cn", "co.in", "com.mx",
        "co.za", "com.ar", "com.co", "eu.org", "us.com", "uk.com", "de.com",
        // CentralNic pseudo-suffixes: "apple-supports.sa.com" belongs to whoever registered apple-supports
        "sa.com", "br.com", "cn.com", "eu.com", "gb.com", "gb.net", "hu.com", "jpn.com", "kr.com", "no.com", "qc.com",
        "ru.com", "se.com", "se.net", "uk.net", "us.org", "uy.com", "za.com", "in.net", "ae.org", "com.de", "jp.net", "mex.com",
    };

    /// <summary>Free site builders and hosting where anyone can publish under a shared domain.</summary>
    private static readonly string[] FreeHosting =
    {
        "yolasite.com", "webflow.io", "ucraft.site", "ucraft.net", "wixsite.com", "weebly.com", "tilda.ws", "netlify.app",
        "vercel.app", "pages.dev", "workers.dev", "r2.dev", "github.io", "gitlab.io", "firebaseapp.com", "web.app",
        "glitch.me", "herokuapp.com", "onrender.com", "replit.app", "repl.co", "000webhostapp.com", "blogspot.com",
        "godaddysites.com", "square.site", "wordpress.com", "jimdosite.com", "site123.me", "mystrikingly.com",
        "carrd.co", "framer.app", "framer.website", "notion.site", "webnode.page", "ukit.me", "surge.sh",
        "ngrok-free.app", "ngrok.io", "ngrok.app", "trycloudflare.com", "ipfs.io", "dweb.link", "fleek.co",
        "translate.goog", "sites.google.com", "forms.gle", "linktr.ee", "fanlnk.to", "taplink.cc", "teletype.in",
        "telegra.ph", "wixstudio.io", "myshopify.com", "bubbleapps.io", "softr.app", "glide.page", "beget.tech",
        "lovable.app", "bolt.host", "web.core.windows.net", "blob.core.windows.net", "azurewebsites.net",
        "s3.amazonaws.com", "amazonaws.com", "cloudfront.net", "storage.googleapis.com", "firebasestorage.googleapis.com",
        "googleusercontent.com", "docs.google.com", "drive.google.com", "script.google.com", "forms.office.com",
        "onedrive.live.com", "1drv.ms", "sharepoint.com", "dropboxusercontent.com", "canva.site", "my.canva.site",
        "wpenginepowered.com", "wpengine.com", "wasmer.app", "pagekite.me", "deno.dev", "fly.dev", "up.railway.app",
        "koyeb.app", "hf.space", "streamlit.app", "infinityfreeapp.com", "rf.gd", "epizy.com", "wuaze.com", "free.nf",
        "webcindario.com",
    };

    /// <summary>Link shorteners: a redirect from them to an official site is normal.</summary>
    private static readonly string[] Shorteners =
    {
        "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at",
        "l.facebook.com", "lm.facebook.com", "l.instagram.com", "t.me", "clck.ru", "u.to", "admitad.com", "ad.admitad.com",
    };

    public static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "top", "xyz", "site", "online", "shop", "store", "icu", "rent", "help", "click", "live", "buzz", "cfd", "sbs",
        "bond", "cyou", "monster", "rest", "quest", "tk", "ml", "ga", "cf", "gq", "pw", "work", "link", "support",
        "digital", "fun", "space", "website", "club", "vip", "lol", "mom", "autos", "boats", "homes", "today",
        "cam", "uno", "win", "bid", "loan", "date", "racing", "download", "zip", "mov", "info", "cc", "su",
    };

    /// <summary>Words in a hostname that phishers use as bait.</summary>
    public static readonly string[] HostLureWords =
    {
        "compens", "viplat", "vyplat", "dopomog", "dopomoh", "prize", "gift", "bonus", "verify", "verif", "secure",
        "login-", "-login", "signin", "sign-in", "log-in", "support", "confirm", "unlock", "refund", "payout",
        "delivery-", "-delivery", "dostavka", "oplata", "-pay.", "pay-", "wallet", "airdrop", "claim", "recover",
        "account-", "-account", "update-", "oferta", "ogloszenie", "aukcja", "suporte", "soporte", "atendimento",
        "seguranca", "verificacao", "verificacion", "desbloqueio",
    };

    /// <summary>Second-level labels under two-letter country TLDs: x.com.kz, x.co.za, x.org.vn...</summary>
    private static readonly HashSet<string> GenericSecondLevels = new(StringComparer.OrdinalIgnoreCase)
    {
        "com", "net", "org", "co", "gov", "edu", "ac", "or", "ne", "go", "mil", "biz", "info", "web", "my", "sch",
        "nom", "ltd", "plc", "firm", "gen", "int", "name", "pro", "med",
    };

    /// <summary>Labels that look like a top-level domain when they appear inside a hostname.</summary>
    private static readonly HashSet<string> TldLike = new(StringComparer.OrdinalIgnoreCase)
    {
        "com", "net", "org", "ua", "pl", "de", "ru", "kz", "uk", "us", "eu", "info", "biz", "io", "gov", "app",
        "cz", "sk", "lt", "lv", "ee", "ro", "md", "fr", "it", "es",
    };

    /// <summary>Ordinary subdomain words that are not a brand name.</summary>
    private static readonly HashSet<string> CommonSubdomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "www", "m", "mail", "shop", "app", "api", "my", "en", "uk", "ua", "ru", "pl", "de", "blog", "news", "cdn",
        "static", "img", "web", "mobile", "login", "secure", "account", "accounts", "auth", "id", "signin", "help",
        "support", "online", "portal", "new", "old", "dev", "test",
    };

    private static readonly Regex TldPrefix = new(@"^([a-z]{2,4})(?:-|\d)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DashTld = new(@"^([a-z0-9]{3,})-(com|net|org|ua|pl)(?:-|$)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ManyDigits = new(@"\d{3,}", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Ad and tracking networks. Blocked during rendering: they are irrelevant to phishing and slow pages down.</summary>
    private static readonly string[] AdHosts =
    {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com", "googletagmanager.com",
        "googletagservices.com", "adservice.google.com", "adnxs.com", "rubiconproject.com", "pubmatic.com", "criteo.com",
        "criteo.net", "smartadserver.com", "onetag-sys.com", "bidswitch.net", "1rx.io", "adform.net", "hotjar.com",
        "hotjar.io", "nr-data.net", "creativecdn.com", "mfadsrvr.com", "smilewanted.com", "fwmrm.net", "admanmedia.com",
        "amazon-adsystem.com", "adx.opera.com", "sharethrough.com", "taboola.com", "outbrain.com", "clarity.ms",
        "mc.yandex.ru", "mc.yandex.com", "analytics.tiktok.com", "connect.facebook.net", "casalemedia.com", "openx.net",
        "33across.com", "teads.tv", "admixer.net", "admixer.com", "scorecardresearch.com", "quantserve.com",
        "moatads.com", "adsrvr.org", "lijit.com", "sonobi.com", "indexww.com", "yieldmo.com", "gumgum.com", "3lift.com",
        "contextweb.com", "rlcdn.com", "id5-sync.com", "agkn.com", "bluekai.com", "krxd.net", "tapad.com",
        "mathtag.com", "everesttech.net", "demdex.net", "betweendigital.com", "adhigh.net", "adriver.ru", "bidmatic.io",
        "media.net", "zemanta.com", "yadro.ru", "top-fwz1.mail.ru", "bigmir.net",
    };

    public static string? HostOf(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u) || string.IsNullOrEmpty(u.Host))
        {
            return null;
        }

        return u.IdnHost.Trim('[', ']').TrimEnd('.').ToLowerInvariant();
    }

    /// <summary>"a.b.olx-pay.site" -> "olx-pay.site"; "shop.foo.com.ua" -> "foo.com.ua".</summary>
    public static string Registrable(string host)
    {
        var h = host.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(h, out _))
        {
            return h;
        }

        var parts = h.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 2)
        {
            return h;
        }

        var lastTwo = parts[^2] + "." + parts[^1];
        var multiPart = MultiPartSuffixes.Contains(lastTwo)
            || (parts[^1].Length == 2 && GenericSecondLevels.Contains(parts[^2]));
        return multiPart ? parts[^3] + "." + lastTwo : lastTwo;
    }

    /// <summary>
    /// The domain a hostname pretends to be, or null:
    /// "olx.ua.dostavka24.rent" -> "olx.ua", "allegrolokalnie.pl-459876234.lol" -> "allegrolokalnie.pl",
    /// "paypal-com-aspi-dll.us" -> "paypal.com". The real registrable domain is something else entirely.
    /// </summary>
    public static string? EmbeddedDomain(string host)
    {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (IsIpLiteral(h))
        {
            return null;
        }

        var labels = h.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var regLabels = Registrable(h).Split('.', StringSplitOptions.RemoveEmptyEntries);
        var prefixCount = labels.Length - regLabels.Length;

        // "olx.ua.dostavka24.rent", "brand.com.evil.com": a TLD-looking label inside the subdomain part.
        for (var i = 1; i < prefixCount; i++)
        {
            if (TldLike.Contains(labels[i]) && IsBrandish(labels[i - 1]))
            {
                return labels[i - 1] + "." + labels[i];
            }
        }

        // "allegrolokalnie.pl-459876234.lol", "allegrolokalnie.pl194.sbs": the real domain starts with "pl-" / "pl194".
        if (prefixCount >= 1 && regLabels.Length > 0)
        {
            var m = TldPrefix.Match(regLabels[0]);
            if (m.Success && TldLike.Contains(m.Groups[1].Value) && IsBrandish(labels[prefixCount - 1]))
            {
                return labels[prefixCount - 1] + "." + m.Groups[1].Value;
            }
        }

        // "paypal-com-aspi-dll.us", "olx-ua-dostavka.top"
        if (regLabels.Length > 1)
        {
            var d = DashTld.Match(regLabels[0]);
            if (d.Success)
            {
                return d.Groups[1].Value + "." + d.Groups[2].Value;
            }
        }

        return null;
    }

    /// <summary>A label with a long run of digits ("aukcja8279", "pl-459876234"): typical of throwaway phishing domains.</summary>
    public static bool HasDigitRun(string host) =>
        host.Split('.').Any(label => ManyDigits.IsMatch(label));

    private static bool IsBrandish(string label) =>
        label.Length >= 3 && !CommonSubdomains.Contains(label) && label.Any(char.IsLetter);

    public static string Tld(string host)
    {
        var h = host.TrimEnd('.');
        var dot = h.LastIndexOf('.');
        return dot < 0 ? h : h[(dot + 1)..];
    }

    public static bool IsSameOrSubdomain(string host, string domain) =>
        host.Equals(domain, StringComparison.OrdinalIgnoreCase)
        || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    public static string? FreeHostingRoot(string host) => FreeHosting.FirstOrDefault(d => IsSameOrSubdomain(host, d));

    public static bool IsFreeHosting(string host) => FreeHostingRoot(host) is not null;

    public static bool IsShortener(string host) => Shorteners.Any(d => IsSameOrSubdomain(host, d));

    public static bool IsAdHost(string host) => AdHosts.Any(d => IsSameOrSubdomain(host, d));

    public static bool IsIpLiteral(string host) => IPAddress.TryParse(host.Trim('[', ']'), out _);

    public static bool HasPunycode(string host) =>
        host.Split('.').Any(label => label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase));
}
