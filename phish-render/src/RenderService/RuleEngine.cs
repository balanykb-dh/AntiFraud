namespace RenderService;

public sealed record RuleOutcome(string Verdict, int Score, string? Brand, bool Official, bool Unreachable, List<string> Reasons);

/// <summary>
/// Transparent scoring: every signal adds points and a human-readable reason.
/// 60+ = phishing, 35-59 = suspicious, below = safe. Official brand domains are always safe.
/// </summary>
public sealed class RuleEngine
{
    public const int PhishingThreshold = 60;
    public const int SuspiciousThreshold = 35;

    /// <summary>Lower-case bait phrases seen on Ukrainian (and some global) phishing pages.</summary>
    private static readonly string[] Lures =
    {
        // compensation / social payments
        "отримати компенсац", "компенсацію від", "виплати від", "виплата від", "отримає виплат", "отримати виплат",
        "грошову допомогу", "фінансову допомогу", "єпідтримк", "епідтримк", "єдопомог", "едопомог",
        // marketplace "delivery" scheme
        "безпечна угода", "безпечної угоди", "olx доставка", "olx delivery", "кошти за товар", "отримання коштів",
        "отримати кошти", "отримати оплату", "покупець оплатив", "оплату отримано", "оплата успішна",
        // card harvesting
        "підтвердіть картку", "підтвердження картки", "верифікація картки", "введіть дані картки", "дані вашої картки",
        "баланс картки", "для зарахування коштів",
        // prizes
        "ви виграли", "ваш приз", "отримайте приз", "призовий фонд",
        // parcels
        "посилка затримана", "посилку затримано", "оплатіть доставку", "сплатіть доставку", "доставку не вдалося",
        // account scare
        "рахунок заблоковано", "картку заблоковано", "обліковий запис заблоковано", "підтвердьте особу",
        // Russian
        "получить компенсацию", "получить выплату", "безопасная сделка", "подтвердите карту", "вы выиграли",
        "получить средства", "данные карты",
        // English
        "verify your account", "confirm your identity", "account has been suspended", "account is suspended",
        "unusual activity", "update your payment", "you have won", "claim your", "account locked",
        "verify your identity", "confirm your payment",
    };

    /// <summary>Hosting providers' "this site was removed" pages: the phishing is already gone.</summary>
    private static readonly string[] TakedownMarkers =
    {
        "website takedown notice", "has been taken down", "contact your hosting provider", "this deployment has been disabled",
        "this site has been disabled", "this site has been suspended", "site has been blocked due to", "сайт заблоковано за",
    };

    /// <summary>Interstitials that browsers/CDNs show in front of already-reported phishing.</summary>
    private static readonly string[] PhishingWarningMarkers =
    {
        "suspected phishing site ahead", "reported for potential phishing", "deceptive site ahead", "dangerous site ahead",
    };

    private readonly BrandRegistry _brands;

    public RuleEngine(BrandRegistry brands) => _brands = brands;

    public static bool IsTakenDown(RenderResult r)
    {
        var text = $"{r.Title} {r.Text}".ToLowerInvariant();
        return TakedownMarkers.Any(m => text.Contains(m, StringComparison.Ordinal));
    }

    public static bool IsUnreachable(RenderResult r)
    {
        var e = r.Error;
        if (e is not null
            && (e == "dns_failed" || e == "blocked_internal_address" || e == "browser_unavailable"
                || e.StartsWith("net::ERR_", StringComparison.Ordinal)
                || e.StartsWith("navigation_failed", StringComparison.Ordinal)))
        {
            return true;
        }

        var anyCredentialField = r.HasCardInput || r.HasPasswordInput
            || r.CtaStep?.HasCardInput == true || r.CtaStep?.HasPasswordInput == true;
        var errorStatus = r.HttpStatus is 404 or 410 or >= 500;
        return (errorStatus || IsTakenDown(r)) && !anyCredentialField;
    }

    public RuleOutcome Evaluate(RenderResult r, DomainAge? age)
    {
        var reasons = new List<string>();

        if (IsUnreachable(r))
        {
            reasons.Add(IsTakenDown(r)
                ? "Хостинг уже прибрав цей сайт (сторінка про блокування)"
                : "Сторінка недоступна: " + (r.Error ?? $"HTTP {r.HttpStatus}"));
            return new RuleOutcome("unreachable", 0, null, false, true, reasons);
        }

        var requestedHost = DomainTools.HostOf(r.RequestedUrl) ?? "";
        var finalHost = DomainTools.HostOf(r.FinalUrl) ?? requestedHost;
        var officialFinal = _brands.FindOfficial(finalHost);
        var officialRequested = _brands.FindOfficial(requestedHost);

        if (officialFinal is not null)
        {
            var sameSite = officialRequested is not null
                || DomainTools.Registrable(requestedHost) == DomainTools.Registrable(finalHost)
                || DomainTools.IsShortener(requestedHost);
            if (sameSite)
            {
                reasons.Add($"Офіційний домен: {officialFinal.Name}");
                return new RuleOutcome("safe", 0, officialFinal.Name, true, false, reasons);
            }

            // Cloaking: the phishing domain shows the form to victims but sends crawlers to the real site.
            if (_brands.FindInHost(requestedHost) == officialFinal)
            {
                // Brands buy their name in other zones and point it at the main site (kachorovska.com.ua).
                // Phishing domains are days or months old; one held for years is almost always the brand's own.
                if (age?.AgeDays is int heldDays && heldDays > 730)
                {
                    reasons.Add($"Адреса {requestedHost} веде на офіційний сайт {officialFinal.Name} і зареєстрована "
                        + $"{heldDays / 365} р. тому: схоже на захисний домен самого бренду");
                    return new RuleOutcome("safe", 10, officialFinal.Name, false, false, reasons);
                }

                reasons.Add($"Адреса {requestedHost} видає себе за {officialFinal.Name} і перекидає перевірку "
                    + "на справжній сайт: так фішинг ховається від сканерів, а жертвам показує форму");
                return new RuleOutcome("phishing", 65, officialFinal.Name, false, false, reasons);
            }

            reasons.Add($"Неофіційна адреса {requestedHost} перекинула на офіційний сайт {officialFinal.Name}: "
                + "так фішингові сайти ховаються від перевірок");
            return new RuleOutcome("suspicious", 40, officialFinal.Name, false, false, reasons);
        }

        var score = 0;
        string? brand = null;
        var hosts = new[] { requestedHost, finalHost }.Where(h => h.Length > 0).Distinct().ToList();
        var allText = $"{r.Title} {r.Text} {r.CtaStep?.Title} {r.CtaStep?.Text}".ToLowerInvariant();
        var hasCard = r.HasCardInput || r.CtaStep?.HasCardInput == true;
        var hasPassword = r.HasPasswordInput || r.CtaStep?.HasPasswordInput == true;
        var allForms = r.Forms.Concat(r.CtaStep?.Forms ?? new List<FormInfo>()).ToList();
        var hasInputs = hasCard || hasPassword || allForms.Any(f => f.Inputs.Count > 0);

        // 1. Brand impersonation
        var hostBrand = hosts.Select(h => _brands.FindInHost(h)).FirstOrDefault(b => b is not null);
        if (hostBrand is not null)
        {
            score += 35;
            brand = hostBrand.Name;
            reasons.Add($"В адресі назва бренду {hostBrand.Name}, але домен не офіційний ({finalHost})");
        }

        // Phishing kits on hacked sites live in paths: /views/Adobe_Doc.html, /Li/alibaba
        Brand? pathBrand = null;
        if (hostBrand is null)
        {
            pathBrand = new[] { r.RequestedUrl, r.FinalUrl }
                .Select(PathOf)
                .Where(p => p.Length > 1)
                .Select(p => _brands.FindInHost(p))
                .FirstOrDefault(b => b is not null);
            if (pathBrand is not null)
            {
                score += 20;
                brand = pathBrand.Name;
                reasons.Add($"У шляху адреси назва бренду {pathBrand.Name} на чужому сайті");
            }
        }

        if (r.PassedWarning is not null || PhishingWarningMarkers.Any(m => allText.Contains(m, StringComparison.Ordinal)))
        {
            score += 60;
            reasons.Add("Браузер або Cloudflare вже показує попередження про фішинг на цьому сайті");
        }

        var titleBrand = _brands.FindInText(r.Title) ?? _brands.FindInText(r.CtaStep?.Title);
        if (titleBrand is not null)
        {
            score += hostBrand is null ? 20 : 10;
            brand ??= titleBrand.Name;
            reasons.Add($"Заголовок сторінки згадує {titleBrand.Name}");
        }
        else if (_brands.FindInText(allText) is { } textBrand)
        {
            score += 10;
            brand ??= textBrand.Name;
            reasons.Add($"Текст сторінки згадує {textBrand.Name}");
        }

        var embedded = hosts.Select(DomainTools.EmbeddedDomain).FirstOrDefault(e => e is not null);
        if (embedded is not null)
        {
            score += 25;
            reasons.Add($"Адреса починається як {embedded}, а насправді це домен {DomainTools.Registrable(requestedHost)}: класична підробка");
        }

        var lures = Lures.Where(l => allText.Contains(l, StringComparison.Ordinal)).Take(3).ToList();

        // 2. What the page asks for. A card field on a long-established domain that imitates nobody
        //    is how ordinary payment services look (Portmone, EasyPay, iPay), so it weighs less there.
        if (hasCard)
        {
            var established = age?.AgeDays > 730 && hostBrand is null && embedded is null && lures.Count == 0;
            score += established ? 15 : 35;
            reasons.Add(r.HasCardInput
                ? "Сторінка просить дані банківської картки"
                : $"Після кнопки «{r.CtaStep?.ClickedText}» сторінка просить дані картки");
        }

        if (hasPassword)
        {
            score += 15;
            reasons.Add("Є поле для пароля");
        }

        // Each page's forms are compared with that page's own domain (the button may lead to another site).
        var pageDomain = DomainTools.Registrable(finalHost);
        var ctaDomain = DomainTools.HostOf(r.CtaStep?.Url) is { } ctaHost ? DomainTools.Registrable(ctaHost) : pageDomain;
        var foreignAction = FirstForeignAction(r.Forms, pageDomain) ?? FirstForeignAction(r.CtaStep?.Forms, ctaDomain);
        if (foreignAction is not null)
        {
            score += 10;
            reasons.Add($"Форма відправляє дані на інший домен: {foreignAction}");
        }

        // 3. Bait wording. Long pages without inputs are usually articles ABOUT scams: half weight.
        if (lures.Count > 0)
        {
            var points = lures.Count >= 2 ? 25 : 12;
            var shortPage = (r.Text?.Length ?? 0) < 2500;
            if (!shortPage && !hasInputs)
            {
                points /= 2;
            }

            score += points;
            reasons.Add($"Фрази-приманки: «{string.Join("», «", lures)}»");
        }

        // 4. Where it is hosted
        foreach (var host in hosts)
        {
            if (DomainTools.FreeHostingRoot(host) is { } platform)
            {
                score += 20;
                reasons.Add($"Сайт на безкоштовному конструкторі чи хостингу ({platform})");
                break;
            }
        }

        var suspiciousTld = hosts.Select(DomainTools.Tld).FirstOrDefault(t => DomainTools.SuspiciousTlds.Contains(t));
        if (suspiciousTld is not null && !hosts.Any(DomainTools.IsFreeHosting))
        {
            score += 10;
            reasons.Add($"Доменна зона .{suspiciousTld}, популярна у шахраїв");
        }

        var hostLure = hosts
            .SelectMany(h => DomainTools.HostLureWords.Where(w => h.Contains(w, StringComparison.Ordinal)))
            .FirstOrDefault();
        if (hostLure is not null)
        {
            score += 15;
            reasons.Add($"В адресі слово-приманка «{hostLure.Trim('-', '.')}»");
        }

        if (hosts.Any(DomainTools.HasPunycode))
        {
            score += 15;
            reasons.Add("Домен із нелатинськими символами: можлива підміна схожих літер");
        }

        if (hosts.Any(DomainTools.IsIpLiteral))
        {
            score += 20;
            reasons.Add("Замість домену IP-адреса");
        }

        if (age?.AgeDays is int days)
        {
            if (days < 14)
            {
                score += 40;
                reasons.Add($"Домен {age.Domain} зареєстровано {days} дн. тому");
            }
            else if (days < 30)
            {
                score += 30;
                reasons.Add($"Домен {age.Domain} зареєстровано {days} дн. тому");
            }
            else if (days < 180)
            {
                score += 12;
                reasons.Add($"Молодий домен {age.Domain}: {days} дн.");
            }
            else if (days > 730 && hostBrand is null && pathBrand is null && embedded is null)
            {
                // An old domain is reassuring only if it does not pretend to be someone else:
                // hacked old sites hosting a brand's login page are common.
                score -= 10;
                reasons.Add($"Домен {age.Domain} існує {days / 365} р.");
            }
        }

        // 5. Redirect games
        var visited = r.Navigations
            .Select(n => DomainTools.HostOf(n))
            .Where(h => h is not null)
            .Select(h => DomainTools.Registrable(h!))
            .Distinct()
            .ToList();
        if (visited.Count > 1)
        {
            score += 10;
            reasons.Add($"Сторінка перекидала між доменами: {string.Join(" → ", visited)}");
        }

        // Cloaking towards a brand we do not track: a throwaway-looking address that redirects to a real
        // site whose name it borrows ("allegro.aukcja8279.shop" -> allegrolokalnie.pl).
        var requestedDomain = DomainTools.Registrable(requestedHost);
        var finalDomain = DomainTools.Registrable(finalHost);
        if (requestedDomain != finalDomain && LooksThrowaway(requestedHost) && BorrowsName(requestedHost, finalDomain))
        {
            score += 40;
            reasons.Add($"Адреса {requestedHost} імітує {finalDomain} і перекидає перевірку на справжній сайт: "
                + "так фішинг ховається від сканерів");
        }

        score = Math.Clamp(score, 0, 100);
        var verdict = score >= PhishingThreshold ? "phishing" : score >= SuspiciousThreshold ? "suspicious" : "safe";
        if (reasons.Count == 0)
        {
            reasons.Add("Ознак фішингу не знайдено");
        }

        return new RuleOutcome(verdict, score, brand, false, false, reasons);
    }

    private static string? FirstForeignAction(IEnumerable<FormInfo>? forms, string ownDomain) =>
        forms?
            .Select(f => DomainTools.HostOf(f.Action))
            .FirstOrDefault(h => h is not null && DomainTools.Registrable(h) != ownDomain);

    private static string PathOf(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) ? Uri.UnescapeDataString(u.AbsolutePath).ToLowerInvariant() : "";

    private static bool LooksThrowaway(string host) =>
        DomainTools.SuspiciousTlds.Contains(DomainTools.Tld(host))
        || DomainTools.IsFreeHosting(host)
        || DomainTools.EmbeddedDomain(host) is not null
        || DomainTools.HasPunycode(host)
        || DomainTools.HasDigitRun(host)
        || DomainTools.HostLureWords.Any(w => host.Contains(w, StringComparison.Ordinal));

    /// <summary>"allegro.aukcja8279.shop" borrows from "allegrolokalnie.pl": a 5+ letter label of one contains the other.</summary>
    private static bool BorrowsName(string requestedHost, string finalDomain)
    {
        var finalName = finalDomain.Split('.')[0];
        if (finalName.Length < 5)
        {
            return false;
        }

        return requestedHost.Split('.', '-')
            .Where(label => label.Length >= 5)
            .Any(label => label.Contains(finalName, StringComparison.Ordinal) || finalName.Contains(label, StringComparison.Ordinal));
    }
}
