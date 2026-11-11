namespace RenderService;

public static class PageScripts
{
    /// <summary>
    /// Runs inside each frame. Returns a JSON string (parsed in C#) with forms, a password flag,
    /// a payment-card flag and the visible text. Uses getAttribute everywhere because phishing
    /// pages can shadow form.action / form.method with inputs named "action" or "method".
    /// </summary>
    public const string CollectFacts = """
        () => {
          const attr = (el, n) => ((el && el.getAttribute && el.getAttribute(n)) || '').trim();
          const describe = el => {
            const tag = el.tagName.toLowerCase();
            const type = tag === 'input' ? (attr(el, 'type') || 'text').toLowerCase() : tag;
            const label = attr(el, 'name') || attr(el, 'id') || attr(el, 'placeholder') || attr(el, 'aria-label');
            const ac = attr(el, 'autocomplete');
            return [type, label, ac].filter(Boolean).join(':').slice(0, 120);
          };
          const forms = Array.from(document.querySelectorAll('form')).slice(0, 20).map(f => {
            const raw = attr(f, 'action');
            let action = null;
            if (raw) { try { action = new URL(raw, location.href).href; } catch (e) { action = raw; } }
            return {
              action: action,
              method: (attr(f, 'method') || 'get').toLowerCase(),
              inputs: Array.from(f.querySelectorAll('input, select, textarea')).slice(0, 40).map(describe)
            };
          });
          const inputs = Array.from(document.querySelectorAll('input'));
          const cardWords = /card|cc-?num|cvv|cvc|csc|expir|картк|номер карт|термін дії|срок действ/i;
          const cardMask = /^[\dXx*•\s-]{16,23}$/;
          const hasPassword = inputs.some(i => attr(i, 'type').toLowerCase() === 'password');
          const hasCard = inputs.some(i =>
            /cc-(number|csc|exp)/i.test(attr(i, 'autocomplete'))
            || cardWords.test([attr(i, 'name'), attr(i, 'id'), attr(i, 'placeholder'), attr(i, 'aria-label')].join(' '))
            || cardMask.test(attr(i, 'placeholder')));
          const text = document.body ? (document.body.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 5000) : '';
          return JSON.stringify({ forms: forms, hasPassword: hasPassword, hasCard: hasCard, text: text });
        }
        """;

    /// <summary>
    /// Finds the most prominent visible call-to-action ("Отримати компенсацію", "Продовжити", "Claim"...),
    /// marks it with data-pr-cta="1" for Playwright to click, and returns its label (or null).
    /// Cookie banners, menus and language switchers are skipped.
    /// </summary>
    public const string MarkCallToAction = """
        () => {
          const want = /(отрима|продовж|далі|підтверд|оформ|оплат|забра|перейти|почати|зареєстр|увійти|получ|продолж|подтверд|далее|войти|claim|continue|verify|confirm|next|proceed|get started|sign in|log in|login|receive)/i;
          const skip = /(cookie|кукі|закрити|close|прийняти|accept|згоден|agree|мова|language|меню|menu|пошук|search|завантаж|download|app store|google play|додатк)/i;
          const labelOf = el => ((el.innerText || el.value || el.getAttribute('aria-label') || '') + '').replace(/\s+/g, ' ').trim();
          const nodes = Array.from(document.querySelectorAll('a, button, input[type=submit], input[type=button], [role=button]'));
          let best = null, bestArea = 0;
          for (const el of nodes) {
            const label = labelOf(el);
            if (!label || label.length > 60 || !want.test(label) || skip.test(label)) continue;
            const href = el.tagName === 'A' ? (el.getAttribute('href') || '') : '';
            if (/^(mailto:|tel:|sms:|viber:|tg:|javascript:void)/i.test(href)) continue;
            const r = el.getBoundingClientRect();
            const s = getComputedStyle(el);
            if (r.width < 40 || r.height < 20 || s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) === 0) continue;
            const area = r.width * r.height;
            if (area > bestArea) { best = el; bestArea = area; }
          }
          if (!best) return null;
          best.setAttribute('data-pr-cta', '1');
          return labelOf(best).slice(0, 60);
        }
        """;
}
