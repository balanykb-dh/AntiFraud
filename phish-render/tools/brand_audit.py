#!/usr/bin/env python3
"""Аудит клонів бренду: знаходить схожі домени, перевіряє живі через /check і складає таблицю.

    sudo python3 tools/brand_audit.py --brand kachorovska --official kachorovska.com --out audit_out

Звідки беруться кандидати:
  1. Журнал SSL-сертифікатів (Certificate Transparency, crt.sh): будь-який домен із назвою бренду,
     на який хтось випустив сертифікат. Так видно й ті клони, які вже прибрали.
  2. Перебір підробок назви: пропущена/подвоєна/переставлена літера, сусідня клавіша, транслітерації,
     кирилиця замість латиниці, приставки на кшталт -sale, -outlet, fb-, і популярні доменні зони.
Далі: DNS (чи домен живий), рендер і вердикт через /check, класифікація.
Кожен живий домен відкривається двічі: як звичайний відвідувач і як відвідувач з реклами у Facebook
(fbclid + Referer). Фейкові магазини часто показують клон лише другим, а решті - нейтральний магазин.
Попередження Cloudflare «Suspected Phishing» проходиться, щоб побачити сторінку за ним.

Лише стандартна бібліотека Python. Результат у --out:
  candidates.csv  - усі живі кандидати з категорією, вердиктом і поясненнями
  ct_history.csv  - усі домени з журналу сертифікатів (включно з мертвими) і дата першого сертифіката
  <n>.jpg, <n>-cta.jpg, <n>-ad.jpg, official.jpg - скриншоти (-ad: візит «з реклами»)
  summary.md      - коротке зведення
"""
import argparse
import base64
import csv
import difflib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
API = os.environ.get("CHECK_URL", "http://127.0.0.1:8080/check")
UA = "phish-render-audit/1.0"

TLDS = [
    "com", "net", "org", "ua", "com.ua", "in.ua", "kiev.ua", "shop", "store", "online", "site", "top", "xyz",
    "sale", "fashion", "boutique", "info", "live", "club", "icu", "pro", "co", "eu", "biz", "life", "space",
    "website", "buzz", "cfd", "sbs", "vip", "shoes", "clothing", "world", "fun", "bond", "pl", "de",
]
HOT_TLDS = ["com", "com.ua", "ua", "shop", "store", "online", "site", "top", "xyz", "sale", "fashion", "net",
            "boutique", "icu", "sbs", "cfd", "vip", "life", "live", "pro"]
AFFIXES = ["sale", "sales", "shop", "store", "outlet", "ua", "official", "online", "discount", "promo", "buy",
           "fb", "ig", "insta", "brand", "shoes", "bags", "market", "skidki", "znyzhky", "blackfriday", "eu",
           "kyiv", "uk", "us", "new", "club", "vip", "best"]
KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
    "p": "ol", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn",
    "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
# Latin -> visually identical Cyrillic
HOMOGLYPHS = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "k": "к", "x": "х", "y": "у", "s": "ѕ", "h": "һ"}
IDN_TLDS = ["com", "net", "shop", "store", "online", "site", "top", "xyz"]
PARKED_MARKERS = [
    "domain is for sale", "this domain is for sale", "buy this domain", "domain may be for sale", "is for sale",
    "parked free", "parkingcrew", "sedo", "dan.com", "afternic", "godaddy.com/domainsearch", "hugedomains",
    "продається домен", "домен продається", "домен продается", "this domain has been registered", "coming soon",
    "index of /", "welcome to nginx", "apache2 ubuntu default page", "it works!", "default web site page",
    "підтримується сервісом nic.ua", "поддерживается сервисом nic.ua", "domain is available to be registered",
    "is registered, but may still be available", "припарковано безкоштовно", "parked free of charge",
    "get this domain", "отримати цей домен",
]
# Not sites at all: cloud proxies, router and NAS dynamic DNS, hosting control-panel hostnames. Never rendered.
SERVICE_SUFFIXES = (
    "mcas.ms", "admin-mcas.ms", "keenetic.link", "keenetic.pro", "keenetic.io", "keenetic.name", "quickconnect.to",
    "synology.me", "myqnapcloud.com", "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "dynv6.net", "cloud-ip.cc",
    "regruhosting.ru", "hostingerapp.com",
)
# cPanel/mail hostnames: mail.x.com is x.com seen through the mail server; checked once as x.com.
SERVICE_PREFIXES = (
    "cpanel.", "webmail.", "webdisk.", "whm.", "autodiscover.", "autoconfig.", "cpcalendars.", "cpcontacts.",
    "mail.", "pop.", "smtp.", "imap.", "mx.", "ftp.", "ns1.", "ns2.",
)
MULTI_SUFFIXES = {
    "com.ua", "in.ua", "kiev.ua", "kyiv.ua", "org.ua", "net.ua", "pp.ua", "co.ua", "biz.ua", "gov.ua", "edu.ua",
    "if.ua", "lviv.ua", "od.ua", "dp.ua", "kh.ua", "zp.ua", "te.ua", "lg.ua", "co.uk", "org.uk", "com.pl", "com.tr",
    "com.br", "com.au", "co.za", "my.id", "co.id", "web.id", "com.ru", "msk.ru", "spb.ru",
}
# Categories worth a person's time: shown in detail in summary.md, everything else only counted.
ACTIONABLE = ["ймовірний клон", "клон лише для відвідувачів з реклами", "згадує бренд — перевірити вручну",
              "домен активний, сайт вимкнений"]
LISTED = ["ймовірно домен бренду", "перенаправляє на офіційний сайт"]
MATCH_ORDER = {"точна назва": 0, "окремим словом": 1, "злитно з іншим словом": 2, "схоже написання": 3,
               "всередині іншого слова": 4}


# ---------- candidates ----------

def typo_variants(name):
    out = set()
    n = len(name)
    for i in range(n):
        out.add(name[:i] + name[i + 1:])                      # omission
        out.add(name[:i] + name[i] + name[i:])                # repetition
        if i < n - 1:
            out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])   # transposition
        for k in KEYBOARD.get(name[i], ""):
            out.add(name[:i] + k + name[i + 1:])              # adjacent key
        if name[i] in "aeiouy":
            for v in "aeiouy":
                out.add(name[:i] + v + name[i + 1:])          # vowel swap
    out.discard(name)
    return {v for v in out if len(v) >= 4}


def transliterations(name):
    """Common alternative spellings of Ukrainian names. Tuned for -ovska/-ivska style brand names."""
    out = set()
    swaps = [("ch", "tch"), ("ch", "cz"), ("ch", "h"), ("v", "w"), ("ska", "skaya"), ("ska", "skaia"),
             ("ska", "skaja"), ("ska", "skiy"), ("o", "a"), ("k", "c"), ("y", "i")]
    singles = {name.replace(a, b) for a, b in swaps if a in name}
    out |= singles
    # two swaps at once: kachorovska -> kaczorowska (Polish spelling), katchorowska...
    for v in list(singles):
        for a, b in swaps:
            if a in v:
                out.add(v.replace(a, b))
    out.discard(name)
    return out


def homoglyph_variants(name):
    out = set()
    for i, ch in enumerate(name):
        if ch in HOMOGLYPHS:
            out.add(name[:i] + HOMOGLYPHS[ch] + name[i + 1:])
    return out


def affix_variants(name):
    out = set()
    for a in AFFIXES:
        out |= {f"{name}-{a}", f"{a}-{name}", f"{name}{a}", f"{a}{name}"}
    return out


def build_candidates(name, official):
    cands = {}

    def add(domain, source):
        if domain not in official and domain not in cands:
            cands[domain] = source

    for tld in TLDS:
        add(f"{name}.{tld}", "та сама назва, інша зона")
    for v in sorted(typo_variants(name) | transliterations(name)):
        for tld in HOT_TLDS:
            add(f"{v}.{tld}", "помилка/транслітерація назви")
    for v in sorted(affix_variants(name)):
        for tld in HOT_TLDS:
            add(f"{v}.{tld}", "назва з приставкою")
    for v in sorted(homoglyph_variants(name)):
        for tld in IDN_TLDS:
            add(f"{v}.{tld}", "кирилиця замість латиниці")
    return cands


# ---------- certificate transparency ----------

def crtsh_json(query, attempts=3):
    """crt.sh web API. Returns (rows or None, note). crt.sh answers an empty body when its query times out."""
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": query, "output": "json"})
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = resp.read().decode("utf-8", errors="replace").strip()
            if body:
                rows = json.loads(body)
                return rows, f"crt.sh API «{query}»: {len(rows)} записів"
            last = "порожня відповідь"
        except Exception as e:  # noqa: BLE001 - crt.sh is often slow, retry
            last = e
        time.sleep(10 * (i + 1))
    return None, f"crt.sh API «{query}»: не відповів ({last})"


# crt.sh also exposes its database read-only (guest, no password). Full-text search over certificate names
# is what its web form does too, but here it is not cut off by the web timeout.
CT_SQL = [
    "SELECT lower(cai.name_value), min(x509_notBefore(cai.certificate))::date FROM certificate_and_identities cai "
    "WHERE to_tsquery('certwatch', '{name}:*') @@ identities(cai.certificate) AND cai.name_value ILIKE '%{name}%' "
    "GROUP BY 1",
    "SELECT lower(cai.name_value), min(x509_notBefore(cai.certificate))::date FROM certificate_and_identities cai "
    "WHERE plainto_tsquery('certwatch', '{name}') @@ identities(cai.certificate) AND cai.name_value ILIKE '%{name}%' "
    "GROUP BY 1",
]


def crtsh_sql(name):
    """Returns ({host: first_date} or None, note)."""
    if not shutil.which("psql"):
        return None, "crt.sh SQL: немає psql (встановлюється з setup.sh)"
    notes = []
    for i, sql in enumerate(CT_SQL, 1):
        for attempt in range(2):  # the replica cancels long queries during recovery: retry once
            try:
                out = subprocess.run(
                    ["psql", "-h", "crt.sh", "-p", "5432", "-U", "guest", "-d", "certwatch", "-w", "-A", "-t", "-F", "\t",
                     "-v", "ON_ERROR_STOP=1", "-c", sql.format(name=name)],
                    capture_output=True, text=True, timeout=300, env={**os.environ, "PGCONNECT_TIMEOUT": "30"})
            except subprocess.TimeoutExpired:
                notes.append(f"запит {i}: тайм-аут")
                break
            if out.returncode == 0:
                found = {}
                for line in out.stdout.splitlines():
                    host, _, when = line.partition("\t")
                    host = host.strip().lstrip("*.").strip(".")
                    if host and name in host and " " not in host and "@" not in host:
                        if host not in found or (when and when < found[host]):
                            found[host] = when.strip()
                return found, f"crt.sh SQL (запит {i}): {len(found)} імен"
            err = ((out.stderr or "").strip().splitlines() or [f"код {out.returncode}"])[-1]
            notes.append(f"запит {i}: {err}")
            if "could not translate host" in err or "connection" in err.lower():
                return None, "crt.sh SQL: " + "; ".join(notes)  # no database at all: other queries won't help
            time.sleep(5)
    return None, "crt.sh SQL: " + "; ".join(str(n) for n in notes)


def ct_domains(entries, name):
    """{hostname: first not_before} from crt.sh rows."""
    seen = {}
    for e in entries or []:
        names = set((e.get("name_value") or "").lower().split("\n")) | {(e.get("common_name") or "").lower()}
        when = (e.get("not_before") or "")[:10]
        for host in names:
            host = host.strip().lstrip("*.").strip(".")
            if not host or name not in host or " " in host or "@" in host:
                continue
            if host not in seen or (when and when < seen[host]):
                seen[host] = when
    return seen


def merge_ct(into, found):
    for host, when in found.items():
        if host not in into or (when and (not into[host] or when < into[host])):
            into[host] = when


def collect_ct(name, official):
    """All certificate names containing the brand, from every source that answers.
    A result without the brand's own site is incomplete (the official site surely has certificates)."""
    ct, notes = {}, []
    for query in (f"%{name}%", name):
        rows, note = crtsh_json(query)
        notes.append(note)
        if rows:
            merge_ct(ct, ct_domains(rows, name))
        if any(registrable(h) in official for h in ct):
            break
    if not any(registrable(h) in official for h in ct):
        found, note = crtsh_sql(name)
        notes.append(note)
        if found:
            merge_ct(ct, found)
    complete = any(registrable(h) in official for h in ct)
    return ct, notes, complete


# ---------- dns ----------

def resolve(host):
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, UnicodeError, OSError):
        return []


# ---------- service ----------

def load_key():
    key = os.environ.get("RENDER_API_KEY")
    if key:
        return key.strip()
    try:
        with open(os.path.join(HERE, "..", ".env"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("RENDER_API_KEY="):
                    return line.split("=", 1)[1].strip()
    except PermissionError:
        sys.exit("Немає доступу до .env — запусти через sudo")
    except FileNotFoundError:
        pass
    sys.exit("Не знайшов RENDER_API_KEY")


def post(path, payload, key, timeout=240):
    url = API.rsplit("/", 1)[0] + path
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "X-Api-Key": key})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 503 and attempt < 2:
                time.sleep(5)
                continue
            return {"verdict": "error", "error": f"http_{e.code}"}
        except Exception as e:  # noqa: BLE001
            return {"verdict": "error", "error": f"client_error: {e}"}
    return {"verdict": "error", "error": "busy"}


AD_REFERER = "https://l.facebook.com/"


def ad_query():
    """What a click on a Facebook/Instagram ad appends to the shop URL."""
    fbclid = "IwAR" + base64.urlsafe_b64encode(os.urandom(45)).decode().rstrip("=")
    return f"?utm_source=facebook&utm_medium=paid&utm_campaign=sale&fbclid={fbclid}"


def check(domain, key, ad_visit=False):
    # llmPool=audit: a separate daily LLM quota, so a big audit never starves ordinary checks.
    payload = {"mobile": True, "followCta": True, "useLlm": True, "passWarning": True, "llmPool": "audit"}
    if ad_visit:
        # The model reads utm/fbclid as a sign of a paid lure and over-flags; the ad visit is only compared.
        payload.update(referer=AD_REFERER, useLlm=False)
    suffix = ad_query() if ad_visit else ""
    res = post("/check", {**payload, "url": f"https://{domain}/{suffix}"}, key)
    render = res.get("render") or {}
    err = render.get("error") or ""
    if res.get("verdict") == "unreachable" and err.startswith("net::ERR_") and "NAME_NOT_RESOLVED" not in err:
        retry = post("/check", {**payload, "url": f"http://{domain}/{suffix}"}, key)
        if retry.get("verdict") not in ("unreachable", "error"):
            return retry
    return res


def shows_other_page(plain, ad, brand_word):
    """True when the ad visitor gets a different site than a plain visitor (cloaking)."""
    a, b = plain.get("render") or {}, ad.get("render") or {}
    if (ad.get("verdict") in ("unreachable", "error")) or (plain.get("verdict") in ("unreachable", "error")):
        return plain.get("verdict") != ad.get("verdict")
    if host_of(a.get("finalUrl") or "") != host_of(b.get("finalUrl") or ""):
        return True
    text_a, text_b = (a.get("text") or "").lower(), (b.get("text") or "").lower()
    if (brand_word in text_b) != (brand_word in text_a):
        return True
    norm = lambda t: re.sub(r"\W+", " ", (t or "").lower()).strip()  # noqa: E731
    if norm(a.get("title")) != norm(b.get("title")):
        return True
    return difflib.SequenceMatcher(None, text_a[:2000], text_b[:2000]).ratio() < 0.4


# ---------- registrar (for takedown requests) ----------

def _vcard(entity, field):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return str(item[3])
    return ""


_RDAP_CACHE = {}
_RDAP_LOCK = threading.Lock()


def rdap_info(domain):
    """Registrar, abuse e-mail and name servers from RDAP (rdap.org redirects to the zone's registry).
    Cached per registrable domain: z.bukovel.net and torba.bukovel.net are one lookup."""
    reg = registrable(domain)
    with _RDAP_LOCK:
        if reg in _RDAP_CACHE:
            return _RDAP_CACHE[reg]
    info = {"registrar": "", "abuse": "", "ns": set()}
    try:
        req = urllib.request.Request("https://rdap.org/domain/" + urllib.parse.quote(reg),
                                     headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        for ent in data.get("entities") or []:
            if "registrar" not in (ent.get("roles") or []):
                continue
            info["registrar"] = _vcard(ent, "fn") or info["registrar"]
            for sub in ent.get("entities") or []:
                if "abuse" in (sub.get("roles") or []):
                    info["abuse"] = _vcard(sub, "email") or info["abuse"]
        info["ns"] = {str(n.get("ldhName") or "").lower().rstrip(".") for n in data.get("nameservers") or []} - {""}
    except Exception:  # noqa: BLE001 - best effort, the report says "unknown"
        pass
    with _RDAP_LOCK:
        _RDAP_CACHE[reg] = info
    return info


def registrar_key(name):
    """'Internet Invest, Ltd. dba Imena.ua' and 'Internet Invest LLC' are the same registrar."""
    return " ".join(re.findall(r"[a-z0-9]+", (name or "").lower())[:2])


def likely_brand_owned(host, name, info, age_days, official_infos):
    """The brand's own spare domain (bukovel.net, moneyveo.com.ua), not a clone: exactly the brand name in another
    zone AND the same DNS servers as the official site, or the same registrar for over two years.
    A fresh look-alike shares neither."""
    if site_label(host) != name:
        return False
    for off in official_infos:
        if info["ns"] and info["ns"] & off["ns"]:
            return True
        if (age_days or 0) > 730 and info["registrar"] and registrar_key(info["registrar"]) == registrar_key(off["registrar"]):
            return True
    return False


# ---------- classification ----------

def registrable(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def site_label(host):
    """bukovel.com.ua -> bukovel; z.bukovel.net -> bukovel."""
    return registrable(host).split(".")[0]


def service_host(host):
    return any(host == s or host.endswith("." + s) for s in SERVICE_SUFFIXES)


def strip_service_prefix(host):
    for p in SERVICE_PREFIXES:
        if host.startswith(p) and host.count(".") >= 2:
            return host[len(p):]
    return host


def name_match(host, name):
    """How the brand name sits in the domain. Bukovel is a place and Karabas a common word: karabash.ru or
    karabasakhome.com contain the letters but not the brand, and must not crowd out real look-alikes."""
    labels = registrable(host).split(".")[:1] + host[:-len(registrable(host))].strip(".").split(".")
    labels = [lab for lab in labels if lab]
    best = "схоже написання"
    for lab in labels:
        if name not in lab:
            continue
        if lab == name:
            return "точна назва"
        i = lab.find(name)
        before, after = lab[:i], lab[i + len(name):]
        rest = (before + after).strip("-")
        bounded = (not before or before.endswith("-") or before[-1].isdigit()) and \
                  (not after or after.startswith("-") or after[0].isdigit())
        if bounded or rest in AFFIXES:
            found = "окремим словом"
        elif (not before or not after) and len(rest) >= 3:
            found = "злитно з іншим словом"
        else:
            found = "всередині іншого слова"
        if MATCH_ORDER[found] < MATCH_ORDER[best] or best == "схоже написання":
            best = found
    return best


def host_of(url):
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def classify(res, official, brand_word, owned=False, match="точна назва"):
    render = res.get("render") or {}
    verdict = res.get("verdict", "error")
    final_host = host_of(render.get("finalUrl") or "")
    text = f"{render.get('title') or ''} {render.get('text') or ''}".lower()
    llm = res.get("llm") or {}
    if verdict in ("unreachable", "error"):
        return "неактивний"
    if final_host and registrable(final_host) in official:
        return "перенаправляє на офіційний сайт"
    if any(m in text for m in PARKED_MARKERS):
        return "припаркований або продається"
    if "dns resolution error" in text or "error 1001" in text:
        return "домен активний, сайт вимкнений"  # still pointed at Cloudflare: the clone can return any minute
    if owned:
        return "ймовірно домен бренду"
    in_title = brand_word in (render.get("title") or "").lower()
    imitates = brand_word in text or (llm.get("isPhishing") and brand_word in (llm.get("brand") or "").lower())
    if llm and not llm.get("error"):
        # The model saw the page: trust it over the letters in the domain name.
        sure = llm.get("isPhishing") and (llm.get("confidence") or 0) >= 0.75
        if sure and imitates:
            return "ймовірний клон"
        if (llm.get("isPhishing") or verdict == "phishing") and imitates:
            return "згадує бренд — перевірити вручну"
        return "сторонній сайт"
    # Rules only (LLM off or out of quota): a clone needs a "phishing" verdict, not just the name in the domain.
    if verdict == "phishing" and imitates:
        return "ймовірний клон"
    if imitates and (in_title or MATCH_ORDER.get(match, 9) <= 1):
        return "згадує бренд — перевірити вручну"
    return "сторонній сайт"


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand", required=True, help="латинська назва бренду, як у домені: kachorovska")
    ap.add_argument("--official", required=True, nargs="+", help="офіційні домени бренду")
    ap.add_argument("--out", default="audit_out")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--extra", nargs="*", default=[], help="домени з інших джерел (новини, скарги клієнтів)")
    args = ap.parse_args()

    name = args.brand.lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", name):
        sys.exit("--brand: лише латиниця, цифри й дефіс, як у домені")
    official = {d.lower() for d in args.official}
    os.makedirs(args.out, exist_ok=True)
    key = load_key()
    t0 = time.time()

    print("==> Журнал SSL-сертифікатів (crt.sh)", flush=True)
    ct, ct_notes, ct_complete = collect_ct(name, official)
    for note in ct_notes:
        print(f"    {note}", flush=True)
    print(f"    знайдено імен у сертифікатах: {len(ct)}" + ("" if ct_complete else " (неповно: немає навіть офіційного сайту)"),
          flush=True)

    print("==> Перебір схожих назв", flush=True)
    cands = build_candidates(name, official)
    for host, when in ct.items():
        if registrable(host) not in official:
            cands.setdefault(host, f"журнал сертифікатів (перший сертифікат {when})")
    for host in args.extra:
        host = host.lower().strip().replace("[.]", ".")
        if host:
            cands[host] = "з публікацій / скарг"
    services = sorted(h for h in cands if service_host(h))
    for h in services:
        cands.pop(h)
    for h in list(cands):
        parent = strip_service_prefix(h)
        if parent != h:
            cands.setdefault(parent, cands.pop(h))
    print(f"    кандидатів для перевірки DNS: {len(cands)} (службових адрес пропущено: {len(services)})", flush=True)

    print("==> DNS: які з них існують", flush=True)
    hosts = list(cands)
    with ThreadPoolExecutor(max_workers=64) as pool:
        ips = dict(zip(hosts, pool.map(resolve, hosts)))
    live = [h for h in hosts if ips[h]]
    # www.x.top and x.top are the same site: render once
    live = [h for h in live if not (h.startswith("www.") and h[4:] in ips and ips[h[4:]])]
    print(f"    живих доменів: {len(live)}", flush=True)

    with open(os.path.join(args.out, "ct_history.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "first_certificate", "resolves_now"])
        for host, when in sorted(ct.items(), key=lambda kv: kv[1] or "", reverse=True):
            if service_host(host) or strip_service_prefix(host) != host:
                continue  # proxies, routers, cpanel./mail. twins: no news for the monitor
            state = "офіційний" if registrable(host) in official else ("так" if ips.get(host) else "ні")
            w.writerow([host, when, state])

    print("==> Офіційний сайт для порівняння", flush=True)
    off = post("/render", {"url": f"https://{sorted(official)[0]}", "mobile": True}, key)
    if off.get("screenshotJpeg"):
        with open(os.path.join(args.out, "official.jpg"), "wb") as f:
            f.write(base64.b64decode(off["screenshotJpeg"]))

    official_infos = [rdap_info(d) for d in sorted(official)]
    for d, info in zip(sorted(official), official_infos):
        print(f"    {d}: реєстратор {info['registrar'] or '?'}, DNS {', '.join(sorted(info['ns'])) or '?'}", flush=True)

    print(f"==> Рендер і вердикт для {len(live)} живих доменів (звичайний візит і візит «з реклами»)", flush=True)
    rows = []

    def save_shots(res, n, tag):
        render = res.get("render") or {}
        shot = render.pop("screenshotJpeg", None)
        if shot:
            with open(os.path.join(args.out, f"{n}{tag}.jpg"), "wb") as f:
                f.write(base64.b64decode(shot))
        cta = render.get("ctaStep") or {}
        cta_shot = cta.pop("screenshotJpeg", None)
        if cta_shot:
            with open(os.path.join(args.out, f"{n}{tag}-cta.jpg"), "wb") as f:
                f.write(base64.b64decode(cta_shot))
        with open(os.path.join(args.out, f"{n}{tag}.json"), "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)

    def needs_ad_visit(plain, category):
        """Cloaking fake shops live on fresh domains. An old site (a hotel in Bukovel, a blog) or a page that
        already shows the clone gains nothing from a second visit, and a popular brand has hundreds of those."""
        if category in ("перенаправляє на офіційний сайт", "ймовірний клон", "неактивний", "ймовірно домен бренду"):
            return False
        age = (plain.get("domainAge") or {}).get("ageDays")
        return age is None or age < 365

    def work(item):
        n, host = item
        plain = check(host, key)
        info = rdap_info(host)
        age = plain.get("domainAge") or {}
        aged = age.get("domain") or ""
        age_days = age.get("ageDays") if aged and (host == aged or host.endswith("." + aged)) else None
        match = name_match(host, name)
        owned = likely_brand_owned(host, name, info, age_days, official_infos)
        category = classify(plain, official, name, owned, match)
        ad = check(host, key, ad_visit=True) if needs_ad_visit(plain, category) else None
        return n, host, plain, ad, info, owned, match, category

    def llm_text(res):
        llm = res.get("llm") or {}
        return "" if not llm else (llm.get("error") or f"{llm.get('isPhishing')}/{llm.get('confidence', 0):.2f}: {llm.get('reason') or ''}")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for n, host, res, ad, info, owned, match, category in pool.map(work, enumerate(live, 1)):
            save_shots(res, n, "")
            cloaked = False
            ad_category = ""
            if ad is not None:
                save_shots(ad, n, "-ad")
                ad_category = classify(ad, official, name, owned, match)
                cloaked = shows_other_page(res, ad, name)
                if cloaked and ad_category == "ймовірний клон" and category != "ймовірний клон":
                    category = "клон лише для відвідувачів з реклами"
            render = res.get("render") or {}
            ad_render = (ad or {}).get("render") or {}
            cta = render.get("ctaStep") or {}
            age = res.get("domainAge") or {}
            registrar, abuse = info["registrar"], info["abuse"]
            rows.append({
                "n": n, "domain": host, "name_match": match,
                "source": cands[host], "first_certificate": ct.get(host) or ct.get("www." + host, ""),
                "ips": " ".join(ips[host][:3]),
                "category": category, "verdict": res.get("verdict", "error"), "score": res.get("score", ""),
                "final_url": render.get("finalUrl") or "", "title": (render.get("title") or "")[:120],
                "passed_warning": render.get("passedWarning") or "",
                "has_card": render.get("hasCardInput"), "has_password": render.get("hasPasswordInput"),
                "cta": cta.get("clickedText") or "", "domain_age_days": age.get("ageDays", ""),
                "registered": (age.get("registered") or "")[:10],
                "registrar": registrar, "abuse_email": abuse,
                "llm": llm_text(res),
                "reasons": " | ".join(res.get("reasons") or []) or res.get("error", ""),
                "ad_visit_differs": "так" if cloaked else ("ні" if ad is not None else ""),
                "ad_visit_category": ad_category,
                "ad_visit_verdict": "" if ad is None else f"{ad.get('verdict', 'error')} {ad.get('score', '')}",
                "ad_visit_title": (ad_render.get("title") or "")[:120],
                "ad_visit_llm": "" if ad is None else llm_text(ad),
            })
            note = " | з реклами: інший вміст" if cloaked else ""
            print(f"    [{n}/{len(live)}] {host:<40} {category:<34} {res.get('verdict', 'error')}{note}", flush=True)

    rows.sort(key=lambda r: r["n"])
    fields = ["n", "domain", "name_match", "source", "first_certificate", "ips", "category", "verdict", "score", "final_url", "title",
              "passed_warning", "has_card", "has_password", "cta", "domain_age_days", "registered", "registrar", "abuse_email",
              "llm", "reasons",
              "ad_visit_differs", "ad_visit_category", "ad_visit_verdict", "ad_visit_title", "ad_visit_llm"]
    with open(os.path.join(args.out, "candidates.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    llm_seen = sum(1 for r in rows if r["llm"].startswith(("True/", "False/")))
    llm_failed = sum(1 for r in rows if r["llm"] and not r["llm"].startswith(("True/", "False/")))
    lines = [f"# Аудит клонів: {name}", "",
             f"- Офіційні домени: {', '.join(sorted(official))}",
             f"- Імен у журналі сертифікатів: {len(ct)}" + ("" if ct_complete else " (неповно: crt.sh не віддав навіть офіційний сайт)"),
             *[f"  - {note}" for note in ct_notes],
             f"- Перевірено варіантів назви: {len(cands)}, живих: {len(live)}",
             f"- Службових адрес пропущено (проксі, роутери, панелі хостингу): {len(services)}",
             f"- LLM переглянула сторінок: {llm_seen}" + (f"; недоступна для {llm_failed} — там вердикт лише правил" if llm_failed else ""),
             f"- Тривалість: {(time.time() - t0) / 60:.1f} хв", "", "| Категорія | Доменів |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]

    def ranked(category):
        return sorted((r for r in rows if r["category"] == category),
                      key=lambda r: (MATCH_ORDER.get(r["name_match"], 9), -int(r["score"] or 0)))

    for category in ACTIONABLE:
        found = ranked(category)
        if not found:
            continue
        lines += ["", f"## {category[0].upper() + category[1:]} ({len(found)})", ""]
        for r in found:
            lines.append(f"- **{r['n']}. {r['domain']}** ({r['name_match']}; {r['verdict']}, {r['score']}; "
                         f"вік {r['domain_age_days'] or '?'} дн.) — {r['source']}")
            lines.append(f"  - {r['title']} → {r['final_url']}")
            if r["registrar"] or r["abuse_email"]:
                lines.append(f"  - Реєстратор: {r['registrar'] or 'невідомо'}; скарги: {r['abuse_email'] or 'невідомо'}")
            if r["passed_warning"]:
                lines.append(f"  - Cloudflare показував «{r['passed_warning']}»; скриншот — сторінка за попередженням")
            lines.append(f"  - {r['reasons'][:600]}")
            if r["ad_visit_differs"] == "так":
                lines.append(f"  - Візит «з реклами» показує інше: {r['ad_visit_title']} ({r['ad_visit_category']}, {r['ad_visit_verdict']})")
    for category in LISTED:
        found = ranked(category)
        if found:
            lines += ["", f"## {category[0].upper() + category[1:]} ({len(found)})", "",
                      ", ".join(r["domain"] for r in found)]
    lines += ["", "Решта категорій — лише в candidates.csv."]
    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines[:16]))


if __name__ == "__main__":
    main()
