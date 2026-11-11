#!/usr/bin/env python3
"""Свіжі живі фішингові адреси з публічного фіду phishunt.io (CC0) -> CSV для evaluate.py.

    python3 tools/fetch_feed.py testdata/live_feed.csv [кількість=40] [--all]

Бере найновіші записи, не більше одного на зареєстрований домен, і знешкоджує адреси ([.] і hxxp).
Домени, які вже потрапляли в попередні оцінки, пропускає (список у testdata/feed_seen.txt):
так кожен прогін перевіряє детектор на адресах, під які правила ще не підлаштовували.
--all вимикає цей фільтр.

Фід не ідеальний (сам phishunt пише, що впевненість не 100%), тож мітки трохи шумні.
"""
import csv
import json
import os
import sys
import urllib.request
from urllib.parse import urlsplit

FEEDS = ["https://phishunt.io/feed.json", "https://phishunt.io/feed.txt"]
UA = "phish-render-eval/1.0"
TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testdata")
SEEN = os.path.join(TESTDATA, "feed_seen.txt")            # grows on the server with every run
SEED = os.path.join(TESTDATA, "feed_seen_seed.txt")       # shipped with the code: domains already used for tuning
# Shared platforms: every customer gets a subdomain, so they are deduplicated by full host, not by domain.
SHARED = {"blogspot.com", "pages.dev", "vercel.app", "weebly.com", "workers.dev", "netlify.app", "github.io", "web.app",
          "firebaseapp.com", "yolasite.com", "webflow.io", "wixsite.com", "r2.dev", "glitch.me", "herokuapp.com",
          "onrender.com", "wordpress.com", "godaddysites.com", "square.site", "ucraft.site", "tilda.ws", "carrd.co",
          "framer.app", "notion.site", "replit.app", "surge.sh", "ngrok-free.app", "trycloudflare.com", "gitlab.io",
          "000webhostapp.com", "jimdosite.com", "site123.me", "mystrikingly.com", "webnode.page", "myshopify.com"}
MULTI = {"com.ua", "org.ua", "net.ua", "gov.ua", "in.ua", "kiev.ua", "co.uk", "org.uk", "com.pl", "com.br", "com.au",
         "co.za", "co.jp", "com.tr", "com.cn", "com.mx", "co.in", "com.ar"}
GENERIC_SLD = {"com", "net", "org", "co", "gov", "edu", "ac", "or", "ne", "go", "mil", "biz", "info"}


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_json(text):
    data = json.loads(text)
    if isinstance(data, dict):
        lists = [v for v in data.values() if isinstance(v, list)]
        data = lists[0] if lists else []
    items = []
    for row in data:
        if isinstance(row, str):
            items.append({"url": row})
        elif isinstance(row, dict) and (row.get("url") or row.get("domain")):
            items.append(row)
    return items


def parse_txt(text):
    return [{"url": line.strip()} for line in text.splitlines() if line.strip() and not line.startswith("#")]


def registrable(host):
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = parts[-2] + "." + parts[-1]
    if last_two in MULTI or (len(parts[-1]) == 2 and parts[-2] in GENERIC_SLD):
        return ".".join(parts[-3:])
    return last_two


def dedupe_key(host):
    domain = registrable(host)
    return host.lower() if domain in SHARED else domain


def defang(url):
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    scheme = parts.scheme.replace("http", "hxxp", 1)
    host = parts.netloc.replace(".", "[.]")
    rest = parts.path + (("?" + parts.query) if parts.query else "")
    return f"{scheme}://{host}{rest}"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    use_seen = "--all" not in sys.argv
    out = args[0] if args else "testdata/live_feed.csv"
    limit = int(args[1]) if len(args) > 1 else 40

    seen = set()
    if use_seen:
        for path in (SEED, SEEN):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    seen |= {line.strip() for line in f if line.strip() and not line.startswith("#")}

    items, source = [], None
    for feed in FEEDS:
        try:
            text = download(feed)
            items = parse_json(text) if feed.endswith(".json") else parse_txt(text)
            if items:
                source = feed
                break
        except Exception as e:  # noqa: BLE001 - try the next format
            print(f"{feed}: {e}", file=sys.stderr)
    if not items:
        sys.exit("Не вдалося завантажити фід phishunt.io")

    def first_seen(row):
        return row.get("first_seen") or row.get("date") or ""

    items.sort(key=first_seen, reverse=True)
    rows, used, skipped = [], set(), 0
    for row in items:
        url = (row.get("url") or row.get("domain") or "").strip()
        if not url:
            continue
        host = urlsplit(url if "://" in url else "https://" + url).hostname or ""
        domain = dedupe_key(host) if host else ""
        if not domain or domain in used:
            continue
        if domain in seen:
            skipped += 1
            continue
        used.add(domain)
        rows.append({
            "id": f"F{len(rows) + 1}",
            "label": "phishing",
            "url_defanged": defang(url),
            "impersonates": row.get("company", ""),
            "feature": "",
            "year": first_seen(row)[:10],
            "source": "phishunt.io",
        })
        if len(rows) >= limit:
            break

    with open(out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "label", "url_defanged", "impersonates", "feature", "year", "source"])
        writer.writeheader()
        writer.writerows(rows)
    if use_seen:
        with open(SEEN, "a", encoding="utf-8") as f:
            for domain in sorted(used):
                f.write(domain + "\n")
    print(f"{len(rows)} свіжих адрес з {source} -> {out} (пропущено вже бачених доменів: {skipped})")


if __name__ == "__main__":
    main()
