#!/usr/bin/env python3
"""Моніторинг клонів бренду: аудит, порівняння з попереднім прогоном, сповіщення в Telegram.

    sudo python3 tools/monitor.py --brand kachorovska              # прогін і сповіщення
    sudo python3 tools/monitor.py --brand kachorovska --dry-run    # показати повідомлення, нічого не надсилати
    sudo python3 tools/monitor.py --brand kachorovska --from-dir audit_out --dry-run   # без нового аудиту
    printf '%s\\n' "$TOKEN" | sudo python3 tools/monitor.py --telegram-setup        # підключити бота
    sudo python3 tools/monitor.py --telegram-test

Файли (усе в monitor/ поруч із tools/):
  <brand>.json            налаштування бренду: офіційні домени, відомі безпечні, чати клієнта
  telegram.env            токен бота й чат адміністратора (chmod 600, не потрапляє в архів і контейнер)
  state/<brand>.json      що було живим учора: з цим порівнюється кожен прогін
  state/<brand>-events.jsonl  журнал усіх подій (для місячного звіту)
  runs/<brand>/<дата>/    повні результати аудиту, зберігаються останні 30

Що вважається подією:
  новий живий домен · домен став клоном · змінився вміст сторінки · новий SSL-сертифікат на домен
  з назвою бренду (сайт ще не відповідає) · домен не відповідає два прогони поспіль.
Перший прогін лише запам'ятовує стан і надсилає зведення.

Лише стандартна бібліотека Python.
"""
import argparse
import csv
import datetime as dt
import fcntl
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MON = os.path.join(ROOT, "monitor")
STATE_DIR = os.path.join(MON, "state")
RUNS_DIR = os.path.join(MON, "runs")
TG_ENV = os.path.join(MON, "telegram.env")
HEALTH_URL = os.environ.get("HEALTH_URL", "http://127.0.0.1:8080/health")
KEEP_RUNS = 30
AUDIT_TIMEOUT_S = 40 * 60

CLONE = {"ймовірний клон", "клон лише для відвідувачів з реклами"}
DORMANT = {"домен активний, сайт вимкнений", "неактивний", "припаркований або продається"}
OFFICIAL_REDIRECT = "перенаправляє на офіційний сайт"

TITLES = {
    "new_live": "новий живий домен",
    "became_clone": "домен став клоном",
    "content_changed": "змінився вміст",
    "new_cert": "новий сертифікат",
    "went_down": "домен більше не відповідає",
}

try:
    from zoneinfo import ZoneInfo
    KYIV = ZoneInfo("Europe/Kyiv")
except Exception:  # noqa: BLE001 - no tzdata: dates in UTC are still fine
    KYIV = dt.timezone.utc


# ---------- small helpers ----------

def now_kyiv():
    return dt.datetime.now(KYIV)


def esc(value):
    return html.escape(str(value or ""), quote=False)


def defang(domain):
    return domain.replace(".", "[.]")


_DOMAIN_RE = re.compile(r"(?<![@\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)


def defang_text(text):
    """Domains in free text become non-clickable (kachorovskaua[.]club); e-mail addresses stay as they are."""
    return _DOMAIN_RE.sub(lambda m: defang(m.group(1)), text or "")


def trunc(text, n):
    text = text or ""
    return text if len(text) <= n else text[: n - 1] + "…"


def norm_title(text):
    return re.sub(r"\W+", " ", (text or "").lower()).strip()


def matches(domain, names):
    return any(domain == n or domain.endswith("." + n) for n in names)


def read_env(path):
    values = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and key and not key.startswith("#"):
                    values[key] = value
    except FileNotFoundError:
        pass
    return values


# ---------- telegram ----------

def _multipart(fields, files):
    boundary = uuid.uuid4().hex
    out = bytearray()
    for key, value in fields.items():
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
    for key, (name, data, mime) in files.items():
        out += (f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"; filename="{name}"\r\n'
                f"Content-Type: {mime}\r\n\r\n").encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def tg_call(token, method, fields, files=None, attempts=4):
    """Never puts the token into an error message: the URL that contains it is not printed."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    last = "немає відповіді"
    for attempt in range(attempts):
        if files:
            body, ctype = _multipart(fields, files)
        else:
            body, ctype = urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            try:
                data = json.loads(e.read() or b"{}")
            except ValueError:
                data = {}
            last = f"HTTP {e.code}: {data.get('description', '')}"
            if e.code == 429:
                time.sleep(int((data.get("parameters") or {}).get("retry_after", 5)) + 1)
                continue
            if e.code < 500:
                break
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = type(e).__name__
        time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"Telegram {method}: {last}")


class Notifier:
    """Sends to Telegram, or prints when dry-run / not configured."""

    def __init__(self, dry_run):
        env = read_env(TG_ENV)
        self.token = env.get("TELEGRAM_BOT_TOKEN", "")
        self.admin = env.get("TELEGRAM_ADMIN_CHAT", "")
        self.dry_run = dry_run or not (self.token and self.admin)
        if not dry_run and self.dry_run:
            print("Telegram не підключено (bash monitor.sh telegram): повідомлення лише в консоль", flush=True)

    def send(self, chats, text, photo=None):
        for chat in [c for c in chats if c]:
            if self.dry_run:
                print(f"\n--- до чату {chat}{' (зі скриншотом ' + os.path.basename(photo) + ')' if photo else ''} ---")
                print(text)
                continue
            fields = {"chat_id": chat, "parse_mode": "HTML", "link_preview_options": json.dumps({"is_disabled": True})}
            try:
                if photo and os.path.exists(photo) and len(text) <= 1024:
                    with open(photo, "rb") as f:
                        data = f.read()
                    tg_call(self.token, "sendPhoto", {**fields, "caption": text},
                            files={"photo": (os.path.basename(photo), data, "image/jpeg")})
                else:
                    tg_call(self.token, "sendMessage", {**fields, "text": text})
            except RuntimeError as e:
                print(f"Не надіслав у чат {chat}: {e}", file=sys.stderr, flush=True)


def telegram_setup():
    token = sys.stdin.readline().strip()
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{30,}", token):
        sys.exit("Це не схоже на токен бота від @BotFather")
    try:
        me = tg_call(token, "getMe", {})["result"]
    except RuntimeError as e:
        sys.exit(f"Токен не спрацював ({e}). Перевір, що скопіював його повністю.")
    updates = tg_call(token, "getUpdates", {"limit": 100}).get("result") or []
    chat = None
    for upd in reversed(updates):
        msg = upd.get("message") or upd.get("my_chat_member") or {}
        if (msg.get("chat") or {}).get("type") == "private":
            chat = msg["chat"]
            break
    if chat is None:
        sys.exit(f"Бот @{me.get('username')} ще не бачив твого повідомлення. "
                 f"Відкрий його в Telegram, натисни Start і запусти команду ще раз.")
    os.makedirs(MON, exist_ok=True)
    fd = os.open(TG_ENV, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"TELEGRAM_BOT_TOKEN={token}\nTELEGRAM_ADMIN_CHAT={chat['id']}\n")
    os.chmod(TG_ENV, 0o600)
    tg_call(token, "sendMessage", {"chat_id": chat["id"],
                                   "text": "Моніторинг клонів підключено. Сюди надходитимуть зміни й щоденне зведення."})
    print(f"Готово: бот @{me.get('username')}, чат {chat.get('first_name') or chat['id']}. Тестове повідомлення надіслано.")


# ---------- audit ----------

def render_service_ok():
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=15) as resp:
            return json.load(resp).get("status") == "ok"
    except Exception:  # noqa: BLE001
        return False


def run_audit(cfg, run_dir):
    os.makedirs(os.path.dirname(run_dir), exist_ok=True)
    log = run_dir + ".log"
    cmd = [sys.executable, os.path.join(HERE, "brand_audit.py"), "--brand", cfg["brand"],
           "--official", *cfg["official"], "--out", run_dir]
    if cfg.get("extra"):
        cmd += ["--extra", *cfg["extra"]]
    with open(log, "w", encoding="utf-8") as f:
        proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=AUDIT_TIMEOUT_S, check=False)
    if proc.returncode != 0 or not os.path.exists(os.path.join(run_dir, "candidates.csv")):
        with open(log, encoding="utf-8", errors="replace") as f:
            tail = f.read().strip().splitlines()[-6:]
        raise RuntimeError("аудит завершився з помилкою:\n" + "\n".join(tail))
    os.replace(log, os.path.join(run_dir, "audit.log"))


def read_audit(run_dir):
    with open(os.path.join(run_dir, "candidates.csv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    certs = {}
    ct_path = os.path.join(run_dir, "ct_history.csv")
    if os.path.exists(ct_path):
        with open(ct_path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                host = r["domain"][4:] if r["domain"].startswith("www.") else r["domain"]
                when = r.get("first_certificate") or ""
                if host not in certs or (when and when < certs[host]):
                    certs[host] = when
    summary = ""
    if os.path.exists(os.path.join(run_dir, "summary.md")):
        with open(os.path.join(run_dir, "summary.md"), encoding="utf-8") as f:
            summary = f.read()
    ct = re.search(r"Імен у журналі сертифікатів: (\d+)", summary)
    ct_ok = bool(ct) and "неповно" not in summary
    ct_names = int(ct.group(1)) if ct else 0
    m = re.search(r"Перевірено варіантів назви: (\d+), живих: (\d+)", summary)
    checked = (int(m.group(1)), int(m.group(2))) if m else None
    return rows, certs, ct_ok, checked, ct_names


def snapshot(r):
    return {
        "category": r.get("category", ""), "verdict": r.get("verdict", ""), "score": r.get("score", ""),
        "title": r.get("title", ""), "final_url": r.get("final_url", ""), "registered": r.get("registered", ""),
        "registrar": r.get("registrar", ""), "abuse": r.get("abuse_email", ""), "n": r.get("n", ""),
        "reasons": r.get("reasons", ""), "missing": 0,
    }


# ---------- what changed ----------

def compute(cfg, prev, rows, certs, ct_ok):
    """Returns (events, new_state). prev is None on the first run: then no events, only a baseline."""
    official = cfg["official"]
    ignore = list((cfg.get("ignore") or {}).keys())

    def watched(domain, category):
        return not matches(domain, official) and not matches(domain, ignore) and category != OFFICIAL_REDIRECT

    cur = {r["domain"]: snapshot(r) for r in rows}
    prev_live = (prev or {}).get("live", {})
    events = []
    live = {}

    for d, s in cur.items():
        live[d] = s
        if prev is None or not watched(d, s["category"]):
            continue
        p = prev_live.get(d)
        if p is None:
            events.append({"kind": "new_live", "domain": d, "now": s})
        elif s["category"] in CLONE and p["category"] not in CLONE:
            events.append({"kind": "became_clone", "domain": d, "now": s, "was": p})
        elif not p.get("missing") and norm_title(s["title"]) != norm_title(p["title"]):
            events.append({"kind": "content_changed", "domain": d, "now": s, "was": p})

    for d, p in prev_live.items():
        if d in cur:
            continue
        missing = p.get("missing", 0) + 1
        if missing >= 2:
            if watched(d, p["category"]):
                events.append({"kind": "went_down", "domain": d, "was": p})
        else:
            live[d] = {**p, "missing": missing}  # one miss can be a network hiccup: wait for the second

    known_certs = dict((prev or {}).get("certs", {}))
    if ct_ok:
        if prev is not None:
            reported = {e["domain"] for e in events}
            for host, when in sorted(certs.items()):
                if host in known_certs or host in cur or host in reported or not watched(host, ""):
                    continue
                events.append({"kind": "new_cert", "domain": host, "first_cert": when})
        known_certs.update(certs)

    state = {"updated": now_kyiv().isoformat(timespec="seconds"), "live": live, "certs": known_certs}
    return events, state


# ---------- messages ----------

def event_text(cfg, ev):
    name = cfg.get("display_name") or cfg["brand"]
    lines = [f"<b>{esc(name)} · {TITLES[ev['kind']]}</b>", f"<code>{esc(defang(ev['domain']))}</code>"]
    if ev["kind"] == "new_cert":
        lines.append(f"Перший SSL-сертифікат: {esc(ev['first_cert'])}. Сайт поки не відповідає: домен, схоже, готують до запуску.")
        return "\n".join(lines)
    if ev["kind"] == "went_down":
        lines.append(f"Не відповідає два прогони поспіль. Останній стан: {esc(ev['was']['category'])}.")
        return "\n".join(lines)
    s = ev["now"]
    lines.append(f"Категорія: {esc(s['category'])} ({esc(s['verdict'])}, {esc(s['score'])})")
    if ev["kind"] == "content_changed":
        lines.append(f"Було: «{esc(defang_text(trunc(ev['was']['title'], 90)))}»")
    lines.append(f"Сторінка: «{esc(defang_text(trunc(s['title'], 120)))}»")
    registered = " · ".join(x for x in (s["registered"], s["registrar"]) if x)
    if registered:
        lines.append(f"Зареєстровано: {esc(registered)}")
    if s["abuse"]:
        lines.append(f"Скарги: {esc(s['abuse'])}")
    signs = [r for r in s["reasons"].split(" | ") if r and not r.startswith("LLM")]
    text = "\n".join(lines)
    for sign in signs[:3]:  # as many signs as fit into a photo caption (1024 characters)
        candidate = text + ("\nОзнаки: " if "Ознаки:" not in text else "; ") + esc(defang_text(trunc(sign, 160)))
        if len(candidate) > 1000:
            break
        text = candidate
    return text


def screenshot_for(run_dir, ev):
    s = ev.get("now")
    if not s or not s.get("n"):
        return None
    names = [f"{s['n']}-ad.jpg", f"{s['n']}.jpg"] if s["category"] == "клон лише для відвідувачів з реклами" \
        else [f"{s['n']}.jpg"]
    for name in names:
        path = os.path.join(run_dir, name)
        if os.path.exists(path):
            return path
    return None


def priority(category):
    if category in CLONE:
        return 0
    if category in DORMANT:
        return 2
    return 1


def digest_text(cfg, rows, checked, ct_ok, ct_names, events, baseline):
    name = cfg.get("display_name") or cfg["brand"]
    ignore = list((cfg.get("ignore") or {}).keys())
    watched = [r for r in rows if not matches(r["domain"], cfg["official"]) and not matches(r["domain"], ignore)
               and r.get("category") != OFFICIAL_REDIRECT]
    lines = [f"<b>{esc(name)} · {now_kyiv():%d.%m.%Y}</b>"]
    if checked:
        lines.append(f"Перевірено варіантів назви: {checked[0]}, живих доменів: {checked[1]}.")
    lines.append(f"Імен у журналі сертифікатів: {ct_names}." if ct_ok
                 else "Журнал сертифікатів сьогодні не відповів: перевірено лише варіанти назви.")
    if baseline:
        lines.append("Це перший знімок. Далі надходитимуть лише зміни.")
    else:
        lines.append("Змін за добу немає." if not events else f"Змін за добу: {len(events)}, деталі вище.")
    if watched:
        lines += ["", f"<b>Під наглядом ({len(watched)}):</b>"]
        for r in sorted(watched, key=lambda r: (priority(r.get("category", "")), r["domain"])):
            lines.append(f"• <code>{esc(defang(r['domain']))}</code> — {esc(r.get('category', ''))}")
    return "\n".join(lines)


# ---------- main ----------

def load_config(brand):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", brand):
        sys.exit("--brand: лише латиниця, цифри й дефіс")
    path = os.path.join(MON, f"{brand}.json")
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Немає налаштувань бренду: {path}")
    cfg.setdefault("brand", brand)
    cfg["official"] = [d.lower() for d in cfg.get("official") or []]
    if not cfg["official"]:
        sys.exit(f"{path}: порожній список official")
    return cfg


def prune_runs(brand_dir):
    runs = sorted(d for d in os.listdir(brand_dir) if os.path.isdir(os.path.join(brand_dir, d)))
    for old in runs[:-KEEP_RUNS]:
        shutil.rmtree(os.path.join(brand_dir, old), ignore_errors=True)


def monitor(args):
    cfg = load_config(args.brand)
    notifier = Notifier(args.dry_run)
    admin = [notifier.admin or "адмін"]
    clients = [str(c) for c in cfg.get("client_chats") or []]
    name = cfg.get("display_name") or cfg["brand"]

    if args.from_dir:
        run_dir = os.path.abspath(args.from_dir)
    else:
        if not render_service_ok():
            notifier.send(admin, f"<b>{esc(name)} · прогін не відбувся</b>\nСервіс рендеру не відповідає на /health.")
            sys.exit("Сервіс рендеру не відповідає")
        run_dir = os.path.join(RUNS_DIR, cfg["brand"], now_kyiv().strftime("%Y%m%d-%H%M"))
        print(f"==> Аудит {cfg['brand']} → {run_dir}", flush=True)
        try:
            run_audit(cfg, run_dir)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            notifier.send(admin, f"<b>{esc(name)} · прогін не вдався</b>\n<pre>{esc(defang_text(str(e))[-900:])}</pre>")
            sys.exit(f"Прогін не вдався: {e}")

    rows, certs, ct_ok, checked, ct_names = read_audit(run_dir)
    state_path = os.path.join(STATE_DIR, f"{cfg['brand']}.json")
    prev = None
    if os.path.exists(state_path):
        with open(state_path, encoding="utf-8") as f:
            prev = json.load(f)
    events, state = compute(cfg, prev, rows, certs, ct_ok)
    baseline = prev is None

    order = {"new_live": 0, "became_clone": 1, "content_changed": 2, "new_cert": 3, "went_down": 4}
    for ev in sorted(events, key=lambda e: order[e["kind"]]):
        notifier.send(admin + clients, event_text(cfg, ev), photo=screenshot_for(run_dir, ev))
    digest = digest_text(cfg, rows, checked, ct_ok, ct_names, events, baseline)
    notifier.send(admin + (clients if baseline or cfg.get("client_digest") else []), digest)
    print(f"==> Подій: {len(events)}" + (" (перший знімок)" if baseline else ""), flush=True)

    if args.dry_run:
        print("Пробний режим: стан не збережено")
        return
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = state_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, state_path)
    with open(os.path.join(STATE_DIR, f"{cfg['brand']}-events.jsonl"), "a", encoding="utf-8") as f:
        stamp = now_kyiv().isoformat(timespec="seconds")
        for ev in events:
            f.write(json.dumps({"time": stamp, "kind": ev["kind"], "domain": ev["domain"],
                                "category": (ev.get("now") or ev.get("was") or {}).get("category", ""),
                                "run": os.path.basename(run_dir)}, ensure_ascii=False) + "\n")
    if not args.from_dir:
        prune_runs(os.path.dirname(run_dir))


def main():
    ap = argparse.ArgumentParser(description="Моніторинг клонів бренду")
    ap.add_argument("--brand", help="бренд: monitor/<brand>.json")
    ap.add_argument("--dry-run", action="store_true", help="лише показати повідомлення, стан не зберігати")
    ap.add_argument("--from-dir", help="взяти готовий результат brand_audit.py замість нового прогону")
    ap.add_argument("--telegram-setup", action="store_true", help="токен бота з stdin, чат — з останнього повідомлення боту")
    ap.add_argument("--telegram-test", action="store_true", help="тестове повідомлення адміну")
    args = ap.parse_args()

    if args.telegram_setup:
        telegram_setup()
        return
    if args.telegram_test:
        Notifier(False).send([read_env(TG_ENV).get("TELEGRAM_ADMIN_CHAT", "")], "Тест: моніторинг клонів на зв'язку.")
        return
    if not args.brand:
        ap.error("потрібен --brand")

    os.makedirs(MON, exist_ok=True)
    with open(os.path.join(MON, ".lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.exit("Інший прогін моніторингу ще триває")
        monitor(args)


if __name__ == "__main__":
    main()
