#!/usr/bin/env python3
"""Проганяє CSV з адресами через сервіс рендеру.

Запуск на VPS (лише стандартна бібліотека Python, нічого ставити не треба):
    sudo python3 tools/batch_render.py testdata/phishing_test_set.csv [render_out]

CSV має містити колонку url_defanged (або url); id і label — необов'язкові.
Результат у render_out/: <id>.json, <id>.jpg і summary.csv з одним рядком на адресу.
"""
import base64
import csv
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("RENDER_URL", "http://127.0.0.1:8080/render")
HERE = os.path.dirname(os.path.abspath(__file__))

SUMMARY_FIELDS = [
    "id", "label", "url", "final_url", "http_status", "error",
    "has_password", "has_card", "forms", "redirects", "blocked", "title", "elapsed_ms",
]


def load_key():
    key = os.environ.get("RENDER_API_KEY")
    if key:
        return key.strip()
    env_path = os.path.join(HERE, "..", ".env")
    try:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("RENDER_API_KEY="):
                    return line.split("=", 1)[1].strip()
    except PermissionError:
        sys.exit("Немає доступу до .env — запусти через sudo")
    except FileNotFoundError:
        pass
    sys.exit("Не знайшов RENDER_API_KEY (ні в оточенні, ні в .env)")


def render(url, key, mobile=True, timeout=120):
    body = json.dumps({"url": url, "mobile": mobile}).encode("utf-8")
    req = urllib.request.Request(
        API,
        data=body,
        headers={"Content-Type": "application/json", "X-Api-Key": key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:200]
        return {"error": f"http_{e.code}: {detail}"}
    except Exception as e:  # network error, timeout, bad JSON
        return {"error": f"client_error: {e}"}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "testdata", "phishing_test_set.csv")
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "render_out"
    os.makedirs(out_dir, exist_ok=True)
    key = load_key()

    with open(src, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    summary = []
    for n, row in enumerate(rows, 1):
        url = (row.get("url_defanged") or row.get("url") or "").strip()
        if not url:
            continue
        rid = (row.get("id") or str(n)).strip()
        res = render(url, key)
        if str(res.get("error", "")).startswith("http_401"):
            sys.exit("Сервіс відповів 401: ключ не підходить. Перевір RENDER_API_KEY у .env")

        shot = res.pop("screenshotJpeg", None)
        if shot:
            with open(os.path.join(out_dir, f"{rid}.jpg"), "wb") as img:
                img.write(base64.b64decode(shot))
        with open(os.path.join(out_dir, f"{rid}.json"), "w", encoding="utf-8") as js:
            json.dump(res, js, ensure_ascii=False, indent=2)

        summary.append({
            "id": rid,
            "label": row.get("label", ""),
            "url": url,
            "final_url": res.get("finalUrl", ""),
            "http_status": res.get("httpStatus", ""),
            "error": res.get("error", ""),
            "has_password": res.get("hasPasswordInput", ""),
            "has_card": res.get("hasCardInput", ""),
            "forms": len(res.get("forms") or []),
            "redirects": len(res.get("redirectChain") or []),
            "blocked": res.get("blockedCount", ""),
            "title": (res.get("title") or "")[:120],
            "elapsed_ms": res.get("elapsedMs", ""),
        })
        status = res.get("error") or res.get("httpStatus")
        print(f"[{n}/{len(rows)}] {rid} {row.get('label', '')} {url} -> {status} ({res.get('elapsedMs', '?')} ms)",
              flush=True)

    summary_path = os.path.join(out_dir, "summary.csv")
    with open(summary_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary)

    alive = sum(1 for s in summary if s["http_status"] not in ("", None))
    print(f"\nГотово: {len(summary)} адрес, відкрилось {alive}. Зведення: {summary_path}")


if __name__ == "__main__":
    main()
