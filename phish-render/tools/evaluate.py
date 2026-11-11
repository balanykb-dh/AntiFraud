#!/usr/bin/env python3
"""Оцінка точності детектора: проганяє CSV з мітками phishing/legit через POST /check
і рахує точність окремо для «тільки правила» і для «правила + LLM».

    sudo python3 tools/evaluate.py testdata/live_feed.csv testdata/legit_ua.csv [ще.csv ...] --out eval_out

Лише стандартна бібліотека Python. Результат у eval_out/:
  report.md     - метрики, матриці помилок, список хибних спрацювань і пропусків
  results.csv   - рядок на кожну адресу
  <id>.json     - повна відповідь сервісу (без картинок)
  <id>.jpg, <id>-cta.jpg - скриншоти сторінки і сторінки після кнопки
"""
import argparse
import base64
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
API = os.environ.get("CHECK_URL", "http://127.0.0.1:8080/check")


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


def check(url, key, use_llm, timeout=240):
    body = json.dumps({"url": url, "mobile": True, "followCta": True, "useLlm": use_llm}).encode("utf-8")
    req = urllib.request.Request(API, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Api-Key": key})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 503 and attempt < 2:  # all render slots busy
                time.sleep(5)
                continue
            return {"verdict": "error", "ruleVerdict": "error", "error": f"http_{e.code}"}
        except Exception as e:  # noqa: BLE001
            return {"verdict": "error", "ruleVerdict": "error", "error": f"client_error: {e}"}
    return {"verdict": "error", "ruleVerdict": "error", "error": "busy"}


def save_artifacts(out_dir, rid, res):
    render = res.get("render") or {}
    shot = render.pop("screenshotJpeg", None)
    if shot:
        with open(os.path.join(out_dir, f"{rid}.jpg"), "wb") as f:
            f.write(base64.b64decode(shot))
    cta = render.get("ctaStep") or {}
    cta_shot = cta.pop("screenshotJpeg", None)
    if cta_shot:
        with open(os.path.join(out_dir, f"{rid}-cta.jpg"), "wb") as f:
            f.write(base64.b64decode(cta_shot))
    with open(os.path.join(out_dir, f"{rid}.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)


def metrics(rows, field, lenient):
    """Positive class = phishing. Unreachable/errors are excluded: nothing to judge."""
    tp = fp = tn = fn = 0
    for r in rows:
        pred = r[field]
        if pred in ("unreachable", "error"):
            continue
        positive = pred == "phishing" or (lenient and pred == "suspicious")
        if r["label"] == "phishing":
            tp += positive
            fn += not positive
        else:
            fp += positive
            tn += not positive
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def pct(x):
    return f"{x * 100:.0f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--out", default="eval_out")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--no-llm", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    key = load_key()

    items = []
    for path in args.csv:
        with open(path, encoding="utf-8", newline="") as f:
            for n, row in enumerate(csv.DictReader(f), 1):
                url = (row.get("url_defanged") or row.get("url") or "").strip()
                label = (row.get("label") or "").strip()
                if url and label in ("phishing", "legit"):
                    rid = (row.get("id") or f"{os.path.basename(path)}-{n}").strip()
                    items.append({"id": rid, "label": label, "url": url, "set": os.path.basename(path)})

    print(f"Перевіряю {len(items)} адрес у {args.workers} потоки...", flush=True)
    started = time.time()
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check, it["url"], key, not args.no_llm): it for it in items}
        for done, fut in enumerate(as_completed(futures), 1):
            it = futures[fut]
            res = fut.result()
            if res.get("verdict") == "error" and res.get("error") == "http_401":
                sys.exit("401: ключ не підходить, перевір RENDER_API_KEY")
            render = res.get("render") or {}
            llm = res.get("llm") or {}
            rows.append({
                "id": it["id"],
                "set": it["set"],
                "label": it["label"],
                "url": it["url"],
                "verdict": res.get("verdict", "error"),
                "score": res.get("score", ""),
                "rule_verdict": res.get("ruleVerdict", "error"),
                "rule_score": res.get("ruleScore", ""),
                "brand": res.get("brand") or "",
                "llm": "" if not llm else (llm.get("error") or f"{llm.get('isPhishing')}/{llm.get('confidence', 0):.2f}"),
                "llm_tokens": (llm.get("inputTokens", 0) + llm.get("outputTokens", 0)) if llm else 0,
                "final_url": render.get("finalUrl") or "",
                "cta": (render.get("ctaStep") or {}).get("clickedText") or "",
                "elapsed_ms": render.get("elapsedMs", ""),
                "reasons": " | ".join(res.get("reasons") or []) or res.get("error", ""),
            })
            save_artifacts(args.out, it["id"], res)
            print(f"[{done}/{len(items)}] {it['id']:>4} {it['label']:<8} {res.get('verdict', 'error'):<11} "
                  f"(правила: {res.get('ruleVerdict', '?')}) {it['url']}", flush=True)

    order = {it["id"]: i for i, it in enumerate(items)}
    rows.sort(key=lambda r: order[r["id"]])
    with open(os.path.join(args.out, "results.csv"), "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    write_report(args.out, rows, time.time() - started, not args.no_llm)


def llm_line(rows, used, tokens, requested):
    if used:
        return f"викликів {used}, токенів {tokens}"
    errors = sum(1 for r in rows if r["llm"] and "/" not in r["llm"])
    if errors:
        return f"помилки у {errors} викликах (див. results.csv, колонка llm)"
    if requested:
        return "не використовувалась: на сервері немає ключа (bash set-llm-key.sh <IP>)"
    return "вимкнено (--no-llm)"


def write_report(out_dir, rows, seconds, llm_requested):
    lines = ["# Оцінка точності детектора", ""]
    total = {lbl: sum(1 for r in rows if r["label"] == lbl) for lbl in ("phishing", "legit")}
    dead = {lbl: sum(1 for r in rows if r["label"] == lbl and r["verdict"] in ("unreachable", "error")) for lbl in total}
    llm_used = sum(1 for r in rows if r["llm"] and "/" in r["llm"])
    tokens = sum(int(r["llm_tokens"] or 0) for r in rows)
    lines += [
        f"- Перевірено адрес: {len(rows)} за {seconds / 60:.1f} хв",
        f"- Фішингових: {total['phishing']}, з них недоступних (мертвий домен, 404): {dead['phishing']}",
        f"- Справжніх: {total['legit']}, з них недоступних: {dead['legit']}",
        f"- LLM: {llm_line(rows, llm_used, tokens, llm_requested)}",
        "",
        "Недоступні адреси в метрики не входять: там нема чого оцінювати.",
        "Суворо = фішингом вважається лише вердикт `phishing`. М'яко = `phishing` або `suspicious`.",
        "",
        "| Режим | Точність (precision) | Повнота (recall) | F1 | Хибні тривоги на справжніх | TP | FP | TN | FN |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, field in (("Правила", "rule_verdict"), ("Правила + LLM", "verdict")):
        for mode, lenient in (("суворо", False), ("м'яко", True)):
            m = metrics(rows, field, lenient)
            lines.append(f"| {name}, {mode} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} | "
                         f"{pct(m['fpr'])} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |")

    def listing(title, predicate):
        picked = [r for r in rows if predicate(r)]
        out = ["", f"## {title} ({len(picked)})", ""]
        for r in picked:
            out.append(f"- **{r['id']}** `{r['url']}` → {r['verdict']} ({r['score']}), правила: {r['rule_verdict']} ({r['rule_score']})")
            out.append(f"  - {r['reasons']}")
        return out

    live = lambda r: r["verdict"] not in ("unreachable", "error")  # noqa: E731
    lines += listing("Хибні тривоги: справжні сайти, позначені як фішинг чи підозрілі",
                     lambda r: r["label"] == "legit" and live(r) and r["verdict"] in ("phishing", "suspicious"))
    lines += listing("Пропущений фішинг: живі фішингові сторінки, визнані безпечними",
                     lambda r: r["label"] == "phishing" and live(r) and r["verdict"] == "safe")
    lines += listing("Фішинг, який LLM підняла до вердикту «фішинг» (правила самі не дотягнули)",
                     lambda r: r["label"] == "phishing" and r["verdict"] == "phishing" and r["rule_verdict"] != "phishing")

    report = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    print("\n" + report)


if __name__ == "__main__":
    main()
