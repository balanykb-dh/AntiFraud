#!/usr/bin/env bash
# Оцінка точності детектора на VPS і забір звіту на Mac:
#   bash run-eval.sh [IP] [користувач]
# На сервері: 40 свіжих фішингових адрес з phishunt.io (лише домени, яких ще не було в оцінках),
# наш тестовий набір і 40 справжніх українських сайтів -> /check -> точність.
# Результат: папка eval-results-<дата>/ з report.md, results.csv і скриншотами.
set -euo pipefail
cd "$(dirname "$0")"
source ./vps-common.sh "$@"
OUT="eval-results-$(date +%Y%m%d-%H%M)"
vps_connect

{
  echo "==> Оцінка на сервері (10-20 хв: кожна жива сторінка рендериться, клікається і перевіряється)"
  ssh "${OPTS[@]}" "$TARGET" 'cd phish-render && rm -rf eval_out \
    && sudo python3 tools/fetch_feed.py testdata/live_feed.csv 40 \
    && sudo python3 tools/evaluate.py testdata/live_feed.csv testdata/phishing_test_set.csv testdata/legit_ua.csv --out eval_out \
    && tar czf /tmp/eval_out.tar.gz eval_out'

  echo "==> Забираю результати в $OUT/"
  mkdir -p "$OUT"
  scp "${OPTS[@]}" "$TARGET:/tmp/eval_out.tar.gz" "$OUT/eval_out.tar.gz"
  tar xzf "$OUT/eval_out.tar.gz" -C "$OUT" --strip-components=1
  rm "$OUT/eval_out.tar.gz"
  echo
  echo "Готово: $(pwd)/$OUT/report.md"
} 2>&1 | tee run-eval.log

vps_close
