#!/usr/bin/env bash
# Проганяє тестовий набір через /render на VPS і забирає результати:
#   bash run-tests.sh [IP] [користувач]
# Результат: папка render-results-<дата>/ зі summary.csv, JSON і скриншотами.
set -euo pipefail
cd "$(dirname "$0")"
source ./vps-common.sh "$@"
OUT="render-results-$(date +%Y%m%d-%H%M)"
vps_connect

{
  echo "==> Проганяю тестовий набір на сервері (кілька хвилин)"
  ssh "${OPTS[@]}" "$TARGET" 'cd phish-render && rm -rf render_out && sudo python3 tools/batch_render.py testdata/phishing_test_set.csv render_out && tar czf /tmp/render_out.tar.gz render_out'

  echo "==> Забираю результати в $OUT/"
  mkdir -p "$OUT"
  scp "${OPTS[@]}" "$TARGET:/tmp/render_out.tar.gz" "$OUT/render_out.tar.gz"
  tar xzf "$OUT/render_out.tar.gz" -C "$OUT" --strip-components=1
  rm "$OUT/render_out.tar.gz"
  echo
  echo "Готово: $(pwd)/$OUT/summary.csv"
} 2>&1 | tee run-tests.log

vps_close
