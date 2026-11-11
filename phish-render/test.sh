#!/usr/bin/env bash
# Рендерить одну адресу. Можна знешкоджену: bash test.sh 'hxxps://olx-pay[.]site'
# Результат: result.json (на екран виводиться без картинки) і shot.jpg
# Працює там, де сервіс уже запущений: на VPS після setup.sh або на Mac після local-mac.sh.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  echo "Немає файлу .env, тобто сервіс тут ще не встановлений."
  echo "  На VPS (Ubuntu):            sudo bash setup.sh"
  echo "  На Mac з Docker Desktop:    bash local-mac.sh"
  exit 1
fi

URL="${1:-https://olx.ua}"
MOBILE="${2:-true}"
KEY=$(grep '^RENDER_API_KEY=' .env | cut -d= -f2-)

if command -v jq >/dev/null 2>&1; then
  BODY=$(jq -n --arg u "$URL" --argjson m "$MOBILE" '{url: $u, mobile: $m}')
else
  ESC=${URL//\\/\\\\}
  ESC=${ESC//\"/\\\"}
  BODY=$(printf '{"url":"%s","mobile":%s}' "$ESC" "$MOBILE")
fi

if ! curl -sS --max-time 120 -X POST http://127.0.0.1:8080/render \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $KEY" \
  -d "$BODY" > result.json; then
  echo "Сервіс не відповідає на 127.0.0.1:8080. Перевір: docker compose ps і docker compose logs --tail 50 render"
  exit 1
fi

rm -f shot.jpg
if command -v jq >/dev/null 2>&1; then
  jq 'del(.screenshotJpeg, .html)' result.json
  if jq -e '.screenshotJpeg' result.json >/dev/null; then
    jq -r '.screenshotJpeg' result.json | base64 --decode > shot.jpg
  fi
else
  python3 - <<'PY'
import base64, json
res = json.load(open("result.json", encoding="utf-8"))
shot = res.pop("screenshotJpeg", None)
res.pop("html", None)
print(json.dumps(res, ensure_ascii=False, indent=2))
if shot:
    open("shot.jpg", "wb").write(base64.b64decode(shot))
PY
fi

if [[ -s shot.jpg ]]; then
  echo "Скриншот: $(pwd)/shot.jpg"
  if [[ "$(uname)" == "Darwin" ]]; then
    echo "Відкрити: open shot.jpg"
  else
    echo "Забрати на ноутбук: scp root@<IP>:$(pwd)/shot.jpg ."
  fi
fi
