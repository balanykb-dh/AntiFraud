#!/usr/bin/env bash
# Вмикає LLM-суддю: перевіряє ключ Claude API пробним викликом із сервера, записує його в .env
# на сервері і перезапускає сервіс.
#   bash set-llm-key.sh                    # ключ з файлу phish-render/api-key (або api-key), інакше спитає
#   bash set-llm-key.sh <IP> [користувач]  # інший сервер
set -euo pipefail
cd "$(dirname "$0")"
source ./vps-common.sh "$@"

KEY=""
for f in phish-render/api-key api-key; do
  if [[ -f "$f" ]]; then
    KEY=$(tr -d '\r\n ' < "$f")
    echo "==> Ключ беру з файлу $f"
    break
  fi
done
if [[ -z "$KEY" ]]; then
  read -r -s -p "Встав ключ Claude API (sk-ant-..., символи не відображаються): " KEY
  echo
fi
if [[ "$KEY" != sk-ant-* ]]; then
  echo "Це не схоже на ключ Claude API: він має починатися з sk-ant-"
  exit 1
fi

read -r -d '' REMOTE <<'SCRIPT' || true
set -e
cd ~/phish-render
echo "==> Пробний виклик Claude API з сервера"
code=$(curl -sS --max-time 30 -o /tmp/llm-test.json -w "%{http_code}" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $k" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-haiku-5-5","max_tokens":5,"messages":[{"role":"user","content":"Say OK"}]}') || true
if [ "$code" != "200" ]; then
  echo "Ключ не спрацював: HTTP $code"
  python3 -c 'import json; print(json.load(open("/tmp/llm-test.json")).get("error", {}).get("message", ""))' 2>/dev/null \
    || head -c 300 /tmp/llm-test.json
  rm -f /tmp/llm-test.json
  exit 1
fi
rm -f /tmp/llm-test.json
echo "==> Ключ робочий, записую в .env і перезапускаю сервіс"
sudo sed -i "/^ANTHROPIC_API_KEY=/d" .env
printf "ANTHROPIC_API_KEY=%s\n" "$k" | sudo tee -a .env >/dev/null
sudo docker compose up -d
for _ in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:8080/health 2>/dev/null; then echo; exit 0; fi
  sleep 3
done
echo "Сервіс не відповів, лог:"
sudo docker compose logs --tail 40 render
exit 1
SCRIPT

vps_connect
# Перший рядок stdin - ключ (не потрапляє ні в аргументи команд, ні в логи), решта - скрипт для сервера.
printf '%s\n%s\n' "$KEY" "$REMOTE" | ssh "${OPTS[@]}" "$TARGET" 'read -r k; export k; bash -s'
vps_close
echo "Готово: у відповіді вище має бути \"llm\":\"claude-haiku-5-5\""
