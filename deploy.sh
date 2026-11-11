#!/usr/bin/env bash
# Розгортає phish-render на VPS (запускати на Mac у папці AntiFraud):
#   bash deploy.sh                    # сервер з vps-common.sh / ~/.ssh/config (phish-vps)
#   bash deploy.sh <IP> [користувач]  # інший сервер
# Увесь вивід зберігається в deploy.log, результат тесту - у result-vps.json і shot-vps.jpg.
set -euo pipefail
cd "$(dirname "$0")"
source ./vps-common.sh "$@"
vps_connect

{
  echo "==> Заливаю архів"
  scp "${OPTS[@]}" phish-render.tar.gz "$TARGET:~/"

  echo "==> Встановлюю на сервері (5-10 хв)"
  ssh "${OPTS[@]}" "$TARGET" 'tar xzf phish-render.tar.gz && cd phish-render && sudo bash setup.sh && sudo bash test.sh https://olx.ua'

  echo "==> Забираю результат тесту"
  scp "${OPTS[@]}" "$TARGET:~/phish-render/result.json" ./result-vps.json
  scp "${OPTS[@]}" "$TARGET:~/phish-render/shot.jpg" ./shot-vps.jpg
  echo
  echo "Готово. Скриншот з сервера: $(pwd)/shot-vps.jpg"
} 2>&1 | tee deploy.log

vps_close
