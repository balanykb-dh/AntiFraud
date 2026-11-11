#!/usr/bin/env bash
# Локальна спроба на Mac з Docker Desktop: bash local-mac.sh
#
# ЛИШЕ для легітимних сайтів (olx.ua, novaposhta.ua, monobank.ua...), щоб подивитись,
# як працює сервіс. Тут немає мережевої ізоляції, яку setup.sh ставить на VPS,
# а фішингова сторінка — це ворожий код. Фішинг рендеримо тільки на окремому VPS.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Не знайшов Docker. Встанови Docker Desktop для Mac: https://www.docker.com/products/docker-desktop/"
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker Desktop не запущений. Відкрий його, дочекайся статусу Running і запусти скрипт ще раз."
  exit 1
fi

if [[ ! -f .env ]]; then
  {
    echo "RENDER_API_KEY=$(openssl rand -hex 32)"
    echo "MAX_CONCURRENCY=1"
    echo "RENDER_MEM_LIMIT=2g"
  } > .env
  chmod 600 .env
  echo ".env створено"
fi

echo "Збираю і запускаю (перший раз 5-10 хв: качаються .NET SDK і Chromium)..."
docker compose up -d --build

echo "Чекаю, поки сервіс відповість..."
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo
    echo "Готово: $(curl -sS http://127.0.0.1:8080/health)"
    echo "Перевірка:  bash test.sh https://olx.ua   потім   open shot.jpg"
    echo "Зупинити:   docker compose down"
    exit 0
  fi
  sleep 3
done

echo "Сервіс не відповів за 3 хвилини. Останні рядки логу:"
docker compose logs --tail 80 render
exit 1
