#!/usr/bin/env bash
# Встановлює сервіс рендеру на чисту Ubuntu (24.04 або новішу). Запуск: sudo bash setup.sh
# Можна запускати повторно: нічого не зламає, просто перезбере і перезапустить.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запусти з правами root: sudo bash setup.sh"
  exit 1
fi
cd "$(dirname "$(readlink -f "$0")")"
export DEBIAN_FRONTEND=noninteractive

echo "==> 1/6 Пакети і Docker"
# Ubuntu сама ставить оновлення безпеки (unattended-upgrades) і на цей час блокує apt.
# Тому: пакети ставимо лише якщо їх ще немає, а блокування чекаємо до 10 хвилин замість падіння.
APT_WAIT=(-o DPkg::Lock::Timeout=600)
# команда:пакет; psql потрібен аудиту брендів (журнал сертифікатів crt.sh)
MISSING=()
for pair in curl:curl jq:jq ufw:ufw iptables:iptables openssl:openssl python3:python3 psql:postgresql-client; do
  command -v "${pair%%:*}" >/dev/null 2>&1 || MISSING+=("${pair#*:}")
done
if (( ${#MISSING[@]} > 0 )); then
  echo "    бракує: ${MISSING[*]}; якщо зараз іде автооновлення Ubuntu, чекаю його завершення"
  apt-get "${APT_WAIT[@]}" update -y
  apt-get "${APT_WAIT[@]}" install -y ca-certificates "${MISSING[@]}"
else
  echo "    усе потрібне вже встановлено"
fi
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

echo "==> 2/6 Swap (Chromium любить пам'ять)"
if [[ -z "$(swapon --show)" ]]; then
  if fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile; then
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "    swap 2 ГБ додано"
  else
    echo "    swap додати не вдалося, продовжую без нього"
  fi
else
  echo "    swap уже є"
fi

echo "==> 3/6 Фаєрвол: ззовні відкритий лише SSH"
ufw allow OpenSSH >/dev/null
ufw --force enable >/dev/null
ufw status || true

echo "==> 4/6 Ключ API і ліміти"
if [[ ! -f .env ]]; then
  TOTAL_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  MEM_LIMIT_MB=$(( TOTAL_MB * 75 / 100 ))
  if   (( TOTAL_MB >= 7500 )); then CONC=4
  elif (( TOTAL_MB >= 3500 )); then CONC=2
  else CONC=1
  fi
  {
    echo "RENDER_API_KEY=$(openssl rand -hex 32)"
    echo "MAX_CONCURRENCY=$CONC"
    echo "RENDER_MEM_LIMIT=${MEM_LIMIT_MB}m"
  } > .env
  chmod 600 .env
  echo "    .env створено: RAM ${TOTAL_MB} МБ, одночасних рендерів $CONC, ліміт контейнера ${MEM_LIMIT_MB} МБ"
else
  echo "    .env уже є, не чіпаю"
fi

echo "==> 5/6 Ізоляція мережі контейнера"
install -m 755 firewall/render-egress.sh /usr/local/sbin/render-egress.sh
install -m 644 firewall/render-egress.service /etc/systemd/system/render-egress.service
systemctl daemon-reload
systemctl enable render-egress.service >/dev/null 2>&1
systemctl restart render-egress.service

echo "==> 6/6 Збираю і запускаю (перший раз 5-10 хв: качається Chromium)"
docker compose up -d --build

echo "==> Чекаю, поки сервіс відповість"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo
    echo "Готово: $(curl -sS http://127.0.0.1:8080/health)"
    echo
    echo "Перевірка однієї адреси:   sudo bash test.sh https://olx.ua"
    echo "Весь тестовий набір:       sudo python3 tools/batch_render.py testdata/phishing_test_set.csv"
    echo "Логи:                      docker compose logs -f render"
    exit 0
  fi
  sleep 3
done

echo "Сервіс не відповів за 3 хвилини. Останні рядки логу:"
docker compose logs --tail 80 render
exit 1
