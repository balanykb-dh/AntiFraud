#!/usr/bin/env bash
# Щоденний моніторинг клонів бренду на сервері. Запускати на Mac у папці AntiFraud.
#   bash monitor.sh telegram          # один раз: підключити бота Telegram
#   bash monitor.sh run [бренд]       # один прогін зараз; зведення й зміни прийдуть у Telegram
#   bash monitor.sh on [бренд]        # щодня о 07:40 за Києвом. Вмикати лише після згоди клієнта
#   bash monitor.sh off [бренд]       # вимкнути щоденний запуск
#   bash monitor.sh status [бренд]    # чи увімкнено, коли наступний запуск, останні події
# Бренд за замовчуванням kachorovska; його налаштування: phish-render/monitor/<бренд>.json
set -euo pipefail
cd "$(dirname "$0")"
CMD="${1:-}"
BRAND="${2:-kachorovska}"
if [[ ! "$BRAND" =~ ^[a-z0-9-]+$ ]]; then echo "Назва бренду: латиниця, цифри й дефіс"; exit 1; fi
if [[ "$CMD" != "telegram" && "$CMD" != "off" && "$CMD" != "status" && ! -f "phish-render/monitor/$BRAND.json" ]]; then
  echo "Немає налаштувань phish-render/monitor/$BRAND.json"; exit 1
fi
set --                      # vps-common.sh читає IP з аргументів: не віддаємо йому команду й бренд
source ./vps-common.sh
UNIT="phish-monitor@$BRAND"

upload() {
  echo "==> Заливаю скрипти моніторингу на сервер"
  COPYFILE_DISABLE=1 tar czf - -C phish-render tools/monitor.py tools/brand_audit.py monitor \
    | ssh "${OPTS[@]}" "$TARGET" 'mkdir -p ~/phish-render && tar xzf - -C ~/phish-render && sudo bash ~/phish-render/monitor/install-units.sh'
}

case "$CMD" in
  telegram)
    cat <<'TXT'
Підключення Telegram (один раз):
  1. Відкрий у Telegram @BotFather, надішли /newbot, дай боту назву й username (закінчується на bot).
  2. BotFather надішле токен виду 123456789:AA... Скопіюй його.
  3. Відкрий свого нового бота й натисни Start, щоб бот дізнався твій чат.
TXT
    read -r -s -p "Встав токен бота (символи не відображаються): " TOKEN
    echo
    if [[ ! "$TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]]; then echo "Це не схоже на токен бота"; exit 1; fi
    vps_connect
    upload
    # Токен іде через stdin: його немає ні в аргументах команд, ні в логах.
    printf '%s\n' "$TOKEN" | ssh "${OPTS[@]}" "$TARGET" 'cd ~/phish-render && sudo python3 tools/monitor.py --telegram-setup'
    ;;
  run)
    vps_connect
    {
      upload
      echo "==> Прогін моніторингу $BRAND на сервері (3-5 хв; обрив зв'язку його не зупинить)"
      ssh "${OPTS[@]}" "$TARGET" "sudo systemctl start --no-block '$UNIT.service'"
      since=$(date -u +%s)
      while true; do
        sleep 15
        state=$(ssh "${OPTS[@]}" "$TARGET" "systemctl is-active '$UNIT.service'" 2>/dev/null || true)
        if [[ -z "$state" ]]; then echo "Зв'язок перервався; прогін іде далі, результат прийде в Telegram"; break; fi
        if [[ "$state" != "activating" && "$state" != "active" ]]; then
          ssh "${OPTS[@]}" "$TARGET" "sudo journalctl -u '$UNIT.service' --since '@$since' -o cat --no-pager | tail -n 25"
          echo "Готово: зведення має прийти в Telegram"
          break
        fi
        echo "   ...іде"
      done
    } 2>&1 | tee monitor.log
    ;;
  on)
    vps_connect
    upload
    ssh "${OPTS[@]}" "$TARGET" "sudo systemctl enable --now '$UNIT.timer' >/dev/null && systemctl list-timers '$UNIT.timer' --no-pager"
    echo "Щоденний моніторинг $BRAND увімкнено. Вимкнути: bash monitor.sh off $BRAND"
    ;;
  off)
    vps_connect
    ssh "${OPTS[@]}" "$TARGET" "sudo systemctl disable --now '$UNIT.timer' 2>/dev/null || true"
    echo "Щоденний запуск $BRAND вимкнено"
    ;;
  status)
    vps_connect
    ssh "${OPTS[@]}" "$TARGET" "echo -n 'Щоденний запуск: '; systemctl is-enabled '$UNIT.timer' 2>/dev/null || echo 'не встановлено'; \
      systemctl list-timers '$UNIT.timer' --no-pager 2>/dev/null | head -n 3; \
      echo; echo 'Останні події:'; tail -n 10 ~/phish-render/monitor/state/$BRAND-events.jsonl 2>/dev/null || echo '  поки немає'; \
      echo; echo 'Останній прогін:'; sudo journalctl -u '$UNIT.service' -n 8 --no-pager 2>/dev/null || true"
    ;;
  *)
    sed -n '2,8p' "$0"
    exit 1
    ;;
esac
vps_close
