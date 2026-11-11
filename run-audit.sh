#!/usr/bin/env bash
# Аудит клонів бренду на сервері. Аудит іде на сервері сам: обрив інтернету чи закритий термінал його не зупиняють.
#   bash run-audit.sh <бренд> <офіційний.домен> [ще.домен ...]      # запустити й чекати результату
#   bash run-audit.sh --no-wait <бренд> <офіційний.домен> [...]     # лише запустити; кілька брендів стають у чергу
#   bash run-audit.sh fetch                                          # забрати всі готові результати й показати, що ще йде
#   EXTRA="домен1 домен2" bash run-audit.sh ...                      # додатково перевірити домени з новин чи скарг
# Без аргументів — Kachorovska. Результат: папка audit-<бренд>-<дата>/ із summary.md, candidates.csv і скриншотами.
set -euo pipefail
cd "$(dirname "$0")"

WAIT=1
MODE=start
if [[ "${1:-}" == "--no-wait" ]]; then WAIT=0; shift; fi
if [[ "${1:-}" == "fetch" ]]; then MODE=fetch; shift; fi

BRAND="${1:-kachorovska}"
if (( $# > 1 )); then shift; OFFICIAL="$*"; else OFFICIAL="kachorovska.com"; fi
# fbkachorovska.top - фейк, про який бренд попереджав (Комерсант, 3 серпня)
if [[ -z "${EXTRA+x}" && "$BRAND" == "kachorovska" ]]; then EXTRA="fbkachorovska.top"; fi
EXTRA="${EXTRA:-}"
if [[ ! "$BRAND" =~ ^[a-z0-9][a-z0-9-]{2,62}$ ]]; then echo "Назва бренду: латиниця, цифри й дефіс"; exit 1; fi
for d in $OFFICIAL $EXTRA; do
  if [[ ! "$d" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]]; then echo "Не схоже на домен: $d"; exit 1; fi
done

set --                      # vps-common.sh читає IP з аргументів: не віддаємо йому бренд
source ./vps-common.sh

# Забирає на Mac усі завершені аудити, яких тут ще немає, і показує ті, що ще йдуть.
fetch_all() {
  local list name state rest got=0
  list=$(ssh "${OPTS[@]}" "$TARGET" 'cd ~/phish-render/audit_runs 2>/dev/null || exit 0
    for d in */; do
      [ -d "$d" ] || continue
      d=${d%/}
      if [ -f "$d/.exit" ]; then echo "$d done $(cat "$d/.exit")"
      elif [ -s "$d/audit.log" ]; then echo "$d running $(tail -n 1 "$d/audit.log" | tr -s " ")"
      else echo "$d queued"; fi
    done')
  while read -r name state rest; do
    [[ -z "$name" ]] && continue
    case "$state" in
      running) echo "  іде: $name — $rest"; continue ;;
      queued)  echo "  у черзі: $name"; continue ;;
    esac
    [[ -d "audit-$name" ]] && continue
    echo "==> Забираю audit-$name"
    mkdir -p "audit-$name"
    ssh "${OPTS[@]}" "$TARGET" "tar czf - -C ~/phish-render/audit_runs '$name'" | tar xzf - -C "audit-$name" --strip-components=1
    if [[ "$rest" != "0" ]]; then echo "    аудит завершився з помилкою (код $rest), дивись audit-$name/audit.log"; fi
    got=$((got + 1))
  done <<< "$list"
  echo "Нових результатів: $got"
}

vps_connect
if [[ "$MODE" == "fetch" ]]; then
  fetch_all
  vps_close
  exit 0
fi

NAME="$BRAND-$(date +%Y%m%d-%H%M%S)"
ARGS="--brand $BRAND --official $OFFICIAL"
if [[ -n "$EXTRA" ]]; then ARGS="$ARGS --extra $EXTRA"; fi
{
  echo "==> Заливаю свіжу версію скрипта аудиту"
  scp -q "${OPTS[@]}" phish-render/tools/brand_audit.py "$TARGET:~/phish-render/tools/brand_audit.py"
  echo "==> Запускаю аудит $BRAND (офіційні: $OFFICIAL) на сервері"
  # systemd-run: аудит живе окремо від SSH. flock: кілька аудитів ідуть по черзі, а не всі разом.
  ssh "${OPTS[@]}" "$TARGET" "mkdir -p ~/phish-render/audit_runs/$NAME && sudo systemd-run --quiet --collect \
    --unit 'phish-audit-$NAME' --working-directory=\"\$HOME/phish-render\" /bin/bash -c \
    'flock audit_runs/.lock python3 tools/brand_audit.py $ARGS --out audit_runs/$NAME > audit_runs/$NAME/audit.log 2>&1; echo \$? > audit_runs/$NAME/.exit'"

  if (( WAIT == 0 )); then
    echo "Запущено: $NAME. Якщо інший аудит ще йде, цей почнеться після нього."
    echo "Забрати результати: bash run-audit.sh fetch"
  else
    echo "==> Чекаю результат (обрив зв'язку чи Ctrl+C аудит не зупинять)"
    shown=0
    while true; do
      if ! out=$(ssh "${OPTS[@]}" "$TARGET" "cd ~/phish-render/audit_runs/$NAME && sed -n '$((shown + 1)),\$p' audit.log 2>/dev/null; echo '@@@'; cat .exit 2>/dev/null || true"); then
        echo
        echo "Зв'язок із сервером перервався, але аудит іде далі."
        echo "Забрати результат пізніше: bash run-audit.sh fetch"
        exit 1
      fi
      log="${out%@@@*}"
      code=$(printf '%s' "${out##*@@@}" | tr -d '[:space:]')
      if [[ -n "$log" ]]; then
        printf '%s' "$log"
        shown=$((shown + $(printf '%s' "$log" | wc -l)))
      fi
      [[ -n "$code" ]] && break
      sleep 15
    done
    fetch_all
    echo
    echo "Готово: $(pwd)/audit-$NAME/summary.md"
  fi
} 2>&1 | tee run-audit.log

vps_close
