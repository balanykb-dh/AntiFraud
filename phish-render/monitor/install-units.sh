#!/usr/bin/env bash
# Ставить systemd-юніти моніторингу. Таймер НЕ вмикає: це робить `bash monitor.sh on` на Mac.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
for f in phish-monitor@.service phish-monitor@.timer; do
  sed "s#@DIR@#$DIR#g" "$DIR/monitor/units/$f" > "/etc/systemd/system/$f"
done
systemctl daemon-reload
chmod 700 "$DIR/monitor"
