# Спільне для скриптів AntiFraud: куди підключатись і як не вводити пароль щоразу.
# Після `bash ssh-setup.sh` вхід іде по ключу через скорочення phish-vps, без пароля.
VPS_IP="91.228.218.128"
if [[ -n "${1:-}" ]]; then
  TARGET="${2:-root}@$1"
elif grep -qx "Host phish-vps" "$HOME/.ssh/config" 2>/dev/null; then
  TARGET="phish-vps"
else
  TARGET="root@$VPS_IP"
fi
SOCK="/tmp/phish-render-ssh-$$"
OPTS=(-o ControlMaster=auto -o ControlPath="$SOCK" -o ControlPersist=60m -o ServerAliveInterval=30 -o StrictHostKeyChecking=accept-new)

vps_connect() {
  if [[ "$TARGET" == "phish-vps" ]]; then
    echo "==> Підключаюсь до сервера по ключу"
  else
    echo "==> Підключаюсь до $TARGET (введи пароль сервера; щоб більше не вводити: bash ssh-setup.sh)"
  fi
  ssh "${OPTS[@]}" "$TARGET" true
}

vps_close() {
  ssh "${OPTS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
}
