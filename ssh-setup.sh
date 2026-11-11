#!/usr/bin/env bash
# Один раз: вхід на сервер по SSH-ключу замість пароля.
#   bash ssh-setup.sh            # сервер 91.228.218.128
#   bash ssh-setup.sh <IP>       # інший сервер
# Після цього deploy.sh, run-eval.sh, run-tests.sh і set-llm-key.sh пароля не питають,
# а на сервер можна зайти просто командою: ssh phish-vps
set -euo pipefail
IP="${1:-91.228.218.128}"
KEY="$HOME/.ssh/id_ed25519"
CONFIG="$HOME/.ssh/config"

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

if [[ ! -f "$KEY" ]]; then
  echo "==> Створюю SSH-ключ $KEY"
  echo "    Можна задати фразу-пароль для ключа (macOS запам'ятає її в Keychain) або двічі натиснути Enter."
  ssh-keygen -t ed25519 -f "$KEY" -C "phish-render $(whoami)@$(hostname -s)"
else
  echo "==> SSH-ключ уже є: $KEY"
fi

echo "==> Кладу публічний ключ на сервер $IP (пароль сервера вводиш востаннє)"
ssh -o StrictHostKeyChecking=accept-new -o PubkeyAuthentication=no "root@$IP" \
  'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; k=$(cat); grep -qxF "$k" ~/.ssh/authorized_keys || echo "$k" >> ~/.ssh/authorized_keys' \
  < "$KEY.pub"

if grep -qx "Host phish-vps" "$CONFIG" 2>/dev/null; then
  echo "==> Скорочення phish-vps у ~/.ssh/config уже є"
else
  echo "==> Додаю в ~/.ssh/config скорочення phish-vps"
  cat >> "$CONFIG" <<CFG

Host phish-vps
  HostName $IP
  User root
  IdentityFile $KEY
  IdentitiesOnly yes
  ServerAliveInterval 30
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h-%p
  ControlPersist 30m
  IgnoreUnknown UseKeychain
  UseKeychain yes
  AddKeysToAgent yes
CFG
  chmod 600 "$CONFIG"
fi

echo "==> Перевіряю вхід без пароля сервера"
if ! ssh -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no phish-vps 'echo "    працює: $(hostname), $(whoami)"'; then
  echo "Вхід по ключу не вдався. Скинь Claude вивід цього скрипта."
  exit 1
fi

echo
read -r -p "Вимкнути на сервері вхід по паролю? Боти, що підбирають паролі, стануть безсилі; доступ без ключа лишиться лише через консоль у панелі хостера. [y/N] " ANSWER
if [[ "$ANSWER" == y* || "$ANSWER" == Y* || "$ANSWER" == т* || "$ANSWER" == Т* ]]; then
  ssh phish-vps 'printf "PasswordAuthentication no\nKbdInteractiveAuthentication no\n" > /etc/ssh/sshd_config.d/10-no-password.conf \
    && sshd -t && (systemctl reload ssh || systemctl restart ssh) && echo "    вхід по паролю вимкнено"'
else
  echo "    Залишаю вхід по паролю як є."
fi

echo
echo "Готово. Тепер просто: bash deploy.sh, bash run-eval.sh, ssh phish-vps"
