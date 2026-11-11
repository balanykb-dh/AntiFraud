#!/usr/bin/env bash
# Network-level isolation for the render container (bridge br-render).
# The container may reach the public internet only: no private networks,
# no cloud metadata (169.254.169.254), no services on the VPS itself.
# Idempotent: safe to run many times (systemd runs it after every Docker start).
set -euo pipefail

IF=br-render
BLOCKED_NETS="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"

ensure() {
  # ensure <chain> <rule...>: insert at the top unless an identical rule exists
  local chain="$1"; shift
  iptables -C "$chain" "$@" 2>/dev/null || iptables -I "$chain" 1 "$@"
}

# Docker creates DOCKER-USER; wait for it after a reboot.
for _ in $(seq 1 30); do
  iptables -L DOCKER-USER -n >/dev/null 2>&1 && break
  sleep 1
done

# Traffic routed out of the container: drop anything aimed at non-public ranges.
for net in $BLOCKED_NETS; do
  ensure DOCKER-USER -i "$IF" -d "$net" -j DROP
done

# Traffic from the container to the VPS itself: only replies to connections the
# host opened (the API port forward). Inserted in this order so ACCEPT ends up first.
ensure INPUT -i "$IF" -j DROP
ensure INPUT -i "$IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "render-egress: rules active on $IF"
