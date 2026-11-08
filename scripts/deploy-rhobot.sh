#!/usr/bin/env bash
# Deploy the committed BYOID tree to rhobot-2 as an immutable release.
# First-time host setup is documented in docs/deploy-rhobot.md.
#
# Usage:
#   ./scripts/deploy-rhobot.sh
#   BYOID_DEPLOY_HOST=root@rhobot.net BYOID_DEPLOY_KEY=$HOME/.ssh/id_droplet ./scripts/deploy-rhobot.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
host=${BYOID_DEPLOY_HOST:-root@rhobot.net}
key=${BYOID_DEPLOY_KEY:-$HOME/.ssh/id_droplet}
sha=$(git -C "$repo_root" rev-parse --short=12 HEAD)
release="/opt/byoid/releases/$sha"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=15)
if [[ -n "$key" ]]; then ssh_opts+=(-i "$key"); fi

if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
  echo "Working tree is dirty; commit or stash before deploying." >&2
  exit 1
fi

echo "[deploy] $host $release"
ssh "${ssh_opts[@]}" "$host" "install -d -m 0755 '$release'"
git -C "$repo_root" archive --format=tar HEAD | ssh "${ssh_opts[@]}" "$host" "tar -x -C '$release'"

ssh "${ssh_opts[@]}" "$host" bash -s <<EOF
set -euo pipefail
cd '$release'
/usr/local/lib/node22/bin/npm ci --omit=dev --ignore-scripts --no-audit --no-fund
rm -rf data
ln -s /var/lib/byoid data
chown -R root:byoid '$release'
chmod -R u+rwX,g+rX,o-rwx '$release'
ln -sfn '$release' /opt/byoid/current.next
mv -Tf /opt/byoid/current.next /opt/byoid/current
systemctl restart byoid
EOF

echo "[deploy] waiting for health..."
ssh "${ssh_opts[@]}" "$host" '
  for i in $(seq 1 20); do
    if curl -fsS --max-time 3 http://127.0.0.1:3100/healthz >/dev/null; then
      curl -fsS http://127.0.0.1:3100/healthz
      exit 0
    fi
    sleep 1
  done
  systemctl --no-pager --full status byoid || true
  journalctl -u byoid -n 40 --no-pager || true
  exit 1
'

# Keep the current release plus four previous ones.
ssh "${ssh_opts[@]}" "$host" '
  current=$(readlink -f /opt/byoid/current)
  find /opt/byoid/releases -mindepth 1 -maxdepth 1 -type d -printf "%T@ %p\n" |
    sort -rn | awk '{print $2}' | grep -v -F "$current" | tail -n +5 |
    xargs -r rm -rf
'
echo "[deploy] done: $release"
