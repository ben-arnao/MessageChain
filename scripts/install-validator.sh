#!/usr/bin/env bash
# install-validator.sh — bootstrap a fresh MessageChain validator on Linux.
#
# Idempotent: re-running picks up where it left off. Does NOT enable any
# systemd services; the operator runs the final `systemctl enable --now`
# commands printed at the end so unattended re-runs can't silently start
# a node with the wrong config.

set -euo pipefail

FROM_GIT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from-git)
            FROM_GIT="$2"
            shift 2
            ;;
        --help|-h)
            cat <<EOF
Usage: sudo ./install-validator.sh [--from-git <url>]

Options:
  --from-git <url>    Clone + install from a git URL instead of pypi
                      (useful until the pypi package is published).
EOF
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "This script must run as root (sudo)." >&2
    exit 1
fi

echo "[1/6] Creating messagechain system user if missing..."
if ! id -u messagechain >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin messagechain
fi

echo "[2/6] Laying out directories..."
mkdir -p /opt/messagechain /var/lib/messagechain /etc/messagechain
chown -R messagechain:messagechain /opt/messagechain /var/lib/messagechain
chown root:messagechain /etc/messagechain
chmod 0750 /etc/messagechain

echo "[3/6] Installing MessageChain..."
if [ -n "$FROM_GIT" ]; then
    if [ ! -d /opt/messagechain/.git ]; then
        rm -rf /opt/messagechain
        sudo -u messagechain git clone "$FROM_GIT" /opt/messagechain
    fi
    cd /opt/messagechain
    sudo -u messagechain pip install --user -e .
else
    pip install --target /opt/messagechain messagechain
fi

echo "[4/6] Running `messagechain init`..."
python3 -m messagechain init --yes --systemd

echo "[5/6] Reloading systemd daemon..."
systemctl daemon-reload

echo "[6/6] Done."
cat <<'EOF'

Next steps (run these as root):

  systemctl enable --now messagechain-validator
  systemctl enable --now messagechain-upgrade.timer
  systemctl enable --now messagechain-rotate-key.timer

Check status with:
  messagechain status
  messagechain doctor
EOF
