#!/usr/bin/env bash
# install-validator.sh — bootstrap a fresh MessageChain validator on Linux.
#
# Idempotent: re-running picks up where it left off. Does NOT enable any
# systemd services; the operator runs the final `systemctl enable --now`
# commands printed at the end so unattended re-runs can't silently start
# a node with the wrong config.

set -euo pipefail

FROM_GIT="https://github.com/ben-arnao/MessageChain.git"
while [ $# -gt 0 ]; do
    case "$1" in
        --from-git)
            FROM_GIT="$2"
            shift 2
            ;;
        --help|-h)
            cat <<EOF
Usage: sudo ./install-validator.sh [--from-git <url>]

Clones MessageChain into /opt/messagechain, installs it, and runs
\`messagechain init\` to lay out the data dir, keyfile, onboard config,
and systemd units.

Options:
  --from-git <url>    Clone + install from a git URL
                      (default: upstream MessageChain repo)
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

echo "[3/6] Installing MessageChain from $FROM_GIT..."
if [ ! -d /opt/messagechain/.git ]; then
    rm -rf /opt/messagechain
    git clone "$FROM_GIT" /opt/messagechain
    chown -R messagechain:messagechain /opt/messagechain
fi
cd /opt/messagechain
# --break-system-packages lets Debian/Ubuntu's pip write to site-packages
# on PEP 668 systems; harmless on distros that don't know the flag.
pip install -e . --break-system-packages 2>/dev/null || pip install -e .

echo "[4/6] Running messagechain init..."
python3 -m messagechain init --yes --systemd

# Init runs as root and writes root-owned files; the validator service
# runs as user `messagechain` so it must be able to read them.
chown messagechain:messagechain /etc/messagechain/keyfile
chown root:messagechain /etc/messagechain/onboard.toml
chmod 0640 /etc/messagechain/onboard.toml

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
