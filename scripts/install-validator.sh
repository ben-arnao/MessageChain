#!/usr/bin/env bash
# install-validator.sh — bootstrap a fresh MessageChain validator on Linux.
#
# Pins the install to the latest canonical `vX.Y.Z-mainnet` tag and
# refuses to proceed unless that tag is SSH-signed by a release signer
# pinned in this script.  Mirrors the supply-chain gate the
# `messagechain upgrade` CLI enforces; see release_signers.py.
#
# Idempotent: re-running picks up where it left off.  Does NOT enable
# any systemd services; the operator runs the final `systemctl enable
# --now` commands printed at the end so unattended re-runs can't
# silently start a node with the wrong config.

set -euo pipefail

FROM_GIT="https://github.com/ben-arnao/MessageChain.git"
PIN_TAG=""
ALLOW_MAIN=0

# --------------------------------------------------------------------
# Pinned MessageChain release signers (SSH allowed-signers format).
#
# MUST stay in sync with messagechain/release_signers.py::ALLOWED_SIGNERS.
# A test (tests/test_install_validator_signers.py) asserts byte-for-byte
# equality, so a divergence between the two fails CI before it can ship.
#
# Why pinned in the script and not fetched at runtime: the adversary
# model here is a compromised GitHub account / repo / branch-protection.
# Fetching the signers list from the repo we're about to install would
# be circular -- the same compromise that lets an attacker push a
# malicious tag also lets them push a malicious signers file.  Pinning
# the signers in the bootstrap script means the operator's only trust
# root at install time is whatever delivered the script (HTTPS to
# raw.githubusercontent.com, or a hash-checked local copy).
# --------------------------------------------------------------------
read -r -d '' PINNED_ALLOWED_SIGNERS <<'PINNED_SIGNERS_EOF' || true
arnaoben@gmail.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfTiMyb62l842YJvhOb3BTuizxEJgFtAGpif/u4SWd1 arnaoben@gmail.com (MessageChain release signer)
PINNED_SIGNERS_EOF

usage() {
    cat <<EOF
Usage: sudo ./install-validator.sh [--from-git <url>] [--tag <vX.Y.Z-mainnet>] [--allow-main]

Clones MessageChain into /opt/messagechain at the latest signed
\`vX.Y.Z-mainnet\` tag, verifies the tag against pinned release
signers, installs it, and runs \`messagechain init\` to lay out the
data dir, keyfile, onboard config, and systemd units.

Options:
  --from-git <url>           Clone + install from a git URL
                             (default: upstream MessageChain repo)
  --tag <vX.Y.Z-mainnet>     Pin to a specific signed tag instead of
                             auto-resolving the latest.  Useful for
                             reproducing a known-good install.
  --allow-main               Skip tag resolution and install from the
                             repo's default branch.  No signature
                             verification.  TESTING ONLY -- never use
                             on a real validator.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from-git)
            FROM_GIT="$2"
            shift 2
            ;;
        --tag)
            PIN_TAG="$2"
            shift 2
            ;;
        --allow-main)
            ALLOW_MAIN=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "This script must run as root (sudo)." >&2
    exit 1
fi

# --------------------------------------------------------------------
# Resolve the target ref.
#
# Default: highest-semver `vX.Y.Z-mainnet` tag reachable via
# `git ls-remote --tags`.  Same canonical-tag pattern the upgrade CLI
# uses, so a fresh install lands on exactly the version that the
# weekly auto-upgrade timer would converge to anyway.
# --------------------------------------------------------------------
resolve_latest_tag() {
    # Format: <sha>\trefs/tags/<name>(\^\{\})?
    # `^{}` is the dereferenced tag object; we only want the names, so
    # strip both the SHA prefix and the `^{}` suffix, then filter.
    git ls-remote --tags "$FROM_GIT" 2>/dev/null \
        | awk '{print $2}' \
        | sed -e 's#refs/tags/##' -e 's#\^{}$##' \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-mainnet$' \
        | sort --version-sort \
        | tail -n 1
}

if [ "$ALLOW_MAIN" -eq 1 ]; then
    if [ -n "$PIN_TAG" ]; then
        echo "--allow-main and --tag are mutually exclusive" >&2
        exit 2
    fi
    TARGET_REF="HEAD"
    REF_DESCRIPTION="(default branch -- UNVERIFIED, --allow-main set)"
else
    if [ -n "$PIN_TAG" ]; then
        TARGET_REF="$PIN_TAG"
    else
        echo "Resolving latest vX.Y.Z-mainnet tag from $FROM_GIT..."
        TARGET_REF="$(resolve_latest_tag)"
        if [ -z "$TARGET_REF" ]; then
            echo "no canonical vX.Y.Z-mainnet tags found at $FROM_GIT" >&2
            echo "rerun with --tag <vX.Y.Z-mainnet> to pin explicitly" >&2
            exit 3
        fi
    fi
    REF_DESCRIPTION="(signed mainnet tag)"
fi
echo "Target: $TARGET_REF $REF_DESCRIPTION"

echo "[1/7] Creating messagechain system user if missing..."
if ! id -u messagechain >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin messagechain
fi

echo "[2/7] Laying out directories..."
mkdir -p /opt/messagechain /var/lib/messagechain /etc/messagechain
chown -R messagechain:messagechain /opt/messagechain /var/lib/messagechain
chown root:messagechain /etc/messagechain
chmod 0750 /etc/messagechain

echo "[3/7] Cloning $FROM_GIT @ $TARGET_REF..."
if [ ! -d /opt/messagechain/.git ]; then
    rm -rf /opt/messagechain
    if [ "$ALLOW_MAIN" -eq 1 ]; then
        git clone "$FROM_GIT" /opt/messagechain
    else
        # --branch accepts both branch names and tag names.  Cloning
        # at the tag (not the branch tip) is what makes the signature
        # verify in step 4 meaningful: a malicious commit pushed to
        # main between resolution and clone is not what gets installed.
        git clone --branch "$TARGET_REF" "$FROM_GIT" /opt/messagechain
    fi
    chown -R messagechain:messagechain /opt/messagechain
fi

echo "[4/7] Verifying $TARGET_REF signature against pinned release signers..."
if [ "$ALLOW_MAIN" -eq 1 ]; then
    echo "  SKIPPED -- --allow-main is set.  Do not use for a real validator."
else
    SIGNERS_FILE="$(mktemp -t mc-allowed-signers.XXXXXX)"
    # shellcheck disable=SC2064  # want SIGNERS_FILE expanded NOW
    trap "rm -f '$SIGNERS_FILE'" EXIT
    printf '%s\n' "$PINNED_ALLOWED_SIGNERS" > "$SIGNERS_FILE"
    # Override any operator-level allowedSignersFile so only the pinned
    # set decides outcome.  --git-dir + --work-tree avoid relying on
    # ambient cwd (script may be invoked from anywhere).
    if ! GIT_VERIFY_OUT="$(
        git --git-dir=/opt/messagechain/.git \
            --work-tree=/opt/messagechain \
            -c "gpg.ssh.allowedSignersFile=$SIGNERS_FILE" \
            -c "gpg.format=ssh" \
            tag -v "$TARGET_REF" 2>&1
    )"; then
        echo "FATAL: tag $TARGET_REF failed signature verification:" >&2
        echo "$GIT_VERIFY_OUT" >&2
        exit 4
    fi
    if ! printf '%s' "$GIT_VERIFY_OUT" | grep -qi 'good'; then
        echo "FATAL: tag $TARGET_REF verified with unexpected output:" >&2
        echo "$GIT_VERIFY_OUT" >&2
        exit 4
    fi
    echo "  Signature OK."
fi

echo "[5/7] Installing MessageChain..."
cd /opt/messagechain
# Non-editable install: site-packages owns the runtime copy, so a
# stray `git pull` in /opt/messagechain doesn't silently change what
# the validator runs on next restart.  `messagechain upgrade` remains
# the only sanctioned mutation path.
# --break-system-packages lets Debian/Ubuntu's pip write to
# site-packages on PEP 668 systems; harmless on distros that don't
# know the flag.
pip install . --break-system-packages 2>/dev/null || pip install .

echo "[6/7] Running messagechain init..."
python3 -m messagechain init --yes --systemd

# Init runs as root and writes root-owned files; the validator service
# runs as user `messagechain` so it must be able to read them.
chown messagechain:messagechain /etc/messagechain/keyfile
chown root:messagechain /etc/messagechain/onboard.toml
chmod 0640 /etc/messagechain/onboard.toml

echo "[7/7] Reloading systemd daemon..."
systemctl daemon-reload

cat <<'EOF'

Done.

Next steps (run these as root):

  systemctl enable --now messagechain-validator
  systemctl enable --now messagechain-upgrade.timer
  systemctl enable --now messagechain-rotate-key.timer

Check status with:
  messagechain status
  messagechain doctor

Back up the following BEFORE staking — losing them after stake lands is
unrecoverable, and a keyfile-only restore on a fresh disk WILL trigger
a 100% slash for WOTS+ leaf reuse:

  /etc/messagechain/keyfile             (validator identity, hex secret)
  /var/lib/messagechain/leaf_index.json (block-signing leaf watermark)
  /var/lib/messagechain/receipt_leaf_index.json (receipt-signing watermark)

The leaf-index files record which one-time WOTS+ leaves the keyfile has
already burned.  Restore them together or not at all.  See README.md
"Operating a live validator -> Back up the keyfile AND the leaf-index
files" for the full backup/migration recipe.
EOF
