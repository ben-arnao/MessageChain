"""Generate a faucet wallet key and push private material to GCP Secret Manager.

Usage:  python scripts/generate_faucet_key.py <gcp-project> <secret-name>

Prints the 32-byte public key (hex) on stdout. Private material -- the
24-word BIP-39 phrase, the hex-checksummed format, and the raw 64-char
hex the daemon consumes -- is sent straight to
`gcloud secrets versions add --data-file=-` via stdin.  The secret
never touches the filesystem and the only thing this script writes
to stdout/stderr is the public key + the gcloud confirmation line.
The script's process memory holds the private key briefly, then exits.

Tree height is forced to 16 (65,536 lifetime signatures), which is
plenty for years of bootstrap drips at the FAUCET_WINDOW_DRIPS rate
(4 drips / 15 min = 384 drips/day worst case, ~170 days to leaf
exhaustion at full saturation -- a comfortable rotation runway).
Cold keygen takes ~10-20 minutes at this height; warm restarts hit
the keypair cache and are instant.  Override via env var
$MESSAGECHAIN_MERKLE_TREE_HEIGHT before invoking if needed; do NOT
change after generation since the same height must be supplied at
sign time to rebuild the same Merkle tree (silent pubkey divergence
otherwise).

Operator deployment workflow:
  1. python scripts/generate_faucet_key.py <project> mc-faucet-key
     -> records the public key (hex) printed on stdout; that is the
     entity_id-derivation pubkey to fund.
  2. Update the validator's deploy script to fetch the secret to
     /dev/shm/mc-faucet-key (raw hex, 0400 mode) at boot and pass
     --faucet-keyfile /dev/shm/mc-faucet-key to server.py.
  3. Restart the validator; it generates the keypair (slow first
     time) and the faucet sits idle waiting for funds.
  4. From any wallet with sufficient balance, transfer enough
     tokens to cover the desired drip runway:
        messagechain transfer --to <faucet-pubkey> --amount <N>
     A common starting allocation is FAUCET_DRIP * 2000 = 600,000
     tokens (~5 days at the per-window cap, 4 drips / 15 min).
  5. POST {"address": "<entity_id_hex>"} to /faucet on the public
     feed to verify a drip lands.
"""

import os
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: generate_faucet_key.py <gcp-project> <secret-name>",
            file=sys.stderr,
        )
        return 2

    project = sys.argv[1]
    secret_name = sys.argv[2]

    os.environ.setdefault("MESSAGECHAIN_MERKLE_TREE_HEIGHT", "16")

    from messagechain.identity.identity import Entity
    from messagechain.identity.key_encoding import encode_private_key
    from messagechain.identity.mnemonic import encode_to_mnemonic

    key = os.urandom(32)
    entity = Entity.create(key)
    mnemonic = encode_to_mnemonic(key)
    encoded_hex = encode_private_key(key)

    payload = (
        f"# MessageChain faucet wallet key\n"
        f"# Tree height: 16\n"
        f"# Public key: {entity.public_key.hex()}\n"
        f"# Entity ID:  {entity.entity_id_hex}\n"
        f"#\n"
        f"# DO NOT store this material outside Secret Manager.  This\n"
        f"# wallet drips bootstrap funds to anyone who hits POST\n"
        f"# /faucet -- a leaked private key drains the faucet within\n"
        f"# minutes.  Treat as you would the cold authority key.\n"
        f"\n"
        f"recovery_phrase: {mnemonic}\n"
        f"private_key_hex: {encoded_hex}\n"
        f"private_key_raw: {key.hex()}\n"
    )

    gcloud_bin = os.environ.get(
        "GCLOUD_BIN",
        "gcloud.cmd" if os.name == "nt" else "gcloud",
    )
    proc = subprocess.run(
        [
            gcloud_bin, "secrets", "versions", "add", secret_name,
            f"--project={project}",
            "--data-file=-",
        ],
        input=payload,
        text=True,
        check=False,
    )

    del payload
    del mnemonic
    del encoded_hex
    del key

    if proc.returncode != 0:
        print(
            f"error: gcloud secrets versions add exited {proc.returncode}",
            file=sys.stderr,
        )
        return proc.returncode

    print(entity.public_key.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
