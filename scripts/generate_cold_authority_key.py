"""Generate a cold authority key and push private material to GCP Secret Manager.

Usage:  python scripts/generate_cold_authority_key.py <gcp-project> <secret-name>

Prints the 32-byte public key (hex) on stdout. Private material — the
24-word BIP-39 phrase and the hex-checksummed private key — is sent
straight to `gcloud secrets versions add --data-file=-` via stdin.
The secret never touches the filesystem and the only thing this
script writes to stdout/stderr is the public key + the `gcloud`
confirmation line. The script's process memory holds the private
key briefly, then exits.

Tree height is forced to 8 (256 lifetime signatures) since the cold
key only signs rare authority operations: set-authority-key,
unstake, emergency-revoke. Override with $MESSAGECHAIN_MERKLE_TREE_HEIGHT
if a different cap is wanted before invoking; do NOT change after
generation since the same height must be supplied at sign time to
rebuild the same Merkle tree.
"""

import os
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: generate_cold_authority_key.py <gcp-project> <secret-name>",
            file=sys.stderr,
        )
        return 2

    project = sys.argv[1]
    secret_name = sys.argv[2]

    os.environ.setdefault("MESSAGECHAIN_MERKLE_TREE_HEIGHT", "8")

    from messagechain.identity.identity import Entity
    from messagechain.identity.key_encoding import encode_private_key
    from messagechain.identity.mnemonic import encode_to_mnemonic

    key = os.urandom(32)
    entity = Entity.create(key)
    mnemonic = encode_to_mnemonic(key)
    encoded_hex = encode_private_key(key)

    payload = (
        f"# MessageChain cold authority key\n"
        f"# Tree height: 8\n"
        f"# Public key: {entity.public_key.hex()}\n"
        f"# Entity ID:  {entity.entity_id_hex}\n"
        f"#\n"
        f"# DO NOT store this material outside Secret Manager. Treat as\n"
        f"# the recovery phrase for an offline cold wallet.\n"
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
