"""Pinned authorized release-tag signers for ``messagechain upgrade``.

Baked-in SSH pubkey(s) whose signatures authorize a ``vX.Y.Z-mainnet``
tag for automated installation.  The upgrade CLI refuses to install
any tag not signed by one of these keys — a tag pushed by anyone
else, even with repo write access, is treated as a supply-chain
compromise attempt and rejected before the clone is swapped into
place.

Why pinned-at-binary rather than fetched: the adversary model here
is a compromised GitHub account / token / branch-protection bypass.
A key file fetched from the same repo (or from any online source
tied to repo credentials) would be compromised in the same attack.
Binding the allowed signers to the already-installed binary means
the attacker must also compromise the running validator's on-disk
code — at which point they already have what the upgrade would give
them and don't need the upgrade path.

To rotate or add a signer: edit this file in a release commit,
tag that commit under an existing allowed signer, and cut a normal
release.  Validators running the old binary will refuse the new
signer's tags until they upgrade past this commit — which is the
intended behavior (single-path key rotation, no trust-on-first-use).
"""

# SSH allowed-signers file format, exactly as git(1) expects with
# ``gpg.ssh.allowedSignersFile``.  Each non-comment line:
#   <principal> [namespaces="<ns>"] <ssh-keytype> <base64-pubkey> <comment>
# ``namespaces="git"`` restricts the key to git object signing so it
# can't double as an SSH login key for the same principal.
ALLOWED_SIGNERS = b"""\
arnaoben@gmail.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfTiMyb62l842YJvhOb3BTuizxEJgFtAGpif/u4SWd1 arnaoben@gmail.com (MessageChain release signer)
"""
