# MessageChain Security Model

What the chain defends against, what it doesn't, and how to scope an
external security audit.

---

## Goals (in priority order)

1. **Messages are permanent and uncensorable forever.**  A committed
   message cannot be erased by any party, at any time, under any
   adversarial condition short of global compromise of the active
   validator set.
2. **Timestamps are trustworthy.**  A reader can look at a tx and
   know it was committed within a bounded wall-clock window of the
   claimed timestamp.
3. **Post-quantum security.**  The chain survives a sufficiently-large
   quantum computer without emergency measures.  No elliptic-curve
   dependency.
4. **Minimal dependencies for 1000-year stability.**  Any dep we take
   is a bet that the dep (or a maintained replacement) exists in
   2125.  Today: zero runtime deps outside Python stdlib.

---

## Threat model

### In scope (we defend against)

| Threat | Defense |
|---|---|
| **Quantum computer breaks ECDSA** | WOTS+ hash-based signatures; no EC assumption anywhere in the chain |
| **Proposer includes a forged tx** | WOTS+ signature verification on every tx at both mempool admission and block validation; signatures committed into merkle_root |
| **Proposer includes a double-spend / invalid tx** | Balance + nonce + state-root checks at block validation; reject the block, not just the tx |
| **WOTS+ leaf reuse (catastrophic if successful)** | Per-entity leaf watermark stored in state; block-level seen-leaves set; reject second use of any (entity, leaf) pair |
| **Replay across chains (testnet → mainnet)** | CHAIN_ID committed into every signable_data; signatures on one chain don't verify on another |
| **Replay across sig-version eras** | SIG_VERSION committed into every signable_data; post-upgrade sigs don't verify against pre-upgrade code |
| **Long-range / history-rewrite attack** | Weak-subjectivity checkpoints (TRUSTED_CHECKPOINTS in config), finalized_by_height ratchet, reorg rejection below finalized height |
| **Single proposer censors a tx** | Forced-inclusion rule: attesters that see a tx waiting > 3 blocks require the next proposer to include it |
| **Single malicious peer floods us with junk** | Per-peer ban manager + offense scoring, rate limits per message category, oversized-payload rejection, RPC read timeout, slow-loris drop at 30s |
| **P2P handshake spoofing** | TOFU cert-to-entity binding (CertificatePinStore stores `{fingerprint, entity_id}` pairs; mismatched reconnect drops the peer) |
| **Treasury overspend by governance** | 2/3 supermajority of total eligible stake; spends deterministically ordered within a block; snapshot stake frozen at proposal creation |
| **Reorg re-spending stake** | Immature rewards + seen-evidence + processed-evidence sets are reorg-durable; slashing is a security ratchet that doesn't reverse across forks |
| **Validator equivocation (double-sign)** | Auto-generated slashing evidence from seen_signatures table; verified cryptographically, 100% stake burned + 10% finder reward |
| **Fee-market manipulation** | Base-fee capped above (MAX_BASE_FEE_MULTIPLIER=10000×MIN_FEE) and below (MIN_FEE); 12.5%/block max change; EIP-1559 style |
| **Governance-spam DoS** | MAX_ACTIVE_PROPOSALS=500 cap, PROPOSAL_FEE=10,000 (spam deterrent), VOTING_WINDOW=~7 days |
| **Validator-rotation race** | Per-validator leaf watermark + rotation_count committed into state_tree leaf; divergence detected at state_root verification |
| **Timestamp-skew slot hijack** | MAX_PROPOSER_FALLBACK_ROUNDS=5 cap on how many rounds a proposer can claim via future-dated timestamp |
| **Mempool memory DoS** | Aggregate pending-pool cap + global-min-fee eviction; orphan pool bounded; sync.peer_heights LRU-capped; mempool-digest maps capped at 4×MAX_PEERS |
| **Byzantine-split finality** | FinalityCheckpoints (persistent, reorg-durable); FinalityTracker (in-memory, snapshotted on reorg rollback) |
| **Hot-key compromise** | Cold-key authority signs Revoke / SetAuthorityKey; Shamir 2-of-3 split means 1 share compromise insufficient |
| **Supply-chain attack via deps** | Zero runtime deps — stdlib only |
| **Tampered keypair cache / Merkle cache on disk** | HMAC-SHA3-256 authentication of cache files with key derived from private_key; tampered cache fails load, triggers rebuild |
| **World-writable chain.db on VM** | ChainDB init checks file mode, logs ERROR naming the file + fix command if world-writable |
| **Schema drift across validator binaries** | `meta.schema_version` stamped on first DB init, checked on every open; mismatch raises RuntimeError |

### Accepted / out of scope (we do NOT defend against)

| Threat | Why accepted |
|---|---|
| **Message content privacy** | Messages are public.  Encrypt at app layer before submit. |
| **Sender identity privacy** | Public keys are bound to messages by design (append-only attribution).  Use fresh keys per message for pseudonymity. |
| **Relay-layer censorship by a relay majority** | Partial defense via forced-inclusion; full defense requires out-of-scope crypto (anonymous broadcast) or slashing-for-non-relay (cryptographically impossible to prove absence) |
| **51% of stake colludes to rewrite history past finality** | No chain defends against majority-stake coordinated attack.  Mitigations: long finality window, weak-subjectivity checkpoints, monitored validator diversity |
| **Founder operates pseudo-independent validators during bootstrap** | Bootstrap explicitly trusts the founder.  Divestment only applies to the one tracked genesis seed.  Good-faith founder requirement, not protocol-enforced. |
| **Lost cold key** | No recovery.  Operator must use Shamir distribution (2-of-3 across named holders in different jurisdictions).  If shares are lost, the affected entity's stake enters permanent unbonding. |
| **Lost hot key without cold-key revoke** | Hot key comes from operator's secrets backend (GCP Secret Manager on the reference validator).  If both the secret store and the cold key are lost, the validator is dead. |
| **Mempool frontrunning** | Fees are first-price + FIFO within same fee tier.  No MEV defense specifically — MEV surface is near-zero on a message-chain (no DEX, no liquidations). |
| **Network-level denial of service** | Out-of-scope for the protocol layer.  Use infrastructure-level mitigation (Cloudflare, DDoS protection) at the operator's discretion. |
| **Full chain-data loss on every node simultaneously** | Daily disk snapshots + multi-validator redundancy (post-bootstrap) are the mitigation.  Protocol doesn't recover from a global data apocalypse. |
| **Compromised compiler / language runtime** | Python runs from source.  A compromised CPython would compromise the chain like any other Python program. |

---

## Scope for external audit

Recommended scope for a 4-8 week external engagement:

### Primary scope (must-audit)

- `messagechain/core/blockchain.py` — block validation, apply, reorg, snapshot
- `messagechain/core/transaction.py` / `transfer.py` / `staking.py` — tx types + signing
- `messagechain/core/block.py` — block structure, merkle, serialization
- `messagechain/crypto/keys.py` / `hash_sig.py` / `merkle_cache.py` — WOTS+ + hash primitives
- `messagechain/consensus/*.py` — attestation, finality, slashing, proposer selection, bootstrap gradient
- `messagechain/governance/governance.py` — proposal/vote/treasury spend
- `messagechain/storage/chaindb.py` — persistence, schema, pruning capability
- `messagechain/network/node.py` / `protocol.py` / `sync.py` / `ban.py` — P2P layer
- `server.py` — RPC handler, auth, rate limiting
- `messagechain/identity/identity.py` / `address.py` — address derivation, checksum

### Secondary scope (should-audit)

- Deploy scripts: `deploy/launch_single_validator.py`, `deploy/cold_key_ceremony.py`
- CLI: `messagechain/cli.py` — operator tooling, flag surface
- Config profiles: `messagechain/config.py` profile logic + env overrides
- SystemD unit + local secret fetch (not in git, inspected on VM)

### Out of audit scope (explicitly)

- Python runtime, stdlib cryptography module
- GCP / cloud provider infrastructure
- Operator personal key-handling practices (the ceremony runbook is
  audited; adherence to it isn't)

---

## Cryptographic assumptions

The chain's security relies on:

1. **SHA3-256 is a secure hash function.**  Collision resistance,
   preimage resistance.  (If broken, HASH_VERSION_CURRENT bump + governance
   migration.)
2. **WOTS+ with our parameters (W=16, 64 chains, tree heights 6–20) is
   EUF-CMA secure under SHA3-256.**  This is the PQ-security assumption.
3. **HMAC-SHA3-256 is a secure MAC.**  Used for keypair cache and Merkle
   cache authentication on disk.
4. **secrets.SystemRandom() provides cryptographically secure randomness.**
   Used for fresh keypair seeds, per-process nonces, and CLI validator
   selection.

If any of these is broken, the chain needs a governance-gated migration.
The version bytes (HASH_VERSION, SIG_VERSION) are in place to support
that migration.

---

## Responsible disclosure

Security findings: file an issue at
https://github.com/ben-arnao/MessageChain/issues with the label
`security` — or if confidential, email the repository owner
directly before public disclosure.
