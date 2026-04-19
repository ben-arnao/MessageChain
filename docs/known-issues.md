# Known Issues and Design Trade-offs

Every concern raised across 33 audit iterations that wasn't fixed,
with rationale.  Two categories:

- **Design choice** — works as intended.  Keep.
- **Deferred** — real improvement, skipped this launch for cost/benefit
  reasons.  Post-launch roadmap lines.

If you are an external auditor: this is the honest state.  Nothing
below is an undisclosed vulnerability; everything is either an
intentional trade-off the team has agreed to or a tracked follow-up.

---

## Design choices (working as intended)

### Permanent history, no pruning, no rent
- Per the project's first principle ("messages permanent and uncensorable
  forever"), the reference validator never invokes `prune()`.  This
  produces chain-DB growth linear in block history forever.
- Operator impact: an archive validator in year 100 stores every message
  and every signature ever produced.  This is the cost of the guarantee.
- `messagechain/storage/pruning.py` exists as a capability for
  relay-only nodes that explicitly do not uphold the permanence
  guarantee (e.g., memory-constrained full nodes used for relaying but
  not archival).

### Genesis block timestamp is wall-clock
- `create_genesis_block()` uses `time.time()`, so two independent mints
  would produce different block-0 hashes.  This matters only if multiple
  operators mint independently; the single-founder launch model
  prevents that by construction.
- All other nodes sync block 0 from peers and verify against the
  committed `_MAINNET_GENESIS_HASH` — no re-mint happens elsewhere.

### Founder can run multiple pseudo-independent validators during bootstrap
- During the 2-year bootstrap window, there is no protocol-level anti-sybil
  mechanism preventing the founder from operating multiple validator
  identities.  The bootstrap model explicitly trusts the founder.
- Post-bootstrap, divestment (seeded only on the original genesis entity)
  forces the founder's one tracked identity to 1 M stake floor.  Any
  pseudo-independent identity the founder spawned is NOT tracked as a
  seed and therefore NOT subject to divestment — the founder CAN retain
  power via those sybils if they choose.
- This is by design: bootstrap trusts the founder, ramp to
  decentralization assumes a good-faith founder who drains their own
  influence.  An adversarial founder who also controls governance and
  refuses to divest is a governance problem, not a protocol bug.

### NEW_ACCOUNT_FEE is entirely burned, not shared with proposer
- Per the user's principle "fight bloat only via fees and storage
  optimization, never optimize for cheapness at the expense of security."
  The NEW_ACCOUNT_FEE (1,000 tokens) is burned to make permanent-state
  creation expensive.  Paying a share to the proposer would weaken the
  burn-as-deterrent model.
- The proposer is paid through the BLOCK_REWARD + the TIP portion of
  fees above base_fee.

### Cold-key exhaustion has no automatic recovery
- The cold authority key is a WOTS+ keypair of its own.  If it signs
  enough emergency-revoke / set-authority-key transactions to exhaust
  its leaves, there's no protocol-level recovery — the authority is
  dead.
- At tree_height=6 (default cold-key size in the ceremony), that's 64
  lifetime cold-key operations.  Over a 100-year chain that's
  essentially never-going-to-happen for a properly-designed ceremony.
- If the exhaustion happens anyway, it's operationally indistinguishable
  from a lost cold key — chain continues; affected entity's stake
  enters permanent unbonding.

### Relay-layer censorship is a threat-model choice
- A majority of P2P relays refusing to forward a specific entity's txs
  is possible in the abstract.  The on-chain defense is `forced_inclusion.py`:
  if an honest attester receives a tx and it goes un-included for 3
  blocks, the next proposer must include it.
- Fully solving relay-layer censorship requires either (a) slashing for
  failure to relay (cryptographically infeasible — impossible to prove a
  negative) or (b) anonymous/Tor broadcast so the relay set can't
  distinguish the sender (partially available via `docs/tor-setup.md`).
- Mitigation at scale: increase validator count past the point where a
  censorship cartel becomes expensive.  At N=3, the cartel needs 2/3+;
  at N=100 it needs 67+ coordinating.  At launch with N=1, censorship
  resistance is purely the founder's responsibility — the same posture
  as every other bootstrap-phase chain.

### Dusting attacks cannot be refused
- The receive-to-exist model means a recipient gets a state entry on
  first incoming transfer.  A malicious sender could spam N different
  addresses to create N state entries.  MAX_NEW_ACCOUNTS_PER_BLOCK=10
  + NEW_ACCOUNT_FEE=1000 (burned) make this expensive.
- An opt-in "accept transfers from X" model would add huge complexity
  (second-party state).  The fee-based deterrent is simpler.

### Block pruning deletes block body data if enabled
- `prune_block_to_header()` deletes block bodies when called.  It is
  never called by the reference validator.  If a relay-only node
  operator deliberately enables pruning, they lose the ability to serve
  message plaintext for pruned blocks.  This is documented in
  `messagechain/storage/pruning.py` as an operator choice.

---

## Deferred (real improvement, skipped for now)

### Per-transaction hash_version commitment
- `Transaction._signable_data()` commits `sig_version` but not
  `hash_version`.  Governance-bumping HASH_VERSION_CURRENT (e.g., when
  SHA3-256 needs replacement in 2100) leaves old transactions without
  a scheme label.
- Why deferred: adding `hash_version` to signable_data changes every
  transaction's hash.  Retroactive application to the live mainnet
  would re-hash every committed tx, breaking every merkle root in the
  chain's history.
- Path forward: include `hash_version` in the signable_data of
  SIG_VERSION_CURRENT=2 when we bump the sig scheme.  Until then, the
  block-level `hash_version` byte (which IS committed) is the era
  indicator.

### Attestation signature growth at full attester load
- Each WOTS+ signature at tree_height=16 is ~2.5 KB.  At 100-attester
  committees and 52,560 blocks/yr that's ~12 GB/yr of attestation
  signatures alone.  Over 20 years = ~240 GB.
- Why deferred: compressing attestation signatures, or storing them
  in a sidecar archive keyed by block hash (keeping only metadata in
  the block), is a storage-layer redesign.  Not a line-level fix.
- Path forward: post-launch optimization budget.  Likely: after
  finality + N confirmations, attestation sigs migrate from block body
  to `attestations_archive` table.  Archive validators continue to
  serve them on request.  No consensus impact.

### `_SCHEMA_VERSION` migration framework
- Schema version is now checked on DB open (iter 18 fix).  A mismatch
  raises.  But there's no migration framework — if v1 → v2 adds a column,
  we need to WRITE the migration before bumping.
- Why deferred: nothing in flight needs a migration yet.  The stub
  check protects against accidental cross-version opens; the real
  migration code is TBD for the first ALTER.

### Single-shared mempool vs per-validator mempool
- The mempool today is a single logical pool.  A validator at very
  high tx load could be memory-pressured by spam even with the
  aggregate cap.
- Why deferred: our spec is slow blocks + high fees.  The natural
  MAX_TXS_PER_BLOCK=20 + MIN_FEE=100 cap keeps mempool sizes tiny in
  practice.  This is a concern for a million-TPS chain, not us.

### Cold-key rotation
- Cold key can sign Revoke + SetAuthorityKey.  But the cold key
  itself can't be rotated — the protocol has no "rotate-cold-key"
  operation.  If the cold key is compromised, the only path is
  SetAuthorityKey-via-old-cold-key to a new cold key.  If the cold
  key is LOST (not compromised), there's no recovery.
- Why deferred: 2-of-3 Shamir in the ceremony makes this small-prob.
  A cold-key self-rotation would add a second cold-key tree at genesis
  that must survive forever — weakens the single-commitment security
  model.

### Mempool persistence
- Mempool save/load functions exist (`mempool.save_to_file`,
  `load_from_file`) but are deliberately not wired into server
  start/stop.  A persisted mempool replays stale txs against a chain
  that moved forward (wrong nonce, stale fee, or already-confirmed).
- Why deferred: the correct design.  Operational rule is "on restart,
  pending txs are rebroadcast by their original senders."  Functions
  stay available for manual ops (forensics, debug).

### hash algorithms beyond SHA3-256
- HASH_ALGO = "sha3_256" is the single choice.  No runtime selection
  of a different hash.
- Why deferred: SHA3-256 is what we need for a decade-plus.  The
  version byte (`HASH_VERSION_CURRENT`) + validation gate
  (`validate_hash_version`) are in place so a governance-gated
  migration is possible when needed.  Actual new hash code is written
  at the time of the migration.

---

## Deliberately NOT addressed (out of scope)

### Anonymity / privacy
- Messages are public and permanent.  The chain is append-only
  plaintext.  Private messaging over the chain is not a goal.  If
  needed, encrypt at the application layer before `messagechain send`.

### Sub-second block times
- Counter to the "naturally slow" principle.  600s blocks are the
  spec.

### Dynamic block size / tx count
- MAX_TXS_PER_BLOCK=20 and MAX_BLOCK_MESSAGE_BYTES=10,000 are fixed.
  Governance can change these, but the defaults are conservative.

### Off-chain scaling (state channels, rollups)
- This is a base-layer message chain.  The throughput target is
  low-and-durable, not high-TPS.

### Alternative crypto suites (ed25519, BLS, etc.)
- Pre-quantum crypto is a non-starter.  WOTS+ was chosen deliberately.
