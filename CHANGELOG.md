# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.82.0] — 2026-05-13

Audit r54 top-3 ships alongside the first three commits of the new
wallet-UI scaffolding: one consensus-visible economics retune that
closes the last unbounded direct-mint path on the issuance side
(new Tier 76 hard fork, activation height 14500), one structural
security-pipeline fix that unifies the WOTS+ leaf-reservation
chokepoint across every signing command (soft, no fork), and one
value-prop fix that lifts the social-primitive flag surface
(--prev / --community-id / --poll-option / --vote-target) onto
the censorship-resistant `send-multi` escape hatch (soft, no fork).

### Added

  * **Local wallet UI scaffolding (`messagechain ui` CLI +
    `LocalWalletServer`).** Empty-shell HTTP server that the future
    browser-side wallet front-end will consume. Three commits land
    incrementally: the empty shell + `messagechain ui` subcommand
    (fe7d9d8), four read endpoints (`/v1/info`, `/v1/latest`,
    `/v1/entity`, `/v1/tx_status`) consumed via the same JSON-RPC
    fan-out as the public feed (b86a103), and keyfile-load +
    `/wallet/me` so the operator's local UI can identify itself
    without an interactive prompt (74dcff5). No wire-format change,
    no consensus rule change; net-new optional surface only.

### Changed (Tier 76, consensus-breaking, height-gated)

  * **Finality-vote inclusion-reward per-block cap (audit r54 #1 --
    economics top-1).** CLAUDE.md pillars at risk: "Mathematical
    decentralization over time" + "Stable active supply".

    Pre-Tier-76, ``_apply_finality_votes`` minted
    ``FINALITY_VOTE_INCLUSION_REWARD = 1`` tokens of direct mint to
    the proposer for EVERY survivor of the pre-filter, up to
    ``MAX_FINALITY_VOTES_PER_BLOCK = 200``. The mint never routed
    through any of the issuance-discipline plumbing every other
    reward path now goes through: ``_split_bps`` (Tier 73/74/75
    round-to-zero clamp + supply-conservation invariant),
    ``effective_weight`` (Tier 70/71 stake-concentration soft cap),
    the ``mint_block_reward`` per-block-cap / redistribute logic, or
    the ``DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500`` dormancy
    controller clamp.

    Whale proposers received a per-vote inclusion bonus that scaled
    linearly with their proposer-slot share (itself sublinear via
    Tier 70/71 effective_weight) -- the linear-on-top compounded
    back toward the plutocracy regime Tier 70 anchored against. And
    200 tokens/block of mint outside the dormancy controller's
    regulated band leaked the anchored issuance envelope: at the
    controller's small-issuance steady state (~50 tokens/block) the
    finality-mint actually dominated the bounded path 4:1.

    Tier 76 caps the per-block finality-mint TOTAL at
    ``FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS =
    MAX_FINALITY_VOTES_PER_BLOCK // 8`` = 25. Cap is grounded in the
    DoS-guard cap (``MAX_FINALITY_VOTES_PER_BLOCK``), not a magic
    number. Pre-fork: byte-identical to legacy at every (n_votes,
    ...) combination so historical-block replay matches. Post-fork:
    the first ``cap`` survivors mint
    ``FINALITY_VOTE_INCLUSION_REWARD`` each; further survivors
    still contribute to the 2/3 finality tally (checkpoint
    safety/liveness uncapped on purpose -- finalization must still
    cross 2/3 at high vote count) but produce no mint -- the
    inclusion service is unpaid past the budget. Honest proposers
    including <= 25 votes/block see zero change; whales packing 200
    votes/block see their bonus capped at 25.

    Activation height ``14500`` sits 2000 blocks above Tier 75
    (12500), matching the Tier 70 -> 71 -> 73 -> 74 -> 75 ~13.9-day
    cohort spacing. (87ca207)

### Fixed

  * **``_resolve_signing_leaf`` chokepoint -- atomic WOTS+ leaf
    reservation on every signing command (audit r54 #2 -- security
    top-1).** CLAUDE.md anchors: honest-operator-insurance +
    crypto-agility.

    Pre-fix only ``cmd_send`` / ``cmd_transfer`` / ``cmd_stake`` /
    ``cmd_submit_evidence`` (4 commands) called
    ``_reserve_leaf_via_rpc`` -- the server-side atomic primitive
    that closes the CLI-vs-daemon race where two processes pick the
    same chain watermark and each sign a different tx at the same
    WOTS+ leaf (publishing both signatures discloses the leaf's
    private chunks -- 100% slash on detection). Every OTHER signing
    command (``cmd_unstake``, ``cmd_rotate_key``, ``cmd_react``,
    ``cmd_propose``, ``cmd_vote``, ``cmd_set_authority_key``,
    ``cmd_bootstrap_seed``, ``cmd_send_multi_submit``) only bound the
    on-disk cursor against the chain watermark -- no atomic
    reservation. Same parallel-paths defect-shape audit r46 #3
    closed for ``cmd_send_multi_submit``'s signing-pipeline
    unification, still alive on the leaf-reservation discipline.

    A vet operator running ``rotate-key`` (the crypto-agility
    primitive) or ``unstake`` on the typical co-resident validator
    host could collide with the daemon's signing loop and produce
    slashable evidence with zero malicious intent.

    Abstraction-over-symptom fix. New ``_resolve_signing_leaf(host,
    port, entity, *, data_dir, watermark_fallback)`` chokepoint --
    one helper above the four existing call sites that previously
    inlined the same pattern. Every CLI signing command now routes
    through it: ``_reserve_leaf_via_rpc`` -> watermark fallback ->
    ``_bind_persistent_leaf_index``. Cold-key signing paths
    (operator-held, not validator-daemon-managed) continue to call
    ``_bind_persistent_leaf_index`` directly with an operator-
    supplied leaf floor.

    Five tests pin the property surface, including a STRUCTURAL
    grep-based pin that no ``cmd_*`` function body still calls
    ``_bind_persistent_leaf_index`` without a chokepoint reservation
    or a documented cold-key / explicit-leaf carve-out above it.
    Soft fix: no consensus rule change, no wire-format change, no
    fork. (b007531)

  * **``send-multi`` accepts reply / community / poll / vote
    (audit r54 #3 -- value-prop top-1).** CLAUDE.md anchor:
    collective censorship-resistance via fan-out.

    Pre-fix the censorship-resistant fan-out path called
    ``create_transaction`` with no ``prev`` / ``community_id`` /
    ``poll_options`` / ``vote_target`` plumbed through, AND the
    ``send-multi`` subparser never registered those flags. Every
    social-primitive shipped on ``cmd_send`` since Tier 5
    (``--prev``), Tier 25 (``--community-id``), and Tier 72
    (``--poll-option`` / ``--vote-target``) was invisible on
    ``send-multi``. The dissident reaching for ``send-multi`` under
    pressure could not reply to a deleted-from-mainstream thread,
    post into a community, vote on a politically-charged poll, or
    create a poll -- the most-likely-to-be-suppressed message
    shapes were the only ones the suppression-resistance path
    could not transmit.

    Abstraction-over-symptom fix. Two new helpers consumed by both
    ``cmd_send`` and ``cmd_send_multi_submit``:
    ``_add_message_tx_flags(parser)`` registers --prev,
    --community-id, --poll-option, --vote-target on a subparser so
    the flag surface is DRY (adding a future social primitive adds
    it on both transports by construction); and
    ``_parse_message_tx_fields(args)`` returns the parsed
    ``(prev_bytes, community_id, poll_options, vote_target)`` tuple
    with NFC-normalization, mutual-exclusion checks, and pre-flight
    diagnostics centralized.

    ``cmd_send_multi_submit`` now parses via the shared chokepoint,
    computes prev/community/poll/vote overhead bytes for the auto-
    fee density bid (mirroring cmd_send's accounting exactly so a
    fan-out tx and a single-RPC tx with the same payload pay the
    same fee), and threads the parsed fields through
    ``create_transaction``. Eleven tests pin the parser surface,
    helper shape, NFC normalization, and an end-to-end mock-and-
    capture pin that ``cmd_send_multi_submit`` threads each field
    through to ``create_transaction``. Soft fix: no consensus rule
    change, no wire-format change, no fork. (30e5707)

## [1.81.0] — 2026-05-12

Audit r53 top-3 ships: one production-active permanence-anchor
storage fix (soft, no fork), one operator-UX fix unwedging the
README "Run a validator" first-spend flow (soft, no fork), and one
consensus-visible economics retune that closes the punishment-side
recurrence of the Tier 73/74 ``_split_bps`` defect class (new Tier
75 hard fork, activation height 12500).

### Fixed

  * **``strip_block_witnesses`` / ``get_block_witness_data`` /
    ``attach_block_witnesses`` cover every signed slot, not just
    ``block.transactions`` (audit r53 #1 -- security / long-term-
    design top-1).**  CLAUDE.md anchors at risk: chain-bloat
    discipline + hobbyist-full-node accessibility for centuries +
    the permanence-promise economics that rely on actual witness-
    separation byte savings.

    Pre-fix the strip path only iterated ``block.transactions``.
    The 14+ other signed-body slots (attestations, transfer / stake
    / unstake / governance / authority / reaction txs, finality_votes,
    slash, custody, inclusion_list, the four evidence kinds) kept
    their ~2.7 KB WOTS+ signatures inline in primary ``blocks.data``
    forever despite ``WITNESS_AUTO_SEPARATION_HEIGHT=1704`` being
    well below mainnet tip.  Attestations + finality_votes dominate
    per-block witness mass, so the auto-separation sweep was
    silently moving only ~5-20% of the witness bytes it claimed to
    offload to the side table.  Every node running past the
    activation height bled the hobbyist-accessibility anchor.

    The sibling ``strip_block_witnesses`` docstring already called
    out listing-slots-one-by-one as the defect form ("listing slots
    one-by-one was the defect form") -- the function itself was the
    named defect form.

    Abstraction-over-symptom fix.  Three changes:

      1. New ``_SIGNED_BLOCK_SLOTS`` registry in
         ``messagechain/core/witness.py`` -- single source of truth
         for every signed-body slot the witness_root commits to.
         ``enumerate_block_signatures`` is refactored to iterate
         the registry, preserving its byte-identical output order.

      2. ``strip_block_witnesses`` walks the registry and replaces
         every signed slot item's signature with the strip sentinel
         via ``dataclasses.replace``.  Future signed-body additions
         register themselves once and inherit the strip discipline
         by construction.

      3. ``get_block_witness_data`` emits a versioned v1 blob format
         (magic 0xFF + version 0x01 + per-entry slot_id/item_index/
         sig_bytes); ``attach_block_witnesses`` autodetects v1 vs
         legacy (transactions-only) and routes accordingly so
         blocks already stripped pre-fix continue to decode without
         re-strip.

    Soft fix: no consensus rule change, no wire-format change, no
    fork.  Storage-format-only.  The witness_root commitment
    recomputes from the restored block on attach exactly as before,
    so the post-activation ``WitnessRootMismatchError`` integrity
    check works unchanged for either blob shape.  Behavioral fix
    lands the moment a validator upgrades; legacy on-disk blobs
    continue to decode for the blocks already stripped pre-fix.
    (12a4899)

  * **Validator bootstrap first-spend stake admission (audit r53
    #2 -- UX / value-prop top-1).**  CLAUDE.md anchors at risk:
    Simplicity (principle #3) + validator-set growth as the
    decentralization anchor.  The README "Run a validator" flow was
    wedged at the stake step for every fresh validator install on
    mainnet.

    Pre-fix two coupled defects: ``cmd_stake`` (cli.py:4035) built
    the StakeTransaction without ``include_pubkey=True`` (audit
    r46 #3 wired ``_should_include_pubkey`` through cmd_send /
    cmd_transfer / cmd_send_multi_submit; cmd_stake was the last
    hold-out), AND ``Server._rpc_stake`` (server.py:2218) hard-
    gated on ``entity_id in self.blockchain.public_keys`` BEFORE
    consulting ``tx.sender_pubkey`` -- so even if the CLI had set
    ``include_pubkey``, admission would still reject "Unknown
    entity".

    Net effect: a fresh validator literally following the README
    -- ``generate-key`` -> fund via /faucet -> ``messagechain
    stake --amount 200`` -- got "Unknown entity" on stake.  Faucet
    funds had landed under their entity_id (transfers reveal the
    SENDER's pubkey, not the recipient's), but the very next
    signing op was rejected with no documented workaround.

    Abstraction-over-symptom fix.  ``cmd_stake`` routes through
    the shared ``_should_include_pubkey`` chokepoint every other
    signing command uses.  ``Server._rpc_stake`` resolves the
    public_key from ``public_keys.get(entity_id)`` first; if None,
    falls back to ``tx.sender_pubkey`` IFF it derives back to
    ``entity_id`` -- mirroring the audit r51 #1 chokepoint
    discipline.  Spoofed ``sender_pubkey`` that doesn't derive to
    ``entity_id`` is still rejected.  Scope-min fix: cmd_stake +
    ``_rpc_stake`` only.  cmd_react / cmd_propose / cmd_vote have
    the same shape defect but their tx classes lack the
    ``sender_pubkey`` field entirely -- closing those requires a
    wire-format change behind a hard-fork height gate, deferred
    to a follow-up.  Soft fix: no consensus rule change, no
    wire-format change, no fork.  (8088bc0)

### Changed (Tier 75, consensus-breaking, height-gated)

  * **Slash min-unit clamp via shared ``_split_bps`` helper (audit
    r53 #3 -- economics top-1).**  CLAUDE.md anchor at risk:
    "Honest operators are insured" -- slashing must produce *small
    fractional* burns on transient hiccups, not *zero* burns that
    silently launder offenses against thin-history offenders.

    Same defect-class as the Tier 73 / Tier 74 ``_split_bps``
    fixes (audit r51 #3 / r52 #3) on the REWARD side, but on the
    PUNISHMENT side: ``slash_validator`` /
    ``burn_slash_proportional`` / ``EscrowLedger.slash_all`` all
    computed the slash as ``basis * slash_pct // 100``.  At the
    Tier 20 anchored ``SOFT_SLASH_PCT = 5``, any basis under 20
    tokens rounded the slash to zero -- the offender kept their
    full stake / pending / escrow entry and the punishment was
    silently a no-op.  Reward and punishment sides are now in
    deliberate symmetry: both clamp positive non-zero results
    away from the integer-floor underflow regime the dormancy
    controller is anchored to produce in steady state.

    Three call sites refactored through
    ``_split_bps(..., min_unit=1, gate=block_height >=
    SLASH_MIN_UNIT_HEIGHT and slash_pct < 100)``:

      1. ``SupplyTracker.slash_validator`` per-bucket
         (``stake_burn``, ``pending_burn``) plus the per-entry
         pending loop.
      2. ``SupplyTracker.burn_slash_proportional``'s
         ``target_total`` (censorship / bogus-rejection / non-
         response / IL-violation evidence apply paths consume this).
      3. ``EscrowLedger.slash_all`` per-entry ``burn`` (attester-
         batch reward escrow entries at the dormancy-controller's
         low-issuance steady state are exactly where small entries
         are common).

    New activation height ``SLASH_MIN_UNIT_HEIGHT = 12500``
    (Tier 75) sits 2000 blocks above Tier 74 (10500), matching
    the Tier 70 -> 71 -> 73 -> 74 ~13.9-day cohort cadence.  A
    punishment-shape change deserves its own operator-runway
    cohort so operators don't absorb a reward-side AND a
    punishment-side retune in the same upgrade cycle.

    Pre-fork the gate evaluates False in all three helpers and
    the math is byte-identical to the legacy floor-divide --
    historical-block replay preserved.  Post-fork the slash is
    clamped to at least 1 token whenever a positive basis would
    otherwise round to zero, and ``_split_bps`` itself never
    exceeds the input ``amount`` so supply conservation is
    preserved.  ``slash_pct == 100`` short-circuits the clamp
    because the full-burn case is unambiguous.

    Pure consensus-rule swap; no new wire format, no new tx
    kinds, no state-tree changes.  (90ecc85)

## [1.80.0] — 2026-05-12

Audit r52 top-3 ships: one production-active permanence-anchor fix
(soft, no fork), one structural security-pipeline fix that unifies
the slashable-evidence injection surface (soft, no fork), and one
consensus-visible economics retune that closes the proposer-share
silent-round-to-zero defect class the Tier 73 CHANGELOG explicitly
deferred (new Tier 74 hard fork, activation height 10500).

### Fixed

  * **``strip_tx_witness`` / ``attach_tx_witness`` preserve every
    MessageTransaction field (audit r52 #1 -- long-term-design /
    security / value-prop top-1).**  CLAUDE.md anchor at risk: the
    headline Mission promise -- "your message can never be deleted."
    Threatened at the storage layer for every Tier 5+ optional field.

    Pre-fix the helpers in ``messagechain/core/witness.py`` rebuilt
    the stripped tx by hand-listing fields, frozen at the pre-Tier-10
    set (entity_id / message / timestamp / nonce / fee / signature /
    version / compression_flag / tx_hash / witness_hash).  Every
    later optional field was silently dropped on the floor:

      - ``prev``           (v2  -- reply / threading pointer)
      - ``sender_pubkey``  (v3  -- first-spend pubkey install)
      - ``community_id``   (v5  -- Reddit-style topic handle)
      - ``poll_options``   (v6  -- structured poll's option list)
      - ``vote_target``    (v6  -- structured vote's (poll, index))

    ``ChainDB.strip_finalized_witnesses`` calls
    ``strip_block_witnesses`` -> ``strip_tx_witness`` and UPDATEs
    ``blocks.data`` with ``stripped.to_bytes()`` in place.
    ``WITNESS_AUTO_SEPARATION_HEIGHT=1704`` sits well under live
    mainnet tip, so the sweep was actively running against every
    block past the ``WITNESS_RETENTION_BLOCKS`` finality window,
    silently erasing Tier 5+ fields from primary block storage.
    Effects:

      - Tier 72 polls past finality+200 lost their option list --
        vote-tx admission failed at ``_poll_lookup`` because
        option_count read back as None.
      - Threads (``prev``) lost their parent pointer.
      - Community-tagged messages lost their handle.
      - First-send-pubkey-install path lost its ``sender_pubkey``
        reveal.

    The companion ``strip_block_witnesses`` ten lines below the
    defective ``strip_tx_witness`` already uses
    ``dataclasses.replace`` and its docstring explicitly says
    *"listing slots one-by-one was the defect form"* --
    ``strip_tx_witness`` itself was the named defect form on the
    sibling function.

    Abstraction fix: both ``strip_tx_witness`` and
    ``attach_tx_witness`` now route through ``dataclasses.replace``,
    mirroring ``strip_block_witnesses``.  Every future
    MessageTransaction field auto-survives the round-trip by
    construction -- adding a Tier-10 optional field cannot regress
    the strip contract because there is no field list to forget to
    update.  Six tests in
    ``tests/test_audit_r52_strip_tx_witness_preserves_optional_fields.py``
    lock the property per field plus an end-to-end on-disk
    round-trip (``strip_block_witnesses -> to_bytes -> from_bytes``).
    Soft fix: no consensus rule change, no wire-format change, no
    fork.  Behavioural fix lands the moment a validator upgrades;
    data previously corrupted on validators that have already run
    the sweep needs separate inspection (the original signed bytes
    remain in the ``block_witnesses`` side-table, so the canonical
    content can be reconstructed from the witness blob's pre-strip
    preimage if a node still holds it).  (2c24213)

  * **Every signed evidence tx admitted via RPC routes through one
    chokepoint that gossips (audit r52 #2 -- security top-1).**
    CLAUDE.md adversary anchor at risk: validator collusion
    (primary).  The chain's primary collusion-deterrence pipeline --
    a user filing slashable evidence against a coercing validator --
    had a single-point-of-failure injection edge on the RPC-target
    validator.

    Pre-fix ``_rpc_submit_censorship_evidence`` (server.py:3393)
    admitted to the mempool's censorship-evidence pool but NEVER
    called ``_schedule_pending_tx_gossip``.  Every other non-message
    tx pool admit (stake / unstake / authority / governance) DID
    call gossip, so this was a verify-by-inspection regression
    invisible at unit-test scope.  The handler's docstring even
    claimed *"gossiped peers see the same tx via the P2P pending-
    tx relay"* -- the claim was false.  Plus the matching gap on
    the receiver side: ``_handle_announce_pending_tx`` had no
    ``"censorship_evidence"`` kind branch, so even if some other
    caller had been routing CE through gossip the peers would
    silently drop the announce.

    Abstraction-over-symptom fix.  Extract
    ``_rpc_submit_evidence`` as the unified chokepoint for every
    signed evidence tx admitted via RPC::

        deserialize -> validate -> cross-pool leaf check
        -> mempool admit -> _schedule_pending_tx_gossip

    Parameterised over (kind, tx_cls, validate_fn, admit_fn,
    pool_full_error, success_result_extra) so any future evidence
    kind slots in via one row in a per-kind thin wrapper -- the
    gossip step is structurally guaranteed.
    ``_rpc_submit_censorship_evidence`` becomes a thin wrapper
    around the chokepoint, with the CE-specific validator, mempool
    admit (with submitter pubkey lookup wired), and result fields
    supplied via callables.  The receiver side gains a matching
    ``"censorship_evidence"`` branch in
    ``_handle_announce_pending_tx`` that validates via the same
    ``validate_censorship_evidence_tx`` gate and admits to the CE
    pool with the same submitter pubkey lookup -- mirroring the
    apply path so peers reach the same admission verdict as the
    originator.  Soft fix: no consensus rule change, no wire-format
    change, no fork.

    Scope note (deferred follow-up): the original audit-r52 finding
    also flagged ``BogusRejectionEvidenceTx`` and
    ``NonResponseEvidenceTx`` having NO RPC submission path.
    Closing that completely requires adding mempool pools for both
    kinds, propose_block drain wiring, new RPC method names +
    dispatcher rows, and CLI command implementations (the existing
    CLI flags carry an explicit ``(NOT YET WIRED)`` placeholder).
    That's a multi-component feature build, not a defect fix --
    left to a follow-up audit round.  This commit lands the
    chokepoint shape they will plug into when their mempool
    plumbing arrives: a new wrapper passes a different
    (kind, tx_cls, validate_fn, admit_fn) tuple and inherits the
    gossip discipline by construction.  (9d678fa)

### Changed (Tier 74, consensus-breaking, height-gated)

  * **Proposer-share / per-block-cap min-unit clamp + shared
    ``_split_bps`` helper (audit r52 #3 -- economics top-1).**
    CLAUDE.md pillars at risk: "Perpetual security via fees, not
    issuance" + "Stable active supply" + "Mathematical
    decentralization over time".  The dormancy-controller (Tier 47+)
    is *designed* to emit small per-block issuance when
    ``active_supply`` is close to ``TARGET`` -- so the small-reward
    regime is the steady state, not a corner case.  In that regime
    the proposer + per-block-cap shares were silently rounding to
    zero.

    Pre-fix sites in ``SupplyTracker.mint_block_reward``::

        proposer_share = reward * PROPOSER_REWARD_NUMERATOR
                       // PROPOSER_REWARD_DENOMINATOR    # = reward * 1 // 4
        # And, post-PROPOSER_CAP_HALVING_HEIGHT:
        effective_cap  = reward * PROPOSER_REWARD_NUMERATOR
                       // PROPOSER_REWARD_DENOMINATOR

    At ``reward in {1, 2, 3}`` both silently round to 0 and the
    entire issuance routes to the attester pool / per-block burn;
    the per-block cap also silently turns OFF in the regime it's
    anchored to bound (mega-staker capture of attester reward).
    This was the exact "sibling defect-shape DEFERRED" the audit
    r51 #3 (Tier 73) CHANGELOG named:

        "the wider abstraction calls for a shared ``_split_bps(
         amount, bps, denom=10_000, min_unit=1)`` helper to catch
         every future ``bps // 10_000`` site that could round to
         zero under a realistic minimum."

    Two changes:

      1. New module-level helper
         ``messagechain.economics.inflation._split_bps``::

             def _split_bps(amount, num, den, *, min_unit=1, gate=False) -> int

         Pure function.  Pre-fork callers (``gate=False``) get
         byte-identical floor-divide.  Post-fork callers
         (``gate=True``) clamp to ``min_unit`` only when a positive
         ``amount`` would otherwise round to zero, and NEVER exceed
         the input amount -- supply conservation cannot be silently
         manufactured.

      2. New activation height
         ``PROPOSER_SHARE_MIN_UNIT_HEIGHT = 10500`` (Tier 74),
         gating two consensus-visible call sites in
         ``mint_block_reward``:

           - ``effective_cap`` (post-``PROPOSER_CAP_HALVING_HEIGHT``
             branch)
           - ``proposer_share``

         Both refactored to call ``_split_bps`` with the matching
         gate.  Pre-fork the gate evaluates False at every height
         and the floor-divide matches legacy byte-for-byte --
         historical block replay preserved.  Post-fork both clamp
         to 1 token at ``reward in {1, 2, 3}``, so a small-issuance
         block deterministically pays the proposer 1 and the
         attester pool ``reward-1``.

    Tier 73's attester-fee site (``SupplyTracker.pay_fee_with_burn``)
    is refactored to call ``_split_bps`` too.  Byte-identical on
    both sides of the Tier 73 gate -- the refactor proves
    ``_split_bps`` generalizes the existing site rather than
    diverging from it.  Adding a new ``bps // den`` caller in the
    future cannot reintroduce the silent-round-to-zero defect
    without bypassing the helper.

    Activation height 10500 sits 2000 blocks above Tier 73 (8500) --
    the same ~13.9-day cohort spacing the Tier 70 -> 71 -> 73
    runway used.  Consecutive validator-economics retunes get their
    own cohort so operators absorb each in its own upgrade cycle.
    Eleven tests in ``tests/test_audit_r52_split_bps_helper.py``
    lock the property surface: helper pure-math, mint_block_reward
    legacy vs post-Tier-74 behavior at every (reward in {1..16})
    combination, supply conservation across the clamp, Tier 73
    attester-share preservation under the refactor, and the
    height-ordering assertion between Tier 73 and Tier 74.  Pure
    consensus-rule swap; no new wire format, no new tx kinds, no
    state-tree changes.  (7184f23)

## [1.79.2] — 2026-05-12

Patch release.  Fixes a long-standing gossip-receiver mempool
eviction bug surfaced (again) during the Tier 72 mainnet demo:
when a validator received a block via ``ANNOUNCE_BLOCK`` gossip
from a peer, the post-apply mempool sweep stripped only the
MessageTransactions in the block — confirmed TransferTransactions
were left pending in ``mempool.pending`` forever.

### Fixed

  * **``server.py:_handle_p2p_message`` ANNOUNCE_BLOCK branch
    sweeps both message + transfer txs from mempool after a
    successful ``add_block``, not just messages.**
    CLAUDE.md anchor: "transfer is a first-class, fully supported
    tx type" — first-class includes mempool lifecycle parity with
    messages.

    Pre-fix at server.py:5252:

    ```
    self.mempool.remove_transactions(
        [tx.tx_hash for tx in block.transactions]
    )
    ```

    ``mempool.pending`` holds BOTH messages AND transfers (since
    ``submit_transaction_to_mempool`` dispatches on tx class).
    Stripping only ``block.transactions`` left every confirmed
    transfer pending on the receiver's local view.

    Bite: the next slot's proposer pulled the stale transfer
    back via ``get_transactions_with_entity_cap``, the proposed
    block failed ``add_block`` with "Invalid transfer ...:
    Invalid nonce: expected N+1, got N" (the chain had advanced
    past it), and the proposer wedged into re-proposing the same
    stale block every slot.  Observed on mainnet during the Tier
    72 demo: validator-2's faucet drips landed on validator-2's
    self-proposed block (which had the correct sweep at
    server.py:4580), validator-2 then saw validator-1 gossip
    the same block back via ANNOUNCE_BLOCK, and the receiver
    path's sweep left the drip transfer in validator-2's
    mempool.  Every subsequent validator-2 proposal failed.
    Two faucet drips were enough to halt new-tx inclusion for
    ~40 minutes until an operator restart cleared the
    in-memory mempool.

    Fix: include ``block.transfer_transactions`` in the sweep.
    Twin of the network/node.py:1321 path (which already had
    both legs).  Non-consensus, non-fork.  Mempool lifecycle only.

    Regression test
    (``tests/test_mempool_gossip_block_transfer_eviction.py``)
    pins three properties:
    (a) ``Mempool.remove_transactions`` with combined message +
        transfer hashes strips both kinds,
    (b) stripping only message hashes leaves transfers stranded
        (pins the bug shape so a future revert is caught), and
    (c) source-level pin: ``Server._handle_p2p_message``'s
        ANNOUNCE_BLOCK arm references both
        ``block.transactions`` AND ``block.transfer_transactions``
        in the sweep.

## [1.79.1] — 2026-05-12

Patch release.  Fixes a long-standing fresh-wallet-first-sign
admission bug surfaced during the Tier 72 mainnet demo: every
brand-new entity submitting its first signed tx (message, transfer,
stake, etc. — anything routed through ``Server._rpc_submit_*``)
was rejected with "WOTS+ leaf already used by another pending tx",
even when no tx with that signer existed in any pool.

### Fixed

  * **``Server._tx_signer_pubkey`` resolves the signer pubkey from
    ``tx.sender_pubkey`` when the entity is not yet on chain.**
    CLAUDE.md anchor: receive-to-exist + Tier 11 first-spend reveal.
    A v3+ MessageTransaction (or v3+ TransferTransaction) carrying
    a ``sender_pubkey`` field reveals its pubkey on apply; that
    install is the WHOLE POINT of the first-spend reveal.

    Pre-fix, ``_tx_signer_pubkey`` did
    ``return self.blockchain.public_keys.get(eid)`` and stopped
    there.  For a fresh entity, ``public_keys`` does not contain
    ``eid`` yet (install happens on apply, not on admission), so
    the lookup returned None.  ``_check_leaf_across_all_pools``
    hits the "incoming_signer is None — fail closed" branch and
    rejects every fresh-wallet first sign with
    ``"WOTS+ leaf already used by another pending tx — leaf
    reuse rejected"`` -- a maximally misleading error string for a
    tx that has no existing leaf to collide with.

    Bite: surfaced during the Tier 72 mainnet demo (1.78.0).  Two
    /faucet-funded fresh wallets each tried to post their first
    message; both failed admission with the leaf-reuse error, even
    though neither had any prior tx on chain or in any pool.  The
    /quickpost path (server-side wallet generation + single message
    sign) sidesteps this because it doesn't go through the public
    submit_transaction RPC -- which is why the bug hadn't been
    flagged before; every fresh wallet to ever post a message on
    mainnet went through /quickpost.

    Fix: when ``public_keys.get(eid)`` returns None, fall back to
    ``tx.sender_pubkey`` IFF it derives back to ``eid`` (matching
    the admission-validation rule that determines whether the tx
    will be admitted at all).  When neither chain registration nor
    a derive-matching ``sender_pubkey`` resolves, return None as
    before — caller still fails closed for truly-unresolvable
    signer cases.

    Non-consensus, non-fork.  Mempool-dedupe-layer only.  Regression
    test (``tests/test_fresh_wallet_first_sign_admission.py``) pins
    four properties: (a) resolves from ``sender_pubkey`` when
    unregistered, (b) prefers ``public_keys`` when registered,
    (c) returns None for v1 tx without ``sender_pubkey``, and
    (d) rejects a spoofed ``sender_pubkey`` that does not derive
    to the claimed ``entity_id``.

## [1.79.0] — 2026-05-12

Audit r51 top-3 ships: one production-runtime security parity fix
(soft, no fork), one value-prop public-surface rollout for the
Tier 72 polls/votes feature shipped in 1.77.0/1.78.0 (soft, no fork),
and one consensus-visible economics retune that closes the silent
fee-redirect-to-zero defect at the steady-state base_fee (new
Tier 73 hard fork, activation height 8500).

### Fixed

  * **r46/r50 chokepoint discipline lifted onto production
    ``server.py`` (audit r51 #1 -- security top-1).**  CLAUDE.md
    adversaries: validator collusion (primary), honest-operator
    insurance, crypto-agility.  ``cli.py:2663`` instantiates
    ``server.Server`` for the validator process; the audit r46 #1
    + r50 #1 + r50 #2 fixes only landed in
    ``messagechain/network/node.py``, leaving Server's three
    parallel handlers each silently re-arming one of those defects
    on the production code path:

    -  ``_handle_announce_attestation`` inserted into
       ``_seen_attestations`` BEFORE signature verification (r50 #1
       gossip dedup-poison surface).
    -  Same handler verified ``verify_attestation(att, pk)`` against
       the CURRENT key, not the key active at
       ``att.block_number`` -- a rotated validator's pre-rotation
       attestation silently verify-failed under the new key, the
       relayer took ``OFFENSE_INVALID_TX``, and honest peers banned
       each other (r50 #2).
    -  Same handler read live ``supply.get_staked(...)`` +
       ``sum(supply.staked.values())`` for the finality denominator,
       diverging from the apply path's pinned-at-target-height
       snapshot during stake-churn windows and forking the chain on
       reorg-rejection (r46 #1).
    -  ``_handle_announce_finality_vote`` verified
       ``verify_finality_vote(vote, pk)`` against the current key
       with the same r50 #2 ban-cascade surface.
       ``KEY_ROTATION_COOLDOWN_BLOCKS=144`` is far below
       ``FINALITY_VOTE_MAX_AGE_BLOCKS=1000``, so an honest
       validator's pre-rotation votes remain in flight for up to
       1000 blocks after they rotate.
    -  ``_maybe_attest_accepted_block`` (the local-broadcast path
       -- this validator attesting a block it just accepted) read
       live stake for the local finality update; same r46 #1
       divergence trap as the gossip-ingress path.

    Abstraction fix: lift the exact chokepoint shape from
    ``Node._handle_announce_attestation`` /
    ``Node._handle_announce_finality_vote`` /
    ``Node._attest_block_if_allowed`` into Server.  The helpers
    (``Blockchain._verify_signer_at_height`` and
    ``Blockchain.resolve_pinned_attestation_stake``) already exist;
    the production handlers route through them by construction.
    Three call sites on Server now share the same denominator
    source for ``FinalityTracker.add_attestation`` (apply path /
    gossip-ingress / local broadcast); two gossip handlers now
    route signed-message verification through
    ``_verify_signer_at_height``.  Five structural guards in
    ``tests/test_audit_r51_server_gossip_chokepoint_parity.py``
    lock the discipline against Server source so a future
    refactor cannot silently re-introduce any of the three
    defect-shapes.  Soft fix: no fork, no consensus rule change,
    no wire-format change.  Behavioural fix lands the moment a
    validator upgrades.  (b914fc1)

### Added

  * **Tier 72 polls + structured votes surface end-to-end
    (audit r51 #2 -- value-prop top-1).**  Tier 72 shipped its
    wire format in 1.77.0 and its consensus rules in 1.77.0 /
    1.78.0, but every public surface a newcomer touches had zero
    awareness of the feature -- exact repeat of the Tier 25
    community-handle ship-dead pattern.  CLAUDE.md positioning
    anchor at risk: "decentralized reddit/twitter core" framing.

    Single abstraction:
    ``Blockchain._poll_vote_render_fields(tx)`` returns the
    ``kind`` discriminator + ``poll_options`` / ``vote_target``
    payload shape for any tx.  Consumed by all four JSON surfaces
    (``get_recent_messages``, ``get_recent_messages_by_entity``,
    ``get_tx_status_public``, ``Server._build_included_status``);
    adding a future structured-tx kind surfaces on every UI by
    extending the one helper.  Same "one schema, two ports"
    pattern as audit r43 #2, lifted to kind-discriminated content
    shapes.

    Per-surface render additions:
      - Receipt page (``/r/<tx_hash>``) dispatches
        ``renderMessageBody`` on ``result.kind`` -- poll receipts
        list options with a live tally aggregated from chain,
        vote receipts read "Voted: green" with a clickable link
        to the parent poll's receipt (the new ``poll_tally``
        and ``vote_option_label`` schema fields mean one HTTP
        round-trip suffices).
      - Feed page (``/``) renderMessage dispatches on ``m.kind``
        -- poll cards show question + option list + "open poll
        receipt for live tally"; vote cards show "Vote on poll
        (option #N) on poll <tx>" with the parent linked.

    Docs: README adds two examples (--poll-option ×3 + --vote-
    target); COMPARISON.md adds a "Structured polls + on-chain
    votes with consensus-enforced tally" row (✓ for MC, ✗ for
    every named competitor); ``guides/forum-primitives.md``
    gains a §6 polls section documenting create / vote /
    consensus-enforced uniqueness / binding-forever / no-close /
    out-of-scope items.  Soft fix: no fork, no consensus rule
    change, no wire-format change.  Visibility lands the moment
    a validator upgrades and a feed-page visitor refreshes.
    (da9c924)

### Changed (Tier 73, consensus-breaking, height-gated)

  * **Attester fee-share minimum unit -- the long-horizon
    validator-security fee channel is never silently dead at the
    floor (audit r51 #3 -- economics top-1).**  CLAUDE.md pillar
    at risk: "Perpetual security via fees, not issuance."  Tier 4
    redirected ``ATTESTER_FEE_SHARE_BPS / 10_000 = 50%`` of every
    fee burn to the per-block attester pool; integer arithmetic
    silently broke the redirect at the steady-state base_fee:

        base_fee = 1                  # MARKET_FEE_FLOOR=1 binds
        attester_share = 1 * 5000 // 10_000 = 0

    At ``base_fee=1`` (the dominant regime on a low-utilization
    chain whenever no spam wave has lifted base_fee above the
    protocol floor), 100% of every fee burns and attesters
    receive nothing from the fee channel.  The long-horizon
    validator-security pillar quietly goes dark in the regime
    the chain spends most of its life in.

    Tier 73 clamps the redirect to a minimum of 1 token whenever
    ``base_fee > 0`` so the channel is guaranteed non-zero
    whenever a fee actually burns.  The clamp is gated on
    ``base_fee > 0`` so off-chain audit / test paths with
    ``base_fee = 0`` do not manufacture pool credit; the clamp
    can never exceed ``base_fee`` (at ``base_fee=1`` the
    redirect becomes 1 and the burn is 0 that round; at
    ``base_fee >= 2`` the clamp is a no-op because the floor-
    divide is already non-zero).

    Activation height ``ATTESTER_FEE_MIN_UNIT_HEIGHT = 8500``
    sits 2000 blocks above Tier 71 (6500) -- ~13.9 days cohort
    spacing matching the Tier 70->71 runway.  Two consecutive
    validator-economics retunes deserve their own cohorts so
    operators can absorb each in its own upgrade cycle.  Tier 72
    (POLL_HEIGHT=2400) is below this and disjoint -- wire format
    only, no economic interaction.

    Pre-fork is byte-identical to legacy at every (base_fee, fee)
    combination so historical-block replay matches.  No new wire
    format, no new tx kinds, no state-tree changes.  Pure
    consensus-rule swap inside
    ``SupplyTracker.pay_fee_with_burn``; sim-vs-apply parity
    falls out trivially because ``pay_fee_with_burn`` is the
    single chokepoint both paths route fee payments through.

    Sibling defect-shape DEFERRED (scope-bounded for this round):
    the wider abstraction calls for a shared
    ``_split_bps(amount, bps, denom=10_000, min_unit=1)`` helper
    to catch every future ``bps // 10_000`` site that could
    round to zero under a realistic minimum.  Other current call
    sites (``DEFLATION_REBATE_BPS // 10_000``,
    ``ATTESTER_REWARD_SPLIT_BPS // 10_000``, etc.) do not round
    to zero in the typical regime, so this round addresses only
    the one site the audit demonstrated as producing user-
    visible economic harm.  (aff161e)

## [1.78.0] — 2026-05-12

Completes the **Tier 72 poll + vote** rollout from 1.77.0.  Adds
two protocol-level constraints that the initial cut left to the
indexer, lowers ``POLL_HEIGHT`` for immediate activation, and
surfaces ``--poll-option`` / ``--vote-target`` on ``messagechain
send``.  TX_VERSION_POLL stays at v6; the wire format is unchanged.

### Added

  * **No self-vote on own poll.**  ``_poll_lookup`` now returns
    ``(block_height, option_count, author_entity_id)``; verify rejects
    when ``vote_tx.entity_id == author_entity_id``.  A poll's
    creator cannot also vote on their own poll.

  * **One vote per (entity, poll) at consensus** -- protocol-level
    reject, not indexer-side dedup.  New ChainDB table
    ``vote_records`` indexes every confirmed vote tx by
    ``(poll_txid, voter_id, block_hash)``; populated in
    ``store_block``.  New ``ChainDB.has_voted_canonical`` filters
    rows by canonical block_hash via the existing canonical-walk
    cache, so a vote that landed in an orphaned branch does NOT
    block a re-vote on the new canonical chain.  New
    ``Blockchain._has_voted_canonical`` is wired into
    ``verify_transaction`` via the new ``vote_check`` callback at
    all three call sites (mempool admit + both block-validate
    paths).

  * **Intra-block vote dedup**: each block-validate path maintains
    a ``seen_votes_this_block`` set so a proposer cannot pack two
    votes from the same entity on the same poll into one block
    (the canonical-chain check above only catches votes already in
    PRIOR blocks).

  * **CLI**: ``messagechain send`` learns ``--poll-option TEXT``
    (repeat 1..4 times) and ``--vote-target POLL_TXID:INDEX``,
    mutually exclusive.  Both pre-flight-validate locally before
    burning a WOTS+ leaf on signing.

  * **Permanence implication**: under one-vote-per-(entity, poll),
    the FIRST vote is binding forever -- there is no in-protocol
    mechanism to override.  An entity that wants to register a
    change of mind must do so via app-layer messaging; the
    consensus record stays with the first vote.  This is a
    deliberate tradeoff for tally-from-chain-alone simplicity --
    indexers can now naively count rows without any dedup logic.

### Changed

  * **``POLL_HEIGHT`` lowered from 8500 to 2400** -- immediate
    activation, ~110 minutes of upgrade runway above tip (~2389 at
    cut).  Tier 72 and Tier 71 are disjoint subsystems so the
    earlier-than-Tier-71 ordering is operationally safe; the
    previous ordering assertion was protective design intent, not
    a correctness requirement.

## [1.77.1] — 2026-05-12

Patch release.  Audit r50 top-3 ships: three independent signature-
verification hardening fixes spanning the gossip-ingress, in-block,
and proposer-side surfaces.  No new tx kinds, no new wire format,
no consensus rule change at the validator boundary, no hard fork.

### Fixed

  * **Attestation gossip dedup inserts AFTER signature verify, not
    before (audit r50 #1 -- security top-1).**  CLAUDE.md adversary
    anchor: validator collusion (primary).  CLAUDE.md anchor:
    censorship resistance is a *collective decision* -- "any
    deviation from pure inclusion requires a coordinated majority
    *and* willing to absorb the slashing risk that exposed
    collusion produces."  A gossip-layer dedup poison sidesteps
    the slashable surface entirely.

    Pre-fix ``_handle_announce_attestation`` inserted the
    ``(validator_id, block_number, block_hash)`` triple into the
    ``_seen_attestations`` LRU on the line BEFORE calling
    ``verify_attestation``.  All three components of the triple
    are publicly predictable from chain state: ``validator_id``
    is any committee member, ``block_number`` is parent+1,
    ``block_hash`` is the just-accepted parent.  A peer who
    pre-relayed a forged-signature attestation with the right
    triple poisoned the LRU; the genuine, correctly-signed
    attestation arriving later short-circuited at the dedup
    membership check and never reached the FinalityTracker or
    the relay broadcast.

    Attack cost: one bogus packet per (validator, height) pair.
    Reward: silent collective-decision censorship of any honest
    validator's attestations -- no slashable evidence is produced
    because no malformed block is ever proposed; the suppression
    happens entirely at the gossip layer.

    Abstraction fix: "seen" means "seen-AFTER-verify".  The
    membership CHECK remains pre-verify (cheap gate skips
    expensive verification of already-accepted entries), but the
    INSERT moves below the ``verify_attestation`` success branch.
    Discipline is documented inline so any future signed-gossip
    handler that adds an explicit dedup cache inherits it by
    convention.  (7fb2ed2)

  * **Attestation + finality-vote verify routes through historical-
    key candidate set (audit r50 #2 -- security top-2).**  CLAUDE.md
    anchors at risk: honest-operator insurance, crypto-agility
    (rotation is the migration mechanism), and collective-decision
    censorship resistance (silent gossip-layer suppression of
    valid signed messages sidesteps the slashable-evidence
    surface).

    Pre-fix four call sites verified attestation/finality-vote
    signatures against ``self.public_keys[vid]`` -- the CURRENT
    key at validation time: ``Blockchain._validate_attestations``
    (in-block validation), ``Blockchain._validate_finality_votes``
    (in-block validation), ``Node._handle_announce_attestation``
    (gossip ingress), and ``Node._handle_announce_finality_vote``
    (gossip ingress).  ``KEY_ROTATION_COOLDOWN_BLOCKS = 144`` is
    << ``FINALITY_VOTE_MAX_AGE_BLOCKS = 1000``.  An honest
    validator whose previously-signed finality votes are still in
    flight when they rotate: those votes verify-fail under the
    new key, get dropped from gossip, fail the entire block when
    an honest proposer includes them, and the relaying peer is
    hit with ``OFFENSE_INVALID_TX`` and banned by peers.
    Inversely, an attacker can replay a rotator's pre-rotation
    gossip votes to make honest peers ban each other -- forged-
    data-free ban cascades that fragment the gossip mesh.  The
    same shape silenced any attestation whose validator rotated
    between sign-time and inclusion.

    The slashing-evidence path already routes through a multi-
    key candidate set: every distinct pubkey the offender ever
    held plus the current key (see ``validate_slash_transaction``
    / ``verify_slashing_evidence``).  Every candidate is a key
    the entity legitimately published on-chain (each rotation
    step is signed by the prior key), so matching any candidate
    is proof the entity produced the signature -- attackers
    cannot forge a match.  This release extends the same shape
    to attestation and finality-vote verification.

    Abstraction-over-symptom fix: new
    ``Blockchain._verify_signer_at_height(obj, entity_id,
    signed_at_height, verifier)`` chokepoint.  All four call
    sites route through it, parameterised by the standalone
    verifier function and the consensus-implied signing height
    (``v.signed_at_height`` for FinalityVote, ``att.block_number``
    for Attestation).  Adding a new signed-aggregation verifier
    that goes around the helper reintroduces the defect by
    definition.  (aabfbc4)

  * **``propose_block`` pre-filters bad-sig attestations + finality
    votes (audit r50 #3 -- security top-3).**  CLAUDE.md anchors
    at risk: honest-operator insurance (a proposer who packs a
    single planted bad-sig entry loses the entire block + a WOTS+
    leaf -- cost without offense), and validator-collusion defense
    (the cheap proposer-grief surface this round's signature-
    aggregation lens flagged).

    Pre-fix ``_validate_attestations`` and
    ``_validate_finality_votes`` return False on the first invalid
    signature, rejecting the whole block.  Mirroring the apply-side
    ``survivors`` filter at validation time would change the
    block-acceptance criterion (which votes count toward
    finality) -- a hard-fork-required consensus change.  CLAUDE.md
    anchor "minimize hard forks" rules that out for a defense-in-
    depth concern already mostly closed by audit r50 #2's
    historical-key candidate set on the gossip-ingress path.

    Soft-fix shape -- a proposer-side pre-filter ensures an honest
    proposer NEVER constructs a block with a bad signature in the
    first place.  New ``Blockchain._partition_verified_aggregation(
    objs, *, get_entity_id, get_signed_at_height, verifier)``
    partitions any signed-aggregation list into (verified,
    dropped), using audit r50 #2's ``_verify_signer_at_height``
    helper for the candidate-set verify.  ``propose_block`` routes
    both ``attestations`` and ``finality_votes`` through it; bad-
    sig entries are dropped (and logged at WARNING) before block
    assembly.  Adding a new signed-aggregation kind to
    ``propose_block`` and routing it through the helper inherits
    the discipline by construction.

    Non-consensus, non-fork, defense-in-depth.  Old proposers (no
    pre-filter) still produce valid blocks when their inputs are
    clean; new proposers additionally survive a corrupted mempool
    / finality-tracker without burning a leaf.  The in-block
    validator path is unchanged: blocks containing bad sigs are
    still rejected by every peer.  (fcf1127)

## [1.77.0] — 2026-05-12

Minor release.  Adds **Tier 72: structured polls + structured votes**
as a new message-tx capability (TX_VERSION_POLL = v6, activation at
height ``POLL_HEIGHT = 8500``).  New CLAUDE.md anchor; no other
behavior change.

### Added

  * **Tier 72 — Structured polls + structured votes.**  A message tx
    may now carry EITHER a ``poll_options`` field (poll-creating mode:
    1..4 short UTF-8 option strings, each ≤32 bytes, unique, NFC,
    same charset whitelist as message body) OR a ``vote_target``
    field (vote-casting mode: 32-byte ``poll_txid`` + 1-byte
    ``option_index``).  Mutually exclusive at the wire level.  Counts
    toward stored bytes for the per-stored-byte fee floor and the
    proposer's fee-per-byte ranking.  Excluded from
    ``MAX_MESSAGE_CHARS`` -- poll options are structural metadata,
    not the user's speech, same treatment as ``community_id``.

    Protocol-level enforcement of vote→poll resolution: a vote
    admits only when its ``poll_txid`` resolves to a confirmed
    poll-creating tx in a strictly earlier block AND its
    ``option_index`` is in ``[0, len(target_poll.options))``.  No
    free-text vote labels, no out-of-range indices, no votes on
    non-poll messages, no same-block vote.  Resolution chains
    ``ChainDB.get_tx_location`` (O(1)) → ``get_block_by_number`` →
    tx at index → ``poll_options`` -- mirrors the Tier 27
    ``get_message_author`` pattern.

    **No protocol-level vote close** -- polls are open forever in
    line with the permanence anchor.  **No protocol-level
    one-vote-per-entity dedup** -- multiple votes from the same
    entity are admissible at consensus; indexers compute
    "current effective vote" per ``(voter, poll)`` as
    last-vote-wins, and older votes remain on chain forever.

    Wire format: v6 inherits the v5 trailer layout (length-prefixed
    signable_data + always-emitted prev / sender_pubkey /
    community_id presence-flag blocks) and appends two new
    presence-flag blocks: ``poll_options`` (1B flag; when set, 1B
    count + per-option [1B length + N UTF-8 bytes]) and
    ``vote_target`` (1B flag; when set, 32B poll_txid + 1B option
    index).  Pre-activation v6 admission is rejected; v1-v5 MUST
    NOT carry either field (rejected at verify with a clear
    structural error rather than as a generic signature failure).

    New CLAUDE.md anchor: **"Polls are structured, votes are
    minimal-payload references, neither closes."**  Reverting to a
    free-text "labels are strings" tally model, opting into
    protocol-level vote dedup, adding ranked-choice / weighted /
    secret-ballot machinery, or enforcing a close-height is out of
    scope without a new anchor justifying the conflict.

    New config constants: ``POLL_HEIGHT = 8500``,
    ``MAX_POLL_OPTIONS = 4``, ``MAX_POLL_OPTION_BYTES = 32``.
    Mainnet tip at fork-design time is ~2400, so ~42 days of runway
    above tip plus the standard 2000-block cohort buffer above the
    previous tier.

## [1.76.2] — 2026-05-11

Patch release.  Audit r49 top-3 ships: three independent network /
storage / mempool hardening fixes, all on long-stable surfaces.  No
new tx kinds, no new wire format, no consensus rule change at the
validator, no hard fork.

### Fixed

  * **``ChainDB.get_block_by_number`` returns the canonical-chain
    sibling, not an arbitrary row (audit r49 #1 -- security top-1).**
    CLAUDE.md anchors: honest-operator insurance + accidental-fork
    auto-recovery -- a node ending up on a minority/unintentional fork
    must auto-resync to the canonical chain without operator state
    surgery, and must not accumulate slashable evidence solely from
    being briefly on the wrong tip.

    Pre-fix ``get_block_by_number(h)`` ran ``SELECT data FROM blocks
    WHERE block_number=? LIMIT 1`` with no ``ORDER BY`` and no join
    against ``chain_tips`` -- when fork siblings coexisted at the
    same height (the steady-state after any reorg), sqlite returned
    whichever sibling row it picked (typically insertion order).
    Docstring claimed "the one on the best chain"; the SQL didn't
    enforce it.

    Callers walking ``range(tip_height + 1)`` to rebuild chain state
    silently picked non-canonical siblings post-restart:
    ``Blockchain._load_from_db`` (cold-load chain rehydration),
    ``integrity.reindex_state``, ``ChainDB._migrate_v1_to_v2`` /
    ``_migrate_v2_to_v3``, and the ``get_message_author`` tx-status
    path.  A coerced/colluding proposer that gossips a competing
    sibling at a recent height -- perfectly valid behaviour -- could
    push some honest nodes' rebuilt chain into a state that diverges
    from peers, blocking forward sync and creating slashable-evidence
    opportunities against honest operators.

    Abstraction-over-symptom fix: new ``ChainDB._build_canonical_hash_map``
    helper walks back from best_tip via the ``(block_hash, prev_hash,
    block_number)`` columns -- no Block.from_bytes() needed -- and
    caches ``{block_number -> block_hash}`` for the canonical chain.
    ``get_block_by_number`` now resolves the canonical block_hash at
    the target height and loads via the unambiguous
    ``get_block_by_hash`` path; a height not reachable from best_tip
    returns ``None`` rather than a sibling guess.  The cache is
    invalidated on every ``add_chain_tip`` / ``remove_chain_tip`` /
    ``store_block`` mutation so a fork-choice swap or a newly-stored
    block immediately reshapes the canonical view.

    Three callers (cold-load, reindex, migration) and the tx-status
    path all benefit from the single chokepoint -- adding a new
    caller in the future cannot reintroduce the sibling-ambiguity
    defect without bypassing the helper.  Callers that genuinely want
    a non-canonical sibling must explicitly use ``get_block_by_hash``
    or ``get_blocks_at_height`` and pick by hash; the silent fallback
    is gone.  (fc7ce2c)

  * **``/faucet`` + ``/quickpost`` reject non-JSON Content-Type to
    close cross-origin CSRF (audit r49 #2 -- security top-2).**
    CLAUDE.md adversaries: AI-spam flooding (primary defended-against)
    plus the operator-side aspect of validator-collusion -- a coercer
    who can drain the operator's faucet budget weakens the public-
    square on-ramp the chain depends on.

    Pre-fix the public-feed POST routes read ``Content-Length`` worth
    of bytes and ran ``json.loads`` on whatever arrived, with no
    Content-Type validation.  Response headers carry
    ``Access-Control-Allow-Origin: *``.  A "simple CORS" POST with
    ``Content-Type: text/plain`` is dispatched by the browser without
    a preflight (simple-request rules ignore ``Allow-Methods``
    entirely), so any cross-origin web page a wallet user visits
    could drive either endpoint from the visitor's browser.

    Faucet attack: the PoW challenge is bound to the recipient address
    only (not the source IP).  An attacker who pre-mines a challenge
    solution for ``attacker_addr`` could serve a malicious page (or
    ad creative) to many visitors and silently siphon the operator's
    per-/24 IP cooldown + per-window cap through the visitor pool --
    the real attacker IP never appearing in access logs.  Same shape
    covered ``/quickpost``.

    Abstraction-over-symptom fix: new
    ``_FeedHandler._content_type_is_json`` helper is the single
    chokepoint every POST route consults at ``do_POST``.  Media-type
    prefix match accepts ``application/json`` (and ``application/
    json; charset=utf-8``) and refuses everything else with HTTP 415
    BEFORE any rate-limit / PoW state is consulted.  Mirrors
    ``submission_server``'s ``application/octet-stream`` gate -- one
    helper covers ``/faucet``, ``/quickpost``, and any future POST
    route adopting the same pattern.

    Browser implications: ``fetch(..., {headers: {"Content-Type":
    "application/json"}, body: JSON.stringify(...)})`` triggers a CORS
    preflight; the preflight response does not advertise POST in
    ``Allow-Methods``, so the browser blocks.  Non-browser CSRF
    (curl, malicious CLIs) remains out of scope for a public, per-IP-
    rate-limited faucet -- the per-/24 cooldown + window cap already
    bound that surface, and the IP that originated the abuse is in
    the operator's logs.  Bonus mitigations (challenge IP binding)
    are separate follow-ups; this release is scoped to the
    abstraction fix that closes the browser CSRF vector
    deterministically.  (f77f538)

  * **Mempool slash + censorship-evidence pools admit by fee-per-byte;
    finality pool evicts oldest (audit r49 #3 -- security top-3).**
    CLAUDE.md primary adversary: validator collusion -- a colluding
    subset that can suppress slashing-evidence txs at trivial cost
    silently disarms the chain's collective-defense anchor.  Also
    CLAUDE.md fee-model anchor: "Selection priority is fee-per-byte,
    never absolute fee.  Don't carve out per-type fee logic."

    Pre-fix three mempool-resident pools admitted FIFO and refused
    any new entry when full, with selectors returning insertion order
    (``list(pool.values())``): ``slash_pool``,
    ``censorship_evidence_pool``, ``finality_pool``.  Same defect-
    shape the 1.76.1 release closed for the server-side
    ``_pending_*_txs`` pools but never reached for the mempool-
    resident pools.  A flooder paying the floor fee could fill either
    fee-bearing pool (1000 / 1000 cap each) and crowd out higher-
    density legitimate entries at trivial cost.  Cost to flood the
    censorship-evidence pool: ``1000 * MARKET_FEE_FLOOR`` per refill
    -- effectively free against a colluding-validator economic stake.

    Abstraction-over-symptom fix: two new shared Mempool helpers,
    each the single chokepoint its callers route through.

      * ``Mempool._admit_with_density_eviction(pool, key, obj,
        max_size)`` -- density-ranked admit for fee-bearing pools.
        When full, finds the lowest-density existing entry; if the
        incoming density is strictly higher, evicts and admits;
        otherwise refuses.  Returns ``(inserted, evicted_key_or_None)``
        so callers can tear down their own bookkeeping (e.g.
        ``_evidence_arrival_heights``).  Density uses the same
        ``_fee_per_byte`` helper messages already consult, with
        ``self._stored_bytes`` as the shared by-tx_hash cache.

      * ``Mempool._admit_with_oldest_eviction(pool, key, obj,
        max_size, age_attr)`` -- oldest-by-attribute admit for fee-
        less pools.  FinalityVote carries no fee (the flooder-pays-
        floor attack does not apply -- a vote requires a real
        validator key), but strict refuse-when-full was a liveness
        gap under a saturated validator set.  When full, evicts the
        entry with the smallest ``signed_at_height``.

    Selectors now sort by density descending so the proposer pulls
    the highest-revenue entries first when the byte budget binds.
    Sibling cleanup for arrival-height bookkeeping is wired in to
    ``add_censorship_evidence_tx`` so evicted entries no longer
    leave stale rows behind in the forced-inclusion source walk.

    Sibling defects DEFERRED (acknowledged in the audit r49
    synthesis, out of scope for this release): RBF
    (``try_replace_by_fee``) lifted to slash / censorship-evidence /
    finality / react pools, keyed by ``(sender, nonce)`` or
    analogous identity.  (2109b08)

## [1.76.1] — 2026-05-11

Patch release.  Audit r48 top-3 ships: three independent local-only
fixes spanning the proposer-side selection model, validator in-memory
state hygiene, and CLI fee-resolution discipline.  No new tx kinds,
no new wire format, no consensus rule change at the validator, no
hard fork.

### Fixed

  * **Non-message pending pools rank by fee-per-byte, not absolute
    fee (audit r48 #1 -- economics top-1).**  CLAUDE.md fee-model
    anchor: "Selection priority is fee-per-byte, never absolute fee.
    ... Don't carve out per-type fee logic; if a new tx kind is added,
    slot it into this model rather than inventing a parallel one."
    Two parallel ranking surfaces silently violated the anchor:
    ``Server._admit_to_pool`` evicted by raw ``tx.fee`` (within-pool
    AND cross-pool ``global_min`` scan), and the proposer drain at
    ``Server._select_block_transactions`` sliced
    ``list(pending_<kind>.values())[:MAX_TXS_PER_BLOCK]`` in
    insertion order for the stake, unstake, and governance pools.
    A 10 kB rotation paying fee=2000 evicted a 60-byte stake paying
    fee=1900 even though the stake offered ~30x the revenue-per-
    stored-byte; an attacker could spam high-absolute-fee envelopes
    to evict legitimate small bids across the global PENDING_POOL_MAX
    _SIZE*2 cap; the proposer leaked revenue per block under byte-
    budget pressure.

    Abstraction-over-symptom fix: route every server-side ranking
    site through the same
    ``messagechain.core.mempool._fee_per_byte`` helper the Mempool
    already uses for message-tx selection.  Single chokepoint;
    adding a new non-message pool (or a new tx kind that joins an
    existing pool) now picks up density ranking by construction.
    Pre-fix and post-fix orderings are both valid blocks; selection
    is local to the proposer; an old node and a new node producing
    different blocks at the same height has always been allowed.
    Sibling defects deferred to a follow-up cycle: RBF lifted to
    every pool, and ``NEW_ACCOUNT_FEE`` / ``KEY_ROTATION_FEE`` flat
    surcharges retuned to per-byte (hard-fork-gated economic
    retune).  (523bd9f)

  * **Prune in-memory ``Blockchain._stake_snapshots`` at the same
    window as chaindb (audit r48 #2 -- security top-1).**  The
    in-memory map was append-only forever even though the chaindb
    mirror was already pruned at
    ``FINALITY_VOTE_MAX_AGE_BLOCKS`` via
    ``prune_stake_snapshots_before(cutoff)``.  A long-running honest
    validator accumulated ~2.6M block-entries/year * ~50 validators
    * ~40 B per row -> multi-GB resident state inside a year.  Two
    CLAUDE.md anchors at risk: honest-operator insurance (OOM-driven
    restart churn turns into slashable false-positives during
    chaotic reboots) and hobbyist full-node accessibility for
    centuries.

    The "permanent in-memory stake snapshots" framing of commit
    4af0c8d asserted a stronger property than the system actually
    delivers, and was inconsistent with the chaindb prune added
    later.  Specifically: the chaindb mirror is already pruned at
    the same window, so a cold-restarted node only rehydrates the
    trailing FINALITY_VOTE_MAX_AGE_BLOCKS worth of snapshots; if
    those older snapshots were truly consensus-required, cold
    restart would break the chain (it doesn't, because no consumer
    reads beyond the window).  Stake snapshots are a deterministic
    function of accumulated tx history -- a derived index, not a
    primary record.

    Abstraction-over-symptom fix: new
    ``Blockchain._prune_stake_snapshots_before(height_cutoff)``
    helper is the single chokepoint for the in-memory prune,
    mirroring chaindb's helper of the same name.
    ``_record_stake_snapshot`` computes the cutoff once from
    FINALITY_VOTE_MAX_AGE_BLOCKS and applies it to BOTH surfaces in
    lockstep.  Supersedes the stale
    ``tests/test_stake_snapshot_permanence.py`` from 4af0c8d.
    (248cb3c)

  * **Unify signing-command fee floor through the server's live
    quote (audit r48 #3 -- UX top-1).**  Pre-fix only ``cmd_transfer``
    (audit r45 #2) consulted ``server_min_fee``.  Every other signing
    command -- ``cmd_send``, ``cmd_react``, ``cmd_stake``,
    ``cmd_unstake``, ``cmd_propose``, ``cmd_vote``, ``cmd_rotate_key``,
    ``cmd_send_multi_submit`` -- validated explicit ``--fee`` against
    a stale local constant (``calculate_min_fee``, ``KEY_ROTATION_FEE``,
    ``GOVERNANCE_VOTE_FEE``, ``proposal_fee_floor``) or skipped the
    floor check entirely.  CLAUDE.md anchors at risk: dual-purpose-
    token / "mainstream-asset quality bar" (silent over/under-charge
    is the canonical violation), and the fee-model anchor "when the
    fee model shifts, every auto-fee path shifts with it -- don't
    leave a tx kind defaulting to a stale flat fee while others
    auto-bid by density."  Audit r45 #2 closed this for transfer;
    this round extends the same closure to every other signing
    command via a shared chokepoint.

    Abstraction-over-symptom fix: new
    ``cli._resolve_fee_with_server_floor(*, kind, host, port, args,
    estimate_extra=None, auto_fee_extra=None, local_min_hint=None,
    target_height=None)`` helper is the single chokepoint every
    non-transfer signing command now routes through.  Calls
    ``estimate_fee`` once to extract both ``server_min_fee`` AND
    ``mempool_fee``, picks ``auto_fee`` if ``--fee`` is omitted,
    floors the picked fee at ``max(server_min_fee, local_min_hint)``
    as defense-in-depth, and ``sys.exit(1)``s on explicit ``--fee``
    below the live floor with a friendly error that quotes the
    server's number.  Adding a new signing path that bypasses this
    helper reintroduces the audit r48 #3 defect by definition.
    (4ae6c28)

## [1.76.0] — 2026-05-11

Minor release.  Audit r47 top-3 ships: one new hard fork (Tier 71 --
``effective_weight`` flows to per-slot attester reward sizing,
activation height 6500), one consensus-layer determinism refactor
(fork-choice cumulative weight routes through a single pinned-stake
chokepoint, same recurrence-pattern as the audit r46 #1 attestation
fix), and one network-layer security fix (submission receipt
suppressed when the validator's outbound relay raises, closing an
honest-operator slashing-magnet under broken relay paths).

### Changed (Tier 71, consensus-breaking, height-gated)

  * **``effective_weight`` flows to per-slot attester reward sizing
    (audit r47 #2 -- economics top-1).**  Tier 70 (1.75.0) introduced
    the rational soft-cap ``effective_weight(s) = s * C / (s + C)``
    and routed three selection-active call sites through it:
    ``weights_for_progress`` (attester-committee SELECTION),
    ``select_proposer_vrf`` (active proposer-selection), and
    ``Blockchain._selected_proposer_for_slot`` fallback.  But the
    per-slot attester reward SIZING path in
    ``SupplyTracker.mint_block_reward`` (and its sim mirror in
    ``Blockchain.compute_post_state_root``) was NOT routed through
    the helper -- both the bps numerator and the total-active-stake
    denominator read RAW stake:

        total_active_stake = sum(self.staked.values())          # raw
        stake_bps = self.staked.get(eid, 0) * 10_000 // total   # raw

    The v4 reward-curve multiplier then sized each attester's per-
    slot reward off that raw bps -- so on a chain with a single
    dominant staker, the small-stake validator's ``stake_bps``
    rounded toward 0 (e.g. at 200 / 50M = 0.04 bps -> 0 under
    integer division) while the founder absorbed the bulk of the
    per-slot pool via raw-bps weighting, even though Tier 70 had
    already compressed the selection-probability distribution.

    CLAUDE.md anchor at risk: "Stake concentration is softly capped
    via diminishing returns -- rich-get-richer in absolute terms,
    but their share of issuance compresses over time."  Tier 70
    compressed SELECTION share; without this fix the per-slot reward
    sizing path stretches the compression back out to linear.  The
    anchor's load-bearing property ("smaller validators earn at a
    strictly higher per-unit rate than larger ones") was therefore
    only half-realized post-Tier-70.

    Abstraction fix: Tier 71 routes the per-slot reward sizing
    through the same ``effective_weight`` chokepoint Tier 70
    anchored.  Both numerator and denominator flip to effective-
    weight in lockstep so the bps share inherits the soft-cap
    compression.  Pre-fork is byte-identical to legacy.  Post-fork
    the small-stake validator's bps share becomes meaningfully non-
    zero (~2 bps at 200/50M with C=1M), feeding through to the v4
    multiplier's small-staker bonus.

    Both code paths flip at the same height -- the apply path
    (``SupplyTracker.mint_block_reward``) and the sim mirror
    (``Blockchain.compute_post_state_root``) -- so the state-root
    commitment matches the apply path bit-for-bit at the activation
    block.

    Activation height 6500 sits 2000 blocks above Tier 70 (4500) --
    ~13.9d cohort spacing matching the Tier 69->70 runway.  Two
    consecutive reward-distribution changes need their own cohorts;
    piling reward-distribution changes into the same cohort forces
    operators to absorb the combined change in one upgrade cycle.

    Sibling holes audit r47 surfaced but DEFERRED:
      - The proposer-cap redistribute path inherits the compression
        automatically once ``attestor_rewards`` are effective-weight-
        bps-sized.
      - ``FINALITY_VOTE_INCLUSION_REWARD`` direct-mints to the
        proposer outside both the cap and ``effective_weight``;
        pooling into the attester pool is deferred to a later audit
        cycle.
      - ``ProofOfStake.select_proposer`` (dead but exported, uses
        raw stake); currently unreached on the consensus path,
        routing or hard-deleting is a separate refactor.

    No new wire format, no new tx kinds, no state-tree changes.
    (8b3ef24)

### Fixed

  * **Fork-choice cumulative weight routes through pinned-stake
    helper (audit r47 #1 -- security top-1).**  ``Blockchain._append_
    block`` computed fork-choice block weight against live
    ``self.supply.staked``, then ``_process_attestations`` ran, then
    the per-block stake snapshot was pinned at
    ``_stake_snapshots[block_number]``.  Walk-back recompute paths
    (``_compute_cumulative_weight`` and
    ``_compute_full_cumulative_weight``) read the pinned snapshot.

    Today nothing between weight-compute and pin mutates
    ``supply.staked``, so the stored value and the walk-back value
    coincide on the live mainnet.  But the SHAPE of the bookkeeping
    -- "compute against live, pin later" -- is the same defect-shape
    audit r46 #1 just closed for the attestation-finality denominator
    (``resolve_pinned_attestation_stake``).  Any future refactor that
    introduces a mutation between weight-compute and pin (slashing
    on attestation processing, witness-tier post-finality stake
    adjustments, etc.) would silently produce two values that
    disagree -- and under the lex-smaller-hash fork-choice tie-break
    a fork that should have lost wins a spurious reorg.

    Abstraction fix: new ``Blockchain._pinned_stake_at(block_number)``
    helper is the single chokepoint every cumulative-weight call
    site routes through.  ``_append_block`` pins the snapshot BEFORE
    computing fork-choice weight so weight and snapshot are sourced
    from the same dict by construction; ``_compute_cumulative_weight``
    and ``_compute_full_cumulative_weight`` replace their inline
    pinned-with-fallback patterns with the same helper.  Distinct
    from ``resolve_pinned_attestation_stake`` (strict, returns None
    on missing pin) because fork-weight has legitimate snapshot-
    pruned-era callers that need the live fallback to keep walking
    back over ancient blocks.

    Functional effect today is byte-identical; what changes is the
    abstraction boundary.  Adding a new fork-weight caller in the
    future without going through the helper is exactly the
    recurrence-shape audit r46 #1 closed for the attestation path.
    No fork, no consensus rule change at the validator boundary,
    no wire-format change, no new tx kinds.  Pure refactor closing
    a recurrence pattern.  (6aff303)

  * **Suppress SubmissionReceipt when relay_callback raises (audit
    r47 #3 -- security top-2).**  The HTTPS submit handler caught
    any exception from the optional ``relay_callback`` hook, logged
    it, and proceeded to write the JSON response including the
    SubmissionReceipt the validator just signed.  The receipt was
    made public; the validator was committed to a promise they could
    not honor.

    Scenario: an honest validator whose outbound relay surface
    silently breaks (misconfigured firewall, transient partition,
    peers churning) admits a tx to its mempool and issues a receipt.
    The tx ages out of the validator's mempool TTL having never
    reached another node -- no peer has it, so no proposer ever
    includes it.  ``EVIDENCE_INCLUSION_WINDOW`` elapses; the
    submitter files a ``CensorshipEvidenceTx``; the validator loses
    ``CENSORSHIP_SLASH_BPS`` (10%) of stake per matured slash.

    CLAUDE.md anchors at risk: honest-operator insurance ("honest,
    well-configured nodes should rarely if ever be slashed under
    normal operation") and validator-collusion defense (a
    coordinated attacker can target small/honest validators with
    broken relay paths and drain their stake one 10%-slice at a
    time for the cost of a tx submission per filing -- mainnet-
    exploitable on either validator).

    Fix: on relay failure, suppress ``receipt_hex`` from the
    response.  The tx is still admitted (200 OK with ``tx_hash``,
    mempool entry intact), but no SubmissionReceipt bytes leave the
    validator's process.  Without those bytes, the submitter cannot
    weaponize this validator's signature into a CensorshipEvidenceTx
    -- the slashing-magnet is closed.  The receipt-subtree leaf is
    privately burnt (the WOTS+ key was used internally), but the
    signed receipt was never published, so no PUBLIC commitment was
    made -- the validator hasn't lied to anyone.

    Senders who want a receipt can fan out via ``send-multi`` to peer
    validators whose relay surface is intact.  This is the exact
    "single validator can't be coerced into silent drop" escape
    hatch the censorship-evidence pipeline exists to provide;
    suppressing the receipt on the broken-relay validator routes the
    submitter toward that fan-out, not toward a slash filing they
    could later misuse.

    The fix preserves the existing fail-open semantics from the
    receipt-budget gate (audit 2026-04-28): a response with
    ``ok=true`` and no receipt field is already a documented success
    shape, so honest clients (including ``send-multi``) handle it
    correctly.  No wire-format change, no consensus rule change, no
    fork, no new tx kinds.  Pure network-layer hardening.  (ad2e845)

## [1.75.0] — 2026-05-11

Minor release.  Audit r46 top-3 ships: one hard fork (Tier 70 --
stake-concentration soft cap), one consensus-layer determinism fix
(gossip-ingress attestations must read pinned-at-target-height stake,
not live), and one CLI / value-prop fix (``send-multi`` unified with
``cmd_send``'s signing pipeline so the censorship-resistance escape
hatch actually accepts the keyfile formats ``generate-key`` produces
and handles first-spend through the fan-out path).

### Changed (Tier 70, consensus-breaking)

  * **Stake-concentration soft cap -- sublinear concave reward curve
    (audit r46 #2 -- economics top-1).**  CLAUDE.md anchor "Stake
    concentration is softly capped via diminishing returns -- rich-
    get-richer in absolute terms, but their *share* of issuance
    compresses over time."  Pre-Tier-70 the live code was strictly
    linear: ``weights_for_progress`` blended uniform -> stake linearly
    and at ``progress=1`` (always, after the ~2yr bootstrap)
    weight = raw stake.  ``select_proposer_vrf`` and ``Blockchain._
    selected_proposer_for_slot`` fallback both did cumulative-stake
    walks on raw stake.  Founder-scale stake captured ~99% of proposer
    slots AND ~99% of attester-committee picks indefinitely --
    precisely the "permanent rent-extracting majority" CLAUDE.md says
    is out of scope.  Sybil-fragmentation of a whale was also mildly
    INCENTIVIZED (splitting 1M into 100x10k was reward-neutral to
    positive).

    Tier 70 introduces the rational soft-cap form

        effective_weight(s) = s * C / (s + C)

    with C = ``STAKE_CONCENTRATION_SOFT_CAP`` = 1_000_000 tokens.
    Properties (matching the CLAUDE.md anchor exactly):
      - monotonically increasing in s (whale's absolute reward still
        rises -- 24/7 honest operation always preferred over withdraw)
      - per-unit yield w(s)/s = C/(s+C) monotonically DECREASES in s
        (smaller validators earn at a strictly higher per-unit rate)
      - asymptote: w(s) -> C as s -> infinity ("asymptotic soft cap")
      - no hard cap: w(s) < C always but approaches it
      - concave; second derivative everywhere negative
      - at s << C: w(s) ~= s (min-stake validators see no curve bite)
      - at s >> C: whales see strongly diminishing returns

    At founder-scale (50M stake) effective weight ~= 980k vs a min-
    stake (200) validator's ~200; the per-unit-yield ratio at
    progress=1 is ~51x -- a min-stake validator earns ~51 tokens of
    weight for every 1 token the founder earns per unit staked, on
    the strict letter of the anchor.

    Single chokepoint: new ``effective_weight(stake, block_height)``
    helper in ``consensus/attester_committee.py``.  All three
    consensus-active call sites route through it:
      - ``weights_for_progress`` (attester-committee weighting)
      - ``select_proposer_vrf`` in ``consensus/vrf.py`` (active
        proposer path)
      - ``Blockchain._selected_proposer_for_slot`` fallback (pre-VRF /
        very-early-chain proposer path)

    Pre-fork ``effective_weight`` is the identity, so historical-block
    replay is byte-identical and all pre-existing tests continue to
    pass without modification.

    Activation height 4500 sits 1800 blocks above Tier 69 (2700) --
    ~12.5 days cohort spacing well above the Tier 49-69 tight-cohort
    pattern.  An economic-distribution change is qualitatively
    different from honesty-curve tightening, so the runway is longer
    for validator coordination.  No new wire format, no new tx kinds,
    no state-tree changes.  The asymptotic-soft-cap SHAPE is the
    anchored choice; the soft cap C and the activation height are
    tuning knobs a future Tier may re-tune.  (96a2cea)

### Fixed

  * **Gossip-ingress attestation must use pinned stake snapshot, not
    live (audit r46 #1 -- security top-1).**  ``Node._handle_announce_
    attestation`` and the local-broadcast path
    (``Node._attest_block_if_allowed``) both read live ``supply.staked``
    when computing the (validator_stake, total_stake) denominator
    passed to ``finality.add_attestation``.  The consensus apply path
    (``Blockchain._process_attestations``) reads the pinned-at-target-
    height snapshot from ``self._stake_snapshots``; gossip-ingress
    dedup is keyed ``(validator_id, height, hash)``, so whichever path
    arrived first won the stake contribution.  During stake-churn
    windows two honest peers could land different ``attested_stake[bh]``
    totals on the same key and reach different ``is_finalized()``
    answers -- splitting the persistent finalized set and forking the
    chain on reorg-rejection.

    CLAUDE.md adversary at risk: validator collusion (#1, primary).
    On the currently-2-node mainnet, small-set arithmetic amplifies
    the divergence: any peer holding minority stake could trigger
    split finalization across the network during a stake-churn
    window.  Honest-operator-insurance also threatened -- a benign
    restart racing its gossip with a stake change was enough.

    Abstraction fix: new ``Blockchain.resolve_pinned_attestation_
    stake(att)`` helper is the single chokepoint every writer to the
    FinalityTracker denominator now routes through.  Returns
    ``(validator_stake, total_stake)`` from the pinned snapshot at
    ``att.block_number``, or ``None`` when no pin exists.  Callers
    must skip the finality update on the None path; substituting
    live state is the divergence trap.  Three call sites --
    ``_process_attestations`` (already consensus-correct, now DRY),
    ``_handle_announce_attestation`` (was buggy, now fixed), and
    ``_attest_block_if_allowed`` (was buggy, now fixed) -- share the
    helper, so a new finality writer in the future can't silently
    reintroduce the live-stake fallback.  Soft fix: no fork, no
    consensus rule change, no wire-format change.  (95fdaea)

  * **``cmd_send_multi_submit`` unified with ``cmd_send``'s signing
    pipeline (audit r46 #3 -- UX x security x value-prop).**  The
    censorship-resistance escape hatch had three coupled defects, all
    rooted in one missing abstraction (the shared signing pipeline
    ``cmd_send`` evolved but ``cmd_send_multi_submit`` never adopted):

      (a) Keyfile load was hand-rolled ``bytes.fromhex(hex_key)`` --
          only accepted bare 64-char hex.  Rejected 24-word BIP-39
          mnemonics and 72-char checksummed hex, the only formats
          the README's ``generate-key`` actually produces.  A user
          who pasted their recovery phrase or checksummed backup
          got "keyfile must contain a 64-char hex private key" and
          fell back to ``cmd_send`` -- the single-RPC path the
          escape hatch exists to AVOID.

      (b) Skipped the Tier 11 first-spend pubkey-install probe.
          A fresh-key first-spend through ``send-multi`` landed as
          a v1 tx without ``sender_pubkey``, and every endpoint
          rejected with "Unknown entity -- must register first."
          The most likely use case for ``send-multi`` (a fresh-key
          dissident's first controversial post) was silently
          broken; the failure looked like validator-collusion
          censorship but was actually missing pubkey install.

      (c) ``--keyfile`` wasn't named in ``send-multi --help`` and
          wasn't shown in the README example.

    Abstraction fix: new ``_should_include_pubkey(host, port,
    entity_id, target_height)`` helper is the single chokepoint for
    the first-spend pubkey-install probe.  ``cmd_send`` and
    ``cmd_send_multi_submit`` both route through it.  Adding a new
    signing path that bypasses this helper reintroduces the audit
    r46 #3 defect.  ``cmd_send_multi_submit`` now uses
    ``_resolve_private_key(args, personal_wallet=True)`` -- the same
    helper 27 other signing commands use.  Parser description and
    README's send-multi example both name ``--keyfile``.  No fork,
    no consensus rule change, no wire-format change, no new tx
    kinds.  (18bb0f7)

## [1.74.1] — 2026-05-11

Patch release.  Audit r45 top-3 ships: three independent bugfixes
spanning the network-layer ban subsystem, the CLI's transfer fee
floor, and the censorship-evidence on-disk artifact path.  No new
tx kinds, no new wire format, no consensus rule change at the
validator, no hard fork.

### Fixed

  * **Ban auto-clear requires strictly-newer semver (audit r45 #1
    -- security top-1).**  Pre-fix
    ``PeerBanManager.clear_ban_on_version_change`` cleared a ban
    whenever the reported version was any non-empty, non-``"unknown"``
    string that differed from the stored ``peer_version``.  Bypass
    cycle:

      1. attacker earns ``OFFENSE_INVALID_TX`` (instant-ban),
         ``peer_version="1.46.0"``;
      2. reconnect with ``version="x"`` -> clear, ``peer_version="x"``;
      3. attacker re-offends -> banned again, ``peer_version="x"``;
      4. reconnect with ``version="y"`` -> clear; repeat indefinitely.

    Every banscore-graded defense (gossip flood, invalid-tx flood,
    invalid-block flood, protocol-violation flood) collapsed to
    ~zero cost -- the ban subsystem was purely advisory.  CLAUDE.md
    anchor at risk: Security (principle #1, never compromise).
    Adversaries no longer defended: validator-collusion + AI-spam
    flooding (both banscore-graded), plus the general "honest-
    operator's network-layer defense surface" the ban subsystem
    exists to provide.

    Fix: the reported version must (a) parse as a valid semver per
    ``parse_release_version``, AND (b) be strictly newer than the
    stored ``peer_version`` per
    ``release_version_is_strictly_newer`` -- the same comparator the
    release-manifest consensus apply path uses.  An attacker's
    bypass set is bounded by the chain's actual forward release-tag
    progress, not by their choice of garbage strings.  The
    legacy-empty-peer_version path (pre-1.48 ban entries that loaded
    with no ``peer_version`` field) is preserved -- any valid semver
    clears once, then subsequent bans go through the strict-newer
    gate.  Pure network-layer hardening; no fork, no consensus rule
    change, no wire-format change.

    8 regression tests in
    ``tests/test_audit_r45_ban_version_strict_newer.py``.  Existing
    ``tests/test_ban_decay.py`` suite (10 cases) continues to pass
    -- all its strings were already real semvers.  (c3e8e18)

  * **CLI transfer fee follows server's live floor, not legacy
    MIN_FEE (audit r45 #2 -- economics top-1).**  Pre-fix
    ``cmd_transfer`` (and the ``client.py`` mirror) computed
    ``required_floor = max(MIN_FEE, server_min_fee)``.  ``MIN_FEE``
    is the legacy pre-FLAT_FEE_HEIGHT constant of 100.  Tier 49
    (``UNIFIED_FEE_FLOOR_HEIGHT=1750``, long since live) collapsed
    the unified transfer / stake / unstake admission floor to
    ``MARKET_FEE_FLOOR=1``.  The server's ``estimate_fee`` RPC
    returned this correctly via ``tx_floor`` (height-aware), and
    ``auto_fee("transfer", ...)`` picked the right number via the
    same helper.  But the CLI's local clamp inflated the result
    back up to 100 -- silently over-charging every wallet user 100x
    the protocol floor on every transfer since Tier 49 activated.

    CLAUDE.md anchors at risk: dual-purpose-token /
    "mainstream-asset quality bar" -- wallet, transfer, and balance-
    handling code is held to mainstream-asset standards (a silent
    100x overcharge is the canonical violation); and the fee-model
    anchor ("when the fee model shifts, every auto-fee path shifts
    with it -- don't leave a tx kind defaulting to a stale flat fee
    while others auto-bid by density").

    Fix: drop the ``max(MIN_FEE, server_min_fee)`` clamp and trust
    ``server_min_fee`` directly (the height-aware ``tx_floor``
    result).  ``auto_fee`` already enforces the right floor
    internally; the post-auto-fee floor is now
    ``max(auto_fee_result, server_min_fee)`` -- defense-in-depth
    against a stale local height -- with no legacy ``MIN_FEE``
    constant in the path.  Error messages on explicit under-payment
    quote the live server floor, not the stale constant.  The
    brand-new-recipient surcharge branch (the chain validator hard-
    codes ``MIN_FEE + NEW_ACCOUNT_FEE``) stays correct via the
    server returning that total on the ``recipient_is_new`` branch.

    6 regression tests in
    ``tests/test_audit_r45_cli_transfer_fee_floor_drift.py`` pin:
    (1) auto-fee for existing-recipient transfer at post-Tier-49
    height yields a fee < ``MIN_FEE``; (2) ``--fee 50`` at post-
    Tier-49 height is accepted, not rejected with "below MIN_FEE
    100"; (3) ``--fee`` below the live server floor is still
    rejected, and the error text names ``server_min_fee`` not the
    legacy constant; (4) new-recipient surcharge path still binds
    correctly; (5) structural -- ``cli.py`` source no longer
    contains ``max(MIN_FEE, server_min_fee)``; (6) structural --
    ``client.py`` mirror.  (1164535)

### Added

  * **``cmd_transfer`` + ``cmd_react`` persist server-issued receipt
    bundle (audit r45 #3 -- UX / value-prop top-1).**  Pre-fix only
    ``cmd_send`` and ``cmd_send_multi_submit`` wrote the validator-
    issued ``SubmissionReceipt`` to
    ``~/.messagechain/receipts/<tx_hash>.json`` in the bundle shape
    ``submit-evidence censorship --receipt <path>`` consumes.
    ``cmd_transfer`` and ``cmd_react`` -- the only OTHER user-facing
    signed-tx commands whose server admit path actually issues a
    receipt (``Server._rpc_submit_transfer`` and
    ``Server._rpc_submit_react`` both surface ``payload["receipt"]``
    when the validator issued one) -- silently dropped
    ``result["receipt"]`` on success.  Without the on-disk bundle,
    the user holds no artifact to file as ``CensorshipEvidenceTx``
    if a coerced validator silently drops the transfer or react.

    CLAUDE.md collective-censorship-resistance anchor: "a tx that is
    well-formed, pays at least the per-byte floor, and fits the
    byte budget cannot be suppressed by anything weaker than a full
    validator-set majority actively colluding *and* willing to
    absorb the slashing risk."  The slashable-evidence path is the
    structural defense; saving the receipt the moment the server
    returns it is the user-facing surface that makes it accessible.
    Also dual-purpose-token / "mainstream-asset quality bar" --
    transfer is a first-class tx type and the censorship-evidence
    promise must apply to transfers just like to messages.

    Fix: route ``cmd_transfer`` and ``cmd_react`` success paths
    through the same ``_save_receipt_bundle`` helper ``cmd_send``
    uses, with ``tx_kind="transfer"`` / ``tx_kind="react"`` so
    ``_load_receipt_bundle`` picks the right deserialiser.  Best-
    effort write -- a disk failure logs a warning but does NOT fail
    the command (the tx is already on the wire).  Receipt-absent
    path is preserved (no bundle written when the server didn't
    issue one, e.g. receipt-subtree-budget pressure).  Other signed-
    tx commands (``cmd_stake`` / ``cmd_unstake`` / ``cmd_propose`` /
    ``cmd_vote`` / ``cmd_rotate_key`` / ``cmd_emergency_revoke``)
    are intentionally NOT in scope -- their server admit paths do
    not issue receipts today; extending those is a separate,
    larger structural change.

    7 regression tests in
    ``tests/test_audit_r45_transfer_react_save_receipt_bundle.py``
    pin: (1) ``cmd_transfer`` with server-returned receipt writes
    bundle; (2) bundle carries ``tx_kind="transfer"`` + serialized
    ``TransferTransaction`` that round-trips through
    ``deserialize()``; (3) ``cmd_transfer`` with NO server receipt
    writes no bundle (and does not crash); (4) ``cmd_react`` with
    server-returned receipt writes bundle; (5) bundle carries
    ``tx_kind="react"`` + serialized ``ReactTransaction``; (6, 7)
    structural -- ``cmd_transfer`` / ``cmd_react`` bodies invoke
    ``_save_receipt_bundle``.  (02c1bed)

## [1.74.0] — 2026-05-11

Minor release.  Audit r44 top-3 ships: three independent
public-surface / value-prop fixes covering the chain's headline
value-prop demo URL, the censorship-resistance escape hatch's
escalation path, and the social-platform framing of the entity
profile page.  No new tx kinds, no new wire format, no consensus
rule change at the validator, no hard fork.

### Added

  * **`/e/<entity_id>` profile page renders recent messages
    (audit r44 #3 -- value-prop top-1).**  Pre-fix the profile page
    rendered only four counter grids (Funds / Activity / Reputation
    / Governance).  A visitor clicking "from mc1..." on any feed
    card landed on a block-explorer-style page with no list of the
    entity's actual messages.  No mainstream social product hides
    the profile owner's posts; this gap broke the chain's
    "decentralized reddit/twitter core" positioning at the third
    click of every visitor's exploration loop.

    CLAUDE.md anchor at risk: Positioning (decentralized social-
    platform framing on the public surface).

    Fix is three layers, all read-only, no protocol or wire-format
    change:

      * `Blockchain.get_recent_messages_by_entity(entity_id, count)`
        -- new chain helper mirroring `get_recent_messages`' schema
        (message / entity_id / timestamp / tx_hash / block_number /
        ups / downs / up_pct / optional prev + community_id).
        Filters on entity_id, returns newest-first, capped to
        count.
      * `GET /v1/entity_messages?id=<64-hex>&limit=N` -- new
        public-feed HTTP endpoint.  id is validated as 64-hex;
        limit is clamped to `PUBLIC_FEED_MAX_LIMIT`.  Returns
        `{ok, height, messages}` with the same per-entry schema
        as `/v1/latest` so the profile-page client reuses the
        global feed's card pattern with no schema branching.
      * `entity.html` gains a "Recent messages" section under
        the existing four counter sections.  New CSS for
        `.msg-card` matches the visual register of the global
        feed.  `loadMessages(id)` runs in parallel with the
        existing profile fetch so a slow chain scan doesn't
        block the counters from rendering.  Each card carries
        body text (textContent for XSS safety), a "Permanent"
        permalink to `/r/<tx_hash>`, block number, relative
        timestamp, optional community chip, vote summary, and
        an optional reply-thread arrow linking to `/r/<prev>`.

    9 regression tests in `tests/test_audit_r44_entity_recent_
    messages.py` pin: chain helper schema/newest-first/filter/
    count-cap behaviour, HTTP endpoint shape + malformed-id +
    limit-clamp, and entity.html section + endpoint reference +
    receipt-permalink wiring.

    Surfaced by audit r44 value-prop axis #1.  (4985b24)

### Fixed

  * **Receipt page renders pending state (audit r44 #1 --
    value-prop top-1).**  Pre-fix the dispatch in
    `receipt.html`'s `loadStatus` was binary:

        if (result.status === "included") renderIncluded(...);
        else                              renderNotFound(...);

    The public-feed shim `get_tx_status_public` deliberately
    returns only `"included" | "not_found"` (no `"pending"` --
    the public feed does not see the mempool, by design).  Net
    effect: every share-URL printed by `cmd_send` opened in the
    first ~10 min after submit landed on a red "Not found /
    suspect censorship" card for a tx that was behaving
    normally.  The chain's headline value-prop demo moment
    (the 1.71.0 share-URL + 1.73.0 message-body render)
    inverted itself on every successful send.

    CLAUDE.md anchor at risk: Mission ("your message can never
    be deleted") + Permanence -- the share-URL is THE public-
    facing permanence demo, and shipping it as a suspect-
    censorship card on the first ten minutes of every send
    actively trained share-link recipients to distrust the
    verdict.

    Fix is purely in `receipt.html`; the public-feed shim's
    "no mempool exposure" anchor is preserved.  New
    `renderPending(txHash)` uses the existing `.verdict.pending`
    CSS class (styled but unreached) and surfaces a "Waiting
    for inclusion -- typical for ~10 min after submission"
    verdict with a countdown of remaining retries.
    `loadStatus`'s not_found branch routes through
    `renderPending` for the first `PENDING_RETRY_BUDGET`=48
    polls (48 * 15s = 12 min) and self-polls via setTimeout,
    only falling through to `renderNotFound` (the existing
    suppression narrative + slashable-evidence escalation
    pointer) once the budget exhausts.

    Pure client-side fix.  No server change, no public-feed
    schema change.

    6 regression tests in `tests/test_audit_r44_receipt_
    pending_render.py` pin: `renderPending` exists, uses
    `.verdict.pending` class, surfaces a reassuring "typical
    wait" narrative, `loadStatus` dispatches not_found through
    `renderPending`, auto-refresh via setTimeout is wired,
    retry budget eventually falls through to `renderNotFound`.

    Surfaced by audit r44 #1.  (77d8225)

  * **`send-multi` writes JSON receipt bundles (audit r44 #2 --
    censorship-defense escalation path).**  Pre-fix the
    `send-multi` success path wrote `<tx_hash>_<issuer>.bin`
    files containing raw `receipt.to_bytes()` -- a format the
    slashable-evidence CLI cannot consume.
    `_load_receipt_bundle` (the `submit-evidence censorship
    --receipt <path>` loader) requires a JSON object with
    `receipt` AND `message_tx` keys and raises
    `ValueError("receipt bundle missing 'message_tx' field")`
    on a raw .bin.

    Net effect: a dissident reaches for `send-multi` (the only
    CLI path that defends against validator collusion), the
    censoring node silently drops their tx, they try
    `submit-evidence censorship --receipt receipts/<tx>_<issuer>
    .bin` to file the slashable evidence -- and the CLI rejects
    their own receipt with "missing `message_tx`".  The
    structural defense at the protocol level exists; the
    user-facing path to invoke it was broken end-to-end.

    CLAUDE.md anchors at risk: Censorship resistance ("one
    honest validator is enough" must be USABLE, not just
    structurally true); collective-decision framing -- the
    chain's anti-suppression machinery demands that evidence
    flow from individual users to the on-chain slashing path.

    Fix: `_save_receipt_bundle` gains an optional
    `filename_suffix` parameter (per-issuer keying for the
    multi-validator case while preserving byte-identical
    behaviour for the existing `cmd_send` single-receipt call);
    `cmd_send_multi_submit`'s success-path receipt write loop
    now calls `_save_receipt_bundle` with `filename_suffix=
    r.issuer_id.hex()[:16]` instead of writing raw .bin.  Each
    accepting validator's receipt lands as a JSON bundle the
    slashable-evidence CLI consumes without translation.

    Pure CLI ergonomics + on-disk format change; no protocol
    change, no wire-format change, no consensus rule change, no
    new tx kinds.

    3 regression tests in `tests/test_audit_r44_send_multi_
    json_receipts.py` pin: success path writes JSON (not .bin);
    bundles are keyed per (tx_hash, issuer_id) so N validators'
    receipts coexist; every written bundle round-trips through
    `_load_receipt_bundle`.  Companion update to
    `test_submit_client.py::TestCliMultiSubmit::test_cli_multi_
    submit_against_real_validator_persists_receipts` mirrors
    the format change.

    Surfaced by audit r44 #2.  (5582a7d)

## [1.73.0] — 2026-05-11

Minor release.  Audit r43 top-2 ships: the per-message permanence-
receipt page at `/r/<tx_hash>` now renders the message body
itself (the value-prop demo moment lands as "[body] — Permanent",
not as a bureaucratic hash-and-percentages explorer page), and
`send-multi` (the censorship-resistance escape hatch) gains the
smart-defaults parity with `cmd_send` it should have shipped with
— auto-fee, auto-nonce, auto-leaf-watermark via a new optional
`--server` for chain-state queries, plus a README "Defending
against single-node suppression" subsection so the protocol's
structural defense against validator collusion has a usable
surface.  No new tx kinds, no new wire format, no consensus rule
change at the validator, no hard fork.

### Added

  * **Receipt page renders the message body (audit r43 #2 --
    value-prop top-1).**  Pre-fix the 1.71.0 shareable-receipt
    URL at `/r/<tx_hash>` -- the URL every `cmd_send` success
    now prints alongside the `Share:` line -- rendered only the
    inclusion verdict + finality stats + Merkle inclusion proof.
    A friend who followed the share link saw a `Permanent` badge
    attached to an opaque 64-hex `tx_hash`, with no message
    body visible.  The chain's headline mission ("your message
    can never be deleted") was invisible at the exact moment a
    share-receipt link should make it visceral.

    CLAUDE.md anchor at risk: Mission + dual-purpose-token /
    mainstream-asset quality bar -- the receipt page is the
    value-prop in motion, and shipping it as a hash-and-
    percentages explorer reads as "trust the verdict" rather
    than "here's the permanent artifact."

    Fix:

      * `Blockchain.get_tx_status_public` (the public-feed HTTP
        shim backing `/v1/tx_status`; consumed by `/r/<tx>`)
        now includes the message body, author `entity_id`,
        optional `community_id`, and optional `prev`-pointer
        hash for an included `MessageTransaction`.  Fields are
        surfaced only when meaningful -- `community_id` / `prev`
        omitted when None, `message`-body only on
        `MessageTransaction` (transfer / react / slash carry no
        user-readable body).
      * `Server._build_included_status` (the JSON-RPC twin
        consumed by `messagechain receipt` CLI) mirrors the same
        fields so the receipt UI sees a consistent schema
        regardless of port hit.
      * `messagechain/static/receipt.html` `renderIncluded` now
        renders a new Message section between the verdict and
        the block-stats grid: body text (`textContent`, XSS-safe
        -- chain payloads are arbitrary user bytes),
        `by <entity_id>` link to `/e/<hex>`, optional community
        badge linking to `/?community=<handle>`, optional
        reply-parent link to `/r/<prev>`.  Section is hidden
        when `result.message` is absent so transfer / react
        receipts and pre-fix browser caches stay clean.

    Pure value-prop / read-only HTTP surface fix.  No fork, no
    consensus rule change, no wire-format change, no new tx
    kinds.  `get_tx_status_public` is read-only metadata about
    txs already on chain -- every included tx's plaintext,
    `entity_id`, `community_id`, and `prev` are already public
    anyway via `canonical_block_tx_hashes` and full-block
    fetches.

    7 regression tests in `tests/test_audit_r43_receipt_renders_
    message_body.py` pin: (1) `get_tx_status_public` returns
    `message` + `entity_id` for an included message; (2)
    `community_id` surfaces when set; (3) `community_id` omitted
    when None (no empty placeholder); (4) `prev` surfaces when
    set; (5) `Server._build_included_status` mirrors all four
    fields for CLI parity; (6) `receipt.html` references
    `result.message` in the JS source; (7) `receipt.html`
    references `result.entity_id` and links to `/e/`.

    Surfaced by audit r43 value-prop axis #1 -- every share-
    receipt link issued from CLI or feed now lands on a page
    that surfaces what was actually anchored, not just the
    verdict that something was.  (dae6023)

  * **`send-multi` auto-resolves fee + nonce + leaf watermark
    (audit r43 #3 -- UX top-1).**  Pre-fix the censorship-
    resistance escape hatch (the only CLI path that defends a
    single user against validator collusion / single-RPC-node
    suppression) required the user to hand-supply `--fee`
    (`required=True`), defaulted `--nonce` to 0 (silently wrong
    on any non-fresh account), and used `--nonce` as the
    `--leaf-index` floor with no reconciliation against the
    chain's actual watermark.  A dissident reaching for this
    command under pressure was exactly the population that
    would set `--nonce 0` from muscle memory and either bounce
    off "nonce too low" or, on a fresh-machine + previously-
    used keyfile combination, burn a WOTS+ leaf the chain had
    already seen -- grounds for equivocation slashing.

    The on-disk per-entity leaf cursor (1.40.x cross-process
    defense, `_bind_persistent_leaf_index`) already closed the
    same-machine reuse window, so the agent's "100% slash on
    first reuse" framing overstated the risk in the common
    case -- but the cross-machine fresh-disk + reused-keyfile
    path was still uncovered, and the manual-everything
    ergonomics kept the structural-defense surface effectively
    invisible to the population it exists for.

    CLAUDE.md anchors at risk: censorship resistance ("one
    honest validator is enough" must be usable, not just
    structurally true); honest-operator insurance (leaf-reuse-
    via-default is a stake-destroying footgun); Simplicity
    (principle #3 -- hidden complexity is fine, surfaced
    complexity is not).

    Fix:

      * `--fee` is now optional; `cmd_send_multi_submit` routes
        through the shared
        `messagechain.economics.auto_fee.auto_fee` when omitted
        (same path as `cmd_send`).  New `--urgency` argument
        {low, normal, high} tunes the picker.
      * `--nonce` is now optional; auto-resolved via the
        `get_nonce` JSON-RPC against the new `--server`
        (defaults to your local node).
      * `--leaf-index` is now optional; auto-resolved to the
        `leaf_watermark` returned by the same `get_nonce` RPC
        -- parity with `cmd_send`.  The on-disk cursor
        continues to floor it independently so two consecutive
        runs cannot reuse the same leaf even on a fresh machine.
        Together the two defenses close the cross-machine
        fresh-disk + reused-keyfile window.
      * New `--server host:port` argument is the SOURCE of
        chain state for the auto-defaults above; it is
        INDEPENDENT of the fan-out `--endpoint` set, which
        continues to drive the multi-validator HTTPS submission.
        For trust-minimisation, users should point `--server`
        at their own node.
      * README "Defending against single-node suppression"
        subsection names `send-multi` directly with a worked
        example, plus a one-liner in the CLI reference.  The
        protocol's structural defense against validator
        collusion now has a doc surface.

    Pure CLI ergonomics + read-only RPC use; no fork, no
    consensus rule change, no wire-format change, no new tx
    kinds.  Explicit `--fee N` / `--nonce N` /
    `--leaf-index N` overrides are preserved exactly as before;
    the change is purely additive.

    5 regression tests in `tests/test_audit_r43_send_multi_
    smart_defaults.py` pin: (1) parser accepts `send-multi`
    without `--fee`; (2) omitted `--nonce` resolves to the
    chain's nonce via `get_nonce`, AND the resulting signature
    uses the chain's `leaf_watermark` (not nonce-as-fallback);
    (3) omitted `--fee` threads through `auto_fee` (sentinel
    return value lands on the tx); (4) explicit `--fee`
    overrides the auto-pick; (5) README mentions `send-multi`.

    Surfaced by audit r43 UX axis #1 -- the chain's structural
    defense against its primary adversary now has a usable
    surface.  (c503a79)

## [1.72.0] — 2026-05-11

Minor release.  Tier 69 hard fork — three coupled honesty-curve
refinements that push the slashing curve further toward the
CLAUDE.md "honest operators are insured against accidents" anchor
without weakening the deliberate-Byzantine bar.  Activation at
height 2700, ~8.3h cohort spacing above Tier 68.

### Changed (Tier 69, consensus-breaking)

- **``slash_offense_counts`` decay sweep.**  Pre-Tier-69 the per-
  offender slash counter was monotonic — one transient slash
  permanently disqualified a validator from Tier 24 amnesty AND
  from full honest-history relief for the rest of their tenure.
  That mismatched the third track-record factor ("good-vs-bad
  RATE"): a long-tenured operator with one ancient slip and
  millions of good blocks was treated as if the slip just
  happened.  Post-Tier-69 every ``HONESTY_CURVE_DECAY_PERIOD_BLOCKS``
  (= 4_320, ≈ 30 days at 600s blocks) of progress past activation
  decays every positive prior by 1, so a single offense recovers
  to amnesty-eligible after one period of clean operation.
  Sustained bad actors accumulate priors faster than they decay,
  so the deliberate-bad-actor curve is unchanged.  Sweep runs at
  the END of ``_apply_block_state`` (after the audit-r41 deferred
  bump loop) so sim and apply paths agree on the pre-decay
  priors during severity computation — the decay takes effect
  for the NEXT block.

- **Restart-drift window widened 120s → 600s.**  Pre-Tier-69 the
  AMBIGUOUS-vs-UNAMBIGUOUS classifier admitted block-header
  restart-shape evidence only if the two timestamps differed by
  ≤120s.  Honest restart cycles on heavy load (mempool rebuild +
  disk fsync + WOTS+ leaf seek) routinely take longer; the
  tight window was forcing legitimately-honest restart artifacts
  onto the UNAMBIGUOUS path (50% floor on first, 100% repeat).
  Post-Tier-69 the window widens to 600s (10 min).  Pure
  classification change — restart-shape evidence carries no
  fork-grinding economic value at any drift width (same parent,
  same state_root, same checkpoint), so widening the window
  cannot help an attacker.

- **AMBIGUOUS-path cap tightened 10% → 3%.**  Pre-Tier-69 the
  Tier-51 cap bounded AMBIGUOUS-path output at 10%.  10% is
  "small fractional" against a wipe, but for a restart-shape
  repeat-offense pattern it is still operationally painful (5
  events compound to ~40% of stake lost over time).  Post-
  Tier-69 the cap tightens to 3%, firmly in "operational
  nuisance, recoverable" territory.  UNAMBIGUOUS path is
  untouched — deliberate Byzantine evidence still carries the
  50%+ first-offense floor and 100% repeat.

### Added

- ``_apply_slash_offense_decay`` — the decay-sweep chokepoint.
  Routes each decrement through ``_bump_slash_offense_count`` so
  the chaindb mirror picks up the writes at the same chokepoint
  as the +1 path.  Iterates ``sorted(keys())`` for replay
  determinism.

- ``_bump_slash_offense_count`` now clamps at 0 — the decay sweep
  calls it with ``delta=-1`` and must not underflow on a clean
  validator.

- New config constants: ``HONESTY_CURVE_TIER69_HEIGHT``,
  ``HONESTY_CURVE_DECAY_PERIOD_BLOCKS``,
  ``HONESTY_CURVE_RESTART_DRIFT_SECS_TIER69``,
  ``HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69``.  Asserts at the
  bottom of the block enforce that the fork is a one-way leniency
  move (wider drift, tighter cap).

- ``classify_block_evidence`` takes an optional ``current_height``
  parameter (default 0 for pre-fork legacy callers); the caller
  in ``_compute_slash_pct`` passes ``self.height`` so the
  classifier picks the active drift window deterministically.

### Tests

- ``tests/test_honesty_curve_tier69.py`` — 30 tests across the
  three changes: constants exist with the right shape, pre-fork
  byte-identical behavior, post-fork tightened cap binds,
  UNAMBIGUOUS path untouched, drift-window boundary cases (≤120s
  pre-fork AMBIGUOUS, 121–600s post-fork AMBIGUOUS, >600s
  UNAMBIGUOUS), different-state_root / different-prev_hash still
  UNAMBIGUOUS at the wider window, decay sweep no-op
  pre-activation, decay sweep no-op on activation block, decay
  sweep fires at first period boundary, repeated sweeps recover
  high-prior validators, post-decay amnesty eligibility for a
  long-tenured one-slip validator, ``_bump`` clamp at 0 for
  negative-delta calls.


## [1.71.1] — 2026-05-11

Patch release.  THE actual root-cause hotfix for the 2026-05-11
v2 reorg-then-reject incident that the 1.71.0 rollout
surfaced.  ``Blockchain._reorganize``'s forward-replay loop
was applying each replayed block via ``_apply_block_state(blk)``
ONLY -- it was silently skipping the two per-block bookkeeping
calls the normal ``add_block`` path makes after apply:
``_process_attestations(blk, self.supply.staked)`` (which bumps
``self.reputation`` for every attester AND updates
``self.finality``) and ``_record_stake_snapshot(blk.header.
block_number)`` (which pins the per-block stake map for
downstream finality vote validation).  No fork, no consensus
rule change at the validator, no new wire format, no new tx
kinds, no new CLI surface -- pure forward-apply / reorg-replay
symmetry fix.

### Fixed

  * **``_reorganize`` replay loop calls ``_process_attestations``
    and ``_record_stake_snapshot`` per replayed block (audit r42
    #3 -- actual root cause of v2 incident).**  Pre-fix the
    replay loop in ``Blockchain._reorganize`` was::

        for blk in apply_blocks:
            if self.height > 0:
                valid, reason = self.validate_block(blk)
                if not valid: ...
            self._apply_block_state(blk)
            self.chain.append(blk)
            self._block_by_hash[blk.block_hash] = blk

    The normal ``add_block`` path (the same file, ~250 lines
    above) makes TWO additional calls after each
    ``_apply_block_state``:

      1. ``self._process_attestations(blk, self.supply.staked)``
         -- consensus-visible: bumps ``self.reputation`` for
         each attester in the block AND updates
         ``self.finality`` (justified / finalized hashes).
         Reputation drives ``select_lottery_winner`` at every
         ``LOTTERY_INTERVAL`` block during bootstrap, which
         MINTS tokens directly into the winner's balance.  A
         frozen reputation tracker on the reorged node + a
         bumped one on uprestarted peers picks different
         lottery winners -> different per-entity balances ->
         diverged supply.staked-sum -> diverged state_root on
         the very next block apply.
      2. ``self._record_stake_snapshot(blk.header.block_number)``
         -- pins the per-block stake map for downstream
         finality vote validation.  Without per-block pins on
         replay, future finality vote processing for the
         replayed range falls back to live ``supply.staked``,
         diverging the 2/3 denominator from uprestarted peers.

    Both calls were SILENTLY ABSENT from the reorg-replay loop.

    Concrete cascade reproduced on validator-2 during the
    2026-05-11 1.71.0 rollout (now landed v1.71.0 + this fix):

      1. v2 had built its own 35-block losing fork from blocks
         2199-2233.
      2. v1 produced 46 blocks 2199-2244 on the canonical
         chain.
      3. v2 received v1's blocks via ``_handle_fork`` gossip
         (stored to chaindb but kept v2's losing-fork blocks
         too -- chaindb keys on block_hash, not block_number,
         so both forks coexist).
      4. ``_reorganize`` fired.  Reorg-restore at ancestor
         #2198 from chaindb's snapshot row worked correctly
         (snapshots at 2198 on both forks are functionally
         identical -- diff verified during incident response).
      5. Forward-replay applied v1's blocks 2199-2244 via
         ``_apply_block_state(blk)`` only.  Reputation tracker
         frozen at the #2198 value while v1's reputation
         tracker bumped 46 times along the canonical fork.
         Bootstrap lottery firing somewhere in the replayed
         range consulted v2's frozen reputation map and picked
         a different winner than v1 did.
      6. v2's ``self.supply.balances`` diverged from v1's at
         that block.  ``compute_current_state_root`` on v2
         produced ``1d4af466e9c5757b...`` while v1's stored
         header.state_root at #2244 was ``0ee75af765ec6ae9..``
         (committed by v1's forward-apply path with all
         per-block bookkeeping intact).
      7. v1 produced block #2245 at 13:01:24 UTC.  v2's
         ``add_block`` ran ``compute_post_state_root`` (sim)
         and computed a state_root that did NOT match v1's
         header.state_root for #2245 (because v2's pre-state
         at #2244 was wrong).  v2 rejected with "Invalid
         state_root -- state commitment mismatch" and banned
         v1.
      8. The 1.52.0 chain-load invariant correctly caught the
         same divergence on the upgrade smoke test, refusing
         to install 1.71.0 on v2.  Recovery: SQLite
         online-backup of v1's canonical chain.db, scp to v2,
         swap into ``/var/lib/messagechain/chain.db``, clear
         ``ban_scores.json``, run standard upgrade.

    CLAUDE.md anchor at risk: "Honest, well-configured nodes
    should rarely if ever be slashed under normal operation"
    -- the reorg-replay path is supposed to be transparent
    state healing.  An incomplete replay that leaves the node
    unable to accept canonical blocks is a textbook anchor
    violation: the operator did everything right, the
    protocol's own recovery machinery wedged them.

    Permanent fix: the replay loop now matches normal
    ``add_block`` ordering exactly::

        for blk in apply_blocks:
            ...
            self._apply_block_state(blk)
            self.chain.append(blk)
            self._block_by_hash[blk.block_hash] = blk
            self._process_attestations(blk, self.supply.staked)
            self._record_stake_snapshot(blk.header.block_number)

    Pre-fix, the reorg-replay loop would silently desync any
    reorged node; post-fix reorg replay produces
    byte-identical state to a node that forward-applied the
    same blocks without reorging.  Soft fix -- no fork, no
    consensus rule change at the validator, no new wire
    format, no new tx kinds.

    3 structural regression tests in
    ``tests/test_reorg_replay_state_consistency.py`` pin the
    symmetry: (1) ``_process_attestations(blk, self.supply.
    staked)`` appears in ``_reorganize``'s body; (2)
    ``_record_stake_snapshot(blk.header.block_number)`` does
    too; (3) both calls appear AFTER
    ``_apply_block_state(blk)`` so the apply happens before
    the per-block bookkeeping (mirror add_block ordering).
    Surfaced by audit r42 deep-dive on the live v2 incident.
    Diverged-state diagnostic preserved at
    ``/var/lib/messagechain/chain.db.diverged-20260511-131452``
    on validator-2 for any future investigation.  (98a6654)

## [1.71.0] — 2026-05-11

Minor release.  Audit round 42 top-2 ships: one consensus-layer
liveness fragility close (the fork-emergency detector no longer
falls through to LIVE ``supply.staked`` for FinalityVotes whose
target_block_number references a block this node has not yet
appended) plus one value-prop CLI ergonomics fix (``cmd_send``'s
success block now prints a shareable ``<PUBLIC_FEED_URL>/r/<tx_
hash>`` receipt URL alongside the existing CLI verifier).  No
new tx kinds, no new wire format, no consensus rule change at
the validator, no hard fork.

### Fixed

  * **``observe_finality_vote`` refuses future-height votes
    (audit r42 #1 -- liveness fragility close).**  Pre-fix
    ``Blockchain.observe_finality_vote`` (the public hook
    ``_handle_announce_finality_vote`` calls after gossip-time
    sig verify so the fork-emergency detector sees votes BEFORE
    they land in a block) resolved signer stake as
    ``pinned = self._stake_snapshots.get(vote.target_block_
    number); stake_map = pinned if pinned is not None else
    dict(self.supply.staked)``.  Pinned snapshots only exist
    for blocks the chain has actually appended.  A vote whose
    ``target_block_number >= self.height``
    (= ``len(self.chain)``, so valid indices are
    ``0..height-1``) references a block this node has not yet
    appended -- no snapshot, falls through to LIVE
    ``supply.staked``.

    Two operational consequences, both load-bearing for
    liveness on today's bootstrap mainnet:

      1. **Benign-bug class:** an honest validator's own
         scheduler / replay / clock-skew misfire that emits a
         signed FinalityVote at ``target > tip`` is enough to
         single-fault the 2/3 detector threshold against live
         stake (founder ~all-of-stake bootstrap distribution).
         Detector flags an emergency, validators auto-halt
         block production + finality voting per the
         ``fork_emergency`` module's load-bearing contract.
         The network freezes with no adversary at all.

      2. **Adversarial:** any 2/3-stake holder (today the
         founder; in general any post-bootstrap stake-majority
         cartel) publishes well-formed signed FinalityVotes at
         attacker-chosen future heights for any hash and
         triggers the same auto-halt on every honest peer.
         The votes do not produce slashable evidence -- the
         signer is a registered staked validator, the only
         thing "wrong" is that the target references a block
         that does not yet exist locally.

    CLAUDE.md anchor at risk: "censorship resistance is a
    *collective decision* -- any new inclusion / mempool /
    proposer rule must raise the evidentiary cost of
    suppression."  The fork-emergency detector's halt is a
    load-bearing safety mechanism; weaponising it via a one-
    vote liveness halt collapses the evidentiary cost of
    suppression to zero.

    Fix: refuse future-height votes at the observe-hook
    entry::

        height = vote.target_block_number
        if height >= self.height:
            return

    Honest gossip references already-appended blocks.  A vote
    outside that window is either a bug (drop it) or an
    attack (drop it).  Pinned-snapshot resolution and detector
    ingestion are unchanged for past- and current-tip votes --
    the legacy fallback to ``dict(self.supply.staked)`` for
    past-height votes without a pin is preserved because the
    consensus apply path uses the same fallback, so the
    detector denominator continues to match consensus exactly
    for legitimate ingest.

    Soft fix.  No fork, no consensus rule change at the
    validator, no new wire format, no new tx kinds, no new
    CLI surface -- pure observe-hook narrowing.  The detector
    is advisory by design (its halt only fires runtime-side;
    consensus state is unchanged whether or not the detector
    observes a vote), so dropping votes from the early-warning
    path cannot diverge chain state across nodes.

    3 regression tests in
    ``tests/test_fork_emergency_future_height_guard.py`` pin
    (1) a single supermajority-signed future-height vote does
    NOT trigger the emergency; (2) a sweep of supermajority
    votes at offsets 0 / 1 / 2 / 3 / 10 / 100 / 1000 from tip
    likewise do not trigger; (3) must-not-regress -- a
    divergent-hash vote at a real in-chain height from the
    same supermajority signer STILL triggers the emergency
    (the legitimate early-warning path remains intact).
    Surfaced by audit r42 top-3 #1 (the only original-top-3
    finding that survived live-code verification; the
    inclusion-list-byte-budget and signature-aware-evidence-
    fee findings did not -- see audit r42 transcript for the
    full pool).  (ea26bef)

### Added

  * **``cmd_send`` success prints shareable receipt URL
    (audit r42 #2).**  Pre-fix the success block named the
    permanence guarantee + pointed at the
    ``messagechain receipt <tx_hash>`` CLI verifier, but
    stopped there.  A user who had just paid real tokens to
    anchor a message had NO shareable artifact -- no URL to
    hand to a journalist, a friend, or anyone who needs to
    confirm the post is on chain.  The receipt page already
    exists at ``<PUBLIC_FEED_URL>/r/<tx_hash_hex>`` (rendered
    by the static-asset server, queries ``/v1/tx_status``
    itself, surfaces a polished "permanent -- this message
    is on-chain and can never be deleted" card any non-
    technical reader can verify) but was discoverable only
    by hunting through docs.  Net effect: every send was a
    missed share-event, and the chain's headline value-prop
    (permanence as a public artifact) was literally invisible
    at the moment a user just paid to create one.

    CLAUDE.md anchor at risk: dual-purpose-token / mainstream
    -asset quality bar -- the receipt-page surface is the
    value-prop in motion, and gating its discoverability
    behind doc-spelunking inverts the bar.  Also Principle #3
    (Simplicity) -- the user's gesture "let me share what I
    just posted" had no one-step answer on the prior CLI.

    Fix:

      * New config constant ``PUBLIC_FEED_URL`` (default
        ``https://messagechain.org``, no trailing slash) is
        the canonical override knob for testnets /
        alternative feed deployments so they do NOT need to
        fork the CLI.
      * ``cmd_send``'s success block now prints a ``Share:``
        line immediately after the ``Permanence:`` paragraph,
        naming the fully-qualified URL
        ``<PUBLIC_FEED_URL>/r/<tx_hash>`` with the literal
        hash substituted -- additive to the existing CLI
        verifier pointer, not a replacement.  Failure path
        is unchanged (no URL when no tx landed).
      * Late-binds the host via ``getattr(cli_module,
        "PUBLIC_FEED_URL", PUBLIC_FEED_URL)`` so a test can
        monkey-patch the module attribute and exercise the
        override path without rewriting the config import.

    Pure CLI ergonomics fix.  No fork, no consensus rule
    change, no wire-format change, no new tx kinds.  4
    regression tests in
    ``tests/test_cli_send_shareable_url.py`` pin: (1)
    success block contains ``<feed_host>/r/<tx_hash>`` with
    the literal hash; (2) URL appears alongside the existing
    receipt-CLI pointer (additive); (3) ``PUBLIC_FEED_URL``
    monkey-patch redirects the share URL cleanly (and the
    production host doesn't leak); (4) failure path emits
    NO ``/r/`` URL.  Surfaced by audit r42 value-prop axis
    (recommended path-2 swap after the original-top-3
    verification cycle).  (4d8c49f)

## [1.70.6] — 2026-05-10

Patch release.  **THE actual root-cause hotfix for the 2026-05-10
mainnet stall at block 2199.**  1.70.2 / 1.70.3 / 1.70.4 / 1.70.5
all closed real defects (slash-tx fee, proposer_sig_counts
deferral, slash_offense_counts deferral, no self-slash), but the
chain still wedged.  In-process diag4 on validator-2 (the
proposer for the stuck slot) pinned the divergence to ONE TOKEN
of ``sim_staked[v2]`` vs apply's ``self.supply.staked[v2]`` on
an empty block.  Root cause: sim's
``apply_inactivity_leak`` call used
``current_height=self.height + 1`` while apply used
``current_height=block.header.block_number`` -- an off-by-one
that fires exactly at Tier-N activation boundaries.

### Fixed

  * **sim's ``apply_inactivity_leak`` passes ``block_height``,
    not ``self.height + 1`` (audit r41 #4 -- THE actual mainnet
    wedge trigger).**  Pre-fix
    ``compute_post_state_root`` built the sim path's inactivity-
    leak call with::

        _ail(sim_staked, sim_blocks_since_fin, _inactive,
             min_stake=VALIDATOR_MIN_STAKE,
             current_height=self.height + 1,    # <-- OFF BY ONE
             blockchain=self)

    while ``_apply_block_state`` built it with::

        apply_inactivity_leak(
            self.supply.staked,
            self.blocks_since_last_finalization,
            inactive,
            min_stake=VALIDATOR_MIN_STAKE,
            current_height=block.header.block_number,
            blockchain=self,
        )

    Since the chain has exactly ``self.height`` blocks indexed
    0..(self.height-1) BEFORE the new block is appended, the new
    block's number IS ``self.height``, NOT ``self.height + 1``.
    Equivalently: ``block.header.block_number == self.height`` at
    the moment sim or apply runs.  Sim's ``self.height + 1`` is
    one greater than apply's value.

    The bug fires EXACTLY at Tier-N activation boundaries.  On a
    block proposed at the activation height itself:
      * apply computes
        ``current_height = block.header.block_number =
        activation - 1`` and takes the pre-fork branch (legacy
        formula).
      * sim computes ``current_height = self.height + 1 =
        activation`` and takes the post-fork branch (new
        formula).

    When the new formula produces a different per-validator
    penalty than the legacy formula, sim and apply diverge on
    ``staked[inactive_validator]`` -> different state-tree leaf
    hashes -> ``Invalid state_root -- state commitment
    mismatch`` rejection -> chain wedges with no honest path
    forward.

    Concrete bite at h=2199 mainnet:
      * Tier 59 (``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT = 2200``)
        flips the inactivity-leak formula from legacy ``BASE *
        blocks² / QUOTIENT`` (stake-independent, floors to 0 at
        every realistic stall length) to stake-scaled ``stake *
        BASE * blocks² / QUOTIENT_STAKE_SCALED`` (non-zero even
        for short stalls).
      * h=2199 block: apply uses ``current_height=2199`` (pre-
        Tier-59, legacy formula, penalty=0, no mutation).  Sim
        uses ``current_height=2200`` (Tier-59 ACTIVE, stake-
        scaled formula, non-zero penalty after relief
        multiplier, mutates ``sim_staked[inactive_validator]``).
      * Diag4 on v2 captured the exact divergence:
        ``SIM-SET eid=8954a7196026ef95 new_tuple=(...,
        22511499, ...) prev_committed=(..., 22511500, ...)`` --
        sim decrements v2's stake by exactly 1 token from the
        stake-scaled penalty multiplied by the long-tenured
        relief multiplier.  Apply leaves it at 22511500.  One-
        token divergence -> different leaf hash -> different
        state_root -> chain wedge for 16+ hours.

    CLAUDE.md anchor at risk: Mission ("permanent ledger");
    honest-operator insurance.  Same defect class as the earlier
    1.70.3 (proposer_sig_counts deferral) and 1.70.4
    (slash_offense_counts deferral) -- a sim-vs-apply divergence
    on the inactivity-leak path -- but those fixes addressed the
    HONESTY-CURVE-RELIEF-MULTIPLIER INPUTS while this fix
    addresses the HEIGHT GATE itself.  All four together ship a
    complete sim-vs-apply lockstep on the inactivity-leak path.

    Permanent fix: change sim's ``current_height=self.height +
    1`` to ``current_height=block_height`` at the
    ``_ail(sim_staked, ...)`` call site in
    ``compute_post_state_root``.  ``block_height`` is already in
    scope as the parameter passed to ``compute_post_state_root``.
    Same value apply uses.  Companion comment block rewritten to
    call out the off-by-one rationale so the next reader can't
    revert it.

    Soft fix.  No fork, no consensus rule change at the
    validator, no new wire format, no new tx kinds, no new CLI
    surface -- pure sim correction.  No replay impact: every
    historical block whose state_root is already on-chain was
    admitted by the canonical block validator on identical
    (sim==apply) state_root.  The bug prevented future blocks
    from being added; historical state is untouched.  Pre-Tier-N
    activation heights are byte-identical because legacy and
    post-fork formulas both produce penalty=0 at those heights --
    so the height arg's value doesn't affect the result.  Post-
    Tier-N (no historical state above the wedge) the fix is the
    new correct behavior.

    3 regression tests in
    ``tests/test_audit_r41_sim_inactivity_height_offbyone.py``
    pin: (1) sim's call uses ``current_height=block_height``,
    (2) apply's call uses ``current_height=block.header.
    block_number`` (companion guard so sim/apply stay in
    lockstep), (3) anti-revert: literal
    ``current_height=self.height + 1`` MUST NOT appear in sim's
    inactivity-leak block.

    Surfaced post-1.70.5 rollout via in-process diag4 dump of
    sim vs apply per-entity leaf tuples -- audit r41 #4, THE
    actual trigger.  (203976b)

Roll-out note: rolling 1.70.6 to validators currently on 1.70.5
clears the in-memory mempool on restart and re-attempts block
2199 with sim and apply now agreeing on every height gate;
proposed block admits, chain advances past 2199.

## [1.70.5] — 2026-05-10

Patch release.  ACTUAL root-cause hotfix for the 2026-05-10 mainnet
stall.  1.70.2 / 1.70.3 / 1.70.4 closed real defects -- the slash-
tx-fee admission floor and the proposer_sig_counts /
slash_offense_counts bumps that diverge sim-vs-apply through the
inactivity-leak honesty-curve relief multiplier -- but in-process
diagnostic on validator-1 confirmed that the failing block at
height 2199 is PRE-Tier-59 (the inactivity-leak stake-scaled gate
sits at 2200), so the relief multiplier path is INACTIVE for the
stuck block.  The actual wedge trigger is a separate defect class:
the watcher self-slashing on operator restart cycles.

### Fixed

  * **Equivocation watcher must never self-slash (audit r41 #3 --
    actual mainnet wedge trigger).**  Pre-fix
    ``EquivocationWatcher._emit_slash``
    (``messagechain/consensus/equivocation_watcher.py``) and the
    finality-double-vote drain
    ``_emit_pending_finality_slashes``
    (``messagechain/network/node.py``) both built slash txs without
    checking whether the offender is the same entity as the
    watcher's submitter.  Concrete cascade observed at block 2199
    on mainnet:

      1. v1's chaindb ``seen_signatures`` table holds v1's signature
         on a previous-attempt block #2199 (persisted by
         ``add_seen_signature`` from a prior failed propose-block
         attempt -- the sig was emitted, the block then failed to
         add for an unrelated reason, but the sig was already
         stored).
      2. v1 boots.  The proposer slot fires, builds a NEW block
         #2199.  Slightly different content (timestamp drift, fresh
         block header) -> byte-different sig at the same
         (validator, height, round).
      3. Watcher.observe_block_header runs the new sig through
         ``_check_equivocation``, sees the stored prior-attempt
         sig, classifies the conflict as "equivocation".
      4. ``_emit_slash`` builds a SlashTransaction with
         ``offender_id = v1.entity_id`` and
         ``submitter_id = v1.entity_id`` (self-slash).
      5. Block #2199 candidate is built with the self-slash tx in
         ``slash_transactions``.
      6. ``add_block`` runs.  Sim and apply diverge on the self-
         slash apply (integer-rounding edge in the fee + finder-
         reward + stake-burn flow when ``submitter == offender ==
         proposer`` are all the same entity).  ``Invalid
         state_root -- state commitment mismatch`` rejection.
         Chain wedges.  Watcher re-fires every slot.

    CLAUDE.md anchor at risk: "honest operators are insured against
    accidents" + "honest, well-configured nodes should rarely if
    ever be slashed under normal operation."  An operator's own
    restart cycle -- the canonical "operational mishap" the anchor
    exists to insulate -- was being slashed at the WATCHER layer,
    NOT at the chain consensus layer (the chain never even saw the
    slash because ``add_block`` kept rejecting the block).  The
    watcher slashing the operator for retrying their own propose
    path is a textbook anchor violation.

    Censorship-resistance is preserved: if a different honest
    watcher genuinely sees us double-sign on the wire (vs.
    observing our chaindb-replayed prior attempt), that watcher
    emits the slash from THEIR submitter context and lands it on
    chain via standard gossip.  The local watcher's job is
    detection + on-chain emission ONLY when the local node was not
    itself the offender.

    Permanent fix: every watcher path that builds a slash tx drops
    it when ``offender == submitter`` (= local entity).

      * ``EquivocationWatcher._emit_slash`` gains an early-return
        guard right after the ``submitter_entity is None`` detect-
        only-mode short-circuit:
        ``if validator_id == self.submitter_entity.entity_id:
        return``.
      * ``_emit_pending_finality_slashes`` gains the symmetric
        guard inside the per-evidence loop:
        ``if offender_id == entity.entity_id: continue``.

    Soft fix.  No fork, no consensus rule change at the validator,
    no new wire format, no new tx kinds, no new CLI surface -- pure
    watcher-side behavior tightening.  No replay impact: every
    slash tx already on-chain was admitted by the canonical block
    validator, so any historical slash that landed had to clear
    admission with a non-self submitter (or come from a peer's
    watcher).  The legacy-self-slash code path's mempool-pooled-
    but-never-confirmed txs were never durable consensus state.

    3 regression tests in
    ``tests/test_audit_r41_no_self_slash.py`` pin:
    (1) watcher does NOT pool a slash tx when offender is the
        submitter entity;
    (2) symmetric must-not-regress: a DIFFERENT validator
        equivocating still produces a slash tx (censorship-
        resistance defense intact);
    (3) companion guard for the finality-double-vote drain path.

    Surfaced post-1.70.4 rollout to validator-1 -- audit r41 #3.
    (f6ffc3b)

## [1.70.4] — 2026-05-10

Patch release.  Companion hotfix to 1.70.3 -- same audit r41 root
cause, second instance of the same defect class.  1.70.3 deferred
the ``proposer_sig_counts`` bump until after the inactivity /
coverage leaks; 1.70.4 does the same for the
``slash_offense_counts`` bump in the inline slash-tx loop of
``_apply_block_state``.

### Fixed

  * **``slash_offense_counts`` bump deferred until after inactivity-
    leak + coverage-leak blocks (audit r41 #2 root cause).**  Pre-
    fix the inline slash-tx loop in ``_apply_block_state`` called
    ``self._bump_slash_offense_count(stx.evidence.offender_id)``
    BEFORE the inactivity / coverage leaks below it.
    ``compute_post_state_root_for_block``'s sim path doesn't mirror
    ``slash_offense_counts`` mutations (the dict is not in the
    state-tree leaf).  But the honesty-curve helper
    ``_apply_honesty_curve_relief`` -- via ``_track_record`` (post-
    Tier-24 ``HONESTY_CURVE_RATE_HEIGHT`` rate factor) AND via
    ``_prior_offenses`` (the ``prior >= 1 -> no relief`` branch
    gate) -- READS ``self.slash_offense_counts`` directly when the
    inactivity / coverage leaks compute their per-validator relief
    multiplier.

    Concrete cascade: when a slash applies in block N to an
    offender who is ALSO in the inactivity-leak inactive set (the
    canonical case in a 2-validator network -- the slash target is
    by definition NOT attesting to the slasher's block, so they're
    "inactive" for that block), apply's relief multiplier reads
    post-bump priors (``>= 1`` -> no relief, full nominal penalty)
    while sim reads pre-bump priors (``0`` -> relief applies,
    reduced penalty).  Different per-validator burn -> different
    ``staked[offender]`` -> different state_root -> chain wedges
    with ``Invalid state_root -- state commitment mismatch``,
    identical fingerprint to the audit r41 #1 wedge that 1.70.3
    closed.  Observed on validator-1 immediately after the 1.70.3
    upgrade: the self-proposal at the post-boot catch-up slot
    included v1's slash-against-v2 from the watcher's mempool, and
    the inactivity-leak relief multiplier divergence on the
    offender (v2) wedged the proposed block.

    CLAUDE.md anchor at risk: same as audit r41 #1 -- "honest
    operators are insured against accidents" via the inactivity-
    leak relief multiplier; sim-vs-apply divergence on the
    multiplier's inputs makes that anchor actively chain-wedging.

    Permanent fix: capture each slash's ``offender_id`` during the
    inline slash-tx loop into a deferred list, then bump
    ``slash_offense_counts`` for every captured offender via the
    ``_bump_slash_offense_count`` chokepoint AFTER both the
    inactivity leak and the coverage leak have run.  Both leak
    paths thus read ``slash_offense_counts`` at its pre-block
    value -- matching what sim sees in
    ``compute_post_state_root`` (which never mutates the dict).

    All other slash mutations (``pay_fee_with_burn``, escrow drain,
    ``slash_validator`` stake/pending/finder,
    ``slashed_validators.add`` on 100% slashes,
    ``_clear_reputation``, ``slash_sig_counts``, watermark bump)
    keep their original position; only the
    ``slash_offense_counts`` bump moves.  Pre-Tier-59 the reorder
    is byte-identical to the legacy order on every historical
    block (penalty=0 -> relief multiplier delta has nothing to
    multiply).  Post-Tier-59 (no historical state) the new order
    applies cleanly.

    Soft fix.  No fork, no consensus rule change at the validator,
    no new wire format, no new tx kinds, no new CLI surface.  2 new
    structural regression tests in
    ``tests/test_audit_r41_proposer_sig_counts_pre_bump.py`` pin:
    (1) the deferred bump call must follow both leak call sites in
    ``_apply_block_state`` source; (2) exactly ONE
    ``_bump_slash_offense_count(`` call shape in the whole function
    (a partial revert that adds an inline call back without
    removing the deferred one would double-count every slash).
    Surfaced post-1.70.3 rollout to validator-1 -- audit r41 #2
    root cause (companion to #1).  (7d01cf3)

Roll-out note: rolling 1.70.4 to validators currently on 1.70.3
clears the in-memory mempool on restart and re-attempts block 2200
with both deferrals in place; sim and apply now agree on every
relief-multiplier input, the proposed block admits, the chain
advances.  The original height-2199 transient race won't slash
either validator -- the equivocation evidence in chaindb
``seen_signatures`` requires a SECOND conflicting block at height
2199 to retrigger and no such block will be gossiped now that the
chain has moved on.

## [1.70.3] — 2026-05-10

Patch release.  Root-cause hotfix for the 2026-05-10 mainnet stall
at block 2200.  Defers the proposer's
``proposer_sig_counts[proposer_id] += 1`` bump in
``Blockchain._apply_block_state`` until after the inactivity-leak
and coverage-leak blocks so the apply path reads the same
``proposer_sig_counts`` value the sim path reads -- closing the
sim-vs-apply divergence on the inactivity-leak honesty-curve
relief multiplier that wedged the chain at exactly the height
``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT`` (Tier 59) activated.  The
slash-tx-fee fix shipped in 1.70.2 was a downstream cascade fix;
this is the underlying defect.  No fork, no consensus rule change
at the validator, no new wire format, no new tx kinds, no new CLI
surface -- pure ordering correctness inside ``_apply_block_state``.

### Fixed

  * **``proposer_sig_counts`` bump deferred until after inactivity-
    leak + coverage-leak blocks (audit r41 root cause).**  Pre-fix
    ``Blockchain._apply_block_state`` bumped
    ``proposer_sig_counts[proposer_id] += 1`` BEFORE the
    inactivity-leak block (and the coverage-leak block).
    ``compute_post_state_root_for_block``'s sim path mirrors NONE
    of that -- it reads ``self.proposer_sig_counts`` directly (sim
    never mutates ``proposer_sig_counts``) and computes the
    inactivity-leak relief multiplier against the PRE-bump track
    record.  Apply, in the same call, computed the relief
    multiplier against the POST-bump track record.

    Concrete cascade observed at block 2200: both validators have
    BYTE-IDENTICAL pre-block state (verified during diagnosis via
    ``state_root`` / ``balances_sha256`` / ``staked_sha256``
    probes), but every block-2200 proposal -- whether proposed by
    v1 or v2 -- failed internally on its own ``add_block`` because
    the proposer's claimed state_root (computed via sim, pre-
    bump) didn't match the actual state_root (computed via apply,
    post-bump).  ``Invalid state_root -- state commitment
    mismatch`` rejection on every proposal slot, no honest path
    to advance.  The slash-tx-fee mismatch the watcher then
    surfaced was a downstream cascade of equivocation re-detection
    that the chain could no longer escape.

    The bug only bites when ALL THREE of the following hold:

      1. The chain crosses
         ``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT = 2200`` (Tier 59).
         Pre-fork the legacy flat formula floors the per-block
         penalty to 0 at every realistic stall length
         (``blocks² < 2²⁴`` requires stalls > 4096 blocks ~28
         days, which the chain has never sustained), so the
         relief-multiplier delta has nothing to multiply -- masking
         the bug for the entire history of the chain.
      2. Finality has stalled past
         ``INACTIVITY_LEAK_ACTIVATION_THRESHOLD = 4`` (so
         ``is_leak_active`` returns True).
      3. The proposer is in the inactive set (didn't attest in
         their own block -- the canonical case in any 2-validator
         network where a proposer's own slot vote is structurally
         omitted from their own block).

    All three preconditions hit on mainnet at exactly block 2200.

    CLAUDE.md anchor at risk: "honest operators are insured
    against accidents" -- the inactivity leak's relief multiplier
    exists PRECISELY to insulate long-tenured operators during
    stalls; sim-vs-apply divergence on the relief multiplier's
    inputs makes that anchor not just toothless but actively
    chain-wedging.  Same defect class as the 1.46.0 / 1.47.0
    sim-vs-apply slash-divergence fixes called out in the
    ``compute_post_state_root_for_block`` pre-check rationale
    comments.

    Permanent fix: defer
    ``self.proposer_sig_counts[proposer_id] += 1`` from its legacy
    location (just after the proposer watermark bump) until AFTER
    both ``apply_inactivity_leak`` and
    ``_apply_inclusion_list_coverage_leak``.  Both leak paths
    route through the same ``_apply_honesty_curve_relief`` helper
    which reads ``self.proposer_sig_counts`` via ``_track_record``;
    with the bump deferred, sim and apply agree on the value at
    relief-multiplier-read time.

    The watermark bump (which IS in the state-tree leaf, and which
    sim mirrors at the same point in its own ordering) stays where
    it is -- only the COUNT bump moves.
    ``attestation_sig_counts`` doesn't move (not read by
    ``_track_record``).  ``slash_offense_counts`` is its own latent
    companion divergence (read by ``_track_record`` post-Tier-24,
    mutated by slash-apply pre-leak) but only fires when an
    offender is ALSO in the inactive set; deferred to a follow-up
    audit since it doesn't bite the current mainnet wedge.

    Soft fix.  Pre-Tier-59 the reorder is byte-identical to the
    legacy order on every historical block (penalty=0 -> nothing
    to multiply -> bump-order doesn't matter) so chain replay is
    unchanged.  Post-Tier-59 (no historical state -- chain has
    produced zero blocks at >= 2200) the new order applies
    cleanly.  3 regression tests in
    ``tests/test_audit_r41_proposer_sig_counts_pre_bump.py`` pin
    the structural ordering contract.  Surfaced by mainnet stall
    at height 2200 on 2026-05-10 -- audit r41 top root cause.
    (51d56b0)

Roll-out note: rolling 1.70.3 to a stalled validator clears the
in-memory mempool on restart and re-attempts block 2200 with the
fixed apply order; sim and apply now agree, the proposed block
admits, the chain advances.  No slashing fires for the original
height-2199 transient race -- the equivocation evidence in chaindb
``seen_signatures`` requires a SECOND conflicting block at height
2199 to retrigger, and no such block will be gossiped now that the
chain has moved on.

## [1.70.2] — 2026-05-10

Patch release.  Hotfix for an observed mainnet stall (~9h, height
2199, 2026-05-10).  Pure soft-fix on the equivocation watcher's
slash-tx fee computation -- no fork, no consensus rule change at
the validator, no new wire format, no new tx kinds, no new CLI
surface.

### Fixed

  * **Equivocation watcher slash-tx fee clears MIN_FEE admission
    floor.**  Pre-fix
    ``EquivocationWatcher._emit_slash``
    (``messagechain/consensus/equivocation_watcher.py``) and the
    finality-double-vote drain
    ``_emit_pending_finality_slashes``
    (``messagechain/network/node.py``) both built slash txs with
    ``fee = supply.base_fee``.  At quiet mempool the EIP-1559-style
    controller decays ``base_fee`` toward ``MARKET_FEE_FLOOR=1``.
    But ``Blockchain.validate_slash_transaction`` calls
    ``enforce_signature_aware_min_fee(..., flat_floor=MIN_FEE)``,
    whose first comparison ``tx_fee < flat_floor`` rejects any fee
    below ``MIN_FEE=100``.

    Concrete cascade observed at height 2199 on mainnet: both
    validators independently produced two distinct block-2199
    candidates (transient race / restart).  Each watcher detected
    the other's equivocation and emitted a slash tx at
    ``fee = supply.base_fee = 1``.  Mempool admission did not run
    the chain-level fee gate, so the under-priced slash tx admitted
    -- but every subsequent block-proposal slot included it from
    mempool, called ``validate_slash_transaction``, got the "Fee 1
    below signature-aware minimum" rejection, and the whole block
    failed validation.  Chain wedged at height 2199 for ~9 hours
    with no honest path to advance.

    CLAUDE.md anchor at risk: "Honest operators are insured against
    accidents" -- the slash mechanism that backs collective
    censorship-resistance must not also be the mechanism that wedges
    the chain under a quiet-mempool race.  Specifically the watcher
    MUST produce a slash tx that admits to the chain it detected
    the equivocation on; no permutation of ``base_fee`` should
    produce an inadmissible slash.

    Permanent fix: new helper ``compute_slash_tx_min_fee(
    current_height, signature_bytes)`` in
    ``messagechain/consensus/slashing.py`` mirrors the validator's
    ``enforce_signature_aware_min_fee(..., flat_floor=MIN_FEE)``
    height-aware logic and returns the smallest fee that clears
    admission at any height regime.  Today's
    ``MARKET_FEE_FLOOR_HEIGHT`` and beyond -> ``MIN_FEE``; legacy
    ``[FEE_INCLUDES_SIGNATURE_HEIGHT, FLAT_FEE_HEIGHT)`` -> max
    against the signature-aware bump; pre-
    ``FEE_INCLUDES_SIGNATURE_HEIGHT`` -> ``MIN_FEE``.  Both watcher
    call sites now compute
    ``fee = max(supply.base_fee, compute_slash_tx_min_fee(height))``,
    preserving the busy-mempool tracking property
    (``pay_fee_with_burn`` rejects below ``base_fee``) AND the
    admission-floor floor.

    Soft fix.  Watchers are local-only paths that emit txs into
    mempool; the chain-side validator is unchanged.  Pre-fix-shape
    txs (fee < MIN_FEE) were already rejected at admission, so any
    historical slash tx in chain history had to clear the floor;
    the fix retroactively closes the rejection-loop case.  8
    regression tests in
    ``tests/test_audit_r41_slash_tx_fee_floor.py`` pin (1) the
    helper's output across every height regime, (2)
    ``EquivocationWatcher._emit_slash`` admission with
    ``base_fee=1`` (the failing case), (3) busy-market high-
    ``base_fee`` tracking, (4)
    ``_emit_pending_finality_slashes`` admission with
    ``base_fee=1``.  (17cc8e2)

Roll-out note: rolling 1.70.2 to a stalled validator clears the
in-memory mempool on restart and re-emits the outstanding slash
txs at the correct fee, allowing the chain to advance.  Slashing
will fire on the underlying double-proposal evidence -- expected
post-unstick behaviour, severity governed by the honesty curve
(long-tenured / high-volume / high-honesty operators get the
fractional first-offense relief, not catastrophic loss).

## [1.70.1] — 2026-05-10

Patch release.  Audit round 40 top-3 #1 ships: pure CLI routing
correctness fix on ``_parse_server`` (``messagechain/cli.py``).  No
new wire format, no new tx kinds, no new CLI surface, no consensus
impact -- the fix is bounded to the wallet-side helper that resolves
``--server`` arguments to a ``(host, port)`` tuple for JSON-RPC
clients.

### Fixed

  * **``_parse_server`` defaults to ``RPC_DEFAULT_PORT`` (9334), not
    the P2P port (9333).**  Pre-fix the bare-host branch
    (``--server seed.example.com`` with no explicit ``:port``) and
    the dev-fallback branch (``--server`` unset, all seeds dead, last-
    resort localhost) both resolved to ``DEFAULT_PORT = 9333`` -- the
    P2P listener.  Every wallet-facing caller of this helper
    (``send`` / ``transfer`` / ``balance`` / ``read`` / ``propose`` /
    ``vote`` / ``react`` / ``receipt`` / ``validators`` / ``status``
    when overriding default) speaks JSON-RPC and needs the RPC port
    (9334).  Routing an RPC client to the P2P listener succeeds at
    TCP-connect, mismatches at protocol, and surfaces to the user as
    a generic ``Could not connect`` / hang with no hint that the port
    is wrong.

    Multi-year-stable footgun.  The sibling helper
    ``_parse_server_local_default`` already does the right thing
    (resolves bare-host and the localhost default to
    ``RPC_DEFAULT_PORT``); the existing test
    ``test_client_routing.py::test_explicit_host_only`` had encoded
    the wrong behaviour as expected (``config.DEFAULT_PORT``), which
    is exactly what kept the bug invisible across audit rounds --
    test passed, code was wrong.  The matching ``_all_seeds_down``
    fallback test pinned the same wrong port.

    CLAUDE.md anchor at risk: Principle #3 (Simplicity) and the
    E2E-newcomer-flow standing-focus item -- the user does exactly
    what ``--help`` told them to and gets a silent connection
    failure with no actionable diagnostic.  Same defect class as
    the operator-side ``status``-routes-to-wrong-validator bug that
    motivated ``_parse_server_local_default`` in the first place,
    just on the wallet-side.

    Soft fix; no fork, no consensus impact, no wire-format change --
    pure CLI routing correctness.  Two-line code change plus a
    docstring note calling out port-default discipline so future
    contributors can't quietly re-introduce the bug.  13 regression
    tests in ``tests/test_client_routing.py`` pass; the two
    previously-wrong assertions are flipped to assert
    ``RPC_DEFAULT_PORT`` for both bare-host and dev-fallback.
    Surfaced by audit r40 top-3 #1.  (37d712e)

## [1.70.0] — 2026-05-09

Minor release.  Audit round 39 top-3 ships: one new hard fork (Tier
68 closes the silent-drop censorship 2-validator-collusion bypass
on the witnessed-submission slashing pipeline), one operator-tool
correctness fix (``backup-wallet`` now includes
``receipt_leaf_index.json`` by default, eliminating a stake-loss
trap on disk-loss restore for receipt-issuing validators), and one
network-layer DoS gate (``ANNOUNCE_PENDING_TX`` gossip routes to
its dedicated ``pending_tx`` rate-limit bucket instead of the wide
``general`` bucket).  No new top-line CLI surface beyond two new
``backup-wallet`` flags; no new tx kinds.

### Added

  * **Tier 68 -- witness-ack issuer-binding (hard fork, activation
    height 2650).**  Pre-fix ``Blockchain.witness_ack_registry:
    dict[bytes, int]`` was keyed only on ``request_hash``.  Any
    registered validator's ack landing in the registry discharged
    the silent-drop obligation of the request's ACTUAL target,
    regardless of who issued the ack.

    Concrete attack: validator V_target receives a witnessed
    ``SubmissionRequest`` and silently drops it (TCP-level
    censorship).  Q honest peers sign ``WitnessObservation``
    records.  Before the assembled ``NonResponseEvidenceTx`` lands,
    attacker validator V_attacker (any registered validator -- a
    sybil under the registration burn is fine) signs a
    ``SubmissionAck`` for the same request_hash and a colluding
    proposer embeds it in ``acks_observed_this_block``.  The
    chain's apply path writes ``witness_ack_registry[rh]`` keyed
    only on ``rh``.  ``validate_non_response_evidence_tx`` and
    ``NonResponseEvidenceProcessor.process`` then reject honest
    evidence with "ack present in chain state: obligation was met"
    -- discharging V_target's silent-drop obligation by V_attacker's
    ack.  Net pre-fix: the entire silent-drop censorship arm of the
    witnessed-submission slashing pipeline collapses to a 2-
    validator collusion threshold.  CLAUDE.md anchor at risk:
    "censorship resistance is a *collective decision* ... any new
    inclusion / mempool / proposer rule must raise the evidentiary
    cost of suppression."

    Tier 68 fix: maintain a parallel per-issuer registry
    ``witness_ack_by_issuer: dict[request_hash, dict[issuer_id,
    ack_height]]`` populated at apply time alongside the legacy
    registry.  Post-fork the discharge readers (admission gate, sim
    path, NonResponseEvidenceProcessor.process) consult
    ``witness_ack_by_issuer[rh].get(target_validator_id)`` so only
    the TARGET's own ack discharges the obligation.  Pre-fork the
    legacy single-key reader runs unchanged for byte-identical
    replay of historical mainnet blocks.  First-write-wins per
    ``(rh, issuer)`` so multiple distinct issuers each get tracked
    under the same request_hash.  Pruning extends
    ``_prune_witness_ack_registry`` to drop per-issuer entries
    symmetrically with the legacy registry.

    State-sync caveat: the per-issuer registry is in-memory only at
    v23 of the snapshot envelope.  A node bootstrapping from a v23
    snapshot at/after the activation height has an empty per-issuer
    registry until the legacy registry's prune window passes;
    during that window discharge-by-target-ack does not short-
    circuit, so the slash gates run their deadline + active-set +
    quorum checks (no incorrect slash, just no early discharge).
    Next snapshot version bump will add the per-issuer registry to
    the snapshot; deferred to keep the fix scope-tight.

    Hard-fork gate.  Activation height 2650 sits 50 blocks above
    Tier 67 (2600) -- ~8.3h cohort spacing matching the Tier 49-67
    pattern.  Mainnet tip at ship time is height ~1837 (probed via
    ``https://messagechain.org/v1/info``), so the upgrade window is
    ~5.6 days at 600s blocks.  Two-validator coordinated upgrade.
    No new wire format, no new tx kinds, no state-tree changes.
    10 regression tests in
    ``tests/test_audit_r39_witness_ack_issuer_binding_tier68.py``.
    Surfaced by audit r39 top-3 #1.  (c6ed0ed)

  * **``backup-wallet`` ``--receipt-leaves`` and
    ``--no-receipt-leaves`` flags.**  Default-resolve the receipt-
    subtree leaf cursor from the resolved ``data_dir``
    (``<data_dir>/receipt_leaf_index.json``) and include it in the
    backup tarball when present on disk.  ``--receipt-leaves PATH``
    overrides the default location; ``--no-receipt-leaves`` opts
    out (validators that do NOT issue receipts) and prints a
    visible warning naming the file being skipped.  See the Fixed
    section below for the operator-harm rationale.

### Fixed

  * **``backup-wallet`` includes ``receipt_leaf_index.json`` by
    default.**  Pre-fix ``cmd_backup_wallet`` packed the keyfile
    plus the block-signing leaf cursor only.  The receipt-signing
    subtree's leaf cursor (``<data_dir>/receipt_leaf_index.json``)
    was silently omitted even though README.md:300-326 names it as
    one of three security-critical files an operator MUST back up,
    and the documented manual ``tar`` example at README.md:339
    includes it.

    Concrete operator harm: a diligent validator who reads the
    README, runs ``messagechain backup-wallet``, and trusts the
    resulting tarball as a "complete" wallet backup will, on disk-
    loss restore, re-sign already-burned WOTS+ leaves on the
    receipt subtree -- producing equivocation evidence on chain.
    Pre-Tier-20 the per-offense penalty was 100% stake; post-Tier-
    20 the geometric soft-slash compounds ``(1 - 0.05)^N`` toward
    total stake loss as each re-used leaf surfaces a distinct
    equivocation event.  Operator did exactly what the
    documentation said; tool dropped the load-bearing file.
    CLAUDE.md anchor at risk: "Honest, well-configured nodes should
    rarely if ever be slashed under normal operation."  No fork, no
    consensus impact, no on-chain change -- pure operator-tool
    ergonomics.  5 regression tests in
    ``tests/test_audit_r39_backup_wallet_receipt_leaves.py``.
    Surfaced by audit r39 top-3 #2.  (1870d17)

### Security

  * **``ANNOUNCE_PENDING_TX`` gossip routes to dedicated
    ``pending_tx`` rate-limit bucket.**  Pre-fix
    ``messagechain.network.dispatch.message_category`` had no case
    for ``MessageType.ANNOUNCE_PENDING_TX``; the message type fell
    through to the wide ``general`` bucket (RATE_GENERAL = 30/s,
    burst 100) instead of the dedicated ``pending_tx`` bucket
    (RATE_PENDING_TX = 2/s, burst 20) that ``ratelimit.py`` defines
    and ``PeerRateLimiter._ensure_buckets`` provisions.

    Concrete attack: ``ANNOUNCE_PENDING_TX`` carries WOTS+-signed
    stake / unstake / authority / governance transactions.  Each
    receipt forces the receiver to parse and WOTS+-verify the
    signature -- ~2.7 KB of signature material and ~thousand hash
    invocations per message.  With the legacy ``general`` bucket
    gating, a single peer could sustain 30 WOTS+ verifies per
    second indefinitely (with a 100-burst), an asymmetric CPU-DoS
    targeting honest validators trying to keep up.  Same shape as
    the ``signed_announce`` carve-out already shipped for
    ``ANNOUNCE_ATTESTATION`` / ``ANNOUNCE_FINALITY_VOTE`` /
    ``ANNOUNCE_SLASH`` / ``ANNOUNCE_CUSTODY_PROOF`` -- the
    routing-layer DoS gate analogous to the WOTS+-verify-cost
    asymmetry defense.  Pre-fix the bucket existed and was sized
    correctly; only the dispatch routing was missing.  CLAUDE.md
    anchor at risk: "Spam ceiling is block timing, not per-tx fee
    inflation"; the gossip-layer rate limit is the analogous
    defense-in-depth at the network layer.

    Fix: one-line addition to ``message_category`` -- route
    ``MessageType.ANNOUNCE_PENDING_TX`` to ``"pending_tx"``.  No
    fork, no consensus impact, no wire-format change -- pure
    network-layer DoS gate that activates immediately.  4
    regression tests in
    ``tests/test_audit_r39_pending_tx_dispatch_routing.py``.
    Surfaced by audit r39 top-3 #3.  (e37c050)

Activation cohort spacing: Tier 68 = 2650 sits 50 blocks above Tier
67 (2600) at ~8.3h gaps at 600s blocks, matching the Tier 49-67
pattern.  Mainnet tip at ship time is height ~1837 (probed via
``https://messagechain.org/v1/info``), so the upgrade window is
~5.6 days at 600s blocks for Tier 68.  Two-validator coordinated
upgrade.

## [1.69.0] — 2026-05-09

Minor release.  Public-feed UX polish + comparison-doc tightening
+ a cross-tenet economic-invariants test pin.  No protocol /
consensus / wire-format changes; no new tx kinds; no new CLI
surface.  Validators upgrading from 1.68.0 will replace the
bundled `feed.html` static asset (the only operator-facing change
they'll notice) and pick up the new test file.

### Added

  * **Public feed: paginate at 10 + clickable block-number filter
    (`messagechain/static/feed.html`).**  Default render trims the
    public feed (https://messagechain.org) to the 10 newest cards;
    a "Show 10 more" link below the list expands the visible
    budget by 10 per click, up to the server's
    `PUBLIC_FEED_MAX_LIMIT` mirror (50).  Each fetch pulls one
    PAGE_SIZE buffer beyond the display budget so the affordance
    knows whether the chain has more rows to reveal without an
    extra round-trip.  Block numbers in each card's meta row
    become anchor links to `#block=<n>`; clicking filters the feed
    to just that block, with its own banner + clear link
    mirroring the existing community-filter pattern.  The two
    filters stack (a card has to match both to remain visible).
    Purely client-side; no server / API change. (0a6903e)

  * **Cross-tenet economic invariants test
    (`tests/test_economic_tenets_invariants.py`).**  Pin three
    cross-cuts that hold the three Core Economic Tenets in
    tension simultaneously, not just individually: (A)
    `compute_dormancy_issuance` output unchanged across orders-of-
    magnitude sweeps of fee/burn/mint bookkeeping fields
    (Tenet 2's "issuance for supply integrity, not security-
    budget funding" can't quietly drift); (B) at zero / low /
    high / extreme fee throughputs, small validators strictly
    earn more per-unit-stake revenue than large validators (the
    concave attester-pool curve enforces this; the linear-in-
    stake tip channel does not break the inequality); (C) at-
    target / above-target / fixed-below-target controller
    outputs are unchanged across 0× / 1× / 100× fee bookkeeping
    (stable supply target invariant to fee throughput).  13
    tests, ~1.9s.  No production-code changes. (3c2aeb6)

### Changed

  * **`COMPARISON.md`: top-5 competitor matrix with single
    strongest advantage per row, plus 11-feature promise
    matrix.**  Replaced the prior per-section narrative with a
    high-level table that surfaces MessageChain's distinct
    advantage against each of the top 5 nearby projects in one
    line, then lays out an 11-feature promise matrix so a
    visitor can see at a glance which guarantees MC ships vs. the
    competitors. (4c9251b, 158b739, 018f775, 1b5826b)

## [1.68.0] — 2026-05-07

Minor release.  Audit round 38 top-3 ships: one new hard fork (Tier
67 keeps the attester-committee weighted-reservoir sort priority as
``decimal.Decimal`` end-to-end, eliminating the cross-platform
IEEE-754 ULP rank-flip risk introduced by the legacy ``float(u.ln()
/ Decimal(w))`` cast at the sort key) plus two security soft-fixes
(non-response evidence verifier walks ``key_history + current``
candidate sets so a key rotation between sign-time and evidence-
admission can no longer defeat the silent-drop censorship slash;
mempool censorship-evidence admission gate now optionally runs the
stateless verifier so a future caller adding a gossip-relay path
cannot free-flood the slashable-evidence pool).  No new top-line
CLI surface, no new tx kinds.

### Added

  * **Tier 67 -- attester-committee Decimal end-to-end (hard fork,
    activation height 2600).**  Pre-fix
    ``_deterministic_weighted_sample`` (in
    ``messagechain.consensus.attester_committee``) computed the per-
    candidate priority as ``decimal.Decimal`` but immediately
    collapsed back to ``float`` before the sort:

        pri = float(u.ln() / Decimal(w))

    Decimal.ln IS deterministic (Tier 62 lesson learned for the
    lottery), but the cast back to float at the sort key
    reintroduces an IEEE-754 rounding hazard.  Two near-equal
    log-keys can rank-flip on different libc / different CPython
    builds, producing different attester sets on different
    platforms -- a chain-wide partition class.  Committee
    selection is consensus-critical (rewards land in
    ``mint_block_reward`` and are committed in ``state_root``), so
    divergent committees mean divergent state-roots -- instant
    network partition.

    Today's homogeneous-Linux-glibc mainnet hides the bug; the
    moment a third validator joins on different libc / arch /
    Python build, partition risk goes live.  CLAUDE.md anchor at
    risk: Mission ("permanent ledger"); honest-operator-insurance
    (a node bounced onto a minority fork by a libc rounding
    difference accumulates resync cost it didn't earn).

    Tier 67 splits the sampler into legacy-float and Decimal-end-to-
    end branches.  ``_deterministic_weighted_sample_legacy_float``
    is byte-identical to the pre-fix implementation;
    ``_deterministic_weighted_sample_decimal`` keeps ``pri`` as
    ``Decimal`` and sorts on Decimal directly (zero-weight items
    use ``Decimal('-Infinity')`` so the comparator stays
    homogeneous).  ``select_attester_committee`` accepts a new
    ``block_height: int | None`` kwarg; both consensus call sites
    in ``core/blockchain.py`` (sim path in
    ``compute_post_state_root`` + apply path in
    ``_apply_block_state``) thread it through so the gate
    activates -- without that thread the height-gate would be
    wired but inert, the bug class belt-and-braces guarded against
    in the Tier 62 ship.

    Pre-fork (height < ``ATTESTER_COMMITTEE_DECIMAL_HEIGHT``) the
    legacy float-cast branch runs unchanged so historical blocks
    replay byte-identically.  Post-fork the deterministic Decimal
    branch is the consensus rule.  Activation height 2600 sits 50
    blocks above Tier 66 (2550) -- ~8.3h cohort spacing matching
    the Tier 49-66 pattern.  Mainnet tip at ship time is height
    ~1837, so the upgrade window is ~5.3 days at 600s blocks.
    Two-validator coordinated upgrade.  No new wire format, no new
    tx kinds, no state-tree changes -- pure consensus-rule swap
    inside the sampler.  14 regression tests in
    ``tests/test_audit_r38_committee_decimal_tier67.py``.
    Surfaced by audit r38 top-3 #2.  (e16a0f2)

### Fixed

  * **Non-response evidence multi-key candidate set closes silent-
    drop censorship rotation evasion.**  Pre-fix
    ``Blockchain.validate_non_response_evidence_tx`` resolved the
    CURRENT ``public_keys[client_id]`` and ``public_keys[witness_id]``
    at admission, not the keys active when the SubmissionRequest /
    WitnessObservation were signed.  Any rotation in the interval
    between sign-time and evidence-admission defeated the evidence
    -- the verifier saw a sig under K_old but resolved K_new and
    rejected as "invalid request signature" / "invalid witness
    observation".  ``KEY_ROTATION_COOLDOWN_BLOCKS`` (144) is well
    within the ``EVIDENCE_EXPIRY_BLOCKS`` admission window, so the
    rotation comfortably fits inside any non-response cycle.

    Concrete attack: a coerced/colluding target validator silently
    drops a witnessed SubmissionRequest.  Q honest peers sign
    WitnessObservations and any entity packages them into a
    NonResponseEvidenceTx.  Before the evidence is admitted, the
    colluder bribes the client (or a quorum of witnesses) to
    perform a routine key rotation -- the evidence becomes
    unverifiable because admission resolves K_new, the request was
    signed under K_old, and the witness pipeline that the chain's
    primary collusion defense rests on has a documented dodge.

    CLAUDE.md anchor at risk: "censorship resistance is a
    *collective decision*" -- the witnessed-submission pipeline
    IS the slashable-evidence layer that backs the collective
    guarantee against silent-TCP-drop censorship.  Same bug class
    as the multi-key candidate fixes already shipped on sibling
    evidence paths: audit r6 (AttestationSlashing / double-
    proposal SlashingEvidence), audit r11
    (FinalityDoubleVoteEvidence), audit r33 (slash-tx submitter
    path).  This patch propagates the same shape to non-response
    evidence.

    Soft-fix: pure verifier widening, no consensus rule change,
    no fork, no new wire format.
    ``verify_non_response_evidence_tx`` widens ``client_public_key``
    and each entry in ``witness_public_keys`` to accept either a
    single 32-byte pubkey (legacy shape, back-compat) OR an
    iterable of candidate pubkeys.
    ``Blockchain.validate_non_response_evidence_tx`` enumerates
    ``key_history + current`` for both the client and each witness,
    mirroring the slash path's candidate enumeration in
    ``validate_slash_transaction``.  Every candidate is a key the
    principal legitimately published, so matching ANY candidate is
    proof of authorship -- attacker cannot exploit the candidate
    set to forge evidence.  Pre-fix legitimate evidence (no
    rotation) admits unchanged; only the rotation-evasion bypass
    is closed.  6 regression tests in
    ``tests/test_audit_r38_non_response_multi_key.py``.  Surfaced
    by audit r38 top-3 #1.  (4adfbad)

### Security

  * **Mempool censorship-evidence admission gate optionally
    verifies submitter signature (defense-in-depth).**  Pre-fix
    ``Mempool.add_censorship_evidence_tx`` checked only ``tx_hash``
    dedup, pool capacity, and ``tx.fee >= MIN_FEE`` at admission.
    There was NO call to ``verify_censorship_evidence_tx`` /
    ``validate_censorship_evidence_tx`` at insert time.  Today's
    only LIVE caller (``server._rpc_submit_censorship_evidence``)
    runs ``Blockchain.validate_censorship_evidence_tx`` BEFORE
    admitting, so no live exploit exists -- but the admission
    gate's correctness silently depended on every caller
    remembering to pre-validate.

    Defense-in-depth gap: the censorship-evidence pool is
    registered as a forced-inclusion external source via
    ``Mempool._external_forced_sources``, so any future caller that
    forgets to validate (a gossip-relay path, a secondary admit
    surface, etc.) opens a free-flood vector at one MIN_FEE per
    slot.  Junk evidence saturates the 1000-entry cap, evicts
    genuine evidence via FIFO, and competes for forced-inclusion
    slots against legitimate censored-tx evidence -- the
    slashable-evidence layer's evidentiary cost collapses to free.
    Exactly the bug class the round-10 governance gossip fix
    caught: admission gate trusted a single caller path; a future
    contributor added a gossip-relay path; the new path forgot to
    validate; the verify-before-admit pattern eventually had to be
    lifted into the gate itself.  This patch lifts it
    proactively, before a second caller appears.

    CLAUDE.md anchor at risk: "any deviation from pure fee-per-
    byte selection requires a coordinated majority -- exactly the
    surface where slashable evidence is supposed to bite."  The
    censorship-evidence pool IS that slashable-evidence layer.

    Fix: add an OPTIONAL ``submitter_public_key_lookup:
    Callable[[bytes], bytes | None]`` kwarg to
    ``add_censorship_evidence_tx``.  When provided, run
    ``verify_censorship_evidence_tx`` against the resolved pubkey
    BEFORE inserting; reject (return False) on bad signature,
    missing pubkey, or any verifier failure.  Cheap-first: dedup,
    capacity, and fee floor still run BEFORE the WOTS+ verify so a
    flooder is dropped before paying the expensive verification
    cost.  Wire ``submitter_public_key_lookup=self.blockchain
    .public_keys.get`` into ``_rpc_submit_censorship_evidence`` so
    the live RPC path picks up the new defense layer.  Legacy
    callers (no lookup) admit unchanged for back-compat with the
    in-process test fixtures that build evidence txs without a
    chain pubkey registry.  Soft-fix, no fork, no wire-format
    change -- apply-time path already validates fully.  7
    regression tests in ``tests/test_audit_r38_censorship_
    evidence_admit_verify.py``.  Surfaced by audit r38 top-3 #3.
    (1c50c88)

Activation cohort spacing: Tier 67 = 2600 sits 50 blocks above
Tier 66 (2550) at ~8.3h gaps at 600s blocks, matching the Tier
49-66 pattern.  Mainnet tip at ship time is height ~1837 (probed
via ``https://messagechain.org/v1/info``), so the upgrade window
is ~5.3 days at 600s blocks for Tier 67.  Two-validator
coordinated upgrade.

## [1.67.0] — 2026-05-07

Minor release.  Audit round 37 top-2 ships: one consensus-tightening
soft fix (closes the fork-path / orphan-path Tier-18 unified-byte-
budget + react-count bypass that let a colluding proposer admit
oversized fork tips into the orphan/fork pool without any slashable
trail) and one new hard fork (Tier 66 makes the per-voter governance
reward cap adaptive in voter count, closing the Tier-65 residual
where today's two-validator bootstrap mainnet still burns 50-75% of
every proposal's voter surcharge).  No new wire format, no new tx
kinds, no state-tree changes beyond a single new constant.

### Added

  * **Tier 66 -- adaptive per-voter governance reward cap (hard fork,
    activation height 2550).**  Pre-fix Tier 65 (1.66.0) made
    voter-reward cap-overflow REDISTRIBUTE to non-cap voters before
    the burn fallback -- correct for skewed-stake distributions
    (whale + small voter, pool now keeps 50% instead of 26%).  But
    the redistribute loop only redistributes *within voters
    present*; it cannot break the per-voter
    ``VOTER_REWARD_MAX_SHARE_BPS`` cap.  When every voter is already
    at the cap, the residual still burns.  At N=1 voter the lone
    voter caps at 25% and 75% of the pool burns; at N=2 voters with
    equal stake each caps at 25% and 50% burns.

    Concrete bite: today's two-validator bootstrap mainnet has
    founder ≈ 100% of stake; the typical participating-voter set on
    a governance proposal is N=1 (founder alone) or N=2 (founder +
    second validator if it votes).  After Tier 65 every governance
    proposal STILL burns 50-75% of the voter surcharge.  CLAUDE.md
    anchor at risk: governance economics anchor -- "voters who cast
    a vote during the window receive a reward funded *out of the
    proposal fee* -- the proposer pays the voters they're asking to
    evaluate the proposal."  When the cap binds for every voter, the
    surcharge isn't going to voters at all -- it's just supply
    deflation.  Same anchor Tier 65 was protecting, viewed from a
    different angle: Tier 65 closed the skewed-stake leak; Tier 66
    closes the small-N leak.

    Tier 66 fix: per-voter cap becomes adaptive in N_voters post-
    activation::

        effective_cap_bps = max(
            VOTER_REWARD_MAX_SHARE_BPS,   # legacy floor (25%)
            10_000 // n_voters,           # mathematical "even share"
        )
        cap = pool * effective_cap_bps // 10_000

      N=1: max(2_500, 10_000) = 10_000 -> 100% (lone voter gets pool).
      N=2: max(2_500,  5_000) =  5_000 -> 50%.
      N=3: max(2_500,  3_333) =  3_333 -> 33.3%.
      N=4: max(2_500,  2_500) =  2_500 -> 25% (legacy floor binds).
      N=5+: max(2_500, ≤2_000) =  2_500 -> 25% (legacy floor binds).

    For N >= 4 the legacy 25% cap is preserved exactly, so the
    anchored "large-N anti-whale" shape is unchanged.  The Tier 65
    redistribute loop runs unchanged on top of the new cap value --
    a skewed N=2 distribution (whale=99 small=1 pool=100) goes whale
    capped at 50 + small lifted to 50 by redistribute -> 100
    distributed, 0 burned (vs Tier-65-only: whale 25 + small 25 = 50
    distributed, 50 burned).

    Hard fork because balance writes shift between the legacy cap
    and the adaptive cap, which is consensus-visible.  Activation
    height 2550 sits 50 blocks above Tier 65 (2500) -- ~8.3h cohort
    spacing matching the Tier 49-65 pattern.  Pre-fork (current_block
    < ``VOTER_REWARD_ADAPTIVE_CAP_HEIGHT``) the legacy 25% cap runs
    byte-for-byte so historical proposals replay identically.  No
    new wire format, no new tx kinds, no state-tree changes -- pure
    function-shape change inside ``Governance.finalize_voter_rewards``
    plus a single new constant.  13 regression tests in
    ``tests/test_audit_r37_voter_reward_adaptive_cap_tier66.py``.
    Surfaced by audit r37 top-3 #3.  (f287421)

### Fixed

  * **Fork-path & orphan-path validators enforce Tier-18 unified
    byte budget + react count.**  Pre-fix
    ``Blockchain.validate_block_standalone`` (the fork-path validator
    dispatched from ``_handle_fork``) and the orphan-path pre-
    validator inline in ``Blockchain.add_block`` both omitted
    ``react_transactions`` from the cross-kind tx-count cap that
    ``validate_block`` enforces post-Tier-18, and capped only
    ``total_message_bytes`` (just the message payloads) -- the
    unified ``MAX_BLOCK_TOTAL_BYTES`` budget was never applied on
    either side path.

    Concrete attack: a colluding proposer mints a fork tip whose
    ``react_transactions`` count pushes the cross-kind total past
    ``MAX_TXS_PER_BLOCK``, OR whose serialized tx bytes summed
    across (message + transfer + react) exceed
    ``MAX_BLOCK_TOTAL_BYTES``.  The canonical-chain ``validate_block``
    rejects such a block; the standalone validator accepted it.
    ``_handle_fork`` would then store the block in
    ``_block_by_hash`` and register it as a fork tip in
    ``fork_choice.tips`` without producing any slashable evidence.
    A future ``_reorganize`` swap admits chain bloat above the
    unified budget that every honest node tried to enforce on the
    linear-extension path.  The orphan-path bypass is structurally
    similar: bloated orphans defeat the "pre-validate before storing
    to prevent garbage" hardening that the orphan pre-validator was
    added for.

    CLAUDE.md anchors at risk: "censorship resistance is a
    *collective decision*" -- the Tier-18 budget IS the cross-kind
    market mechanism that prevents one tx kind from drowning out
    others; reorg-path divergence lets a colluding proposer escape
    it without producing slashable evidence -- and "minimize chain
    bloat & maximize storage efficiency."  Same defect class as the
    unstake-release / cross-pool admission gaps closed in audit
    rounds r12, r28, r31, r33 -- a security gate correctly enforced
    on the canonical-chain path but silently absent from a sibling
    block-entry path.

    Soft-fix: pure tightening of fork-acceptance and orphan-
    acceptance rules.  Every block already in the canonical chain
    passed both gates on the linear-extension path, so the legacy
    chain replays byte-identically; only adversarial fork tips and
    bloated orphans are newly rejected.  No new tier, no new wire
    format, no state-tree changes.  Both call sites mirror
    ``validate_block``'s existing Tier-18 block: cross-kind count
    includes ``react_transactions`` post-``TIER_18_HEIGHT``, and
    total ``len(tx.to_bytes())`` summed across (message + transfer +
    react) is capped at ``MAX_BLOCK_TOTAL_BYTES`` post-
    ``TIER_18_HEIGHT``.  7 regression tests in
    ``tests/test_audit_r37_fork_path_tier18_bypass.py``.  Surfaced
    by audit r37 top-3 #1.  (4cf7f7a)

Activation cohort spacing: Tier 66 = 2550 sits 50 blocks above Tier
65 (2500) at ~8.3h gaps at 600s blocks, matching the Tier 49-65
pattern.  Mainnet tip at ship time is height ~1837 (probed via
``https://messagechain.org/v1/info``), so the upgrade window is ~5.0
days at 600s blocks for Tier 66.  Two-validator coordinated upgrade.

## [1.66.0] — 2026-05-07

Minor release.  Audit round 36 top-3 ships: two new hard forks (Tier
63 wires the documented-but-unenforced ``StateCheckpointDoubleSign
Evidence`` into the slashing pipeline as a kind=3 ``SlashTransaction``
discriminator, Tier 65 makes voter-reward cap-overflow redistribute
to non-cap voters before the burn fallback so the per-proposal pool
no longer ≥75%-burns at bootstrap), plus one soft-fork on the
attester source set (Tier 64 caps per-entity slots in the forced-
inclusion FORCED source set so a single-entity flood cannot evict
a censored victim).  No new top-line CLI surface, no new tx kinds
beyond the kind=3 ``SlashTransaction`` discriminator on the existing
slash-tx wire form.

### Added

  * **Tier 63 -- ``StateCheckpointDoubleSignEvidence`` wired into
    the slashing pipeline (hard fork, activation height 2400).**
    Pre-fix the evidence type and verifier existed in
    ``messagechain/consensus/state_checkpoint.py`` and the docstring
    claimed "Penalty: 100% stake + full escrow burn, same as double-
    proposal / double-attestation / double-finality-vote."  But the
    slashing pipeline only dispatched kinds 0/1/2 (block /
    attestation / finality-vote); ``OffenseKind`` had no entry;
    ``SlashTransaction.{to,from}_bytes`` raised "Unknown slash
    evidence kind" on kind=3; ``validate_slash_transaction`` had no
    branch for it.  The documented slashable offense was therefore
    unenforceable.

    Concrete bite: a validator who signs two distinct ``state_root``
    values for the same checkpoint ``block_number`` fragments
    bootstrap-from-checkpoint sync -- new nodes adopting the >=2/3-
    stake-signed snapshot land in different post-states.  The
    promised 100% slash never fired because no code path could
    carry the evidence into apply.  CLAUDE.md anchor at risk:
    bootstrap survivability + validator-collusion (long-range /
    weak-subjectivity attack on newly-joining full nodes).

    Tier 63 is hard-fork-gated (admission, not decode) at activation
    height 2400, sitting 50 blocks above Tier 62 (2350) -- ~8.3h
    cohort spacing matching the Tier 49-62 pattern.  Five pieces:
    new ``STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT`` constant; new
    ``OffenseKind.STATE_CHECKPOINT_DOUBLE_SIGN`` enum entry (always
    UNAMBIGUOUS -- snapshot ``state_root`` is a function of
    deterministically-replayed chain state, so two distinct values
    at the same height cannot be a benign restart shape);
    ``SlashTransaction.{to,from}_bytes`` / ``serialize`` /
    ``deserialize`` gain kind=3 / ``type="state_ckpt_double_sign"``
    dispatch (encoder unconditional, admission gated);
    ``Blockchain._evidence_block_number`` returns
    ``checkpoint_a.block_number`` for the new evidence shape;
    ``Blockchain.validate_slash_transaction`` walks the multi-key
    candidate set so a rotated-key offender cannot dodge the slash
    by rotating between the two checkpoint signs.  Pre-fork blocks
    replay byte-identically via the height gate.  12 regression
    tests in
    ``tests/test_audit_r36_state_checkpoint_double_sign_slashing.py``.
    Surfaced by audit r36 top-3 #1.  (a94f90a)

  * **Tier 64 -- per-entity cap on the forced-inclusion FORCED
    SOURCE SET (soft fork, activation height 2450).**  Pre-fix
    ``Mempool.get_forced_inclusion_set`` ranked qualifying txs by
    ``(-fee_per_byte, arrival_height, tx_hash)`` and sliced the top
    ``FORCED_INCLUSION_SET_SIZE`` with NO per-entity cap on the
    source set itself.  Tier 37's per-entity cap fix
    (``FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT``) tightened excuse #3
    on the proposer-validator axis, but the attester-side forced
    *source* set this fix governs had no equivalent guard.

    Concrete attack: a colluding cartel pays a high-stake entity to
    flood the mempool with N high-fpb txs from a single
    ``entity_id``.  After ``FORCED_INCLUSION_WAIT_BLOCKS`` those N
    txs occupy the top ``FORCED_INCLUSION_SET_SIZE`` slots, evicting
    the censored victim's lower-fpb tx from the forced set entirely.
    The cartel proposer can then exclude the victim without
    triggering excuse #1 (the victim's tx is no longer in the
    forced set), excuse #3 (Tier 37 reads block-tx counts, not the
    forced source set), or any other structural excuse.  CLAUDE.md
    anchor at risk: "a tx that is well-formed, pays at least the
    per-byte floor, and fits the byte budget cannot be suppressed
    by anything weaker than a full validator-set majority actively
    colluding AND willing to absorb the slashing risk that exposed
    collusion produces."

    Tier 64 caps the FORCED source set at
    ``MAX_TXS_PER_ENTITY_PER_BLOCK = 3``.  Forcing more than 3 from
    one entity is meaningless anyway -- the proposer cannot fit
    them in one block under the existing block-validator cap;
    capping the forced source set at the same constant therefore
    preserves every honest forced-inclusion outcome while denying
    the eviction primitive.  The freed slots fill with the next-
    ranked txs from OTHER entities -- exactly the censored-victim
    path the anchor protects.  Soft-fork because the forced source
    set is per-attester local state, not consensus-relevant block
    content; different attesters can see different mempool views
    and the soft-vote aggregation handles divergence.  Pre-fork
    (height < activation) the legacy uncapped path runs byte-
    identically so historical attester votes replay byte-
    identically.  Activation height 2450 sits 50 blocks above Tier
    63 (2400).  6 regression tests in
    ``tests/test_audit_r36_forced_inclusion_per_entity_cap_tier64.py``.
    Surfaced by audit r36 top-3 #2.  (5cd3414)

  * **Tier 65 -- voter-reward cap-overflow redistributes to non-cap
    voters before the burn fallback (hard fork, activation height
    2500).**  Pre-fix ``Governance.finalize_voter_rewards``
    distributed the per-proposal voter pool pro-rata-by-stake,
    capped each voter at ``VOTER_REWARD_MAX_SHARE_BPS / 10_000``
    (25%) of the pool, and BURNED both cap_excess (overflow above
    the per-voter cap) AND integer-division dust.

    At today's bootstrap (founder ≈ near-100% of active stake) the
    founder hits the 25% cap on every proposal and the other 75% of
    the per-proposal pool burns.  Even after seed-divestment to a
    10M-floor founder + 90M-elsewhere distribution, a small voter
    with 10K stake on a 100M-staked network would earn 50000 × 10K
    / 100M = 5 tokens -- below the vote-tx fee floor of 100.  The
    mechanism currently *demotivates* voting at the small end while
    burning the surcharge that was supposed to motivate it.

    CLAUDE.md anchor at risk: "voters who cast a vote during the
    window receive a reward funded *out of the proposal fee* -- the
    proposer pays the voters they're asking to evaluate the
    proposal."  When ≥75% of every proposal's voter pool incinerates
    instead of paying voters, the anchor is materially inverted.

    Tier 65 redistributes cap_excess to non-cap voters before the
    burn fallback.  The redistribute loop iterates: each round, fill
    non-cap voters pro-rata-by-stake from the remaining excess;
    voters that hit the cap during a round drop out for the next
    round.  Convergence in O(N_voters) rounds -- every round either
    fills another voter to cap or distributes everything to uncapped
    voters.  When no progress can be made (all voters at cap, OR
    only one voter exists), the residual burns via the existing
    ``burned = pool - distributed`` path.  Integer-division dust
    still burns (unavoidable at the per-token level).  Pre-fork
    (current_block < activation) the legacy single-pass code runs
    byte-for-byte so historical proposals replay byte-identically.

    Concrete improvement on the canonical bootstrap-skew shape
    (whale=99 stake + small=1 stake, pool=100, cap=25):
      Pre-fix: whale 25 + small 1 = 26 distributed, 74 burns.
      Post-fix: whale 25 + small lifted-to-25 by redistribute = 50
                distributed, 50 burns.
    Permanent supply-deflation leak halved on this distribution.

    Hard-fork because balance writes shift between the legacy
    single-pass-and-burn path and the iterative redistribute path,
    which is consensus-visible.  Activation height 2500 sits 50
    blocks above Tier 64 (2450).  Two-validator coordinated upgrade.
    No new wire format, no new tx kinds, no state-tree changes --
    pure function-shape change inside ``finalize_voter_rewards``.
    7 regression tests in
    ``tests/test_audit_r36_voter_reward_redistribute_tier65.py``.
    Surfaced by audit r36 top-3 #3.  (bd30d28)

Activation cohort spacing: Tier 63 = 2400 -> Tier 64 = 2450 -> Tier
65 = 2500 (50-block / ~8.3h gaps at 600s blocks), matching the Tier
49-62 pattern.  Mainnet tip at ship time is height ~1837 (probed via
``https://messagechain.org/v1/info``), so the upgrade window is ~3.9
days at 600s blocks for Tier 63, ~4.3 days for Tier 64, ~4.7 days
for Tier 65.  Two-validator coordinated upgrade.

## [1.65.1] — 2026-05-07

Patch release.  Audit round 35 top-1 ships: pure removal of the
dormant ``messagechain.crypto.threshold_rsa`` module.

The module was a "Phase 1 threshold-RSA primitive for MessageChain's
encrypted mempool" with phased Phase 2/3/4 deployment language
(DKG, on-chain wire format, hybrid RSA+AES) -- but the CLAUDE.md
"Settled Design Decisions" anchor is unambiguous: **"Payloads are
fully public.  Hard no, ever on protocol-level encrypted message
types.  Encryption is strictly a user/app-layer concern."** Zero
production callers (only its own test imported it), but its
presence in the ``crypto/`` namespace dressed the anchor as soft
and invited a future contributor to finish the path.  Deletion
ratifies the anchor at the code level.

No consensus impact, no tier, no fork, no wire-format change, no
CLI surface, no new config keys.  Pure dead-code removal plus a
regression pin.

### Removed

  * ``messagechain/crypto/threshold_rsa.py`` (1245 lines) and
    ``tests/test_threshold_rsa.py`` (503 lines).  Surfaced by
    audit r35 top-3 #1.  (baf9124)

### Added

  * ``tests/test_no_protocol_encryption_anchor.py`` --
    regression pin for the CLAUDE.md "no protocol-level encrypted
    message types" anchor.  Three tests assert (a) no
    ``messagechain/crypto/threshold_rsa.py`` file in the tree,
    (b) ``import messagechain.crypto.threshold_rsa`` raises
    ``ModuleNotFoundError``, and (c) no file under
    ``messagechain/crypto/`` carries the load-bearing
    "encrypted mempool" / "threshold decryption" /
    "threshold-rsa primitive" docstring shape (the forbidden-
    phrase scan is precise enough to avoid false-positives on
    legitimate user/app-layer encryption uses like keystore
    at-rest protection).  Re-introducing any of the above trips
    the test immediately.  (baf9124)

## [1.65.0] — 2026-05-07

Minor release.  Audit round 34 top-2 ships: one new hard fork
(Tier 62 swaps ``select_lottery_winner`` from ``math.log`` -- a
libm call whose ULP-level rounding is not portable across glibc /
musl / MSVC libm / macOS libm -- to ``decimal.Decimal.ln()`` at
40-digit precision, eliminating the consensus-fork risk between
heterogeneous-libc validators on the same chain) and one operator-
UX gate (``messagechain start --mine`` now runs the same
``_check_leaf_index`` audit r33 #3 added to ``doctor``, so an
operator who restores from paper backup and skips ``doctor`` is
caught before the daemon takes its first signing turn).  No new wire
format, no new tx kinds, no state-tree changes.

### Added

  * **Tier 62 -- ``select_lottery_winner`` uses
    ``decimal.Decimal.ln()`` (hard fork, activation height 2350).**
    Pre-fix the lottery winner was selected by ranking candidates on
    ``key = math.log(u) / w`` in ``float64``, then comparing keys
    with float-equality tiebreak.  ``math.log`` delegates to a libm
    whose ULP-level rounding is NOT portable across glibc / musl /
    MSVC libm / macOS libm.  Two heterogeneous-libc validators on
    the same chain could disagree on the lottery winner for the
    same ``(randao_mix, candidates)`` input -- producing divergent
    ``supply.balances`` / ``total_supply`` / ``total_minted``
    mutations and a silent state-root split on every lottery
    firing.

    Today's mainnet runs homogeneous Linux glibc on both
    validators, so the chain has not actually forked yet -- the fix
    protects the moment a third validator joins on a different
    libc.  CLAUDE.md anchor at risk: Mission ("permanent ledger");
    honest-operator-insurance (a node bounced onto a minority fork
    by a libm rounding difference accumulates resync cost it didn't
    earn).

    Tier 62 mirrors the same fix ``attester_committee.py`` already
    received pre-mainnet for the same reason: drop into
    ``decimal.Decimal.ln()`` at 40-digit precision inside a
    ``localcontext()``, byte-identical everywhere CPython runs.
    Algorithm shape (A-Res with k=1, log-key = ln(u_i) / w_i,
    tiebreak on entity_id ascending) matches the legacy path so the
    weighted-probability distribution is preserved -- only the
    arithmetic backend changes.

    Pre-fork (height < ``LOTTERY_DETERMINISTIC_HEIGHT = 2350``) the
    legacy float-math branch runs unchanged so every historical
    lottery-firing block replays byte-identically post-upgrade.
    Post-fork the deterministic Decimal branch is the consensus
    rule.  Both consensus call sites in ``core/blockchain.py`` (sim
    path in ``compute_post_state_root`` + apply path in the
    lottery-firing block) pass ``block_height=`` so the gate
    actually activates.

    Activation height 2350 sits 50 blocks above Tier 61 (2300) --
    ~8.3h cohort spacing matching the Tier 49-61 pattern.  Mainnet
    tip at ship time is height ~1837 (probed via
    ``https://messagechain.org/v1/info``), so the upgrade window is
    ~3.6 days at 600s blocks.  Two-validator coordinated upgrade.
    10 regression tests in
    ``tests/test_audit_r34_lottery_deterministic_tier62.py`` pin
    activation constant ordering, pre-fork legacy byte-identity,
    post-fork repeatability, post-fork helper does NOT reference
    ``math.log``, weighted-probability shape preserved post-fork,
    seed exclusion preserved post-fork, edge cases (empty / all-
    seed / all-zero), and BOTH consensus call sites pass
    ``block_height=``.  Surfaced by audit r34 top-3 #1.  (4f83ccb)

### Fixed

  * **``messagechain start --mine`` gates on the leaf-index check
    before the daemon takes its first signing turn.**  Audit r33 #3
    (1.64.0) added ``_check_leaf_index`` to the ``doctor``
    checklist to catch the keyfile-on-fresh-disk-without-cursor
    restore disaster: chain watermark > 0, no ``leaf_index.json``
    on disk -> next sign re-uses a burned leaf -> 100%-slash
    equivocation evidence.  The check is correct, but it only fires
    when the operator runs ``messagechain doctor`` first.

    An operator who restores from paper backup and (a) starts the
    daemon via ``systemctl start messagechain-validator`` directly,
    (b) follows older runbook habits and skips ``doctor``, or (c)
    runs ``messagechain start --mine`` straight, bypassed the gate.
    The next sign re-used the burned leaf; the on-chain watermark
    caught the equivocation on the first observed conflict; full
    stake loss on a documented operator workflow.

    CLAUDE.md anchor at risk: "honest operators are insured against
    accidents" -- a one-off restore that skips ``doctor`` is exactly
    the kind of recoverable misconfig the anchor wants to insulate.

    Fix lifts the same ``_check_leaf_index`` call into ``cmd_start``
    right after entity resolution, BEFORE the daemon takes its
    first signing turn.  Level=2 (RED) prints the diagnostic and
    exits non-zero with the operator remediation message.  Level=1
    (WARN / inconclusive) prints the warning and continues.
    Level=0 (GREEN) is silent so healthy boots stay quiet.  New
    ``--accept-leaf-reuse-risk`` flag mirrors the ``--yes-nat``
    pattern on the reachability probe: operators who have manually
    verified the local cursor exceeds the chain watermark for every
    prior sign can bypass the gate (the bypass path still prints a
    clear warning so the operator's choice is visible in startup
    logs).

    Soft-fix; no consensus rule change, no fork, no new wire
    format.  The CLI surface adds exactly one flag to ``start``.
    5 regression tests in
    ``tests/test_audit_r34_start_leaf_index_gate.py`` pin: parser
    includes the bypass flag, ``cmd_start`` source references
    ``_check_leaf_index``, RED exits non-zero by default,
    ``--accept-leaf-reuse-risk`` bypasses the RED exit (with
    audible warning), GREEN is silent.  Surfaced by audit r34
    top-3 #2.  (eb473aa)

## [1.64.0] — 2026-05-07

Minor release.  Audit round 33 top-3 ships: one cryptographic-
soundness fix on the consensus-vote admission gates (cross-pool
WOTS+ leaf check missing on ``mempool.{finality_pool, slash_pool,
censorship_evidence_pool}`` and on the three gossip-admit handlers
``_handle_announce_{finality_vote, slash, attestation}``); one new
hard fork (Tier 61 switches the inactivity-leak per-block formula
from "floor of per-block-real" to "difference of cumulative-floors"
so the ~2% target drain materialises for every stake size --
pre-fix the Tier 59 stake-scaled formula integer-truncated to zero
for any validator with stake < ~1M tokens, disabling cartel defense
for the rank-and-file validator set); and one operator-side fix
(``messagechain doctor`` now checks the leaf-index file's presence
+ freshness against the chaindb watermark, so the README's #1
catastrophic footgun -- restoring on a fresh disk from
keyfile-only backup, then starting the daemon and 100%-self-
slashing on the first sign -- is detected before the daemon boots
instead of going GREEN through the diagnostic).  No new wire
format, no new top-line CLI surface.

### Added

  * **Tier 61 -- inactivity-leak cumulative-floor formula (hard
    fork, activation height 2300).**  Pre-fix the Tier 59
    stake-scaled per-block formula
    ``stake * BASE * blocks_since_finality² // Q`` with
    ``Q = 16_777_216_000_000`` integer-truncated to zero for any
    validator with stake < ~1M tokens.  Concrete arithmetic at
    stake=10K, blocks=10000:
    ``10_000 * 1 * 10⁸ // 1.68e13 = 0``.  Cumulative drain over a
    full 10000-block stall is the SUM of per-block penalties; if
    every per-block term floors to 0, the SUM is also 0.  Net
    effect: the inactivity leak fired correctly only for whales
    (stake >= ~1M); the rank-and-file validator set
    (stake = 10K..100K -- everyone post-FAUCET-DRIP at the
    ``VALIDATOR_MIN_STAKE_POST_RAISE`` floor of 10K through every
    operator in the bootstrap arc) experienced ZERO drain on
    arbitrarily long partitions.

    CLAUDE.md anchor at risk: "censorship resistance is a
    *collective decision*" -- a 1/3-stake cartel composed of
    small-stake validators withholds attestations indefinitely
    without economic counter-pressure.  The leak is the
    slashing-bearing path that makes coordinated suppression cost
    real money; for small-stake cartels under Tier 59 it cost
    nothing.  CHANGELOG claim "cumulative drain ~2% of stake
    regardless of stake size" was mathematically correct in real
    arithmetic, but the integer-arithmetic implementation lost the
    small-stake half of the calibration target.

    Tier 61 fix is stateless and preserves the calibration
    constants: compute the per-block penalty as the integer
    DIFFERENCE of cumulative-floor values rather than the FLOOR of
    per-block-real::

        cum(k) = stake * BASE * (k * (k+1) * (2k+1) / 6) // Q
        penalty_at_block_k = cum(k) - cum(k-1)

    The cumulative-floor trick integer-truncates at the
    *cumulative* level (which crosses 1-token boundaries even for
    small stakes over realistic partitions) instead of at the
    per-block level (which floored to 0 for stake<~1M).
    Verification arithmetic over a 10000-block stall:

      * stake=10K:   cum(10000) ≈ 198 tokens (~2% drain).
      * stake=1M:    cum(10000) ≈ 19_842 tokens (~2%).
      * stake=100M:  cum(10000) ≈ 1_984_226 tokens (~2%).

    The ``min(penalty, validator_stake)`` cap still applies
    per-block.  Cartel-defense behaviour preserved: a withholding
    coalition pays the same FRACTION of stake per partition window
    as a small honest validator, but in absolute tokens the
    cartel's drain is much larger.  Tier 55 honesty-curve relief
    multiplier still wraps the new shape unchanged.  No new wire
    format, no state-tree changes, no new chaindb table -- pure
    function-shape change inside ``compute_inactivity_penalty``
    plus a new private helper ``_cumulative_inactivity_drain``.

    Activation height 2300 sits 50 blocks above Tier 60
    (``DORMANCY_TARGET_RETUNE_HEIGHT = 2250``) -- ~8.3h cohort
    spacing at 600s blocks, matching the Tier 49-60 pattern.
    Two-validator coordinated upgrade.  Pre-fork (height <
    ``INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT``) the legacy Tier 59
    per-block formula runs unchanged so historical blocks at
    heights [Tier 59, Tier 61) replay byte-identically.  8
    regression tests in
    ``tests/test_audit_r33_inactivity_leak_cumulative_tier61.py``.
    Surfaced by audit r33 top-3 #2.  (ea35aba)

### Fixed

  * **Cross-pool WOTS+ leaf check missing on consensus-vote pools
    and gossip-admit handlers.**  Pre-fix
    ``Server._check_leaf_across_all_pools`` scanned every server-
    side pool plus ``mempool.{react_pool, pending}``, but NOT
    ``mempool.{finality_pool, slash_pool, censorship_evidence_pool}``.
    Plus the three gossip handlers
    ``_handle_announce_{finality_vote, slash, attestation}`` never
    called the cross-pool sweep before pooling/processing.

    Concrete bite: validator V signs a finality vote at leaf=N
    every FINALITY_INTERVAL blocks.  V's local mempool also holds
    a pending message tx at leaf=N (stale watermark, wallet bug,
    race during a restart).  ``mempool.add_finality_vote`` admits
    the vote because the finality_pool is keyed by consensus_hash,
    not by (signer, leaf).  Both signed objects now carry the same
    WOTS+ leaf; the two publications leak enough one-time-key
    preimages for any observer to forge an arbitrary signature at
    that leaf -- including a fresh revoke, full-balance unstake,
    or set-authority rebind transferring authority to the
    attacker.  Validators emit finality votes every cycle so this
    trips strictly more often than the audit r31 user-tx case.

    Same defect class as audit r31 #1 (cross-pool admission gap on
    ``mempool.pending``) and r12 (``react_pool``), this time on
    the consensus-vote side.  Three pieces, all source-pinned:

      (1) ``_tx_signer_pubkey`` resolves ``validator_id``
      (Attestation) and ``signer_entity_id`` (FinalityVote) in
      addition to the existing
      ``entity_id / proposer_id / voter_id / submitter_id``
      fields, so the signer-keyed dedupe identifies the signing
      pubkey for every pooled object kind.

      (2) ``_check_leaf_across_all_pools`` extended to scan
      ``mempool.finality_pool``, ``mempool.slash_pool``, and
      ``mempool.censorship_evidence_pool`` in BOTH the signer-
      keyed (default) and entity-id-keyed (legacy call shape)
      branches.

      (3) The three consensus-vote gossip handlers call
      ``_check_leaf_across_all_pools(...)`` BEFORE the
      ``mempool.add_*`` / ``finality.add_attestation`` step.  On
      collision the source peer is ban-scored
      (``OFFENSE_INVALID_TX``) and the object is dropped without
      pooling or relay.  Existing ``observe_finality_vote`` and
      ``equivocation_watcher.observe_attestation`` calls fire
      BEFORE the cross-pool gate so the fork-emergency /
      equivocation detectors still see the gossip as evidence.

    Soft-fix: admission-side only, no consensus rule change at the
    block validator.  Block-level dedupe still catches anything
    that slips through admission, so this is purely a tightening
    of the admission gate.  No new tier, no new wire format.  10
    regression tests in
    ``tests/test_audit_r33_cross_pool_consensus_votes.py``.
    Surfaced by audit r33 top-3 #1.  (96aa6da)

  * **`messagechain doctor` surfaces leaf-index missing/stale
    state before validator boot.**  Pre-fix ``run_doctor`` checks:
    python, data-dir, keyfile, disk, two ports, seeds, optional
    systemd timers -- NO leaf-index check.  The README warns
    operators in prose that a keyfile-without-leaf-index restore
    is a 100% slash event ("Operating a live validator -> Back up
    the keyfile AND the leaf-index files"), but the diagnostic
    command operators are told to trust silently approved the
    fatal config.

    Concrete bite: operator restores on a fresh disk from
    "keyfile only" backup.  Runs ``messagechain doctor`` -- GREEN.
    Starts the validator; the chaindb gets rebuilt from peer sync,
    but the leaf-index cursor starts at 0.  The first sign re-uses
    leaf 0, publishing a second signature at a leaf the chain's
    leaf_watermark already records as burned.  Equivocation
    evidence lands; 100% stake slash.

    CLAUDE.md anchor at risk: "honest operators are insured
    against accidents... when an honest node IS slashed, the burn
    is a small *fraction* of stake, not a wipe."  100% slash on
    what is structurally a backup mistake is a wipe; the chain
    could surface the misconfig before the slash fires.

    Fix adds a new ``_check_leaf_index(data_dir, entity_id_hex,
    chaindb_open_fn=None)`` helper to the doctor checklist with
    this state machine: data_dir or entity_id_hex unset -> WARN;
    chain.db absent -> GREEN regardless of cursor; chain.db
    present with leaf_watermark[entity]==0 -> GREEN; chain.db
    present with leaf_watermark[entity]>0 AND no leaf_index.json
    -> RED (RESTORE WITHOUT CURSOR); chain.db present with
    leaf_watermark[entity]>0 AND leaf_index.json cursor < watermark
    -> RED (STALE CURSOR); chain.db present with
    leaf_watermark[entity]>0 AND leaf_index.json cursor >= watermark
    -> GREEN.  Database access is via injectable
    ``chaindb_open_fn`` so unit tests can synthesize a minimal
    sqlite db; real-call default opens chain.db read-only via
    ``sqlite3.connect("file:...?mode=ro")`` so a running daemon's
    exclusive lock is uncontested -- a busy daemon falls into the
    YELLOW "chaindb read failed" branch rather than RED.

    Soft-fix: doctor-only, no consensus rule change, no fork.  The
    catastrophic config is detected before the daemon is started,
    so the slash never fires.  9 regression tests in
    ``tests/test_audit_r33_doctor_leaf_index.py``.  Surfaced by
    audit r33 top-3 #3.  (5ddb425)

## [1.63.0] — 2026-05-07

Minor release.  Audit round 32 top-3 ships: three new hard forks,
all anchored to the CLAUDE.md honest-operator-insurance / crypto-
agility / bootstrap-arc anchors.

  * **Tier 58 (height 2150) — cold-key WOTS+ leaf watermark**
    closes the pre-signed-revoke leaf-reuse leak.  Sibling of
    audit r31 #1 (cross-pool admission gap on ``mempool.pending``)
    on the COLD-KEY side: r31 closed the hot-key cross-pool
    admission gap; Tier 58 closes the same defect class for cold-
    key-signed txs across BLOCKS.  An operator who pre-signed an
    offline emergency revoke at cold-key leaf=N (the documented
    hardening pattern at ``emergency_revoke.py:21-30``) and later
    signed an unstake / fresh revoke / set-authority cold counter-
    sig at the same cold-key leaf=N would publish two distinct
    payloads under the same WOTS+ leaf, leaking the one-time-key
    secret.  Anyone observing both signatures could forge
    arbitrary cold-key signatures -- including a fresh revoke,
    full-balance unstake, or set-authority rebind transferring
    authority to the attacker.  Total stake loss + identity
    hijack for any operator who followed the recommended
    hardening recipe and slipped on cold-leaf cursor tracking.
    Fix: new ``Blockchain.cold_leaf_watermarks: dict[bytes, int]``
    keyed by COLD PUBKEY BYTES (NOT entity_id, since one cold key
    may sign for multiple entities -- the documented cluster
    pattern).  Validation gates in ``validate_revoke``,
    ``_validate_unstake_tx_in_block``, ``validate_set_authority_
    key`` reject cold-sig leaves below the watermark; apply paths
    bump the watermark identically to the hot-key pattern.
    Persistence via new chaindb table + state-snapshot bump
    v22->v23 with ``_TAG_COLD_LEAF_WATERMARK`` participating in
    the state-root commitment.  Pre-fork blocks replay byte-
    identically via the height gate.  6 regression tests in
    ``tests/test_audit_r32_cold_leaf_watermark_tier58.py``.
    Surfaced by audit r32 top-3 #1.  (005b107)

  * **Tier 59 (height 2200) — inactivity-leak penalty stake-
    scaled** restores honest-operator-insurance for small
    validators.  Pre-fix ``compute_inactivity_penalty`` was FLAT
    in tokens (``BASE * blocks² / quotient``); ``validator_stake``
    was used only as a CAP, not as a scale factor.
    ``compute_coverage_penalty`` IS stake-scaled.  At
    ``INACTIVITY_BASE_PENALTY=1``, ``quotient=2²⁴``,
    ``threshold=4``: a 10k-stake (``VALIDATOR_MIN_STAKE_POST_RAISE``)
    honest-but-isolated validator hits zero stake at
    ``blocks_since_finality≈12700`` (~88 days) while a 1M-stake
    whale at the same blocks_since absorbs <0.06% of stake.  Tier
    55 honesty-curve relief floors at 20% of nominal -- still a
    wipe for the small validator on a long partition.  CLAUDE.md
    anchor at risk: "honest operators are insured against
    accidents ... the burn is a small *fraction* of stake, not a
    wipe."  Fix: post-Tier-59 nominal becomes
    ``stake * BASE * blocks² / Q_V2`` where ``Q_V2 = 2^24 *
    1_000_000`` is calibrated so the cumulative drain over a full
    10000-block stall window is ~2% of stake regardless of stake
    size -- matching the cumulative drain the legacy formula
    imposed on a 1M-stake validator (the bound that survived
    "fractionally" before).  Cartel-defense intent preserved: a
    1/3-stake withholding cartel pays the same FRACTION of stake
    per block as a small honest validator, but in absolute
    tokens the cartel's drain is much larger.  Tier 55 honesty-
    curve relief still wraps the new shape unchanged.  Pre-fork
    blocks replay byte-identically via the height gate.  9
    regression tests in ``tests/test_audit_r32_inactivity_leak_
    stake_scaled_tier59.py``.  Surfaced by audit r32 top-3 #2.
    (7b48817)

  * **Tier 60 (height 2250) — DORMANCY_TARGET retune** restores
    bootstrap-arc issuance.  Pre-fix
    ``DORMANCY_TARGET_ACTIVE_SUPPLY = 100_000_000`` exactly
    matches the founder's genesis balance (100M; treasury 40M is
    excluded from active-supply per ``compute_active_supply``).
    While the founder signs blocks, ``last_active`` bumps each
    block, weight = 10000 bps, contribution = 100M.
    ``gap = 100M - 100M = 0`` -> ``compute_dormancy_issuance``
    returns 0/block, indefinitely.  The legacy halving-floor was
    short-circuited at ``DORMANCY_CONTROLLER_HEIGHT`` (Tier 47).
    Validators currently earn ~0/block of issuance during the
    entire 25-year DORMANCY_WINDOW.  CLAUDE.md anchor: founder-
    bootstrap arc -- "early-phase issuance is calibrated so the
    founder can credibly secure the network solo while it has
    only a handful of nodes, and progressively dilutes toward
    broad democratization as more validators stake in".  The
    0/block delivery contradicts the front-loaded shape the
    anchor calls for.  Fix: post-Tier-60 the controller uses
    ``DORMANCY_TARGET_ACTIVE_SUPPLY_V2 = 110_000_000``.  At
    founder=100M-active, gap = 10M; raw_issuance = (10M * 1) //
    200_000 = 50/block; ~2.6M tokens/yr split across validators
    -- comparable to legacy halving-floor era (4/block = ~210k/yr),
    generously front-loaded for the bootstrap arc without
    overshooting.  Shape-preserving: still gap-driven, still
    dormancy-filtered, still capped at MAX_ISSUANCE_PER_BLOCK,
    still zero at active >= target.  Only the equilibrium point
    moves from 100M -> 110M.  Pre-fork blocks replay byte-
    identically via the height gate; the legacy 100M target is
    preserved on the pre-fork branch so every historical block
    under the controller (heights 1710..2249) replays exactly.
    7 regression tests in ``tests/test_audit_r32_dormancy_
    target_retune_tier60.py``.  Surfaced by audit r32 top-3 #3.
    (eae7105)

Activation cohort spacing: Tier 58 = 2150 -> Tier 59 = 2200 ->
Tier 60 = 2250 (50-block / ~8.3h gaps at 600s blocks), matching
the Tier 49-57 pattern.  Two-validator coordinated upgrade.  No
new top-line CLI surface, no new tx kinds.  STATE_SNAPSHOT_VERSION
bumps 22 -> 23 to carry the new ``cold_leaf_watermarks`` section
in the wire format and snapshot-root commitment.

### Added

  * Tier 58 hard fork: cold-key WOTS+ leaf watermark
    (``COLD_LEAF_WATERMARK_HEIGHT = 2150``).  See above.  (005b107)
  * Tier 59 hard fork: inactivity-leak stake-scaled
    (``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT = 2200``).  Adds
    ``INACTIVITY_PENALTY_STAKE_SCALED_QUOTIENT = 16_777_216_000_000``
    constant.  See above.  (7b48817)
  * Tier 60 hard fork: dormancy controller TARGET retune
    (``DORMANCY_TARGET_RETUNE_HEIGHT = 2250``,
    ``DORMANCY_TARGET_ACTIVE_SUPPLY_V2 = 110_000_000``).  See
    above.  (eae7105)
  * State-snapshot ``v23``: new ``cold_leaf_watermarks`` section
    + ``_TAG_COLD_LEAF_WATERMARK`` state-root tag.  Encoded
    strictly after v22's ``slash_offense_counts`` so a v22 blob
    is a strict prefix of a v23 blob through the end of v22's
    final field.  ``deserialize_state`` defaults the field to
    ``{}`` so older v22 hand-built dicts decode gracefully.
    (005b107)
  * Chaindb ``cold_leaf_watermarks`` table mirrors
    ``leaf_watermarks`` but keyed by cold pubkey, with matching
    ``get_cold_leaf_watermark`` / ``set_cold_leaf_watermark`` /
    ``get_all_cold_leaf_watermarks`` methods.  Hydrated by
    ``_load_from_db`` on cold restart; persisted from the
    apply-commit path alongside the hot watermark.  (005b107)

## [1.62.0] — 2026-05-07

Minor release.  Audit round 31 top-3 ships: one cryptographic-soundness
fix on the admission gate (cross-pool WOTS+ leaf-reuse window where
a message or transfer in ``mempool.pending`` at leaf=N could collide
with a server-side stake / unstake / authority / governance / react
tx at leaf=N from the same signer, leaking one-time-key secret
material on the second signature), one new hard fork (Tier 57 routes
the transfer apply path through ``pay_fee_with_burn`` so the
attester-fee-funding split, DEFLATION_FLOOR_V2 rolling-fee-burn
accumulator, and ``fee_burn_this_block`` ticker all accrue on
transfer txs -- transfers were the only fee-paying tx kind silently
bypassing these mechanisms), and one README correction (§1
"Generate a private key" instructed users to back up the printed
hex on paper, but ``generate-key``'s actual output prints the
24-word BIP-39 phrase as the primary backup with a built-in
checksum that the hex form lacks).  No new wire format, no new
top-line CLI surface.

### Added

  * **Tier 57 -- transfer apply path routes through
    ``pay_fee_with_burn`` (hard fork, activation height 2100).**
    Pre-fix ``Blockchain._apply_transfer_with_burn`` hand-rolled
    fee accounting (``balances[from] -= fee; balances[proposer]
    += tip; total_supply -= burned``) instead of routing through
    ``SupplyTracker.pay_fee_with_burn``.  Every other tx kind
    (message, stake, governance, react, authority) routes through
    the helper.  Transfers alone bypassed it.

    Three CLAUDE.md anchors break silently as soon as transfer
    volume matters: (a) the **attester-fee-funding split (Tier
    4)** -- post-Tier-4 ``ATTESTER_FEE_SHARE_BPS / 10_000`` of
    base_fee should redirect to ``attester_fee_pool_this_block``
    (consumed by ``mint_block_reward``); transfers were silently
    zeroing this; (b) the **DEFLATION_FLOOR_V2 rolling-fee-burn
    accumulator** -- drives the supply-rebate floor in
    ``calculate_block_reward`` when active-supply runs below
    target; transfers were silently not accruing; (c) the
    **``fee_burn_this_block`` ticker** -- redirects
    ``ARCHIVE_BURN_REDIRECT_PCT`` into the archive reward pool at
    end-of-block; transfers were silently not accruing.

    Today's mainnet has near-zero transfer volume so the leak is
    invisible.  That is the worst possible time to catch it -- the
    moment the dual-purpose-token anchor pays off and transfers
    become a real share of fee burn, the attester pool is
    structurally under-sized by the transfer-share each block,
    the deflation-floor rebate fires later/lower than intended,
    and the archive-reward redirect undercounts.  CLAUDE.md
    anchor: "auto-fee defaults adjust to fit this model -- don't
    leave a tx kind defaulting to a stale flat fee while others
    auto-bid by density."  The unified-fee intent is fee-flow
    uniformity, not just floor uniformity.

    Tier 57 splits the apply path on a height gate.  Pre-fork
    (height < ``TRANSFER_FEE_UNIFIED_HEIGHT``) the legacy
    hand-rolled accounting runs unchanged -- BYTE-IDENTICAL to
    pre-Tier-57 code, so every historical transfer block replays
    identically post-upgrade.  Post-fork the ``(tx.fee -
    surcharge)`` base-fee+tip portion routes through
    ``pay_fee_with_burn``; the helper handles attester-share /
    rolling_fee_burn / fee_burn_this_block / total_fees_collected
    for the base-fee portion uniformly with every other tx kind.
    The ``NEW_ACCOUNT_FEE`` surcharge is a flat state-creation
    tariff; it burns separately (sender debit, total_supply down,
    total_burned up, fee_burn_this_block up, total_fees_collected
    up) so the archive-reward redirect sees the full
    transfer-share burn.

    User-facing invariants preserved at the activation boundary:
    sender total debit, recipient credit, and proposer tip are
    byte-identical between pre- and post-fork apply on the same
    tx.  The only divergence is the *split* between burn and
    attester-pool growth -- exactly the fix's intent.

    Activation height 2100 sits 50 blocks above Tier 56
    (``TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT = 2050``) -- ~8.3h
    cohort spacing at 600s blocks, matching the Tier 49-56
    spacing pattern.  Two-validator coordinated upgrade.  7 new
    regression tests in
    ``tests/test_audit_r31_transfer_fee_unified_tier57.py`` pin
    activation constant ordering, source shape, pre-fork legacy
    replay, post-fork accrual on all three mechanisms, and the
    user-facing invariant.  Surfaced by audit r31 top-3 #2.
    (4645b4c)

### Fixed

  * **Cross-pool WOTS+ leaf-reuse admission gap leaks
    one-time-key secret material.**  Pre-fix
    ``Server._check_leaf_across_all_pools`` scanned every
    server-side pool (``_pending_{stake,unstake,authority,
    governance}_txs``) plus ``mempool.react_pool``, but NOT
    ``mempool.pending`` (which holds both messages and
    transfers).  The two RPC admission paths for messages
    (``_rpc_submit_transaction``) and transfers
    (``_rpc_submit_transfer``) both routed straight through
    ``submit_transaction_to_mempool`` without ever calling
    ``_check_leaf_across_all_pools`` themselves.

    Concrete bite: a message tx admits to ``mempool.pending`` at
    leaf=N.  A subsequent stake / unstake / authority /
    governance / react tx at leaf=N from the same signer calls
    ``_check_leaf_across_all_pools`` -- which scans server-side
    pools but NOT ``mempool.pending`` -- finds no collision,
    admits.  Both signed objects now carry the same WOTS+ leaf;
    the second signature publishes enough one-time-key preimages
    for any observer to forge an arbitrary signature at that
    leaf.  Block-level dedupe (``Blockchain.validate_block``)
    catches the in-block collision and rejects the proposer's
    block -- but the leaked secret is already on the gossip
    surface; the forged sig can be raced into a different
    proposer's mempool before the legitimate watermark advances.
    Twin-of-twin of the round-12 react_pool fix on the OTHER
    side of the cross-pool boundary.

    CLAUDE.md anchor: every signing path on this chain depends
    on WOTS+ one-time-key soundness.  An admission gate that
    lets two distinct payloads share a leaf is a forgery
    primitive -- exactly the kind of foundational-crypto
    regression the security principle (#1) forbids.

    Three pieces, all source-pinned:

      (1) ``_check_leaf_across_all_pools`` extended to scan
      ``mempool.pending`` in BOTH the signer-keyed (default) and
      entity-id-keyed (legacy call shape) branches.

      (2) ``_rpc_submit_transaction`` (message path) calls
      ``_check_leaf_across_all_pools(tx)`` before mempool
      admission.

      (3) ``_rpc_submit_transfer`` (transfer path) calls
      ``_check_leaf_across_all_pools(tx)`` before mempool
      admission.

    The gossip-receiver branches already called
    ``_check_leaf_across_all_pools`` and so pick up the fix
    automatically once the helper itself scans
    ``mempool.pending``.  Soft-fix: admission-side only, no
    consensus rule change at the block validator.  Block-level
    dedupe still catches anything that slips through admission,
    so this is purely a tightening of the admission gate.  No
    new tier, no new wire format.  4 new regression tests in
    ``tests/test_audit_r31_cross_pool_leaf_mempool.py``.
    Surfaced by audit r31 top-3 #1.  (44bbb66)

### Changed

  * **README §1 ("Generate a private key") now instructs users
    to back up the 24-word BIP-39 phrase, not the hex form.**
    Pre-fix the inline comment said ``# write the printed hex on
    paper, 2-3 copies``, but ``cmd_generate_key``'s actual
    output prints the 24-word phrase as the PRIMARY backup
    ("write these down IN ORDER", "the phrase will NOT be shown
    again") and labels hex only as "alternative."  Every new
    user followed the README in order, transcribed a 64-char
    hex string, and only learned later that the protocol-blessed
    backup is a different artifact.  The hex form is a valid
    backup but has NO typo-detection: a single typo on recovery
    silently produces a different key and loses access
    permanently.  The BIP-39 phrase has a built-in checksum
    that catches single-word transcription errors.

    Fix updates the §1 inline comment and adds a paragraph
    explaining the BIP-39 checksum advantage so a reader
    understands why the phrase is preferred over hex (without
    the why, a user who "just prefers" a shorter backup would
    still pick the hex form and lose error protection without
    realizing it).  Pure docs change -- no code, no consensus
    rule, no fork.  3 new content-pin tests in
    ``tests/test_audit_r31_readme_step1_phrase_first.py``.
    Surfaced by audit r31 top-3 #3.  (f0c0fb3)

## [1.61.1] — 2026-05-07

Patch release.  Hotfix for a 1.61.0 consensus-replay regression in
``Blockchain._apply_governance_block``: the Tier 56 implementation
split the apply-time voter-reward surcharge gate per-class so
``TreasurySpendTransaction`` was gated on Tier 56 separately from
``ProposalTransaction`` (Tier 22).  That changed pre-Tier-56
TreasurySpend behavior: a TreasurySpend with ``fee + SURCHARGE``
balance used to escrow ``VOTER_REWARD_SURCHARGE`` (legacy Tier 22)
but the split code escrowed 0 (Tier 56 not yet active).  Result:
state divergence between a 1.61.0 validator and a 1.60.0 validator
on any historical block carrying a well-funded TreasurySpend, hard-
wedging the upgraded validator on a divergent proposer schedule
(the on-disk chain.db was unrecoverable without a full restore from
peer).  No new tier, no new wire format, no new CLI surface.

### Fixed

  * **Tier 56 apply-path replay determinism** -- reverted the per-
    class apply gate.  Tier 56's intent is to tighten the ADMISSION
    rule (``_validate_governance_tx`` rejects fee-only TreasurySpend
    post-activation) while leaving the apply-time mutation
    byte-identical to the legacy single-flag behavior.  The new
    apply path uses one ``proposal_surcharge`` flag for both
    ProposalTransaction and TreasurySpend, gated solely on Tier 22
    (``VOTER_REWARD_HEIGHT``); pre-Tier-56 TreasurySpend continues
    to debit the surcharge if the proposer's balance allows
    (legacy), and post-Tier-56 the admission gate guarantees
    balance allows so the debit always succeeds.  Net effect post-
    Tier-56: voters always get paid -- exactly the audit r30 #3
    intent -- without breaking pre-fork replay.  New regression pin
    in ``tests/test_treasury_spend_voter_surcharge_tier56.py::
    TestPreForkApplyReplayDeterminism`` exercises the apply path at
    a pre-Tier-56 height with a well-funded TreasurySpend and
    asserts the surcharge IS debited and escrowed -- if a future
    change re-introduces a per-class apply gate, this test trips
    immediately.

## [1.61.0] — 2026-05-07

Minor release.  Audit round 30 top-3 ships: two new hard forks
(Tier 55 routes the inactivity & coverage leaks through the
honest-history relief multiplier so honest, long-tenured validators
on a partition or fork-emergency halt no longer get bled at the same
quadratic rate as a withholding cartel; Tier 56 makes
``VOTER_REWARD_SURCHARGE`` mandatory for ``TreasurySpendTransaction``
proposers so voters get paid on the most economically consequential
proposal class) and one CLI/UX fix (``messagechain unstake`` now
honors ``--cold-keyfile`` so cold-authority-hardened operators can
actually retire from the CLI -- previously every operator who
followed the recommended hardening recipe hit a hard chain rejection
when they tried to unstake).  No new wire format, no new top-line
CLI surface beyond the two ``unstake`` flags.

### Added

  * **Tier 55 -- inactivity & coverage leaks consult the honesty
    curve (hard fork, activation height 2000).**  Pre-fix
    ``compute_inactivity_penalty`` and ``compute_coverage_penalty``
    were pure functions of ``(blocks_since_finality,
    validator_stake)`` / ``(consecutive_misses, attester_stake)``.
    Neither consulted ``slashing_severity``, ``_track_record``, or
    ``_prior_offenses`` -- the entire Tier-23/24/51 honesty-curve
    machinery every other slashing path uses.  An honest, long-
    tenured validator on a partition or fork-emergency auto-halt
    was bled quadratically at the same rate as a withholding cartel,
    in direct violation of the CLAUDE.md "honest-operator insurance"
    anchor.

    Tier 55 routes both penalty paths through a new
    ``honest_history_relief_multiplier_bps`` helper that mirrors the
    AMBIGUOUS-path relief in ``slashing_severity``: same chain-state
    inputs (``proposer_sig_counts``, ``reputation``,
    ``slash_offense_counts``), same shape.  Returns 10000 bps (full
    nominal) for fresh validators or repeat offenders, capped at
    FLOOR_NUM/FLOOR_DEN = 1/5 = 2000 bps for long-tenured high-
    honesty operators.  Pure function, integer-only arithmetic,
    consensus-deterministic.  ``apply_inactivity_leak`` /
    ``apply_coverage_leak`` accept optional
    ``current_height``/``blockchain`` kwargs; pre-fork or legacy
    callers get byte-identical legacy bleed.

    Cartel-defense behavior is preserved: a withholding coalition
    is by definition NOT long-tenured-high-honesty (the curve reads
    *accepted* blocks + attestations, both of which a cartel can't
    forge without doing real honest work first).  Activation height
    2000 sits 50 blocks above Tier 54 (1950) -- ~8.3h cohort spacing
    matching the Tier 49-54 pattern.  Two-validator coordinated
    upgrade.  13 new regression tests in
    ``tests/test_inactivity_leak_honesty_curve_tier55.py``.
    Surfaced by audit r30 top-3 #2.  (793f152)

  * **Tier 56 -- TreasurySpend proposers pay
    ``VOTER_REWARD_SURCHARGE`` (hard fork, activation height 2050).**
    Pre-fix ``Blockchain._validate_governance_tx`` required ``fee +
    VOTER_REWARD_SURCHARGE`` for ``ProposalTransaction`` only; the
    ``TreasurySpendTransaction`` branch fell through with
    ``required = fee``.  The apply path tried to debit the surcharge
    for both classes, but without a corresponding validation gate a
    treasury-spend proposer with exactly ``fee`` balance silently
    escrowed ``voter_reward_pool=0`` -- voters did the work of
    evaluating the proposal and got paid nothing.  Treasury spends
    are arguably the *most* economically consequential governance
    class, and they were the only one whose voters didn't get paid
    -- a 50k-token subsidy to treasury-spend proposers paid in
    voter time.

    Tier 56 extends the surcharge requirement to
    ``TreasurySpendTransaction`` symmetrically: validation rejects
    fee-only TreasurySpend admission post-activation; the apply
    path debits the full surcharge into ``voter_reward_pool`` so the
    existing ``finalize_voter_rewards`` distributes voter rewards
    identically to advisory-proposal voters.  Per-class height gates
    (Tier 22 ``VOTER_REWARD_HEIGHT`` for ProposalTransaction, Tier
    56 ``TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT`` for TreasurySpend)
    keep pre-fork TreasurySpend blocks byte-identical.  Activation
    height 2050 sits 50 blocks above Tier 55 (2000), matching the
    Tier 49-55 cohort spacing pattern.  5 new regression tests in
    ``tests/test_treasury_spend_voter_surcharge_tier56.py``.
    Surfaced by audit r30 top-3 #3.  (44855f6)

### Fixed

  * **``messagechain unstake`` silently signed with the hot key on
    every cold-authority-hardened operator -- the recommended
    hardening recipe broke the documented retirement path.**
    Pre-fix ``cmd_unstake`` unconditionally signed the
    ``UnstakeTransaction`` with ``_resolve_signing_entity(...)
    .keypair`` (the hot key); the chain admission rule at
    ``Blockchain._validate_unstake_tx_in_block`` hard-rejected with
    "Unstake must be signed by the authority (cold) key.  The hot
    signing key cannot authorize withdrawal."  Funds weren't lost
    (the operator could build a cold-signed tx by hand) but the
    documented retirement path -- the README's own ``messagechain
    unstake`` instruction -- was broken on the documented hardened
    setup.  CLAUDE.md anchor at risk: Principle #3 (Simplicity) +
    token-as-tradable-asset quality bar.  Mainnet-reachable today
    on the happy path: any operator who hardened and now wants to
    retire hit this disaster path.

    Two pieces, both wired:

      (1) ``create_unstake_transaction`` accepts an optional
      ``signing_keypair`` parameter.  When provided, the tx still
      carries the validator's entity_id (so the chain debits the
      right validator) but the signature is produced by
      ``signing_keypair`` instead of ``entity.keypair``.  Default
      None preserves the legacy hot-key signing path byte-for-byte
      for entities that have not promoted a cold authority key.

      (2) ``cmd_unstake`` adds ``--cold-keyfile`` and ``--cold-leaf``
      flags (mirroring the existing pattern in
      ``set-receipt-subtree-root`` / ``set-authority-key
      --cold-key-path``).  Pre-flight: probe ``get_authority_key``
      for the entity.  If the on-chain authority pubkey !=
      ``entity.public_key`` (cold authority installed), require
      ``--cold-keyfile``, load it as Entity, verify its public_key
      matches the on-chain authority pubkey, and pass
      ``signing_keypair=cold_entity.keypair`` through to
      ``create_unstake_transaction``.  Refusing pre-broadcast saves
      the operator the multi-minute hot-key Merkle keygen + RPC
      round-trip a chain-rejected tx would otherwise cost.

    Soft-fix; no consensus-rule change, no fork.  5 new tests in
    ``tests/test_cli_unstake_cold_keyfile.py`` covering the helper
    API, signature round-trip, chain admission with cold authority
    installed, and the CLI behavior under both the gate and the
    happy path.  Surfaced by audit r30 top-3 #1.  (7ae7481)

## [1.60.0] — 2026-05-06

Minor release.  Audit round 29 top-3 ships: one new hard fork
(Tier 54 -- dormancy controller K_DEN retune so the linear band
reaches MAX at gap = 100M instead of 10M, preventing the scheduled
seed-divestment burn from pegging the controller at ~26%/yr
sustained inflation), one infrastructure fix (HMAC-SHA256 envelope
on persisted state-snapshot blobs so ``pickle.loads`` is unreachable
on a tampered DB / restored backup), and one consensus-resilience
fix (``FinalityCheckpoints._vote_by_signer_height`` now persisted
to chaindb so a validator cannot evade local equivocation detection
by timing a second conflicting finality vote to a network-wide
restart window).  No new wire format, no new CLI surface.

### Added

  * **Tier 54 -- dormancy controller K_DEN retune (hard fork,
    activation height 1950).**  Pre-Tier-54 the controller's gain
    (K = 1 / 20_000) saturated the
    ``DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500`` ceiling at gap = 10M
    tokens.  Combined with the scheduled seed-divestment burn (~85M
    of founder stake, 4 yr), mid-divestment gaps land in the 10–80M
    range -- every one of which would peg the controller at MAX =
    500/block ≈ 26.3M tokens/yr ≈ 26%/yr of TARGET sustained for
    years until active supply recovers above 90M.  That regime
    inverts two CLAUDE.md anchors at once: "the chain's nominal
    token unit must hold its real economic weight across centuries"
    (a 26%/yr regime for years inverts the promise) and "issuance's
    purpose is supply replenishment, not security-funding" (at MAX
    the controller dwarfs every other economic lever).

    Tier 54 widens K_DEN to 200_000 so the linear band reaches MAX
    only at gap = 100M (the founder-fully-dormant catastrophic
    case).  At gap = 10M, raw = 50/block ≈ 2.6M tokens/yr -- order
    of the documented burn rate, no saturation.  At gap = 45M
    (plausible mid-divestment), raw = 225/block ≈ 11.8M tokens/yr
    -- proportional to documented burn.  At gap = 100M, raw still
    pegs at MAX, preserving worst-case crisis response capacity.

    Pure parameter retune; no consensus-shape change.  Pre-fork
    blocks (heights 1710..1949) replay byte-identically via the
    in-function height-gate -- the legacy K_DEN is preserved on
    the pre-fork branch.  Tier 54 sits 50 blocks ≈ 8.3h above
    Tier 53 (1900), matching the cohort spacing pattern Tiers
    49-53 used.  Two-validator coordinated upgrade.  16 new
    regression tests in
    ``tests/test_dormancy_controller_k_den_retune_tier54.py`` pin
    pre/post-activation behavior, the activation boundary, and the
    anchor-preservation properties (at-target zero, monotone-in-gap,
    MAX binding at catastrophic gap).  Surfaced by audit r29 top-3
    #2.  (1af0187)

### Fixed

  * **``pickle.loads`` on persisted state-snapshot blobs is a
    local-RCE primitive on tampered DB / restored backup.**  Three
    ``pickle.loads`` call sites in ``core/blockchain.py`` (cold-boot
    rehydrate, reorg ancestor restore, fork-emergency rewind) ran
    on whatever bytes lived in ``chain.db.state_snapshots`` -- a
    tampered backup tape, a substituted row, a cross-node copy --
    giving anyone with DB-write access local RCE at validator-process
    privilege before any signature or state-root check fired.
    CLAUDE.md "honest-operators-insurance" + "full-node accessibility
    for centuries" both threatened: restore-from-backup was a silent
    compromise vector.

    Fix wraps every persisted snapshot blob in an HMAC-SHA256
    envelope keyed by a per-node secret stored in chaindb.meta.  On
    read, the envelope is verified in constant time before
    ``pickle.loads`` is ever called; mismatch raises
    ``SnapshotEnvelopeError`` and the caller's existing
    ``try/except`` falls through to the legacy field-by-field load.
    Threat surface: an attacker who can write the snapshot row
    alone (backup-restore, filesystem permissions error, hostile
    disk image) can no longer reach ``pickle.loads``.  An attacker
    with full chaindb write access including ``meta`` is outside
    scope -- they could tamper balances directly.  Source-level
    pin in
    ``tests/test_snapshot_envelope_blockchain_integration.py``
    asserts exactly one ``pickle.loads`` call in
    ``blockchain.py`` (inside ``_decode_snapshot_blob``) so a
    future refactor cannot drift back to raw ``pickle.loads`` on
    a chaindb row.  Surfaced by audit r29 top-3 #1.  (1649bca)

  * **``FinalityCheckpoints._vote_by_signer_height`` was in-memory
    only -- restart-window finality equivocation evaded local
    auto-slash.**  Pre-fix attacker scenario: validator V signs
    FinalityVote A for (target H, hash H1), the local node restarts
    (release roll, OS update, validator reboot), V signs
    FinalityVote B for (target H, hash H2 ≠ H1).  Local detection
    has nothing to compare against because the restart flushed the
    map, so the second vote registers as a fresh observation.  In
    a network-wide restart window every node loses its local
    evidence simultaneously -- auto-slash deterrent against
    finality-vote collusion silently amnestied.  Honest peers that
    saw both votes during the staging window still detect, but a
    deliberate attacker times disclosure across the restart window
    to collapse cross-node evidence too.  CLAUDE.md anchor at risk:
    the "raise the evidentiary cost of suppression" frame depends
    on the slashing-evidence backbone surviving operationally
    normal events like a coordinated upgrade.

    Fix mirrors the ``EquivocationWatcher.seen_signatures`` pattern.
    New ``finality_votes_seen`` chaindb table keyed by (signer_id,
    target_block_number); ``add_vote`` consults the persisted row
    when the in-memory cache misses (cold cache after restart) and
    persists each fresh observation as it lands.
    ``rehydrate_from_chaindb`` is called from ``_load_from_db`` to
    warm the cache on cold-restart so the gate fires on the first
    post-restart conflicting observation even when the original was
    made before the restart.  Persistence is opt-in via constructor
    / ``bind_chaindb`` so legacy in-memory tests retain pre-fix
    behavior unchanged (the persistent path is additive, not a
    replacement).  Persistence failures (disk full, sqlite locked)
    do not block consensus -- the in-memory cache still records the
    vote so same-process equivocation still detects; only
    across-restart evidence is at risk.  9 regression tests in
    ``tests/test_finality_vote_persistence_r29.py`` pin the
    round-trip, the restart-window detection, the legacy fallback,
    and the persistence-failure isolation.  Surfaced by audit r29
    top-3 #3.  (55c7543)

## [1.59.0] — 2026-05-06

Minor release.  Audit round 28 top-3 ships: one new hard fork
(Tier 53 -- proposer-cap clawback redistributes instead of burning,
restoring ~50% of every dormancy-controller refill that was being
incinerated on today's 2-validator mainnet) and two consensus-
adjacent bugfixes (rotate-key hot-swap + boot-replay closes the
validator-bricking time-bomb on the auto-rotate timer; censorship-
evidence RPC admit-height drops the wait-gate bypass that let a
single attacker grief the slashing pipeline).

### Added

  * **Tier 53 -- proposer-cap clawback redistributes (was burn).
    Hard fork at height 1900 (~50 blocks above Tier 51 = 8.3h cohort
    spacing).**  CLAUDE.md anchor: stake-concentration soft cap is
    *compression of share* via diminishing returns, NOT punitive
    burn of validator earnings.  ``SupplyTracker.mint_block_reward``
    enforces a per-block cap on the proposer's combined earnings
    (proposer share + their attester slot if they're on the
    committee) at ``PROPOSER_REWARD_NUMERATOR / DENOMINATOR`` of
    issuance.  Pre-fork, when the cap bound the trim was BURNED.
    Post-Tier-21 (the halving-aware cap formula) ``effective_cap ==
    proposer_share`` exactly, so the trim equals the proposer's
    full attester slot every time the cap binds.

    Live impact today: post-Tier-47 (``DORMANCY_CONTROLLER_HEIGHT
    = 1710``) the dormancy controller can mint up to
    ``MAX_ISSUANCE_PER_BLOCK = 500`` per block while the active-
    supply gap closes.  On the live 2-validator mainnet each
    validator both proposes and attests on the other's blocks --
    the cap binds every block, and the per-slot attester reward
    (~187 tokens at reward=500) burns instead of accruing.  Net
    effect: ~50% of every dormancy-controller refill incinerates
    back to ``total_burned`` instead of accruing to validators, so
    the controller's gap-closing function lands at 50% efficiency
    and the bootstrap-arc dilution toward broad democratization
    runs at half pace.  Annualized at ~52K blocks/yr that's
    ~9.7M tokens/yr that should have accrued to honest validators,
    burned instead.

    Tier 53 fix: when the cap binds and there is at least one
    non-proposer attester with positive credit, the trim is
    REDISTRIBUTED pro-rata among those attesters by their existing
    credit.  Anti-disproportionate-capture intent preserved
    (proposer net retention still tops out at ``effective_cap``);
    total issuance accrues to validators (anchor honored); dormancy
    controller's refill efficiency restored to ~100% on
    2-validator mainnet.  When no non-proposer attester has
    positive credit (sole-proposer-attester committee, or all
    others zeroed by the per-validator attester cap), the trim
    falls back to BURN -- preserves the cap's anti-
    disproportionate intent without inventing a tie-breaker on
    who "deserves" the trim.  Rounding remainder from pro-rata
    distribution (< len(others) tokens per block) burns to keep
    the net-inflation invariant tight.

    Pre-fork blocks replay byte-identically: the legacy "claw back
    proposer_att_reward in full and burn it" path is arithmetic-
    equal to the new "trim full proposer_att_reward and fall back
    to burn (no other-credit set)" path when ``overage ==
    proposer_att_reward`` (the post-Tier-21 typical case).

    Activation height 1900 sits above Tier 51
    (``HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT = 1850``) with ~50 blocks
    ≈ 8.3h cohort spacing at 600s blocks, matching the
    1750/1800/1850 spacing pattern Tiers 49-51 used.  Two-
    validator network, both operator-controlled.  Two-validator
    coordinated upgrade.  4 new tests in
    ``tests/test_proposer_cap_redistribute_tier53.py`` pin
    pre-fork legacy replay, post-fork 2-attester redistribute,
    post-fork 3-attester pro-rata, and sole-proposer-attester
    fallback-to-burn.  Surfaced by audit r28 top-3 #3.  (5915d6f)

### Fixed

  * **``rotate-key`` had no daemon hot-swap and no boot replay --
    every successful rotation stranded the running validator on
    the retired Merkle tree, every block it produced was rejected,
    and operator restart did NOT recover.**  After
    ``cmd_rotate_key`` submitted a ``KeyRotationTransaction`` and
    the chain applied it, the daemon's ``wallet_entity.keypair``
    was the original (rotation 0) tree; chain canonical pubkey was
    the rotated root.  Every subsequent block the daemon produced
    verified against the old root (chain rejected), downtime
    slashing accrued, and operator restart re-derived the original
    tree (``Entity.create`` reads the signing seed; ``rotation_
    number`` is chain-state, not seed-state) -- so the same code
    path kept reproducing the bug.

    This is the validator-bricking time-bomb on the auto-rotate
    timer: when the leaf-watermark crosses 95% the timer fires
    ``cmd_rotate_key`` unattended, the chain rotates, and the
    daemon silently cannot sign.  On 2-validator mainnet this is
    a chain-halt risk the moment either node first crosses 95%.
    CLAUDE.md anchor: "key-rotation is a first-class tx type
    whose result is 'same entity, new active key'" -- the result
    was, but only at the chain level, not at the daemon level.

    Two missing pieces, both wired:

      (1) Boot replay.  After ``_load_or_create_entity`` returns
      the base entity, the boot path now consults
      ``server.blockchain.key_rotation_counts.get(entity.entity_
      id, 0)`` and, if non-zero, calls ``_replay_chain_rotations``
      -- a new server helper that derives the rotated keypair via
      ``derive_rotated_keypair(base, rotation_number=count - 1)``
      and builds a new Entity preserving entity_id and _seed
      (anchor: identity continuity across rotation).

      (2) Hot-swap.  Blockchain now exposes
      ``register_post_key_rotation_callback(entity_id, callback)``
      and fires the callback (a) directly inside
      ``apply_key_rotation`` (no rollback risk on the RPC/test
      path) and (b) post-commit in ``_append_block``, walking
      ``block.authority_txs`` for ``KeyRotationTransaction`` and
      dispatching after ``self.db.commit_transaction()``
      succeeds.  Post-commit dispatch is what stops a state-root
      rejection on the same block from racing the daemon into a
      premature wallet-entity swap.  Best-effort: a raising
      callback is logged and swallowed.

    The server installs one callback per daemon at boot.  When
    fired, it re-derives the rotated keypair on-the-fly (no
    rotated-keypair cache yet -- the keygen cost is a one-time
    per-rotation hit) and calls ``server.set_wallet_entity`` with
    the rotated Entity.  The new tree's leaf cursor starts at 0
    by definition (chain resets it in ``apply_key_rotation``), so
    no leaf-advance dance is needed.  5 new tests in
    ``tests/test_key_rotation_hot_swap.py`` pin every layer.
    Surfaced by audit r28 top-3 #1.  (1f5f27c)

  * **``server.py:_rpc_submit_censorship_evidence`` admit dropped
    ``arrival_block_height``, defaulting to 0 -- bypassed the
    ``FORCED_INCLUSION_WAIT_BLOCKS`` source-side wait gate on
    every freshly-arrived ``CensorshipEvidenceTx`` the RPC
    accepted.**  ``self.mempool.add_censorship_evidence_tx(tx)``
    was called with no kwarg; mempool default-when-missing is 0
    (see ``Mempool.add_censorship_evidence_tx`` in
    ``messagechain/core/mempool.py``).  Source-side forced-
    inclusion gate then sees ``current_height - 0 >= FORCED_
    INCLUSION_WAIT_BLOCKS`` for the very NEXT block proposed --
    the wait gate was bypassed entirely.

    Concrete failure mode: an attacker bursts well-formed
    ``CensorshipEvidenceTx``s against the running node.  Each
    lands in the mempool with arrival=0; the next block must
    include them or face the censorship-vote slash.  Honest
    proposers either (a) burn block byte budget on adversarial
    evidence, or (b) defer them at slashing risk to themselves.
    A colluding watcher can race-flush competing evidence sets
    with no aging delay.  Mainnet-reachable today with zero
    adversarial setup -- the wallet's
    ``submit_censorship_evidence`` RPC is the canonical CLI path
    documented in the README.

    CLAUDE.md anchor: "a tx that is well-formed, pays at least
    the per-byte floor, and fits the byte budget cannot be
    suppressed by anything weaker than a full validator-set
    majority actively colluding."  The censorship-evidence
    pipeline is the slashing teeth that backs that anchor; an
    attacker that can flood the forced-inclusion path with no
    aging dilutes the gate's purpose to zero.

    Twin defect of the Tier 43 React-pool admit fix at
    ``messagechain/network/submission_server.py:901-902`` --
    same wiring, different surface, missed in that round
    because the evidence-pool admit lives outside the
    React/Message ingest paths.  Soft-fix: admit-side only, no
    consensus-rule change.  Two-validator coordinated upgrade.
    Test pin in
    ``tests/test_rpc_evidence_arrival_height.py`` drives the
    real ``Server._rpc_submit_censorship_evidence`` against a
    real Blockchain + Mempool and asserts
    ``mempool._evidence_arrival_heights[etx.tx_hash] ==
    chain.height`` at admit time -- a future refactor cannot
    drift the kwarg back off silently.  Surfaced by audit r28
    top-3 #2.  (8fdda6c)

## [1.58.6] — 2026-05-06

Patch release.  Audit round 27 top-3 ships, all bugfixes: one
censorship-resistance regression on the production attester runtime
(server.py wired the forced-inclusion oracle to the message-only
validator and silently excused every non-message forced-tx omission
on every mainnet validator -- exact twin of the audit r25 fix in
node.py, missed in the parallel codepath), one wallet-vs-consensus
drift on the new-account transfer floor (auto-fee quoted 1001
post-Tier-49 while the chain hard-codes 1100, breaking every CLI
new-recipient transfer), and one CLI UX cliff (read / proposals
truncated tx_hash / proposal_id below the 64-hex form react / vote /
receipt / submit-evidence all hard-require, blocking the read-and-
react / read-and-vote loop for any CLI-only user).  No new tier, no
new wire format, no new CLI surface.

### Fixed

  * **``server.py:_maybe_attest_accepted_block`` wired the forced-
    inclusion oracle to the message-only ``validate_transaction`` --
    every non-message forced tx kind silently excused on every
    mainnet validator.**  Twin of the audit r25 #1 fix in
    ``messagechain/network/node.py:1642-1644`` (1.58.3); the
    production validator runtime entered via
    ``cli.py:cmd_run_validator -> from server import Server`` was
    missed in that fix.  Pre-fix the ``_is_includable`` callback
    on the Server class called ``self.blockchain.validate_transaction(tx)``,
    which is hard-coded to ``MessageTransaction`` semantics (reads
    ``tx.message``, references ``self.public_keys[tx.entity_id]``
    under message-tx assumptions).  Every non-message forced tx --
    Transfer, Vote, Proposal, KeyRotation, SetAuthorityKey,
    CensorshipEvidence, NonResponseEvidence, Slash -- returned
    ``(False, ...)`` from the oracle or raised ``AttributeError ->
    False``, the gate triggered excuse #4 ("no longer includable"),
    and honest server-running validators silently still attested
    YES on the suppressing block.

    Concrete failure mode: a colluding proposer drops a forced
    governance Vote, Transfer, SetAuthorityKey, or
    CensorshipEvidence tx that has waited >=
    ``FORCED_INCLUSION_WAIT_BLOCKS`` and pays high fee-per-byte.
    Honest attesters (every mainnet validator) call
    ``_is_includable(forced_tx) -> validate_transaction(forced_tx)
    -> False``, excused.  Block passes the attester gate without
    slash.  CLAUDE.md anchor explicitly requires "a tx that is
    well-formed, pays at least the per-byte floor, and fits the
    byte budget cannot be suppressed by anything weaker than a
    full validator-set majority actively colluding."  Pre-fix the
    suppression took exactly one proposer, with no risk surface
    for any non-message tx kind -- including suppression of the
    very ``CensorshipEvidence`` tx that would have exposed the
    cabal.  Live on mainnet from Tier 43 activation through 1.58.5
    in the Server runtime path.

    Fix mirrors the r25 wiring in ``node.py:1642-1644`` byte-for-
    byte: swap ``self.blockchain.validate_transaction(tx)`` for
    ``self.blockchain.validate_forced_includable_tx(tx)``.  The
    dispatcher already lives on Blockchain (added 1.58.3) and
    routes per-kind via ``isinstance`` to the right validator
    (``validate_transaction`` for Message,
    ``validate_transfer_transaction`` for Transfer, etc.); kinds
    without a stateful re-validator return ``(True, ...)`` so an
    honest proposer is forced to either include the forced tx or
    face the censorship vote.  Soft-fix: attester-side validity
    oracle only, no consensus rule change at the block validator.
    No new tier, no new wire format.  Two-validator coordinated
    upgrade.  New source-level pin in
    ``tests/test_server_forced_inclusion_oracle_dispatch.py``
    twins the existing node.py pin -- a future refactor cannot
    drift back to the bug-shape silently on either codepath.
    Surfaced by audit r27 top-3 #1.  (a815e85)

  * **``auto_fee._transfer_floor`` underbids the chain by 99
    tokens on every post-Tier-49 transfer to a brand-new
    recipient -- silent rejection of the canonical "send tokens
    to a new address" CLI flow.**  The wallet helper computed
    ``_non_message_flat_floor(h) + NEW_ACCOUNT_FEE``, which post-
    Tier-49 (``UNIFIED_FEE_FLOOR_HEIGHT = 1750``) collapses to
    ``MARKET_FEE_FLOOR + NEW_ACCOUNT_FEE = 1 + 1000 = 1001``.
    The consensus rule, however, has no Tier 49 height gate on
    the new-account branch and remains a flat literal
    ``MIN_FEE + NEW_ACCOUNT_FEE = 100 + 1000 = 1100`` at both
    ``Blockchain.verify_transfer_transaction`` (admission-time)
    and ``_validate_transfer_in_block`` (block-validation-time).

    Result: every CLI/wallet ``messagechain transfer --to <new>``
    that reached the auto-fee path quoted 1001; the validator
    rejected with "Transfer to brand-new recipient requires
    fee >= 1100 ...; got 1001."  The first end-to-end "send
    tokens to a brand-new recipient" path documented in the
    README + the operator-bootstrap doc was broken on every
    mainnet node from the Tier 49 activation height (1750)
    onward.  CLAUDE.md anchors: "auto-fee defaults adjust to fit
    this model" + "token-as-tradable-asset quality bar -- wallet/
    transfer/balance code held to mainstream-asset standards."
    Pre-Tier-49 the wallet quote already happened to equal the
    consensus literal (because ``_non_message_flat_floor(pre_fork)
    == MIN_FEE``); the bug only bites post-Tier-49 when the
    unified floor and the legacy ``MIN_FEE`` diverge.

    Fix realigns the wallet quote with the consensus literal:
    ``_transfer_floor(recipient_is_new=True)`` now returns
    ``MIN_FEE + NEW_ACCOUNT_FEE`` directly.  No consensus rule
    change, no fork: only the wallet/CLI surface shifts.  The
    Tier 49 unification covers the *flat protocol baseline*
    across non-message tx kinds for the regular-recipient path;
    the ``NEW_ACCOUNT_FEE`` surcharge is a separate state-creation
    tariff layered on the legacy ``MIN_FEE`` and was never
    migrated.  Source-level pin in
    ``tests/test_auto_fee_transfer_new_account_floor.py`` asserts
    the chain source carries the literal ``MIN_FEE +
    NEW_ACCOUNT_FEE`` so a future migration of the consensus
    path to a unified Tier-N floor trips the pin and forces the
    wallet quote to update in lockstep.  The pre-existing
    ``tests/test_unified_fee_floor_tier49.py::test_transfer_new_account_surcharge_layers_on_top``
    pinned the buggy shape (``MARKET_FEE_FLOOR + NEW_ACCOUNT_FEE``);
    renamed to ``..._on_legacy_min_fee`` and updated to assert
    the corrected literal at both pre- and post-Tier-49 heights.
    Surfaced by audit r27 top-3 #2.  (aac599e)

  * **``messagechain read`` truncated ``tx_hash`` to 12 chars and
    ``messagechain proposals`` truncated ``proposal_id`` to 16,
    while ``react`` / ``vote`` / ``receipt`` / ``submit-evidence``
    all hard-require the full 64-hex form -- the canonical
    "browse the feed, react / vote on a message-or-proposal" CLI
    loop could not complete without round-tripping through the
    web feed.**  Every command that consumes one of these hashes
    rejected anything other than the full form: ``react --target
    <tx>`` rejects with "target must be exactly 64 hex chars" at
    ``cli.py:4881``; ``vote --proposal <id>`` calls
    ``parse_hex(..., expected_len=32)`` which raises on anything
    else; ``receipt <tx>`` and ``submit-evidence censorship
    --receipt <bundle>`` both expect the full hash to compose the
    bundle path.  Result: a CLI-only user (no browser, e.g.
    operating over ``gcloud compute ssh`` or in an offline-air-
    gapped sign workflow) could read the feed but could NOT
    compose the next command without leaving the CLI to look up
    the full hash on the web feed.  CLAUDE.md positioning anchor:
    "decentralized reddit/twitter core" framing -- a feed where
    you can read but cannot react / vote without leaving the CLI
    is not actually social.  Principle #3 (Simplicity).

    Fix preserves the truncated visual chip on the header line so
    human-scanning the feed still works (12 chars is enough to
    distinguish messages by eye), and adds a second indented line
    carrying the full 64-hex hash on its own line so triple-click
    + paste recovers the full form.  Same shape applied to
    ``cmd_proposals``.  The ``prev`` pointer line is widened to
    render the full prev hash inline (it was already on its own
    line, so no visual disruption).  No CLI flag, no new surface,
    no smart-defaults knob.  Pure output-format change; existing
    scripts that grep for the truncated-prefix substring continue
    to match (the full form is a superset of the prefix).  3 new
    tests in ``tests/test_cli_read_proposals_full_hash.py``
    asserting the full hash appears in the output of ``cmd_read``
    (tx_hash + prev pointer) and ``cmd_proposals`` (proposal_id).
    Surfaced by audit r27 top-3 #3.  (f3060f4)

## [1.58.5] — 2026-05-06

Patch release.  Audit round 26 top-3 ships: one censorship-resistance
fix on the attester-side forced-inclusion gate (validator-axis
alignment closes a single-proposer suppression path), one public-doc
correction (UTF-8 has been live since Tier 12 but four guides claimed
ASCII-only), and one cold-wallet UX fix (every first signing command
now shows a progress bar during one-time WOTS+ keygen instead of
looking frozen for minutes).  No new tier, no new wire format, no new
CLI surface.

### Fixed

  * **Forced-inclusion gate's `used_bytes` / `used_count` / per-entity
    tally walked all 9 kinds in `_BLOCK_TX_LIST_ATTRS`; the block
    validator's Tier-18 unified-budget cap only sums message + transfer
    + react bytes and per-entity-caps message-only.**  The Tier 34
    multi-list path summed every kind (stake / unstake / governance /
    authority / non-response-evidence / censorship-evidence) into the
    excuse tallies the gate uses to forgive a proposer's omission of a
    forced tx.  A colluding proposer could legitimately stuff their own
    governance / authority / evidence bytes into the block until the
    gate's `used_bytes` tripped excuse #1 (byte cap exhausted) or until
    `entity_counts[E]` tripped excuse #3 (per-entity cap reached) for
    target entity E — and the block remained fully valid because the
    validator's narrower axis stayed comfortably under cap.  CLAUDE.md
    anchor: "a tx that is well-formed, pays at least the per-byte
    floor, and fits the byte budget cannot be suppressed by anything
    weaker than a full validator-set majority actively colluding."
    Pre-fix the suppression took ONE proposer with no slashable trail.

    Fix introduces `_VALIDATOR_BUDGET_ATTRS` as the single source-of-
    truth for the validator-counted byte/count kinds (message +
    transfer + react).  The gate's `used_bytes` / `used_count` re-key
    onto this narrower walk; per-entity tally re-keys onto
    `block.transactions` (matching the validator's message-only cap);
    excuse #3 only fires when the forced tx is itself a message (the
    validator never per-entity-caps non-message kinds, so there is no
    validator-level cap an excuse could legitimately reflect).
    Inclusion-recognition continues to walk `_BLOCK_TX_LIST_ATTRS` so
    a forced tx in any kind-slot is still recognized as included.

    Soft-fix: attester-side check only, no consensus rule change at
    the block validator.  `check_forced_inclusion` is called only by
    attester vote paths (`should_attest_block` -> attestation), never
    by `validate_block` or `validate_censorship_evidence_tx`; past
    attester votes are already cast and the change does not perturb
    chain state determinism.  Two-validator coordinated upgrade.  Same
    soft-fix shape as the 1.58.1 byte-cap-axis fix and the 1.58.3
    includable-per-kind fix.  9 new tests in
    `tests/test_forced_inclusion_validator_axis_alignment.py` plus
    re-anchored Tier-34 per-entity-cap regression test.  Surfaced by
    audit r26 top-3 #1.  (ac8f7c5)

  * **Personal-wallet first signing commands had no progress UX —
    `messagechain send "hello"` after `generate-key` looked frozen
    for minutes during the one-time WOTS+ keygen.**  At the production
    tree height (20 leaves -> ~1M leaves), Entity.create takes
    multiple minutes; without feedback operators kill the process
    thinking it hung.  `cmd_generate_key` / `cmd_init` /
    `cmd_rotate_key` already installed `_make_progress_reporter` and
    showed a progress bar; ten other signing commands (`send` /
    `transfer` / `stake` / `unstake` / `react` / `propose` / `vote` /
    `submit-evidence` / `emergency-revoke` / `bootstrap-seed`) all
    routed through `_resolve_signing_entity` without it.  CLAUDE.md
    anchors: "newcomer E2E flow" + "smart-defaults coverage" +
    Principle #3 (Simplicity).

    Fix plumbs an optional `progress` callback through
    `load_or_create_personal_wallet_entity` ->
    `_load_or_create_at_height` -> `Entity.create`
    (`KeyPair.generate` already accepted `progress=` end-to-end).
    `_resolve_signing_entity` constructs the reporter eagerly and
    forwards it; on cache hit the callback is never invoked (keygen
    doesn't run) so warm signing commands stay silent.  Reporter is
    sized at `MERKLE_TREE_HEIGHT` to match the cache-miss fallback's
    upper bound, keeping ETA accurate for the worst case.  No fork,
    no consensus rule change, no wire-format change, no new CLI
    surface.  4 new tests in
    `tests/test_personal_wallet_progress_wiring.py` including a
    source-level pin that the reporter wiring stays in
    `_resolve_signing_entity`.  Surfaced by audit r26 top-3 #3.
    (e788547)

### Changed

  * **Four public guides corrected: messages have been UTF-8 since
    Tier 12 (height 705), not "1024 ASCII characters."**
    `guides/forum-primitives.md` (3 sites) and `guides/anti-bloat.md`
    (1 site) asserted "1024 ASCII characters" / "ASCII text only" as
    the message-cap rule.  Live rule is `MAX_MESSAGE_CHARS = 1024`
    UTF-8 bytes after the Tier 12 fork; plaintext is NFC-normalized
    UTF-8 in the Unicode L\*/M\*/N\*/P\*/Zs categories — every modern
    written language is admissible.  CLAUDE.md "Mission" names
    dissidents and AI-spam refugees as target users; both populations
    are heavily non-English-speaking, and a public guide claiming the
    chain is ASCII-only erases the target persona on first read.
    Same defect class as the 1.58.0 1k-floor fiction cleanup.

    `guides/stable-money.md` "When does this activate?" paragraph
    said the dormancy controller "activates at a future block height
    (Tier 47)" with the chain "running the legacy halving-based
    issuance schedule" until then.  Mainnet tip is 1709 with the
    controller activating at 1710 — the future-tense framing was
    about to become incorrect inside the next block.  Rewritten to
    evergreen present-tense: the controller is the anchored issuance
    model, pre-fork heights replay under the legacy schedule for
    determinism, post-fork the controller is the only minting path.

    Docs-only — no code, no consensus rule, no hard fork, no test
    changes.  Surfaced by audit r26 top-3 #2.  (8fcbf5b)

## [1.58.4] — 2026-05-06

Patch release / **mainnet recovery**.  Fixes a wedged-chain
incident: both validators stalled at height 1709 with
``ChainIntegrityError: Supply invariant broken at height 1709`` for
~3 hours.  Tier 52 = ``SUPPLY_RECONCILIATION_FIX_HEIGHT = 1709``,
activates inside the next block both validators apply post-upgrade.

### Fixed

  * **Mainnet wedged at block 1709 with broken scalar supply
    invariant -- both validators stalled, no progress for hours.**
    Diagnostic from the live chain.db: ``total_supply=59,512,707``
    matches ``sum(balances)+sum(staked)``, ``total_burned=33,039,471``,
    ``total_minted=47,161`` -> ``GENESIS+minted-burned=107,007,690``
    -> deficit exactly **47,494,983**.

    Root cause: ``Blockchain._apply_supply_reconciliation`` at the
    1.50.0 ``SUPPLY_RECONCILIATION_HEIGHT`` (= 1708) rebased
    ``total_supply`` to match the bucket-sum invariant
    (``check_supply_conservation``: balances + staked +
    pending_unstakes + treasury + scalar pools) but did NOT bump
    ``total_burned`` by the same delta -- so the SCALAR invariant
    ``total_supply == GENESIS_SUPPLY + total_minted - total_burned``
    was left broken by exactly the rebase delta (-47,494,983 on
    mainnet).

    The scalar invariant fires at the END of every
    ``_apply_block_state``.  At the activation block itself (1708)
    the check ran BEFORE the reconciliation -- the rebase is called
    from ``_append_block`` AFTER ``_apply_block_state`` returns --
    so it passed.  The very NEXT block (1709) tripped the check
    with ``ChainIntegrityError``, the apply rolled back, and the
    chain wedged.  Existing 1.50.0 reconciliation tests covered
    the BUCKET conservation invariant (which the rebase fixed) but
    did NOT cover the SCALAR invariant (which the rebase broke),
    so the bug shipped.

    Fix: a new one-shot at
    ``SUPPLY_RECONCILIATION_FIX_HEIGHT = 1709`` (Tier 52) that bumps
    ``total_burned`` by the gap (or ``total_minted`` if the gap is
    negative -- defensive, not expected on the realized mainnet
    trajectory) to restore the scalar invariant.  Runs at the START
    of ``_apply_block_state`` (alongside
    ``_apply_registration_grandfather``) so the rest of the apply
    path -- including the end-of-apply scalar check -- sees the
    corrected state.  Idempotent via
    ``supply_reconciliation_fix_applied``, snapshotted with the
    supply state for reorg safety (same contract as
    ``treasury_rebase_applied`` and
    ``supply_reconciliation_applied``).

    Why activate at 1709 specifically: that's the next block the
    live mainnet validators are repeatedly failing to apply.  Any
    LATER fix height would leave the chain wedged forever (it can't
    advance to a future fix height when 1709 keeps tripping).  Any
    EARLIER height would change past-block behavior for fresh-genesis
    replay -- a consensus divergence we cannot accept.  1709 is
    the unique correct activation height.

    Why bump ``total_burned`` and not rebase ``total_supply``: the
    bucket sums are the source of truth (every entity's balance is
    in chain.db, every mint/burn between the 1.50.0 reconciliation
    and this fix has updated balances correctly).  ``total_supply``
    matches the bucket sums.  The discrepancy is purely in
    ``total_burned`` not having been bumped at the rebase -- so
    bumping ``total_burned`` to the right value is the minimal
    correct repair, preserving both the scalar AND bucket invariants
    going forward.

    The buggy ``_apply_supply_reconciliation`` is left EXACTLY
    as-is so fresh-genesis replay through block 1708 produces the
    same on-chain state mainnet validators currently have at block
    1708.  Block 1709's fix at apply-start is what makes both code
    paths converge cleanly thereafter.

    Mainnet recovery (operational, see ops runbook):

      1. Both validators upgrade in place to 1.58.4.
      2. Operator-side reset of the same-height-sign-guard at 1709
         on each validator.  The persistent guard correctly refuses
         to re-sign at 1709 because each validator already broadcast
         a pre-fix block 1709 that no peer accepted; the guard
         doesn't know that the prior signing was a no-op from the
         chain's perspective.  The reset is the operator's
         affirmative statement "I am about to sign at this height
         again -- the prior block at this height never made it into
         any peer's chain."
      3. Slot timer fires for height 1709, the selected proposer
         signs a fresh block 1709 with the fix applied at
         apply-start; other validator applies it cleanly; chain
         advances.
      4. Subsequent blocks see the fix as a no-op via the
         idempotent flag.  Tier 47 dormancy controller activates
         at height 1710 as designed.

    The "double-sign at 1709" risk during recovery is theoretical:
    the pre-fix block 1709 signed by a validator before the wedge
    was broadcast but no peer ever applied it (every peer also
    tripped the scalar check); it does not exist in any peer's
    chain.  On a 2-validator chain with both nodes operated by the
    same person, no slashing actor exists.

    5 new test classes in ``tests/test_supply_reconciliation_fix.py``
    pin the fix: activation-height behavior, idempotency, bucket-
    invariant preservation, snapshot round-trip of the new flag,
    and validation of the activation-height constant itself.
    (cacc45d)

## [1.58.3] — 2026-05-06

Patch release.  Audit round 25 top-3 partial ships -- two bugfixes,
one structural finding (incremental ``compute_active_supply`` for
year-50/100 full-node-accessibility) deferred to a dedicated cycle
because the safe shape (running scalar maintained across 38+ balance/
staked/``bump_active`` mutation sites + bucketed taper-aging) exceeds
a single audit-cycle's risk budget.  Pre-fix the consensus rule
``compute_active_supply`` is height-pure -- any future O(1)
implementation that returns identical values is consensus-safe, so
the deferral does not foreclose the future fix.  No new tier, no
new wire format, no new CLI surface.

### Fixed

  * **Forced-inclusion ``_is_includable`` callback was hard-coded to
    the message-only ``validate_transaction``, silently disabling the
    Tier 34 / Tier 43 multi-list censorship gate for every non-message
    forced tx kind.**  Tier 34/43 brought non-message tx kinds
    (Transfer, Vote, Proposal, SetAuthorityKey, KeyRotation,
    CensorshipEvidence, NonResponseEvidence, ...) under the attester-
    enforced forced-inclusion gate.  The gate uses an
    ``is_includable(tx)`` callback as the proposer-time validity
    oracle (excuse #4: "tx is no longer includable").  The production
    wiring on ``messagechain/network/node.py``'s
    ``_maybe_attest_accepted_block`` was

        def _is_includable(tx) -> bool:
            ok, _reason = self.blockchain.validate_transaction(tx)
            return ok

    ``Blockchain.validate_transaction`` is hard-coded to
    ``MessageTransaction`` semantics -- it reads ``tx.message``, calls
    the message-only ``verify_transaction``, and references
    ``self.public_keys[tx.entity_id]`` under message-tx assumptions.
    Every non-message forced tx therefore returned False (or raised
    ``AttributeError`` -> False), and the gate excused the omission as
    "no longer includable" -- silently re-opening the exact attack
    surface Tier 34/43 claimed to close.

    Concrete failure mode: a colluding proposer drops a forced
    governance Vote / Transfer / SetAuthorityKey / censorship-evidence
    tx that has waited >= ``FORCED_INCLUSION_WAIT_BLOCKS`` and is
    paying high fee-per-byte.  Honest attesters call
    ``_is_includable(forced_tx)`` -> ``validate_transaction(forced_tx)``
    -> False, excused.  Block passes the attester gate without slash.
    Live on mainnet since Tier 34 activation (height 1498); CLAUDE.md
    anchor explicitly requires "a tx that is well-formed, pays at
    least the per-byte floor, and fits the byte budget cannot be
    suppressed by anything weaker than a full validator-set majority
    actively colluding."  Pre-fix the suppression took exactly one
    proposer, with no risk surface for any non-message tx kind.

    Fix: add ``Blockchain.validate_forced_includable_tx(tx)`` as the
    single chokepoint.  Dispatches per-kind via ``isinstance`` to the
    right validator (``validate_transaction`` for Message,
    ``validate_transfer_transaction`` for Transfer,
    ``validate_key_rotation`` /
    ``validate_set_authority_key`` / ``validate_revoke`` /
    ``validate_set_receipt_subtree_root`` /
    ``validate_slash_transaction`` /
    ``validate_censorship_evidence_tx`` /
    ``validate_non_response_evidence_tx`` for the others).  Tx kinds
    without a stateful re-validator on Blockchain (Stake / Unstake /
    Governance / React) return ``(True, ...)`` -- the gate's purpose
    is to EXCUSE omissions where chain state moved on, not to
    authorize them.  Without a stateful check the conservative
    default is "still valid," which forces the proposer to either
    include the forced tx or face the censorship vote.  Same default
    for an unrecognized tx kind.

    Soft-fix: attester-side validity oracle only, no consensus rule
    change at the block validator.  No new tier, no new wire format.
    Two-validator coordinated upgrade.  Pre-fork heights replay
    byte-identically because the gate's input set was already empty
    for non-message kinds in the pre-Tier-43 single-pool path; post-
    Tier-43 the gate now consults the right per-kind validator for
    kinds that were already in scope but silently excused.  6 new
    regression tests in
    ``tests/test_forced_inclusion_includable_per_kind.py`` including a
    source-level pin that
    ``node.py:_maybe_attest_accepted_block`` wires its
    ``_is_includable`` through the new dispatcher (so the wrapping
    doesn't drift back to the bug-shape on the next refactor).
    Surfaced by audit r25 top-3 #1.  (050db6e)

  * **``Mempool.get_fee_estimate`` was missing the ``target_blocks``
    kwarg the auto-fee path passes -- urgency knob silently dead on
    every quote.**  The auto-fee path on the server side calls

        mempool.get_fee_estimate(
            message_bytes=quoting_bytes, target_blocks=target_blocks,
        )

    but ``Mempool.get_fee_estimate`` was declared as
    ``(self, message_bytes: int = 0)`` -- no ``target_blocks`` kwarg.
    The server wrapped the call in ``try/except TypeError`` and
    silently fell back to the median (50th percentile) on every quote.
    The urgency field was echoed in the result dict for display (so
    the CLI ``messagechain send --urgency high`` LOOKED like it
    bound) but never reached the bid: every "high" / "normal" / "low"
    quote returned the same number.

    Today's empty mempool hides the bug -- median \approx
    ``MARKET_FEE_FLOOR`` on a quiet chain, so all rungs collapse to
    the floor.  The moment real congestion arrives the regression
    bites: every "high"-urgency user silently underbids and stalls in
    the queue, and every "low"-urgency user overpays.  CLAUDE.md
    anchor: "Auto-fee defaults adjust to fit this model.  When the
    fee model shifts, every auto-fee path shifts with it -- don't
    leave a tx kind defaulting to a stale flat fee while others
    auto-bid by density."

    Fix: add ``target_blocks: int = 3`` (kw-only) to
    ``Mempool.get_fee_estimate`` and apply the same percentile ladder
    the ``FeeEstimator`` (recent-blocks path) uses, so a wallet
    picking the auto-fee urgency rung gets the same shape regardless
    of which estimator backs the quote:

        target_blocks=1   -> 90th percentile (high urgency)
        target_blocks=2-3 -> 75th percentile (normal, default)
        target_blocks=4-5 -> 60th percentile
        target_blocks=6-10-> 25th percentile
        target_blocks>=11 -> 10th percentile (low urgency)

    Default of 3 matches ``DEFAULT_URGENCY = "normal"`` in
    ``messagechain/economics/auto_fee.py``.  The server-side
    ``try/except TypeError`` fallback is no longer load-bearing -- the
    kwarg is now part of the signature.  Removing the fallback closes
    the silent regression and ensures any future signature drift
    surfaces as a real test/lint failure rather than re-disabling the
    urgency knob.

    No fork.  Wallet/CLI helper change only; consensus selection still
    ranks by fee/byte at apply time.  Two upstream tests that mocked
    ``Mempool.get_fee_estimate`` with bare
    ``lambda message_bytes=0: 1`` are updated to also accept the
    kw-only ``target_blocks`` (the lambda shape now matches the
    production signature).  4 new regression tests in
    ``tests/test_mempool_fee_estimate_target_blocks.py`` including a
    source-level pin that ``server.py`` both passes ``target_blocks``
    and no longer carries the dead ``except TypeError`` block around
    the estimator call.  Surfaced by audit r25 top-3 #3.  (46943ce)

## [1.58.2] — 2026-05-06

Patch release.  Audit round 24 top-3 ships, all bugfixes -- one
mainnet-imminent issuance-curve retune gated to land before Tier 47
activates (height 1710), one CLI security regression introduced by
1.58.1's keyfile auto-pickup that silently signed personal-wallet
commands with the validator hot-key on validator hosts, and one
PENDING-receipt UX that pointed users at a deprecated submit-evidence
stub instead of the live censorship-evidence form.  No new tier, no
new wire format, no new CLI surface.

### Fixed

  * **Tier 47 dormancy controller would peg at MAX-cap and ratchet
    founder concentration +7.8 pp once the Tier 47 fork activated.**
    1.58.1 correctly excluded ``TREASURY_ENTITY_ID`` from
    ``compute_active_supply`` -- but the controller's
    ``DORMANCY_TARGET_ACTIVE_SUPPLY`` constant was left at ``140M``
    (= ``GENESIS_SUPPLY`` = founder 100M + treasury 40M).  At
    activation (height 1710) the active-supply measure (treasury
    excluded) returns 100M, gap = ``140M - 100M = 40M``,
    ``raw_issuance = 40M / 20_000 = 2000`` tokens/block, clamped to
    ``DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500``.  The cap binds for
    ~60K blocks (~1.14 yr) until the founder's balance grows to
    ~130M, at which point convergence begins.  Net flow over the
    bind window: ~30M new tokens, ~99.99% of which accrue to the
    founder via the sole-proposer share + stake-pro-rata attester
    pool, ratcheting founder concentration 71.4% -> 79.2% -- the
    *opposite* direction the stake-concentration soft-cap and
    founder-handoff anchors want.  Pre-1.58.2 the constant was
    set to match ``GENESIS_SUPPLY`` so "the chain's active-supply
    economic constant aligns with its founding parameter"; that
    framing predates the 1.58.1 treasury-exclusion fix and stopped
    being correct the moment ``compute_active_supply`` skipped the
    treasury.

    Fix: retune ``DORMANCY_TARGET_ACTIVE_SUPPLY`` from ``140M`` to
    ``100M`` (= ``GENESIS_SUPPLY - TREASURY_ALLOCATION``).  The
    TARGET now equals the *active* portion of genesis supply, the
    same definition ``compute_active_supply`` uses.  At mainnet
    activation: active=100M=TARGET, gap=0, controller mints zero --
    and only mints as real dormancy or burns open the gap, exactly
    as the "stable active supply" anchor intends.  Pure constant
    retune, no consensus-shape change, no new tier; rides under
    the existing Tier 47 height -- pre-fork heights replay byte-
    identically because the controller is height-gated and Tier 47
    has not yet activated on mainnet at edit time (tip ~1640+ vs
    height 1710).  7 new regression tests in
    ``tests/test_dormancy_target_active_supply_retune.py``; the
    pre-existing ``test_founder_plus_treasury_at_target_still_yields_gap``
    asserted the now-broken "perma-mint" outcome and was renamed +
    updated to assert the new anchor.  Surfaced by audit r24 top-3
    #1.  (ce6786d)

  * **``_resolve_private_key`` auto-pickup silently signed personal-
    wallet CLI commands with the validator hot-key on validator hosts
    (regression introduced by 1.58.1).**  1.58.1 closed the
    ``sudo messagechain stake/unstake/rotate-key`` getpass cliff by
    auto-picking a keyfile from ``onboard.toml`` or
    ``default_keyfile()`` whenever no ``--keyfile`` was passed.  The
    fix is correct for validator-state ops -- but the auto-pickup
    chain applied to *every* signing command including ``send``,
    ``transfer``, ``react``, ``propose``, ``vote``.  Concrete failure
    modes on a validator host running as root:

      * ``sudo messagechain transfer --to mc1... --amount 50``
        silently drains validator balance and signs with the
        validator's identity -- fund-loss footgun on a fat-fingered
        shell line.
      * ``sudo messagechain send "hi"`` increments the validator's
        WOTS+ leaf cursor for personal messages, accelerating
        mandatory key-rotation.
      * The on-chain ``entity_id`` of every casual sudo-message is
        the validator's, not a personal wallet -- identity-attribution
        pollution.

    The single ``Using keyfile from default keyfile: ...`` print line
    was the only signal, and operators conditioned to skim daemon
    logs miss it.  Live on mainnet for the 1.58.1 release window.

    Fix gates auto-pickup on a kw-only ``personal_wallet=True``
    parameter.  When the auto-picked path matches the validator
    hot-key default (``/etc/messagechain/keyfile``), personal-wallet
    commands fall through to the interactive prompt instead of
    silently using the validator key, with one print line naming
    what we did.  Five HARD-GATE handlers opt in: ``cmd_send``,
    ``cmd_transfer``, ``cmd_react``, ``cmd_propose``, ``cmd_vote``.
    Validator-state ops (stake / unstake / rotate-key /
    set-authority-key / set-receipt-subtree-root / emergency-revoke
    / bootstrap-seed / broadcast-revoke) leave the flag at its
    default of False -- the 1.58.1 cliff-close still applies for
    them, exactly the persona it was for.  Explicit ``--keyfile``
    bypasses the gate (operator's stated intent wins).  7 new
    regression tests in
    ``tests/test_resolve_private_key_personal_wallet_gate.py``
    including a source-level pin that all five HARD-GATE handlers
    carry the ``personal_wallet=True`` call.  Surfaced by audit r24
    top-3 #2.  (338556c)

  * **``_print_pending_receipt`` named the deprecated
    ``submit-evidence --tx <hash>`` stub form -- silent failure of
    the headline censorship-resistance escalation path.**  The
    PENDING branch of ``messagechain receipt <tx_hash>`` printed
    ``messagechain submit-evidence --tx {tx_hash}``.  That form was
    deprecated in audit r7 (cli.py:5996-6008 already migrated the
    NOT_FOUND branch to the live form) -- running the deprecated
    form today prints a "use ``submit-evidence censorship --receipt
    <bundle.json>`` instead" diagnostic and exits 0 without filing
    anything on chain.  Every user hitting the exact moment
    censorship anxiety peaks (queued tx, suspected validator
    collusion) was handed a copy-paste command that pretended to
    succeed and never actually filed evidence -- silently hollowing
    out the chain's headline censorship-resistance differentiator
    for the most likely usage path.

    Fix mirrors the r7 NOT_FOUND fix exactly: same bundle-path
    construction (``_default_receipts_dir() + tx_hash + .json``)
    and same live-form invocation, so a user who copy-pastes the
    suggestion lands at the canonical evidence path ``cmd_send``
    writes on submit.  3 new regression tests in
    ``tests/test_pending_receipt_submit_evidence_form.py``:
    deprecated form must NOT appear, live form MUST appear with
    the canonical bundle path, status framing + "permanent and can
    never be deleted" guarantee preserved.  Surfaced by audit r24
    top-3 #3.  (9e73db8)

## [1.58.1] — 2026-05-06

Patch release.  Audit round 23 top-3 ships, all bugfixes -- one
mainnet-imminent issuance-cliff fix gated to land before Tier 47
activates (height 1710), one censorship-resistance unit-mismatch
that was silently disabling the Tier-34 forced-inclusion gate's
slash-evidence trail on every block, and one CLI smart-default that
closes the README's exact "Run a validator" walkthrough getting
stuck on a 24-word getpass under sudo.  No new tier, no new wire
format, no new CLI surface.

### Fixed

  * **Tier 47 dormancy controller would mint exactly 0 tokens/block
    at activation -- mainnet validators about to drop to fees-only
    income at floor era.**  ``compute_dormancy_issuance`` calls
    ``compute_active_supply`` and computes ``gap = TARGET - active``;
    pre-fix every active balance summed in, including the treasury's
    40M.  Mainnet allocates exactly 100M to the founder + 40M to
    ``TREASURY_ENTITY_ID`` = ``GENESIS_SUPPLY=140M`` =
    ``DORMANCY_TARGET_ACTIVE_SUPPLY``.  At Tier 47 activation
    (height 1710) the one-shot backfill in
    ``_apply_dormancy_active_bumps`` stamps every entity (founder
    AND treasury) active, ``compute_active_supply`` returned
    ``140M = TARGET``, ``gap = 0``, controller minted 0/block --
    and stayed at 0 for ~25 years (until the dormancy window
    expired) because the treasury's perpetual existence guarantees
    it never goes ``DORMANCY_WINDOW_BLOCKS`` without the existence
    of an entity.  At mainnet's pre-revenue scale (base_fee at
    ``MARKET_FEE_FLOOR=1`` on a quiet chain), this dropped
    validators from the legacy ``BLOCK_REWARD_FLOOR=4`` (~210K
    tokens/yr from issuance) to zero from issuance + zero from
    fees -- net negative operator P&L against any non-trivial
    hosting cost, and a shrinking validator set where the
    censorship-resistance anchor explicitly relies on having more.
    Tier 47 had not yet activated on mainnet (tip ~1640 vs height
    1710), so the constant-shape change was safe in place per the
    in-source comment at ``config.py:3185`` -- no historical
    block-replay output changes.

    Fix: skip ``TREASURY_ENTITY_ID`` in both the balances and
    staked loops of ``compute_active_supply``.  CLAUDE.md anchors
    active supply on holders whose
    "stake/attestation/proposal activity counts as active without
    a transfer" -- the treasury produces none of those signals;
    treating it as max-active forever was a definitional miss.
    After the fix, mainnet's 100M founder + 40M treasury becomes
    100M active, gap = 40M, controller mints proportionally
    (capped at ``DORMANCY_MAX_ISSUANCE_PER_BLOCK=500`` per block).
    The activation backfill at ``blockchain.py:11151-11168`` is
    left alone (it stamps every entity including treasury, but
    treasury's stamp is now ignored by ``compute_active_supply``;
    mirroring the unused stamp is harmless).  4 new tests in
    ``tests/test_dormancy_controller_tier47.py``.  Surfaced by
    audit r23 top-3 #1.  (12a217f)

  * **Forced-inclusion byte cap mismatched the byte axis it gates
    -- a single colluding proposer could suppress any high-fpb tx
    today.**  The Tier 34 multi-list path summed
    ``_stored_bytes_of(tx) = len(tx.to_bytes())`` (stored bytes,
    matching the mempool's fee-per-byte ranking axis) into
    ``used_bytes`` but compared the running total against
    ``MAX_BLOCK_MESSAGE_BYTES = 45_000`` -- the *payload* cap, the
    cap the block-level validator at
    ``blockchain.validate_block`` enforces against
    ``sum(len(tx.message))``.  A WOTS+ ``MessageTransaction``
    with a 9-byte payload serializes to ~2_300 stored bytes
    (~256x amplification, dominated by the WOTS+ signature +
    auth path).  ~20 such txs sum to ~46 KB stored -- over the 45
    KB cap reference -- while their payload sum is ~180 B, miles
    inside both the payload cap and the Tier 18 unified
    stored-byte cap (``MAX_BLOCK_TOTAL_BYTES = 200_000``).  A
    colluding proposer who fills the block with their own
    witness-heavy small-payload messages drives ``used_bytes``
    past 45 KB while the block remains fully valid at the
    validator level -- and the gate excused ANY forced tx as
    "byte budget exhausted".  CLAUDE.md anchors collective
    censorship resistance on the property that a tx paying at
    least the per-byte floor "cannot be suppressed by anything
    weaker than a full validator-set majority actively colluding"
    -- pre-fix the suppression took exactly one proposer, with
    no risk surface.  Tier 34 activated at height 1498; the bug
    has been live on mainnet since.

    Fix: when the multi-list (post-Tier-34) path is taken,
    compare the stored-byte running total against
    ``MAX_BLOCK_TOTAL_BYTES`` -- the unified Tier 18 cap that
    actually bounds stored bytes at the validator level.  The
    legacy pre-Tier-34 path is byte-identical (it sums
    ``len(tx.message)`` and is correctly bounded by
    ``MAX_BLOCK_MESSAGE_BYTES``).  A second regression test pins
    that excuse #1 still fires when stored bytes genuinely
    exhaust ``MAX_BLOCK_TOTAL_BYTES`` -- the fix tightens the
    rule, it does not delete it.  Soft-fix: attester-side check
    only, no consensus rule change at the block validator;
    two-validator coordinated upgrade.  2 new tests in
    ``tests/test_forced_inclusion_all_tx_kinds.py``.  Surfaced
    by audit r23 top-3 #2.  (a7f582f)

  * **``_resolve_private_key`` now auto-picks up a keyfile from
    ``onboard.toml`` (or ``default_keyfile()``) rather than
    re-prompting the 24-word phrase on every signing command.**
    Pre-fix every signing command (``send`` / ``transfer`` /
    ``stake`` / ``unstake`` / ``react`` / ``propose`` / ``vote``
    / ``rotate-key`` / ...) honoured ``args.keyfile`` and
    otherwise fell straight through to ``_collect_private_key``
    -- an interactive ``getpass`` for the 24-word recovery
    phrase.  README's literal "Run a validator" walkthrough
    (``sudo -u messagechain messagechain stake --amount 200``)
    therefore prompted for a phrase under ``sudo`` (env stripped)
    over piped stdin (gcloud compute ssh + sudo) -- a fragile
    path that operators routinely abandoned, or worse, that
    leaked the phrase into shell history when typed at a
    non-TTY-isolated prompt.  Twin in shape with the 1.57.3
    signing-cmd ``data_dir`` auto-fallback (commit 27853bf):
    same defect class (smart-default-coverage gap on the same
    set of signing commands), opposite axis.  Anchored in
    CLAUDE.md "Smart-defaults coverage" (Principle #3,
    Simplicity) and "Honest operators are insured against
    accidents."

    Fix in ``_resolve_private_key``.  Resolution order: (1)
    ``args.keyfile`` (explicit ``--keyfile``, always wins), (2)
    ``onboard.toml.keyfile`` if the file exists, (3)
    ``default_keyfile()`` (``/etc/messagechain/keyfile`` for
    root, ``~/.messagechain/keyfile`` for user) if THAT file
    exists, (4) interactive prompt -- unchanged for personal-
    wallet users who haven't opted into a keyfile.  When
    auto-pickup fires, prints one line naming the source so the
    operator sees where the secret came from.  Auto-picked path
    that fails to load (stale onboard.toml entry pointing at a
    moved file) degrades silently to the prompt; explicit
    ``--keyfile`` that fails to load still hard-errors as
    before.  raw-hex format detection from ``data_dir``-set is
    preserved (validator keyfiles are written in raw 64-hex by
    the daemon).  6 new tests in
    ``tests/test_signing_cmd_keyfile_fallback.py``.  Surfaced
    by audit r23 top-3 #3.  (06ebde4)

## [1.58.0] — 2026-05-06

Minor release.  Audit round 22 top-3 ships: Tier 51 (AMBIGUOUS slash
severity cap, hard fork at height 1850) + the 9th of the recurring
chaindb mirror-leak class (four sibling tables in one batch) + a
guides correction on the headline anti-spam pitch.

### Added

  * **Tier 51 -- AMBIGUOUS slash severity cap (hard fork, activation
    height 1850).**  Pre-Tier-51 the AMBIGUOUS path produced
    escalation-driven severity ``sev = base × (1 + REPEAT_MULTIPLIER
    × prior) × relief`` with ``BASE=5``, ``REPEAT_MULTIPLIER=2``, and
    a relief floor of 1/5.  On a long-tenured operator at
    ``track=200``, ``prior=5`` lands at ``5 × 11 × 0.5 = 27%``; at
    ``prior=10`` -> ``52%``; at very high tenure the relief floor
    pins at 0.2 so a ``prior=20`` veteran still gets ``5 × 41 ×
    0.2 = 41%``.  21--52% on AMBIGUOUS (restart-shape) evidence does
    NOT pass the CLAUDE.md "Honest operators are insured against
    accidents" anchor's "small fraction of stake, not a wipe" bar --
    the math turns the anchor inside out for exactly the long-
    tenured / high-volume class it's named to protect.  Tier 51
    clamps the AMBIGUOUS-path output to
    ``HONESTY_CURVE_AMBIGUOUS_MAX_PCT = 10`` (2× SOFT_SLASH_PCT,
    firmly in "small fraction" territory while still producing a
    real deterrent against repeat hiccups -- 5 events compound to
    ~40% lost over time).  Cap binds AFTER escalation + relief but
    BEFORE the global [MIN_PCT, 100] clamp.  UNAMBIGUOUS path is
    unchanged -- the deliberate-Byzantine bar (50%+ first / 100%
    repeat) still applies, because the anchor explicitly carves out
    "Catastrophic slashes are reserved for unambiguous, intentional
    protocol violations."  Pre-fork heights replay byte-identically
    because every historical AMBIGUOUS slash was applied uncapped --
    only post-fork high-prior + relief-erosion cases see the cap
    bind.  Activation height 1850 sits above Tier 50 (height 1800)
    with ~50 blocks ≈ 8.3h cohort spacing at 600s blocks; current
    tip ~1593+ gives ~257 blocks ≈ 43h of runway.  8 new regression
    tests in ``tests/test_honesty_curve_ambiguous_cap_tier51.py``.
    Surfaced by audit r22 top-3 #2.  (faaf9e8)

### Fixed

  * **Four more chaindb mirror tables leak orphan rows on the
    successful-reorg path (9th of recurring class).**
    ``proposer_sig_counts``, ``slash_offense_counts``,
    ``reputation``, and ``key_rotation_last_height`` all eagerly
    mirror to chaindb on write but the
    ``_persist_state(full_flush=True)`` post-replay path only does
    dirty-only INSERT-OR-REPLACE upserts -- losing-fork rows for
    entity_ids absent from canonical replay survive on disk.  Cold
    restart of any node that processed the losing fork rehydrates
    the orphans into consensus-deterministic state and silently
    forks vs. the warm cluster: ``proposer_sig_counts`` (attester-
    weight + slashing_severity good-history) -> divergent attester
    selection or slash severity; ``slash_offense_counts`` (repeat-
    offense escalation) -> divergent slash_pct -> state_root
    mismatch at the next slash; ``reputation`` (lottery winner +
    good-history) -> different lottery winner OR slash_pct;
    ``key_rotation_last_height`` (rotation cooldown gate) -> cold-
    restarted node rejects a valid KeyRotation tx warm peers
    accept (note: ``restore_state_snapshot`` already wipes this
    table on the FAILED-reorg rollback path; the SUCCESSFUL-reorg
    twin was open).  Same defect class as the eight prior mirror-
    leak fixes (round-2 ``entity_id_to_index``, round-4
    ``key_rotation_last_height`` save/restore, round-7
    ``receipt_subtree_roots``, round-12 ``reaction_choices``,
    round-13 successful-reorg twin, round-14 ``entity_last_active``
    for Tier-47, round-15 ``pending_censorship_evidence``,
    round-21 ``key_rotation_counts``).  Fix mirrors the established
    pattern exactly: four new ``clear_all_*`` chaindb helpers,
    each gated behind ``hasattr`` in ``_persist_state`` for legacy
    chain.db compat; full-flush calls ``clear_all_*`` BEFORE the
    upsert pass and re-emits the entire in-memory dict (not just
    dirty entries).  ``restore_state_snapshot`` (FAILED-reorg
    rollback) is unchanged -- all four tables already wired there
    in earlier rounds.  New
    ``tests/test_mirror_leaks_reorg_roundtrip_r22.py`` (8 tests).
    Surfaced by audit r22 top-3 #1.  (c720b36)

### Changed

  * **Guides corrected: the chain's flat per-tx admission floor is
    1 token, not 1,000.**  ``guides/fees.md``, ``guides/ai-spam.md``,
    ``guides/anti-bloat.md``, and ``guides/stable-money.md``
    asserted a "1,000-token flat per-tx admission floor" as the
    anchored anti-spam mechanism.  Live floor is
    ``MARKET_FEE_FLOOR = 1`` (Tier-16 for messages since height 623;
    Tier-49 unifying transfer/stake/unstake/react at the same value
    post-1750).  The 1,000 number is the LEGACY ``MIN_FEE_POST_FLAT``
    constant retired in favor of MARKET_FEE_FLOOR=1 -- it survives
    only as a config historical reference.  AI-spam-refugees are a
    named target persona (CLAUDE.md "Mission"); these guides build
    their mental model of the chain's spam economics, and a 1000×
    discrepancy on first verification collapses trust on the
    headline pitch.  The pitch itself is real: 1-token floor +
    EIP-1559 base fee + fee-per-byte ranking + per-block byte
    budget DOES deliver spam discipline at any meaningful token
    price.  Updated copy explains that composition rather than
    asserting a fictional flat number.  Surcharges that ARE 1,000
    tokens (NEW_ACCOUNT_FEE, KEY_ROTATION_FEE) remain correctly
    documented; added a missing "Key-rotation surcharge" row to the
    fees-summary table for completeness.  Docs-only -- no code,
    no consensus rule, no hard fork, no test changes.  Surfaced by
    audit r22 top-3 #3.  (03407eb)

## [1.57.3] — 2026-05-05

Patch release.  Audit round 21 top-2 ships -- one chaindb mirror
leak (8th of the recurring class) and one CLI smart-default that
closes a slashable WOTS+ leaf-reuse footgun on the README's exact
validator-bootstrap path.  No new tier, no new wire format, no
new CLI surface.

### Fixed

  * **`key_rotation_counts` chaindb mirror leak (silent consensus
    fork on cold restart).**  ``key_rotation_counts`` is the
    in-memory rotation-counter dict mirrored to disk for cold-boot
    rehydration and committed into the per-leaf state-root via
    ``state_tree.py`` (``rotation_count=...``).  Pre-fix three
    half-built parts (vs the seven prior mirror-leak fixes which
    all wired the full set):

      * ``save_state_snapshot`` did NOT carry
        ``key_rotation_counts``.
      * ``restore_state_snapshot`` did NOT wipe the table on
        rollback.
      * ``_persist_state`` was upsert-only with no orphan-cleanup
        pass on the successful-reorg path.

    Result: an entity X registering + rotating only on a fork that
    loses the reorg leaves an orphan row on disk after
    ``_reset_state`` clears the in-memory dict and canonical replay
    rebuilds it without X.  Cold restart of any node that processed
    the losing fork rehydrates the orphan via
    ``get_all_key_rotation_counts``, state_tree commits the phantom
    rotation_count into the per-leaf state-root, and the restarted
    node silently forks from the warm cluster at the next state-root
    commitment.

    Same defect class as the seven prior mirror-leak fixes (round-2
    ``entity_id_to_index``, round-4 ``key_rotation_last_height``,
    round-7 ``receipt_subtree_roots``, round-12
    ``reaction_choices``, round-13 successful-reorg twin, round-14
    ``entity_last_active`` for Tier-47, round-15
    ``pending_censorship_evidence``).

    Fix mirrors the established pattern exactly: new
    ``clear_all_key_rotation_counts`` chaindb helper;
    ``save_state_snapshot`` adds the field;
    ``restore_state_snapshot`` adds DELETE + re-INSERT inside the
    same SQL transaction; ``_persist_state`` calls
    ``clear_all_*`` on full flush before the upsert loop, gated on
    ``hasattr`` so legacy chain.db files (no helper) load cleanly.
    New ``tests/test_key_rotation_counts_reorg_roundtrip.py`` (4
    tests).  Surfaced by audit r21 top-3 #1.  (3264fe4)

  * **Manual signing-cmd ``data_dir`` falls back to ``onboard.toml``
    -- closes the slashable WOTS+ leaf-reuse footgun on the README's
    validator-bootstrap path.**  Same disaster slot the 1.57.0
    rotate-key-if-needed timer fix (commit c724327) closed for the
    daily timer, but for the manual signing path.  ``cmd_stake``,
    ``cmd_unstake``, ``cmd_rotate_key`` (and every other signing
    command listed in ``_bind_persistent_leaf_index``'s docstring)
    all read ``getattr(args, "data_dir", None)`` and pass it
    directly to the leaf-cursor binder.  An operator running the
    README's step 3 of "Run a validator"
    (``messagechain stake --amount 200`` with no ``--data-dir``)
    routed the leaf cursor to the per-user fallback
    ``~/.messagechain/leaves/<eid>.idx`` while the running validator
    daemon persisted to
    ``<onboard.data_dir>/leaf_index.json``.  Two cursors with no
    fsync handshake re-opens the cross-process WOTS+ leaf-reuse
    window: equivocation evidence on chain, 100% slash on detection
    pre-Tier-20 (geometric soft-slash post).  ``_reserve_leaf_via_rpc``
    is a best-effort fallback only and silently returns None on
    transient RPC errors and on older daemons.

    Fix in ``resolve_defaults``: for the explicitly-enumerated set
    of signing commands (the same set whose handlers route through
    ``_bind_persistent_leaf_index``), if ``args.data_dir`` is None
    and ``onboard.toml`` carries a ``data_dir``, fill it in.
    Explicit ``--data-dir`` still wins.  Personal-wallet path with
    no ``onboard.toml`` is unchanged (``read_onboard_config``
    returns empty dict, fallback is a no-op).  Set is enumerated
    rather than blanket-applied because the leaf-cursor risk is
    specific to commands that route through
    ``_bind_persistent_leaf_index``; non-signing commands that
    happen to expose ``--data-dir`` should not silently inherit the
    daemon's data_dir.  New
    ``tests/test_signing_cmd_data_dir_fallback.py`` (11 tests).
    Surfaced by audit r21 top-3 #3.  (27853bf)

## [1.57.2] — 2026-05-05

Patch release.  Audit round 20 top-2 ships, both consensus
wiring fixes that close real gaps in already-shipped slashing
infrastructure on the production runtime.  No new tier, no new
wire format, no new CLI surface.

### Fixed

  * **Production `Server` had no `ANNOUNCE_FINALITY_VOTE` gossip
    handler — the 1.57.0 + 1.57.1 finality-vote slasher / fork-
    emergency wiring was deaf on mainnet.**  `server.py:Server`
    dispatched every `MessageType.*` except `ANNOUNCE_FINALITY_VOTE`;
    the full handler shape (deserialize, verify, observe via
    `blockchain.observe_finality_vote`, pool via
    `mempool.add_finality_vote`, relay) lived only on
    `messagechain/network/node.py:Node`, which production code never
    instantiates.  `_try_produce_block_sync` also omitted the
    `finality_votes=` kwarg on its `propose_block` call, so even if
    pool-arrived votes existed they would never land in a proposed
    block.  Net consequence: `FinalityCheckpoints.add_vote` only
    fired on votes folded into already-applied blocks (never on free
    gossip), so a divergent supermajority could not be detected
    before honest validators had already extended the wrong tip; the
    `_pending_finality_slashes` accumulator that
    `_after_block_added` drains was empty by construction; and the
    fork-emergency detector's earliest signal arrived only after the
    block-apply tick.  Fix: port the dispatch case + handler + the
    `finality_votes=` propose-block kwarg + the post-add
    `mempool.remove_finality_votes` cleanup from Node into Server.
    Handler ordering mirrors Node — observe BEFORE pool insert so a
    duplicate-pool dedup return doesn't suppress emergency
    surfacing on never-observed signers.  Regression test in
    `tests/test_server_finality_vote_gossip_wiring.py` pins
    handler-exists, observe + pool, unknown-signer-rejection,
    message-router dispatch, and the propose-block drain wiring.
    (35bd64a)

  * **Equivocation watcher fed only on `add_block` success — block
    whose proposer signature verified but whose body failed any
    later validate-block check silently bypassed the watcher.**
    `EquivocationWatcher.observe_block_header` was called
    exclusively from `_after_block_added`, the post-success hook on
    `Blockchain.add_block`.  A block whose proposer signature
    verified but whose body failed any later check (state_root
    mismatch, randao mismatch, contained-tx signature failure, etc.)
    silently bypassed the watcher: `add_block` returned
    `(False, reason)` early, `_after_block_added` was not called,
    and the watcher's `seen_signatures` cache never recorded the
    header — even though the protocol had all the crypto needed to
    slash for the equivocation (the second header carried a valid
    proposer signature over different `signable_data` than the
    first).  Documented attack window: a colluding double-proposer
    signs two headers (A, B) at the same height, broadcasts A
    cleanly and B with a body crafted to fail a late validate-block
    check, and walks away unslashed because honest validators
    rejected B but never observed its header.  Fix: add a
    Blockchain-level observer hook
    (`register_block_header_observer` /
    `_notify_block_header_observer`) invoked from `validate_block`
    and `validate_block_standalone` immediately AFTER the proposer
    signature is verified and BEFORE downstream checks decide
    accept/reject.  Forged-signature blocks never reach the
    observer (the `verify_signature` gate above the hook returns
    False first), so the watcher's `seen_signatures` cache cannot
    be polluted.  `Server.__init__` and `Node.__init__` now register
    `self.equivocation_watcher.observe_block_header` as the
    observer, so the production runtime gets the pre-validation
    feed automatically.  The success-only feed in
    `_after_block_added` is left in place (idempotent on duplicate
    observation) — belt-and-braces against any path that bypasses
    the new hook.  Regression test in
    `tests/test_block_header_observer_pre_validation.py` pins the
    method exists + stores the callback + swallows observer
    exceptions, plus source-level pins on `validate_block`,
    `validate_block_standalone`, `Server.__init__`, and
    `Node.__init__` that catch future regressions in either
    direction (observer call deleted → success-only feed returns;
    observer call moved before sig-verify → watcher pollution
    attack returns).  (05977dd)

## [1.57.1] — 2026-05-05

Patch release.  Audit round 19 top-2 ships, both correctness fixes
to existing slashing infrastructure -- no new tier, no new wire
format, no new CLI surface.

### Fixed

  * **Wire the slashing + fork-emergency enforcement layer onto the
    production ``Server`` runtime (validator-collusion defense, mainnet
    impact).**  CLI launches the validator via ``from server import
    Server`` (``messagechain/cli.py:2345``), so the production mainnet
    runtime is ``server.py:Server`` -- and ``messagechain.network.node.
    Node`` is never instantiated by any production code path.  But the
    entire slashing-evidence + fork-emergency enforcement layer was
    wired only on ``Node``: ``EquivocationWatcher`` (block-header +
    attestation auto-slash) was instantiated only at
    ``messagechain/network/node.py:353``; the 1.57.0 FinalityVote-layer
    slasher emission edge fix (``_emit_pending_finality_slashes``)
    was wired only at ``node.py:562`` via ``_after_block_added``;
    ``_maybe_auto_recover_from_fork_emergency`` (1.57.0 standing-focus
    item "accidental-fork auto-recovery for full nodes") was defined
    only at ``node.py:1733``; and the fork-emergency halt gates were
    only at ``node.py:1613`` (attest) / ``:2315`` (propose), so
    ``server.py``'s ``should_propose`` chain never read
    ``is_in_emergency()``.  Net effect: production mainnet validators
    have been running WITHOUT the chain's primary anchored deterrent
    against validator collusion (the auto-slash backbone) since 1.55.0
    wired ``EquivocationWatcher``.  The 1.55.0 / 1.57.0 release notes
    described fixes that were no-ops on the live path.  CLAUDE.md
    anchors "collective censorship resistance via slashable-evidence
    trail" as the deterrent for validator collusion -- without
    auto-slash actually running, that anchor was unenforced in
    production.  Fix ports the four pieces from ``Node`` to
    ``Server``: (1) ``Server.__init__`` constructs an
    ``EquivocationWatcher`` when a chaindb is present; submitter
    starts as ``None`` (detect-only) and is upgraded in
    ``set_wallet_entity`` once a signing key is attached; (2) new
    ``Server._after_block_added(block)`` post-add hook runs the
    watcher's ``observe_block_header`` + ``prune``, drains
    ``blockchain._pending_finality_slashes`` into mempool slash txs,
    and attempts auto-recovery (full nodes only) -- each step
    try/excepted so one failure never aborts the others; (3) the hook
    is invoked at BOTH add_block-success sites
    (``_try_produce_block_sync`` and the ``ANNOUNCE_BLOCK`` gossip
    handler); (4) fork-emergency halt gates added to
    ``_try_produce_block_sync`` (after ``should_propose`` returns
    ok) and ``_maybe_attest_accepted_block`` (top of body); (5)
    ``_handle_announce_attestation`` feeds verified attestations into
    ``equivocation_watcher.observe_attestation`` after sig verification.
    New ``tests/test_server_slashing_recovery_wiring.py`` (10 tests).
    Surfaced by audit r19 top-3 #1.  (50d1453)

  * **Equivocation-watcher prune horizon must match slash-tx admission
    window (validator-collusion defense gap).**
    ``EquivocationWatcher.prune`` deleted ``seen_signatures`` rows at
    ``current_height - UNBONDING_PERIOD`` (~2176 blocks) but
    ``validate_slash_transaction`` accepts evidence up to
    ``max(UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS)`` blocks old
    (~12960 blocks).  A second conflicting signature gossiped in the
    [UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS] window therefore found
    the watcher's seen-signatures cache empty and was indexed as a
    fresh observation, not a slash trigger -- no auto-slash fired
    despite the chain still admitting evidence for the same offense.
    Adversary: validator collusion (the chain's primary anchored
    adversary).  A colluding subset can equivocate at height H,
    suppress one half from gossip until H+~2200, then release -- every
    honest watcher across the network is silenced identically by
    design.  The fix aligns the prune cutoff with the validation
    gate's ``evidence_ttl = max(UNBONDING_PERIOD,
    ATTESTER_ESCROW_BLOCKS)``.  Cache size grows from
    ~UNBONDING_PERIOD * gossip-rate to ~ATTESTER_ESCROW_BLOCKS *
    gossip-rate -- ~6x larger but still bounded and small (the
    ``seen_signatures`` table stores one row per signed slot, not
    per gossip echo).  Pairs with the wiring fix above -- without #1
    the watcher was dead code; without #2 the watcher would still
    be silenced for any delayed-disclosure equivocation in the
    [UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS] window.  Three new
    regression tests in
    ``tests/test_equivocation_watcher.py::TestRollingPrune``: an
    observation must survive past ``UNBONDING_PERIOD``; rows older
    than ``max(UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS)`` are pruned;
    end-to-end delayed-disclosure equivocation still produces a slash
    transaction.  Surfaced by audit r19 top-3 #2.  (c6f8175)

## [1.57.0] — 2026-05-05

Minor release.  Audit round 18 top-3 ships: a critical operator-side
slashing footgun fix on the daily rotate-key timer (cli leaf-cursor
mismatch with the daemon -- 100% slash on detection on the shipped
systemd unit), the missing emission edge of the FinalityVote-layer
equivocation slasher (detection was wired but the accumulator had
no reader, so equivocators escaped), and Tier 50 (inclusive voter
rewards, hard fork at height 1800) -- closes the "vote yes to get
paid" perverse-incentive that pre-Tier-22 governance carried.  Plus
the standalone fork-emergency auto-recovery wiring committed
post-1.56.0.

### Fixed

  * **`rotate-key-if-needed` timer must propagate `data_dir` to
    `cmd_rotate_key` (operator-honest-fairness, immediate impact).**
    The daily systemd timer (`messagechain-rotate-key.timer`) called
    `cmd_rotate_key_if_needed`, which synthesised an
    `argparse.Namespace(server, yes, fee, keyfile)` and handed it
    to `cmd_rotate_key`.  The synthesised namespace lacked
    `data_dir`, so `cmd_rotate_key`'s
    `getattr(args, "data_dir", None)` returned None and the
    leaf-cursor resolver routed the timer's WOTS+ cursor to the
    per-user fallback `~/.messagechain/leaves/<entity>.idx` while
    the validator daemon kept persisting to
    `<data_dir>/leaf_index.json`.  Two cursors with no fsync
    handshake re-opens the cross-process WOTS+ leaf-reuse window:
    `_reserve_leaf_via_rpc` was the only thing keeping the timer's
    signed rotate-tx from re-using a leaf the daemon already
    burned, and it silently returns None on transient RPC errors
    and on older daemons.  Leaf reuse is detected as equivocation
    under the same rule and slashes 100% of stake pre-Tier-20 /
    decays geometrically post -- exactly the disaster slot the
    README spends ~70 lines warning operators about, occurring on
    the shipped, recommended timer config.  Fix: pull `data_dir`
    (and existing `keyfile`) out of `read_onboard_config()` and
    include both in the synthesised `Namespace`.  Honest operators
    running the daily timer now sign through the same cursor file
    as the daemon.  Regression test in
    `tests/test_rotate_if_needed_data_dir_propagation.py` asserts
    the timer-side `Namespace` carries the cfg-derived `data_dir`
    and that the resolved leaf-cursor path equals the daemon's.
    (c724327)

  * **Drain `_pending_finality_slashes` into mempool slash
    transactions (validator-collusion defense gap).**
    `FinalityCheckpoints.add_vote` auto-detects double-finality-vote
    equivocation and surfaces it via
    `get_pending_slashing_evidence`; `_apply_block_state` appended
    that evidence into `self._pending_finality_slashes`.  But that
    write site was the **only** reference to the accumulator
    anywhere in the codebase (verified by grep: 3 hits, all the
    write site at blockchain.py:8291-8293).  Detection was wired
    -- emission was not.  Equivocators at the FinalityVote layer
    therefore escaped slashing despite the chain being fully able
    to verify and apply `FinalityDoubleVoteEvidence`-bearing
    `SlashTransaction`s.  `EquivocationWatcher` already handled
    the same shape for the block-header and attestation layers;
    this change closes the symmetric gap for the FinalityVote
    layer: new `Blockchain.drain_pending_finality_slashes()`
    returns and clears the accumulator (filtering already-
    on-chain evidence via `_processed_evidence`), new
    `messagechain.network.node._emit_pending_finality_slashes()`
    wraps each drained evidence in a `SlashTransaction` signed by
    the local entity at `base_fee` and pushes into the mempool slash
    pool, and `Node._after_block_added` wires the helper into the
    same post-block hook the notify-on-proposal flow uses.  Detect-
    only nodes (no submitter `entity`) re-stash the survivors so a
    future call with a real submitter can emit them.  5 new
    regression tests in
    `tests/test_pending_finality_slashes_drain.py`.  (dc6aadf)

### Added

  * **Tier 50 -- inclusive voter rewards (hard fork, activation
    height 1800).**  Pre-Tier-50 (Tier 22, `VOTER_REWARD_HEIGHT`)
    violated the governance anchor in CLAUDE.md ("voters who cast
    a vote during the window receive a reward funded out of the
    proposal fee") in two compounding ways: (1) NO-voters never
    earned anything, even on a passing proposal -- the winners
    filter excluded `if not approve: continue`; (2) rejected
    proposals burned the entire pool wholesale.  Net effect: a
    stake-weighted voter has a measurable pay incentive to vote
    YES regardless of merit (50_000-token surcharge × yes-only
    distribution × full-burn-on-reject), corrupting the very
    signal governance is supposed to produce -- and biasing the
    founder-to-community handoff in the wrong direction during
    the bootstrap window where this hurts most.  Tier 50 closes
    both gaps: at and above `VOTER_REWARD_INCLUSIVE_HEIGHT`,
    `finalize_voter_rewards` distributes the per-proposal voter-
    reward escrow pro-rata across ALL voters (yes OR no) by live
    stake at close, regardless of pass/fail.  The proposer paid
    for honest deliberation, not specifically for approval.
    Pre-fork proposals (closed at `current_block <
    VOTER_REWARD_INCLUSIVE_HEIGHT`) preserve byte-identical
    legacy Tier-22 behavior so historical replay is unchanged.
    Activation height 1800 sits above Tier 49
    (`UNIFIED_FEE_FLOOR_HEIGHT = 1750`) with ~50 blocks ≈ 8.3h
    cohort spacing at 600s blocks; current tip ~1593 gives ~207
    blocks ≈ 35 hours of runway.  Two-validator network, both
    operator-controlled, so the cutover is coordinated and the
    runway bound is operational rather than the multi-week
    external-validator notice the band was originally sized for.
    8 new regression tests in
    `tests/test_voter_rewards_inclusive_tier50.py` (pre-fork
    legacy preserved; post-fork passed pays all; post-fork
    rejected still pays all; mixed yes+no all paid; activation-
    height ordering).  (80e2086)

  * **Fork-emergency auto-recovery wired for full nodes.**
    Standing-focus item from prior audits: a node ending up on a
    minority/unintentional fork must auto-resync to the canonical
    chain without operator state surgery.  Wiring landed
    post-1.56.0 was tagged: detector + rewind-via-snapshot path,
    gated on zero-stake (registered validators NEVER auto-flip --
    they HALT instead, preserving "no slashable evidence from
    minority tip"), gated on never crossing finality, with
    snapshot-then-replay rewind and a fall-back to reset+replay
    if the snapshot was already pruned.  (8c94653)

## [1.56.0] — 2026-05-05

Minor release.  Audit round 17 ships two fixes: a critical witness
strip/attach slot-preservation hotfix that becomes load-bearing as
soon as Tier 48 binds at height 1712 (~hours away from the live tip
~1593), and Tier 49 — the unified fee floor across non-message tx
types — which collapses the 100× asymmetry between message and
transfer/stake/unstake admission floors.

### Fixed

  * **Witness `strip`/`attach` must preserve every signed body slot
    (consensus integrity, immediate impact).**  Pre-fix
    `strip_block_witnesses` and `attach_block_witnesses` constructed
    the new `Block` from only 10 of the 17 slots
    `enumerate_block_signatures` walks; these 7 were silently
    dropped: `react_transactions`, `custody_proofs`, `inclusion_list`,
    `censorship_evidence_txs`, `bogus_rejection_evidence_txs`,
    `inclusion_list_violation_evidence_txs`, and
    `non_response_evidence_txs`.  Pre-Tier-48
    (`block_number < WITNESS_ROOT_ACTIVATION_HEIGHT = 1712`) the
    verification gate is skipped, so the data was silently being
    deleted from the on-disk side-table for every stripped block
    carrying a reaction or evidence — the slashing-evidence audit
    trail vaporised on disk while the warm in-memory cache still
    looked correct.  Post-Tier-48 the gate fires and
    `WitnessRootMismatchError` would crash every read of any such
    block, including via `get_block_by_hash(include_witnesses=True)`
    and the imminent auto-separation pass at
    `WITNESS_AUTO_SEPARATION_HEIGHT = 1704`.  Both functions now use
    `dataclasses.replace` to carry every Block field through
    unchanged — the explicit field list was the defect shape, and any
    future block-shape addition (a new evidence kind, a new committee
    tx slot, ...) inherits the correct strip/attach semantics for
    free.  New regression test in
    `tests/test_witness_reattach_verification.py` populates each of
    the 7 slots with an item carrying a real `Signature`, computes
    `header.witness_root` over the full block, then asserts both the
    slot-list pass-through and the post-activation reattach
    round-trip succeed without raising — fails on pre-fix
    `origin/main` for every slot.  (269197a)

### Changed

  * **Tier 49 — unified fee floor across non-message tx types
    (consensus, hard fork, activation height 1750).**  Pre-Tier-49,
    transfer / stake / unstake admission enforced
    `tx.fee >= max(MIN_FEE, MARKET_FEE_FLOOR) = max(100, 1) = 100`,
    while message-tx admission used the Tier-16 `MARKET_FEE_FLOOR=1`
    directly — same fee model, 100× different floors across tx kinds.
    Density-wise, transfer (96 stored bytes / 100 fee = 1.04 fee/byte)
    vs message (~280 bytes / 1 fee = 0.0036 fee/byte) — selection-by-
    fee-per-byte therefore always crowds messages out of the mempool
    by transfers at the floor, exactly the failure the unified
    fee-model anchor is meant to prevent ("Every tx type the chain
    accepts ... follows this same fee model.  Don't carve out
    per-type fee logic").  Reaction txs already moved to
    `MARKET_FEE_FLOOR` at Tier 18; Tier 49 brings transfer / stake /
    unstake into the same regime.  Type-specific surcharges that
    legitimately bind above the protocol floor (`NEW_ACCOUNT_FEE` on
    transfer, `GOVERNANCE_PROPOSAL_FEE`, `KEY_ROTATION_FEE`,
    `AUTHORITY_KEY_FEE`, `REVOKE_TX_FEE`,
    `RECEIPT_SUBTREE_ROOT_FEE`) are unaffected — they layer on top of
    the unified floor at their respective callsites.  Activation
    height 1750 sits above the existing 1700–1712 fork band with
    additional cohort spacing (~38 blocks ≈ 6.3 h at 600s); two-
    validator network, both operator-controlled, so the cutover is
    coordinated and the runway bound is operational rather than the
    multi-week external-validator notice the band was originally
    sized for.  Pre-fork blocks replay byte-identically because every
    historical transfer / stake / unstake on chain paid >=
    `MIN_FEE = 100`, so the verifier admits everything it admitted
    before; only new low-fee txs become acceptable post-fork.
    `economics/auto_fee.py` mirrors the height gate via a new
    `_non_message_flat_floor` helper consumed by `_transfer_floor`,
    `_stake_floor`, `_unstake_floor` — wallet/CLI quotes shift with
    the verifier rule, no over-quote drift.  New
    `tests/test_unified_fee_floor_tier49.py` covers activation
    ordering, pre-fork rejection at sub-`MIN_FEE`, post-fork
    acceptance at `MARKET_FEE_FLOOR`, post-fork zero-fee path stays
    closed, pre-fork history replays byte-identically,
    `auto_fee` quote correctness across the gate, and surcharge
    layering.  (c9b6623)

## [1.55.2] — 2026-05-05

Patch release.  Three audit-round-16 fixes plus the test-suite perf
sweep that landed alongside.  All non-breaking: the witness reattach
verification is a defense-in-depth check that becomes load-bearing
post-Tier-48 activation, the faucet leak fix is operational hygiene,
and the dormancy-controller retune lands before Tier 47 ever
activates so no historical block reward changes.

### Fixed

  * **Tier 48 strip/attach commitment is now enforced on reattach.**
    `attach_block_witnesses` was rebuilding signatures into a block
    without re-deriving `compute_block_witness_root` and asserting
    equality with `header.witness_root`, so any disk corruption,
    archive-node tampering, or future B-3 peer-fetch path could
    deserialize fabricated WOTS+ blobs as "valid" reattached
    transactions (the block_hash still matches because the header
    is unmodified).  Post-activation the reattach now raises
    `WitnessRootMismatchError` on diverge; pre-activation
    (`block_number < WITNESS_ROOT_ACTIVATION_HEIGHT`) is a no-op.
    `get_block_by_hash(include_witnesses=True)` propagates the
    new error.  Also retired the dead `verify_witness_data` helper
    whose legacy single-slot leaf rule would have silently returned
    wrong answers if any future B-3/D wiring imported the obvious-
    looking helper.  New `tests/test_witness_reattach_verification.py`
    + updates to `tests/test_witness_tiering.py`.  (b41f0a4, 9a618f7)

  * **Public-feed faucet `_ip_last_drip` is now bounded.**  Every
    successful drip wrote `cidr → timestamp` and never deleted, with
    `_ip_cidr_24` collapsing only IPv4 to /24 — IPv6 addresses keyed
    on the full address.  An attacker on a /48 (~2⁸⁰ choices) could
    drive unbounded growth at ~50 bytes/entry, eventually inducing
    GC stalls long enough to miss attestation slots on the public-
    feed validator (which the inactivity penalty would then bill to
    the honest operator).  Per-drip eviction now drops every entry
    where `now - timestamp > ip_cooldown_sec` (already a behavioral
    no-op), with a `FAUCET_IP_LAST_DRIP_MAX = 65_536` hard ceiling
    that drops the oldest-timestamp entries when an attacker spins
    new IPs faster than expiration.  New
    `tests/test_faucet_ip_last_drip_eviction.py`.  (f38df24, 27fbbad)

### Changed

  * **Tier-47 dormancy controller retune (no activation height
    change).**  `DORMANCY_MAX_ISSUANCE_PER_BLOCK` 64 → 500 and
    `DORMANCY_CONTROLLER_K_DEN` 100_000 → 20_000.  Pre-retune the
    controller pegged at MAX whenever `gap ≥ 6.4M` (~4.6% of the
    140M target), capping annual issuance at ~3.37M while the
    chain's own documented burn estimate (`config.py`
    `TARGET_CIRCULATING_SUPPLY_FLOOR` commentary) is 10–15M
    tokens/yr — net active supply would have continued falling
    7–12M/yr indefinitely, breaking the anchored "stable active
    supply" promise within a decade post-activation.  Post-retune:
    ~26.3M tokens/yr ceiling (~2× burn) with quarterly gap-halving,
    so the controller can actually close the gap.  Tuning retune
    (not a shape change) per the CLAUDE.md anchor that controller
    curve / ceiling / window are tuning knobs in code.  Safe to
    edit in place because Tier 47 has not yet activated on mainnet
    (activation height 1710, current tip ~1500); the constants are
    consumed only inside `compute_dormancy_issuance` which is
    height-gated, so no historical block-replay output changes.
    New `tests/test_dormancy_controller_ceiling_retune.py`.
    (03225e0, 168a681)

### Perf

  * **Test suite ~5min → ~110s** via setUp hoists, entity-pool
    caching, and asyncio cleanup across 23 test files.  Two prior
    sweeps merged: shrunk Monte-Carlo loop counts on the slowest
    tests and hardened previously-flaky async tests revealed by
    the faster cadence.  No production code touched.  (cc2de07,
    3c1332d, 7179acc, 175879b, a7cbb94, 8abf93b)

## [1.55.1] — 2026-05-05

Patch release.  Compresses every remaining future activation height
into a single tight band just past the live mainnet tip.

### Changed

  * **Compressed schedule for all 13 future activations.**  With the
    network in early bootstrap (only two validators, both operator-
    controlled), the multi-thousand-block runways inherited from the
    1.26.0 / 1.32.0 / 1.38.x fork sweeps no longer serve a purpose —
    they were sized for an external-validator world to give operators
    advance notice.  All 13 forks now activate at consecutive heights
    1700 → 1712, in the same partial order the prior schedule
    enforced (every monotonicity assert in `messagechain/config.py`
    still holds without modification).  Tip at the time of the cut
    was 1567, giving ~133 blocks (~30 hours at observed cadence) of
    runway between this release going live on validators and the
    first fork firing.

    **Schedule (was → is):**

    | Tier | Constant                                           | Was    | Is   |
    | ---- | -------------------------------------------------- | ------ | ---- |
    |  3   | `SEED_DIVESTMENT_REDIST_HEIGHT`                    |  1600  | 1700 |
    | 40   | `REWARD_CURVE_SMOOTH_HEIGHT`                       |  1634  | 1701 |
    | 41   | `ACK_DEADLINE_GRACE_DEFENSE_HEIGHT`                |  1640  | 1702 |
    | 42   | `REWARD_CURVE_SMOOTH_V2_HEIGHT`                    |  2400  | 1703 |
    | (—)  | `WITNESS_AUTO_SEPARATION_HEIGHT`                   |  3000  | 1704 |
    | 43   | `FORCED_INCLUSION_ALL_POOLS_HEIGHT`                |  3134  | 1705 |
    | 44   | `CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT`     |  3834  | 1706 |
    | 45   | `PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT`         |  4534  | 1707 |
    | (—)  | `SUPPLY_RECONCILIATION_HEIGHT`                     |  5000  | 1708 |
    | 46   | `AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT`            |  5234  | 1709 |
    | 47   | `DORMANCY_CONTROLLER_HEIGHT`                       |  5934  | 1710 |
    | 3-S  | `SEED_DIVESTMENT_START_HEIGHT`                     |  7500  | 1711 |
    | 48   | `WITNESS_ROOT_ACTIVATION_HEIGHT`                   | 15000  | 1712 |

    **Operational notes:**

    * Tier 48's witness-root activation lands without B-3 / Milestone C
      / Milestone D having shipped.  Those are local-pruning and
      witness-fetch features — neither is consensus-critical.  Pre-D
      archive nodes still hold full block bodies, so peer-served
      witness data is unaffected.
    * Tier 47's dormancy controller activates two blocks before
      witness-root.  Dormancy backfill runs as designed at activation;
      the dormancy window remains unchanged (centuries-scale).
    * `SUPPLY_RECONCILIATION_HEIGHT` lands inside the band — no
      change to its consensus effect, which is still gated by the
      same height check.

## [1.55.0] — 2026-05-05

Minor release.  Tier 48 — witness-root activation (B-1 + B-2 of the
witness-tier fork).  Block headers commit to a Merkle root over every
signature byte across all signed body slots.  Pre-activation behavior
unchanged; activation gated at `WITNESS_ROOT_ACTIVATION_HEIGHT = 15_000`
(~95 days runway from current ~1_500 mainnet tip).

### Why this matters

Witness separation already runs in production (`strip_block_witnesses`
+ `attach_block_witnesses` in `chaindb.py`) but the existing single-slot
`compute_witness_root` is never called from production code, so today's
separated witnesses have no header commitment to verify against.  A peer
or a corrupted side-table could serve substituted witness data for any
post-finality block, and the current code has no cryptographic way to
detect it without re-verifying every signature individually (which
defeats the storage point of separation).  Tier 48 closes that gap by
binding every signed body slot's signatures into a single Merkle root
that the proposer signs and validators check on receipt.

### Added

  * **`messagechain/core/witness.py`** — canonical multi-slot Merkle
    commitment over block signatures.
      * `enumerate_block_signatures(block)`: slot-id-ordered iterator
        over every `Signature` in every signed body slot, item-index
        tagged.
      * `compute_block_witness_root(block)`: domain-separated Merkle
        root over the iterator's leaves.  Empty-block sentinel
        deliberately distinct from the all-zero default of
        `header.witness_root` to surface "forgot to populate" bugs.
      * 17 stable slot IDs (`SLOT_TX_MESSAGE` 0x01 through
        `SLOT_NON_RESPONSE_EVIDENCE` 0x11).  `SLOT_VALIDATOR_SIG`
        (0x0B) reserved-but-skipped — validator_signatures land
        post-proposer-sign and have their own per-sig integrity via
        `block_hash`.
  * **`messagechain/consensus/pos.py`** — `create_block` populates
    `header.witness_root` before the proposer signs, gated on
    `block_number >= WITNESS_ROOT_ACTIVATION_HEIGHT`.  Pre-activation
    blocks pass the field through at its all-zero default.
  * **`messagechain/core/blockchain.py`** — `validate_block` and
    `validate_block_standalone` recompute the witness root and reject
    "Invalid witness_root" for post-activation blocks whose header
    field disagrees with the body.
  * **`messagechain/config.py`** — `WITNESS_ROOT_ACTIVATION_HEIGHT =
    15_000` (Tier 48).  Asserts ride above
    `NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT` (Tier 35, latest body
    slot) and `DORMANCY_CONTROLLER_HEIGHT` (Tier 47).
  * **22 new tests** (`tests/test_witness_root_activation.py` +
    `tests/test_witness_root_v2.py`) covering enumeration order, slot
    coverage, activation gate, post-activation enforcement, and
    pre-activation no-op.

### Compat

Pre-activation: completely no-op.  `compute_witness_root(transactions)`
and other existing single-slot witness helpers are preserved unchanged
for back-compat with the test suite and any external integrations.
Post-activation (height ≥ 15_000): every block header MUST carry
`witness_root == compute_block_witness_root(block)` — proposers that
omit the field or compute it incorrectly are rejected at validate time.

### Follow-on milestones

This release ships only the consensus-binding piece (B-1 + B-2 of
Milestone B) of the witness-tier fork.  Remaining work — extending
`strip_block_witnesses` / `get_block_witness_data` to walk all 17 slots
(B-3), strippability rule + warm window (Milestone C),
`WitnessProof` type + p2p witness fetch + carrot wiring (Milestone D)
— remains pending and will land in subsequent releases.  Shipping the
commitment piece on its own makes the existing single-slot strip/attach
flow cryptographically safe and gives B-3/C/D a stable consensus base
to build on.

## [1.54.2] — 2026-05-04

Patch release.  Fixes a latent integer-truncation bug in the EIP-1559
`base_fee` decay that pinned the controller above the protocol floor.

### Fixed

  * **EIP-1559 `base_fee` decay floored at 7 instead of reaching
    `MARKET_FEE_FLOOR`=1.**  The decrease branch of `update_base_fee`
    computed `delta = base_fee * deficit // (target * denom)` with no
    minimum step.  At post-Tier-9 `target=22` and `denom=8`, integer
    truncation pushed `delta` to 0 once `base_fee * 22 < 22 * 8`, i.e.
    once `base_fee < 8`.  Result: under sustained empty blocks the
    controller decayed `100 → 99 → … → 8 → 7` and then got stuck at 7
    permanently — the docstring's stated intent ("decay to 1 during
    quiet periods") was unreachable, leaving the EIP-1559 controller
    pinned ~7× above the protocol floor instead of converging on it.
    The decrease branch now mirrors the increase branch's
    `max(1, delta)` floor so quiet periods can drive `base_fee` all the
    way to `MARKET_FEE_FLOOR=1`.  Consensus-visible (changes the value
    persisted in `supply_meta.base_fee`), but unconditional — applied
    at all heights.  Two-validator network, coordinated upgrade, no
    scheduled activation height needed.  Test in
    `tests/test_market_fee_floor.py`
    (`test_decay_reaches_floor_under_empty_blocks`).

## [1.54.1] — 2026-05-04

Patch release.  Two security fixes surfaced by audit round 15.

### Fixed

  * **`pending_censorship_evidence` chaindb mirror leak
    (consensus-critical, slashing surface).**  Same defect class as
    the five mirror tables fixed across the 1.50–1.54 hotfix
    sequence (`entity_id_to_index`, `key_rotation_last_height`,
    `receipt_subtree_roots`, `reaction_choices`,
    `entity_last_active`) — and this one drives slashing directly.
    `restore_state_snapshot` did not wipe `pending_censorship_evidence`
    on reorg, and `_persist_state` was upsert-only with no DELETE
    pass for orphans removed in-memory.  A `CensorshipEvidenceTx`
    admitted on a fork-tip that lost the reorg left an orphan row
    on disk → cold restart rehydrated it into
    `censorship_processor.pending` → next maturity tick at
    `EVIDENCE_MATURITY_BLOCKS` slashed a validator the warm cluster
    never accused → consensus split + an unjustified
    `CENSORSHIP_SLASH_BPS` burn against an honest operator.
    `restore_state_snapshot` now wipes + re-inserts the table inside
    the same SQL transaction; `_persist_state` truncates orphans
    via the new `clear_all_pending_censorship_evidence()` helper
    before the upsert loop on every full flush.  New
    `tests/test_pending_censorship_evidence_reorg_roundtrip.py`
    exercises both paths and fails on pre-fix `origin/main`.
    (eb0e6b9, 003e026)

### Security

  * **Public-feed server honors `X-Forwarded-For` only from a
    `--trusted-proxies` allowlist.**  The public-feed server's
    `_client_ip()` returned `self.client_address[0]` unconditionally,
    so when fronted by Caddy on the live `messagechain.org`
    deployment every visitor's socket peer was the proxy's loopback
    IP.  Per-/24 IP cooldown, per-IP faucet rate-limit, per-IP
    quickpost rate-limit, and `PeerRateLimiter` per-IP buckets all
    collapsed onto a single shared bucket — a single attacker
    could drain the operator-funded faucet wallet at the
    `(PoW × window-cap)` rate and crowd legitimate visitors out
    of the bucket.  PoW (`FAUCET_POW_BITS`) was the only remaining
    defense and is bounded for a "try it" flow.  New
    `--trusted-proxies <cidr>[,<cidr>...]` flag gates header-trust;
    when the socket peer falls inside an allowlisted CIDR the
    rightmost `X-Forwarded-For` (or RFC 7239 `Forwarded: for=`)
    token is honored as the real client IP, otherwise the header
    is ignored unconditionally (textbook OWASP "never trust
    client-supplied identity headers from arbitrary inbound").
    Empty allowlist (the default) preserves pre-fix behavior.
    Malformed forwarded-for tokens from a trusted proxy go to a
    sentinel "unattributable" bucket so attackers can't rejoin the
    legitimate-traffic bucket by sending garbage.  New
    `tests/test_public_feed_trusted_proxies.py` covers the four
    mandatory cases (trusted/untrusted/absent/malformed) plus
    rightmost-token, IPv6, RFC 7239, and parser unit tests.
    Operators fronting the feed via reverse proxy should pass
    `--trusted-proxies 127.0.0.1/32` (or the appropriate
    proxy-side CIDR) so per-IP rate limits attribute correctly.
    (4657cbd, 461acbf)

## [1.54.0] — 2026-05-04

Minor release.  Bundles two consensus / correctness fixes and two UX
improvements surfaced by audit round 14.

### Fixed

  * **Tier-47 `entity_last_active` mirror leak (consensus-critical
    pre-activation fix).**  `restore_state_snapshot` was wiping every
    other reorg-sensitive disk-mirror table (`reputation`,
    `slash_offense_counts`, `stake_snapshots`, `key_rotation_last_height`,
    `receipt_subtree_roots`, `key_history`, …) but left
    `entity_last_active` untouched, and `_persist_state` only upserted
    rows from `last_active_heights` without DELETEing entries removed
    in-memory.  Same defect class as the four mirror leaks the
    1.50–1.52.0 hotfix sequence closed.  Window opens at activation
    height 5934: an entity that signs on a fork-tip that loses the
    reorg leaves an orphan row on disk → cold restart rehydrates the
    orphan → `compute_active_supply` differs from peers →
    `compute_dormancy_issuance` mints a different amount → state-root
    mismatch → honest node permanently forks from the network.
    `restore_state_snapshot` now wipes + re-inserts the table inside
    the same SQL transaction; `_persist_state` truncates + re-emits on
    every full flush.  New tests in
    `tests/test_entity_last_active_reorg_roundtrip.py` exercise both
    paths and fail on pre-fix `origin/main`.  Fix lands ~14 weeks
    before activation. (8bbf7ca, 4dfebbb)

  * **`messagechain send --community-id` no longer ImportErrors.**
    `cmd_send` was importing two symbols that don't exist
    (`COMMUNITY_ID_BYTES` from config, `COMMUNITY_ID_STORED_BYTES`
    from transaction) and sha256-hashing the user-typed handle to
    bytes before passing it to `create_transaction(community_id=…)`,
    whose contract is `str | None` validated against
    `_validate_community_id`'s `[a-z0-9_-]` regex.  Every README-driven
    user trying the Tier-25 communities flow hit a stack trace.  CLI
    now strips + lowercases the handle and forwards it as a `str`,
    using `_community_id_stored_bytes(handle, version)` for fee
    overhead.  New `tests/test_cli_community.py` pins the README
    example end-to-end. (249131d, 3151620)

### Added

  * **Governance confirm prompt + fee preview on
    `propose` / `vote` / `react`.**  Anchored in CLAUDE.md:
    "Governance proposals are deliberately expensive and infrequent."
    The protocol charges `GOVERNANCE_PROPOSAL_FEE = 10_000` tokens
    (≈33 faucet drips, the largest single fee in the protocol), but
    the CLI was auto-feeing, signing, and submitting in one shot —
    a typo on the title or description silently burned tokens with
    no recovery path.  `cmd_propose` now prints a fee-preview banner
    (title / description bytes / fee / entity) and requires typed
    `yes` (or `--yes`/`-y` for scripts) before signing; `cmd_vote`
    and `cmd_react` print a one-line fee preview before submitting
    (no prompt at those fee levels — over-friction).  Mirrors the
    existing `cmd_transfer` / `cmd_stake` / `cmd_unstake` confirm
    pattern.  New `tests/test_cli_propose_confirm.py` covers EOF
    abort, "no" abort, `--yes` submits, fee-preview visibility, and
    fee-preview-before-submit ordering. (6a3c8ff, 1196404)

  * **Per-card permalinks on the public feed are now shortened tx
    hashes.**  Replaces the prior generic "Permanent ↗" anchor.
    Every feed card now exposes its own canonical short-hash link
    (e.g. `deadbeef…`) so users can copy/share a specific message's
    permanence proof.  Static-only change to
    `messagechain/static/feed.html`. (cc3404f, cca77bc)

## [1.53.1] — 2026-05-04

### Changed

  * **Public feed quickstart — "Just try it" is no longer a numbered
    step.**  The server-assisted try-it path on `/feed` short-circuits
    steps 1 + 2 + 3 (server generates a wallet, faucet-funds it, and
    posts the message), so it doesn't belong on the same numbered
    ladder as the real-wallet flow.  The `<li>` keeps the
    primary-button styling but renders without a step number, sits
    under a dashed divider with an "or skip the whole flow —" centered
    label, and drops the now-redundant inline "or" span.  Visual cue
    matches the semantics: it is an alternative to all three steps,
    not a third option of step 3.  Static-only change to
    `messagechain/static/feed.html`; no protocol behavior touched.

## [1.53.0] — 2026-05-04

Coordinated hard fork — Tier 47 (DORMANCY_CONTROLLER_HEIGHT = 5934).
Replaces the legacy halving + deflation-floor schedule with a
dormancy-filtered active-supply controller.  Anchored in CLAUDE.md
"Issuance targets a stable active supply, not a fixed schedule": the
chain's nominal token unit must hold its real economic weight across
centuries, so `X tokens` means roughly `X tokens` to a current user a
hundred years from now.

### Mechanism

  * **`active_supply` is dormancy-filtered.**  Every entity carries a
    `last_active_height` stamp; balances whose owner has not signed an
    outgoing tx, attested, or proposed within `DORMANCY_WINDOW_BLOCKS`
    (~25yr at 600s blocks) taper out of `active_supply`, with a
    `DORMANCY_TAPER_BLOCKS` linear taper to avoid a cliff.  Receiving
    tokens does NOT count as activity by design — that would let an
    attacker keep dormant wallets active by sending dust.  Dormant
    balances are never confiscated; they continue to exist with their
    full balance and rejoin `active_supply` the moment the owner
    transacts (Bitcoin's "lost coins" treatment, made explicit at the
    protocol level).

  * **Issuance is a proportional refill controller.**  Per-block
    issuance = `min(MAX_ISSUANCE_PER_BLOCK, gap × K_NUM // K_DEN)`
    where `gap = max(0, TARGET_ACTIVE_SUPPLY - active_supply)`.  At
    target the controller mints zero — validators run on fees alone,
    which is the long-term design intent (the fee market is the
    security budget; issuance's purpose is supply integrity, not
    validator pay).  Halving + deflation-floor (`BLOCK_REWARD`,
    `HALVING_INTERVAL`, `BLOCK_REWARD_FLOOR`,
    `TARGET_CIRCULATING_SUPPLY_FLOOR`, `DEFLATION_FLOOR_V2_HEIGHT`)
    are bypassed at and above `DORMANCY_CONTROLLER_HEIGHT`.  The
    legacy schedule is preserved byte-for-byte below the activation
    height for re-validation of historical blocks via the
    extracted `_calculate_legacy_block_reward` helper.

  * **Activation backfill.**  At exactly
    `DORMANCY_CONTROLLER_HEIGHT`, every entity with a non-zero balance
    or stake is stamped with `last_active_height = activation_height`
    in one shot (idempotent via the new `dormancy_backfill_applied`
    flag, same reorg-safe pattern as `treasury_rebase_applied` /
    `grandfather_applied`).  At activation `gap ≈ 0`, so the
    controller starts from a defined baseline rather than minting
    its full ceiling.

### Implementation

  * `messagechain/config.py` adds `DORMANCY_CONTROLLER_HEIGHT`,
    `DORMANCY_WINDOW_BLOCKS`, `DORMANCY_TAPER_BLOCKS`,
    `DORMANCY_TARGET_ACTIVE_SUPPLY`, `DORMANCY_CONTROLLER_K_NUM`,
    `DORMANCY_CONTROLLER_K_DEN`, `DORMANCY_MAX_ISSUANCE_PER_BLOCK`
    with full anchor rationale and ordering / sanity assertions.
  * `messagechain/economics/inflation.py` extends `SupplyTracker`
    with `last_active_heights`, `dormancy_backfill_applied`,
    `bump_active`, `_dormancy_weight_bps`, `compute_active_supply`,
    `compute_dormancy_issuance`, and routes `calculate_block_reward`
    through the controller post-fork.
  * `messagechain/core/state_tree.py` folds `last_active_height`
    into `_leaf_value()` via the "0 contributes nothing" data-driven
    convention so pre-Tier-47 leaves hash byte-identically to the
    legacy format and the state-shape transition rides on the data
    flipping from default to non-default at activation.
  * `messagechain/core/blockchain.py` adds `_iter_block_signers`
    and `_apply_dormancy_for_block`, with the apply-path call wired
    into `_apply_block_state` and the sim-path mirror wired into
    `compute_post_state_root` (sim/apply lockstep).  Snapshot /
    restore and `_persist_state` flush both `last_active_heights`
    and `dormancy_backfill_applied` for reorg + cold-restart safety.
  * `messagechain/storage/chaindb.py` adds the additive
    `entity_last_active` table plus `set_last_active_height`,
    `clear_last_active_height`, `get_all_last_active_heights`.
    `bump_active` mirrors writes through to disk; cold start loads
    via `_load_from_db`.
  * `get_supply_stats` exposes `active_supply`,
    `dormancy_target_active_supply`, `dormancy_gap`,
    `dormancy_window_blocks`, `dormancy_taper_blocks`,
    `dormancy_controller_height`, and `dormancy_backfill_applied`.

### Tests

  * `tests/test_dormancy_controller_tier47.py` — 47 new tests
    covering taper boundaries, controller output, pre-fork legacy
    schedule, leaf hash backwards-compat, bump monotonicity,
    activation backfill (one-shot + idempotent + pre-fork no-op),
    reorg snapshot/restore round-trip, ChainDB persistence
    round-trip, and the signer dispatcher.
  * Full suite: 5004 passed, 24 skipped.

### Operator notes

Activation height 5934 is `+700` above Tier 46 (5234) and gives every
live operator multiple weeks of runway at the current ~860-block
tip.  Pre-activation behavior is byte-identical to 1.52.0; running a
1.53.0 binary on a chain that hasn't crossed 5934 yet produces the
same blocks as 1.52.0 would.  The controller's tuning constants are
in code (not CLAUDE.md) and may be retuned by future governance
forks; the SHAPE — dormancy-filtered active supply + supply-
replenishing controller — is anchored.

## [1.52.0] — 2026-05-04

Minor release.  Closes the entire defect class that drove the
1.50.0-1.51.4 release sequence: consensus-critical in-memory
accumulators that aren't persisted to chaindb, where cold-load
creates them at empty defaults while a long-running node has them
populated, causing the two to compute different state_roots on the
next received block (``Invalid state_root -- state commitment
mismatch``).  Each prior fix patched ONE field's persistence
(lottery_prize_pool in 1.41.0, archive_reward_pool in 1.50.0,
genesis allocations in 1.51.4) and missed the next one in the
queue.  This is the structural fix.

### Root cause

Several fields used by the apply path are held in memory only and
never written to chaindb:

  * ``_bootstrap_ratchet.max_progress`` -- gates deflation boost,
    escrow length, attester committee weighting
  * ``validator_archive_misses`` / ``_success_streak`` /
    ``_first_active_block`` -- gates archive reward withhold
  * ``attester_coverage_misses`` -- gates inclusion-list coverage
    leak burns
  * ``archive_active_snapshot`` -- per-epoch active validator set
  * ``_immature_rewards`` -- spendable balance check
  * ``_escrow._entries`` -- attester reward locks

These are accumulated incrementally during block apply.  After
``_load_from_db`` (cold restart, copied chain.db, etc.) they come
back as empty defaults because no chaindb table holds them.  A
long-running node has them populated.  The next time both nodes
apply the same block, the apply paths read these values and produce
DIFFERENT post-state, breaking ``state_root`` consensus.

Witnessed in prod 2026-05-03 (validator-1's chain.db copy from v2,
post 1.51.4 deploy): cold-loaded v1 had ``bootstrap_progress=0.0``,
``validator_archive_misses={}``, etc.; long-running v2 had populated
values.  v1 successfully applied blocks 1366 and 1367 (apply path
happened not to exercise divergence-sensitive code) but failed on
1368 with ``Invalid state_root``.  No quick recovery -- v1 was stuck.

### Added

- **``state_snapshots`` chaindb table** (block_number → blob).  At
  the end of every block apply, the full in-memory state captured
  by ``_snapshot_memory_state()`` (the comprehensive serializer
  already used for reorg-rollback) is pickled and persisted at
  the block's height.  The blob captures EVERY consensus-critical
  field including the in-memory accumulators above.

- **``Blockchain._persist_state_snapshot(block_number)``** -- called
  at end of ``_append_block`` inside the apply transaction so the
  snapshot is atomic with the chain table writes.  Opportunistic
  pruning (every 100 blocks) trims rows below
  ``current - SNAPSHOT_RETENTION_BLOCKS = 1000`` so disk growth
  stays bounded (~50MB steady-state at current scale).

- **Snapshot-on-load in ``_load_from_db``**.  After the existing
  field-by-field rehydration completes, the latest ``state_snapshots``
  row is unpickled and installed via ``_restore_memory_snapshot``
  (the symmetric loader for the serializer above).  Cold-restart
  now produces an in-memory state byte-identical to what a long-
  running node had at the same height -- adding a new in-memory
  accumulator no longer requires a separate persistence path.

- **Snapshot-on-reorg in ``_reorganize``**.  Replaces the prior
  ``_reset_state`` + replay-from-block-1 path (which had the
  1.51.4 genesis-allocation bug as a workaround for one slice of
  this defect class) with: load the snapshot at the common
  ancestor's height, install via ``_restore_memory_snapshot``,
  apply the divergent fork blocks forward.  Same loader as
  cold-restart -- bug in one is bug in the other; they get tested
  together.  Falls back to the legacy reset+replay path if no
  snapshot row exists at the ancestor (e.g. snapshots pruned
  beyond retention; legacy chain.db pre-1.52.0).

- **Load-time invariant assertion**.  After ``_load_from_db``
  completes, asserts ``compute_current_state_root() ==
  latest_block.header.state_root``.  If false, raises
  ``ChainIntegrityError`` with a descriptive message naming the
  cold-load divergence as the cause.  Catches the defect within
  seconds of startup instead of silently producing divergent
  state_roots on the next received block.

### Tests

  * ``test_snapshot_on_apply.py``:
    - chaindb table accessor round-trip
    - genesis does not require a snapshot row (only post-genesis
      blocks produce them)
    - block apply via ``add_block`` writes a snapshot row
    - cold-restart restores ``bootstrap_progress`` and
      ``_immature_rewards`` to long-running values (the defining
      1.52.0 invariant)
    - load with snapshot row deleted falls back cleanly to
      field-by-field rehydration (1.51.x → 1.52.0 upgrade path)

### Operator notes

  * **Upgrade is single-step.**  No coordinated activation height.
    A node upgrading from 1.51.x loads its existing chain.db with
    no snapshot rows, falls through to the legacy field-by-field
    load, applies the next block, and writes its first snapshot
    row.  Subsequent restarts use the snapshot path.

  * **Cold-restart prod recovery for the 2026-05-03 incident:** v1
    upgrades to 1.52.0, restarts, and on next block apply persists
    a snapshot.  All future cold-restarts and reorgs work
    correctly.  But the ALREADY-DIVERGED v1 state from before
    1.52.0 still needs the manual chain.db recovery (already done
    in prod -- v1 is currently running on a copy of v2's healthy
    chain.db).  After 1.52.0 deploys, v1's in-memory accumulators
    will be EMPTY (chain.db has no snapshot row).  v2's accumulators
    are populated.  They will diverge on the next block apply and
    v1 will hit ``ChainIntegrityError`` on next restart -- expected.
    To fully recover: have v1 do a fresh chain.db copy from v2
    AFTER both are on 1.52.0 and v2 has applied at least one block
    post-upgrade (to write a snapshot row); v1 then loads the
    snapshot row and is in lockstep going forward.

## [1.51.4] — 2026-05-03

Hotfix.  The 1.51.3 reorg-fired-correctly fix exposed a pre-existing
defect in ``Blockchain._reorganize``: the replay path corrupts supply
state on any chain that uses genesis allocations.

### Root cause

``_reorganize`` does ``_reset_state()`` (which creates a fresh
``SupplyTracker`` with empty balances/staked) followed by a replay
loop ``for blk in self.chain: if blk.header.block_number > 0:
self._apply_block_state(blk)`` that skips block 0.  Genesis
allocations (founder 100M / treasury 40M / 95M founder stake) are
applied directly in ``initialize_genesis`` /
``_apply_mainnet_genesis_state`` -- NOT inside
``_apply_block_state(genesis)`` -- so the replay produces a chain
with empty initial balances.  Subsequent blocks then operate on
nothing: the founder's stake reads as 0, attestation weights
collapse, the treasury rebase at TREASURY_REBASE_HEIGHT silently
fails (treasury empty), and the resulting supply state diverges from
canonical by the genesis-allocation amount.

Witnessed in prod 2026-05-03 immediately after 1.51.3 deploy:
validator-1's first-ever successful reorg corrupted its supply state.
``total_supply`` jumped from 107M (correct, post-rebase) to 140M
(GENESIS_SUPPLY baseline, no rebase applied).  Balances summed to
**negative 15.5M** because subsequent blocks burned/credited against
the empty post-reset balance map.  v1 could no longer apply v2's
blocks (``"int too large to convert"`` deep in attestation
processing).  Recovery required a filesystem ``chain.db`` copy from
healthy v2.

Why this didn't bite earlier: ``_reorganize`` had never fired on a
production chain before -- the IBD lacked the fork-resolution
walk-back path (fixed in 1.51.0-1.51.3), so no reorg ever completed.
The 1.51.3 fix was the first time ``_reorganize`` actually ran on a
long chain in prod.

### Fixed

- **Extracted ``Blockchain._apply_mainnet_genesis_supply_state``**
  from ``_apply_mainnet_genesis_state`` -- the same identity /
  balance / stake / snapshot mutations, but WITHOUT
  ``self.chain.append(block)``, ``fork_choice.add_tip``,
  ``db.store_block``, or orphan-drain.  These are the wrapper's job;
  the helper is a pure state mutator that reorg can call after
  ``_reset_state`` to restore genesis allocations before the
  block-1+ replay loop.  ``_apply_mainnet_genesis_state`` now
  delegates to the helper for the supply-state portion.

- **``_reorganize`` calls the helper after ``_reset_state``** for
  mainnet chains (PINNED_GENESIS_HASH == _MAINNET_GENESIS_HASH).
  Devnet / test chains use ``initialize_genesis(allocation_table=...)``
  whose allocation_table isn't persisted to chaindb -- a known
  limitation of devnet reorgs, logged at WARNING when the path is
  hit.  Production reorgs now restore genesis state correctly.

### Tests

  - ``test_reorg_replay_genesis_restore.py``:
    * helper restores founder 5M liquid + treasury 40M + founder 95M
      stake on a fresh SupplyTracker without touching chain/fork_choice.
    * full-replay simulation: ``_reset_state`` then helper restores
      pre-reorg founder/treasury balances + stake.
    * post-restore conservation: balances + staked == genesis
      allocation total (no negative balances, no orphan supply).

  All 4948 tests pass on the worktree.

## [1.51.3] — 2026-05-03

Hotfix.  The 1.51.2 fork-resolution path correctly walked back, found
the ancestor, downloaded the competing chain, and recomputed the fork
tip's cumulative weight via the new from-genesis function.  But the
recomputed fork weight still failed the reorg comparison against the
canonical tip's STORED weight, because the two values were computed
under different historical-stake assumptions:

  * Canonical's stored weight was accumulated incrementally as each
    block was applied, capturing the founder's pre-rebalance 47.5M
    stake on early blocks.
  * Fork's recomputed weight walked back to genesis, but on a node
    whose chaindb stake_snapshots have been pruned (we keep only the
    trailing FINALITY_VOTE_MAX_AGE_BLOCKS = 1000 snapshots), the
    walk fell back to LIVE ``self.supply.staked`` for every block
    older than block_number - 1000.  After the rebalance the live
    stake differs from the historical 47.5M.

Witnessed in prod 2026-05-03 immediately after 1.51.2 deploy on
validator-1: fork-resolution found ancestor at 1333, collected v2's
30 competing headers up to 1364, recomputed fork weight to 30.67B
... but canonical was at stored 46.5B (incremental, captures
historical 47.5M v1 stake).  The reorg refused -- 30.67B < 46.5B --
even though both chains share the same 1-1333 history.

### Fixed

- **``recompute_fork_tip_and_maybe_reorg`` now recomputes BOTH the
  candidate fork tip AND the canonical tip via the same
  ``_compute_full_cumulative_weight`` function**, so the comparison
  is like-to-like.  Both undercount the pre-snapshot-pruning era by
  the same amount; the comparison reflects the actual divergent-tail
  difference.  Both stored weights are updated to the recomputed
  values so subsequent reorg checks stay consistent.

  For the prod scenario: both tips now compute as ~1361 * 22.5M ≈
  30.6B for v2's fork (1361 blocks) vs ~1354 * 22.5M ≈ 30.5B for
  v1's canonical (1354 blocks).  v2's fork wins by the 7-block
  divergent-tail margin (~160M).  Reorg fires.

## [1.51.2] — 2026-05-03

Hotfix.  The 1.51.1 fork-resolution path correctly walked back to find
the common ancestor and downloaded the competing chain's blocks, but
the eventual reorg never fired because ``add_block`` for already-known
fork blocks short-circuits at "Block already known" without
recomputing the fork tip's cumulative weight -- AND the legacy
``_compute_cumulative_weight`` is bounded at MAX_REORG_DEPTH+10 (=110)
ancestors, so on any chain longer than 110 blocks the canonical-tip's
accumulated-from-genesis weight is mathematically unbeatable
regardless of how heavy the competing fork actually is.  Witnessed
on validator-1 immediately after the 1.51.1 deploy: fork-resolution
located the correct ancestor at height 1333, collected v2's competing
chain (28 blocks, 1334..1361), but every block came back as "Block
already known" (they were gossiped in earlier) and the stored fork
weight stayed at 2.47B (windowed-110-block sum) while v1's canonical
tip stayed at 46.5B (genesis-accumulated).  The reorg never fired
because 2.47B < 46.5B even though the correct comparison
(genesis-accumulated for both) gives v2's fork ~46.7B vs v1's ~46.5B.

### Root cause

Two separate gaps that compose to break reorg:

  1. ``add_block`` short-circuits at "Block already known" without
     recomputing fork weights.  Blocks accumulated via gossip during
     a brief reconnect carry stale stored weights.

  2. ``_compute_cumulative_weight`` walks back at most
     MAX_REORG_DEPTH+10 ancestors -- a security cap from the
     fork-choice module that bounds reorg-check work on adversarial
     inputs.  But the canonical-tip path stores cumulative weight via
     additive ``new_weight = old_weight + block_weight`` accumulated
     from genesis without bound.  These two values are not
     comparable once the chain exceeds the cap.  Pre-1.51.2 every
     fork-vs-canonical comparison on a long chain compared a
     ``sum-of-110`` against a ``sum-of-N``.

### Fixed

- **New ``Blockchain._compute_full_cumulative_weight``** that walks
  back from a block to genesis without a depth cap, short-circuiting
  at any ancestor whose weight is already known via
  ``fork_choice.tips`` or per-call memoization.  Bounded by
  ``block_number+2`` so a corrupt chain can't cause unbounded
  computation.  Returns a value comparable to the canonical-tip
  additive cumulative.

- **New ``Blockchain.recompute_fork_tip_and_maybe_reorg``** as the
  hook the sync layer (and any other reorg-decision call site) uses
  to:
    a. force a fresh weight computation for a stored fork tip,
    b. update both ``fork_choice.tips`` and the chaindb
       ``chain_tips`` row with the corrected value,
    c. trigger ``_reorganize`` if the candidate now outweighs the
       canonical tip.

  Bypasses the "Block already known" short-circuit in ``add_block``
  and uses the unbounded weight function so the comparison is valid.

- **``ChainSyncer`` calls ``recompute_fork_tip_and_maybe_reorg``** at
  the end of fork-resolution block download (whether blocks were
  freshly applied or already-known).  This is what makes the
  downstream reorg actually fire.

### Why ``_compute_cumulative_weight`` was left unchanged

The legacy bounded function is still consulted by the ``add_block``
fork-storage path that records fork tips as they arrive.  The
existing ``test_fork_weight_snapshot_consistency.py`` tests pin its
behaviour against pinned per-block stake snapshots; changing it
broke the snapshot-consistency invariant those tests guard.  The
new path is additive: a separate, unbounded function called only at
reorg-decision time, leaving the cheap-store-on-receive path
untouched.

## [1.51.1] — 2026-05-03

Hotfix.  The 1.51.0 fork-resolution path correctly located the
common ancestor and collected an initial batch of competing headers,
but treated the FORWARD-CONTINUATION response (when asking the peer
for more headers past the initial batch) as another initial probe.
On the prod 1.51.0 deploy at 22:46:02, validator-1 found ancestor at
height 1333 and collected competing headers up to 1360, then asked
v2 for headers from 1361.  v2's response was empty (its tip was at
1361), and the empty-response path retried with doubled lookback --
which kept re-finding the same ancestor and re-collecting the same
competing headers, doubling the buffer on every iteration until
``FORK_RESOLUTION_MAX_RETRIES`` exhausted.

### Fixed

- **Forward-continuation responses route to a separate handler.**
  ``ChainSyncer._handle_fork_resolution_response`` now dispatches to
  either ``_handle_fork_continuation_response`` (when
  ``competing_headers`` is non-empty -- meaning the ancestor was
  located in a prior round) or the existing ancestor-search path.
  The continuation handler treats an empty response as "peer's tip
  reached, transition to block download," NOT as "lookback too
  shallow, retry."  Validates that the continuation chain extends
  the last-collected header (catches a peer mid-fetch reorging or
  serving spliced headers) and runs the same checkpoint gate as
  the initial probe.

  Pinned by three new tests in
  ``tests/test_sync_fork_resolution.py::TestForkResolutionContinuation``:
  empty continuation is "done not retry," well-formed continuation
  extends the chain to the peer's tip, and gap/malformed
  continuation is rejected with an OFFENSE_INVALID_HEADERS.

## [1.51.0] — 2026-05-03

Patch.  Closes the third defect surfaced by today's incident chain:
the IBD's missing fork-recovery code path, which left validator-1
permanently stuck on a lighter divergent chain after the 1.50.0
ban-clear restored P2P peering between v1 and v2.

### Root cause

After the 1.50.0 legacy ban auto-clear restored peering, validator-1
(at height 1354 on its own divergent fork) tried to sync from
validator-2 (at height 1359 on a heavier divergent fork).  The IBD's
``ChainSyncer.handle_headers_response`` only handles the linear case
where the peer's chain extends our local tip.  When the peer's first
header has a ``prev_hash`` that doesn't match our tip, it logs
``Header chain broken at block #N`` and aborts -- with no fallback
to walk back, find the common ancestor, and feed the divergent chain
through ``Blockchain.add_block``'s existing fork-storage +
``_reorganize`` machinery.  The result was a tight retry loop:

    Starting IBD: our height=1354, target=1359, peer=v2
    Header chain broken at block #1354
    [10s later, identical retry, identical abort]

The reorg machinery itself works -- it had been working since long
before 1.50.0 -- but only fires when fork blocks reach
``add_block``.  No code path ever fed the divergent blocks in.  This
left validator-1 producing solo on the lighter chain while v2
produced solo on the heavier one, indefinitely.

### Added

- **Fork-resolution walk-back in ``ChainSyncer``.**  When IBD detects
  ``Header chain broken at #N`` AND the peer's claimed cumulative
  weight strictly exceeds ours, the syncer now switches to fork-
  resolution mode:

    1. Re-issue ``REQUEST_HEADERS`` from
       ``max(0, N - lookback - 1)`` with ``count = lookback +
       HEADERS_BATCH_SIZE`` so a single round-trip can both find the
       common ancestor AND collect a chunk of the competing chain.
       Initial lookback is ``FORK_LOOKBACK_INITIAL = 16`` blocks.
    2. Walk the response.  The LAST height whose header hash matches
       the local block at that height is the common ancestor.  The
       FIRST height that diverges is the start of the competing
       chain.  All headers from that point onward are stored in
       ``_fork_resolution_competing_headers``.
    3. If the response contains only matching headers (lookback was
       too shallow), double the lookback and re-probe.  Bounded by
       ``FORK_LOOKBACK_CAP = 4096`` (~28 days at 600s/block) and
       ``FORK_RESOLUTION_MAX_RETRIES = 8``; a peer that lies about
       diverging cannot pin us in an infinite probe loop.
    4. If competing headers don't yet cover up to the peer's claimed
       tip, request more headers forward.
    5. When all competing headers are collected, transition to
       ``SYNCING_BLOCKS``.  Each competing block downloaded is
       applied via ``Blockchain.add_block`` -- the existing fork-
       storage path stores it, computes cumulative weight, and
       triggers ``_reorganize`` automatically when the fork outweighs
       canonical.  No new reorg machinery added; the missing code
       was just the path that fed the divergent blocks in.

  Gates:
  * ``_peer_outweighs_local`` short-circuits the trigger when the
    peer's weight is not strictly greater than ours -- chasing a
    divergent-but-lighter chain is bandwidth burn for no consensus
    benefit and a free attack vector for sybils.
  * Weak-subjectivity checkpoint gate also runs against
    fork-resolution headers; a peer cannot smuggle in a checkpoint-
    violating header through the fork path either.

  Pinned by ``tests/test_sync_fork_resolution.py`` (initial probe
  uses correct lookback, common ancestor located correctly,
  doubling on shallow probe, max-retries guard, peer-outweighs gate
  in all four directions, reset clears every field).

### Why this didn't bite earlier

The case requires a P2P partition lasting long enough for both sides
to mint independent blocks AND for both sides to recover network
connectivity AFTER the partition.  Pre-1.50.0, the legacy ban-clear
catch-22 prevented recovery from the most likely cause (cross-
validator ban during a consensus stall), so this code path was
never reached.  The 1.50.0 ban fix is what exposed it.

## [1.50.0] — 2026-05-03

Minor release. Two structural defects surfaced by the 1.49.0 supply-
conservation invariant: (1) a catch-22 in the 1.48.0 ban auto-clear
feature that prevented recovery from the very stall pattern the
feature was designed for, and (2) a permanent ~47.5M phantom-supply
residual on mainnet left behind by the 1.26.0 phantom-supply
migration's incomplete repair, plus two false-positive sources in the
1.49.0 conservation check itself (uncounted scalar pools).

This is a consensus-breaking release (activation-height hard fork at
`SUPPLY_RECONCILIATION_HEIGHT = 5000`). Roll both validators well
before activation; current mainnet tip is ~1351 (2026-05-03), giving
~25 days of runway at 600s/block.

### Root causes

- **Ban auto-clear catch-22 (2026-05-03 incident, P2P broken):**
  validator-2 banned validator-1 at 14:26 today for `Invalid state_root
  mismatch` (a bug 1.48.0's slashing-sim/apply parity fix addresses).
  v2 was upgraded to 1.49.0 at 17:22 and reloaded the ban_scores.json
  entry written by the pre-1.48 binary — that entry has no
  `peer_version` field. The 1.48.0 auto-clear-on-version-change feature
  conservatively refuses to fire when stored `peer_version` is empty,
  so v2 kept rejecting v1's reconnects every 30 minutes for the
  remainder of the 24h ban window. The exact recovery scenario the
  feature was designed for is the one it couldn't handle, because the
  bans that triggered the upgrade were written by the pre-fix binary.
  Operator had to hand-edit ban_scores.json to recover.
- **47.5M phantom supply (1.49.0 conservation invariant flagged):**
  mainnet was launched with `GENESIS_SUPPLY = 1_000_000_000` while the
  actual on-chain allocation table only distributed ~88.5M tokens
  (founder ~47.5M staked + treasury 40M + scattered ~1M). The 1.26.0
  phantom-supply migration assumed `GENESIS_SUPPLY` had been corrected
  to 140M and rebased `total_supply` from 1B to 140M — but the actual
  allocation was never 140M, leaving a permanent ~47.5M phantom that
  the 33M treasury rebase reduced to ~52.5M and the in-flight
  rebalance bookkeeping nudged to the observed 47,494,983. The
  phantom does not affect any user balance (it is purely a counter
  bug in `total_supply`), but it inflates every "% of supply"
  denominator in the fee model, governance thresholds, and analytics
  — exactly the distortion the 1.26.0 migration was trying to fix.
- **1.49.0 conservation check false-positive sources:** the initial
  invariant summed only `balances + treasury + staked +
  pending_unstakes` and missed two scalar pools that genuinely hold
  tokens counted in `total_supply` — `Blockchain.archive_reward_pool`
  and `Supply.lottery_prize_pool`. Plus `archive_reward_pool` was
  persisted ONLY in state snapshots (not chaindb), so any node that
  had been running since genesis lost the in-memory pool on every
  restart while `total_supply` was correctly persisted. Both gaps
  would have caused the invariant to false-positive against legitimate
  fee-burn redirects and lottery accumulation as soon as either bucket
  had non-zero value.

### Fixed

- **Ban auto-clear handles legacy (pre-1.48) entries** in
  `clear_ban_on_version_change`. Empty stored `peer_version` is now
  treated as an unforgeable marker for "this entry was written by
  code that didn't have the field," and reconnection on any
  non-empty version clears the ban (logged at WARNING with a
  "Legacy clear" annotation that distinguishes it from the normal
  version-change clear). The major instant-ban offenses
  (`OFFENSE_INVALID_BLOCK` / `OFFENSE_INVALID_TX`) all fire after
  HANDSHAKE, so all FRESH bans will have `peer_version` stamped via
  the resolver and the standard version-comparison gate runs for
  them. Ban-laundering risk is bounded: a peer whose offense was
  recorded pre-HANDSHAKE gets at most ONE legacy-clear per cycle;
  their next post-HANDSHAKE offense stamps a real version and the
  gate from then on only fires on actual version changes. Pinned by
  `tests/test_ban_decay.py::test_empty_stored_version_legacy_clear`,
  `::test_legacy_disk_row_without_peer_version_clears`, and
  `::test_post_legacy_clear_reban_stamps_peer_version`.

- **Conservation check sums the missing pools.**
  `Blockchain.check_supply_conservation()` now includes
  `archive_reward_pool` and `lottery_prize_pool` in `actual_total`
  and the breakdown dict. The cross-reference test
  `tests/test_supply_conservation_pool_coverage.py` scans the
  codebase for every `*_pool` int attribute on `Blockchain` /
  `Supply` and asserts each is either in the breakdown or in a
  documented per-block-zeroed-accumulator allowlist; a future pool
  added without updating the check fails this test before any
  invariant false-positive can fire.

- **`archive_reward_pool` persisted to chaindb supply_meta.** New
  `ChainDB.set_archive_reward_pool` / `get_archive_reward_pool`
  methods plus a `Blockchain._set_archive_reward_pool` chokepoint
  helper that mirrors every mutation into the DB row. All five
  in-tree mutation sites (snapshot install, snapshot rollback,
  archive-duty withhold, fee-burn redirect, archive payout) routed
  through the helper. Symmetric with `lottery_prize_pool`'s
  persistence (1.41.0). Cold restart now rehydrates the pool from
  the DB row instead of resetting to zero. Pinned by
  `tests/test_archive_reward_pool_persistence.py`.

### Added

- **`SUPPLY_RECONCILIATION_HEIGHT` activation-height hard fork** that
  rebases `total_supply` to the actual on-chain bucket sum, clearing
  the 47.5M residual phantom from the 1.26.0 migration's incomplete
  repair. New `Blockchain._apply_supply_reconciliation` runs in
  `_append_block` AFTER the state-root verify and BEFORE the
  conservation check. Idempotency via
  `SupplyTracker.supply_reconciliation_applied`, snapshotted with the
  rest of the supply state for reorg safety. The rebase mutates only
  the `total_supply` scalar (a supply_meta row, persisted to chaindb;
  NOT in any per-entity SMT leaf), so it does not change `state_root`
  — sim and apply agree on the activation block by construction.
  Activation height is set to **5000** for ~25 days of rollout
  runway from the current ~1351 mainnet tip; coordinate validator
  rolls accordingly. Pinned by
  `tests/test_supply_reconciliation_hard_fork.py` (rebase fires only
  at activation, idempotent on re-apply, reorg-safe round-trip
  through the supply snapshot, leaves state_root unchanged).

### Notes for operators

- **Legacy phantom-supply migration retained.** The 1.26.0
  `chaindb.migrate_phantom_supply_if_needed` (the "subtract 860M if
  the gap is exactly 860M" check) is left in place as an idempotent
  no-op for any pre-1.26.0 state file that still hasn't run it. The
  new `_apply_supply_reconciliation` supersedes it as the proper
  general repair — the docstring on the legacy method points readers
  at the new mechanism.

## [1.49.0] — 2026-05-03

Minor release. Closes the two highest-priority Tier-A risks identified
post-1.48.0: the slashing sim/apply gap (the next predictable chain
stall) and the absence of a token-conservation invariant.

### Fixed

- **Slashing now mirrors in `compute_post_state_root`.** The pre-check
  short-circuit at `_append_block` (`if not block.slash_transactions:`)
  is removed; slash blocks now go through the same state-root
  pre-check as every other block. The sim mirrors every per-leaf
  state mutation slashing performs: `staked` decrement,
  `slashed_validators` insertion (on 100% slash), submitter finder-
  reward credit, escrow burn debit, fee-burn / proposer-tip flow,
  honesty-curve gating via `_compute_slash_pct`, and the submitter's
  WOTS+ leaf watermark bump. Closes the same defect class as the
  1.47.0 unstake-release fix; without this, the next time slashing
  fires on mainnet the chain wedges at that block exactly. Pinned by
  flipping `tests/test_sim_apply_parity.py::test_slash_block` from
  `@expectedFailure` to a regular pass-required test.

### Added

- **Per-block supply-conservation invariant.** New
  `Blockchain.check_supply_conservation()` returns
  `(expected, actual, breakdown)` where the breakdown splits the
  conservation sum into `balances_sum`, `treasury`, `staked_sum`,
  `pending_unstakes_sum`. Wired into `_append_block` after the
  state-root verify. Default-on-violation is `log` (ERROR record +
  block kept — rejecting a block all peers accepted would fork us
  off the network); operators can opt into stricter behavior via
  `supply_invariant_on_violation = "crash" | "reject"`. Catches a
  defect class the in-memory drift check in 1.48.0 misses: a bug
  that mints/burns symmetrically into both memory and disk would
  pass drift but fail conservation.

## [1.48.0] — 2026-05-03

Minor release. Six fixes in a single roll, addressing the structural
issues surfaced by the 1309 stall and recovery: the recurring
sim/apply parity bug class, the round-cap recovery trap, ban-list
poisoning, undetected in-memory state drift, and two operator-tooling
papercuts that ate hours of session time during the recovery.

### Added

- **Sim/apply parity property test** (`tests/test_sim_apply_parity.py`).
  For a small 2-validator chain at every apply-time mutation we know
  about (unstake-release, inclusion-list coverage leak, key rotation,
  authority rebind, attester-fee funding), asserts
  `compute_post_state_root_for_block(candidate)` equals
  `compute_current_state_root()` after `_apply_block_state(candidate)`.
  Six scenarios pass; one (`slash_transactions`) is `xfail` with a
  TODO documenting that the production sim short-circuits and relies
  on snapshot/rollback. Pins the contract so the next apply-path
  mutation that lacks a sim mirror gets caught here instead of in
  production at the first triggering height.

- **Periodic in-memory ↔ disk drift check.** New
  `Blockchain.check_state_drift()` opens a fresh ChainDB read handle
  and diffs every consensus-critical dict (balances, staked,
  pending_unstakes, nonces, authority_keys, public_keys,
  leaf_watermarks, key_rotation_counts, revoked_entities,
  slashed_validators) against in-memory. Wired into the proposer loop
  every `--state-drift-check-interval` blocks (default 100). On
  detection, defaults to `--state-drift-on-detect=log` (ERROR-level
  record + counter); `crash` available for fail-fast operators.
  Closes the gap that left v2's struct-overflow corruption invisible
  until the next propose call surfaced it.

- **`--yes` / `-y` flag on `transfer`.** Skips the "type 'yes' to
  proceed" prompt for script-friendly use over `gcloud compute ssh`
  / sudo / non-tty pipes, matching the existing `--yes` on `stake`,
  `unstake`, `set-authority-key`, `rotate-key`, `emergency-revoke`,
  `broadcast-revoke`, `set-receipt-subtree-root`, and `upgrade`.

### Changed

- **`MAX_PROPOSER_FALLBACK_ROUNDS` removed** from `messagechain/config.py`
  and from both producer-side and validator-side enforcement. The cap
  was load-bearing for the recurring chain-stall recovery trap (the
  producer self-skipped past the very fix that would have unstuck the
  chain), but redundant for grinding defense:
  `MAX_BLOCK_FUTURE_DRIFT / BLOCK_TIME_TARGET = 120 / 600 = 0`, so
  the cap added zero grinding bound above the timestamp-skew rule
  the future-drift check already enforces.

- **`_resolve_signing_entity` consults the validator's data-dir
  keypair cache first** when `--data-dir` is set. CLI signing on a
  validator host now hits the daemon's already-warmed cache instead
  of hanging for minutes regenerating ~65k WOTS+ leaves at
  tree_height=16. Calls `decode_keypair_cache` directly (read-only),
  bypassing `server._load_or_create_entity` because that helper has
  two destructive side-effects: it `os.remove`s the cache on any
  decode error and triggers a multi-minute Merkle-node-cache
  rebuild on a missing leaf-cache file. Falls through to the
  personal-wallet cache and `Entity.create` on miss.

### Fixed

- **Stale peer bans no longer block post-fix recovery.** After the
  1.46.0 + 1.47.0 + 1.47.1 sequence, validator-2 still rejected
  validator-1 reconnects with `Rejected banned peer` for the
  remainder of the ~3-hour ban window — the chain stayed split until
  the operator manually edited `ban_scores.json`. Each `PeerScore`
  now records the peer software version at ban time and auto-clears
  on reconnect from a different version, on the reasoning that a
  binary change means the offence-producing code may no longer
  exist. Conservative gates (currently banned, both versions
  non-empty + non-"unknown", versions actually differ) avoid
  spurious clears. Legacy rows without the version field load as
  `""` and won't auto-clear; first reconnect re-tags them.

## [1.47.1] — 2026-05-03

Hotfix. The 1.47.0 state_root fix was correct, but by the time it
shipped the mainnet round counter was already at ~157 (the
post-1.46.0 stall had wedged the chain for 24h+ and the round
counter ticks up 1 per slot). The pre-existing
`MAX_PROPOSER_FALLBACK_ROUNDS = 100` cap kept the producer
self-skipping every slot — fix landed but never ran. Raise the cap
so the chain can recover.

### Fixed

- **`MAX_PROPOSER_FALLBACK_ROUNDS` raised from 100 → 10_000.** Same
  defense, looser bound: ≈70 days of stall recovery headroom
  (10_000 rounds × 600s block-time). Slot-rotation grinding is
  still bounded; the timestamp-skew defense is still enforced
  separately via `MAX_BLOCK_FUTURE_DRIFT`. The previous 100 → 5
  raise (in 1.26.2) was triggered by a similar 12-round operational
  stall — same shape of fix, just at a larger cap.

## [1.47.0] — 2026-05-03

Minor release. **Fixes a deterministic chain stall at every
unstake-release block.** First triggered on mainnet at height 1309
(release of validator-1's 25M unstake initiated at block 301);
chain wedged for 24+ hours with the producer rejecting its own
candidate every 10 minutes. Same defect class as the proposer-
selection divergence fixed in 1.46.0 — apply-only state mutation
missing from the sim mirror.

### Fixed

- **`compute_post_state_root` now mirrors `process_pending_unstakes`.**
  `_apply_block_state` calls `Supply.process_pending_unstakes(
  block_height)` which credits matured pending-unstake entries
  (release_block <= block_height) back into the unstaker's
  spendable `balances`. The sim path used by both the producer
  (via `propose_block`) and the validator's pre-check never modeled
  this. The first time mainnet reached a release block, the
  producer signed a state_root that omitted the +25M credit, the
  validator's pre-check matched its own (equally wrong) sim, and
  `_append_block`'s post-apply check (`compute_current_state_root`
  vs the claimed root) failed deterministically. Mirror the credit
  in `compute_post_state_root` before the touched-keys assembly;
  pinned with a regression test in `test_block_production.py` that
  injects a release-block-aligned pending unstake and asserts
  `add_block` accepts the resulting candidate.

## [1.46.0] — 2026-04-30

Minor release. **Fixes the recurring chain-stall pattern observed on
mainnet at heights 615 / 793 / 893 / 951 / 993 across versions
1.25.1 through 1.45.2.** Root cause: the producer side and the
validator side of proposer selection were using two different
algorithms whenever `VRF_ENABLED=True`, so a producer would propose
a block its own `validate_block` then rejected with "Wrong proposer
for slot" — chain wedged. Each prior patch release temporarily
unstuck the chain only because the restart bumped past the stuck
slot; the divergent codepath itself was never touched.

### Fixed

- **Producer/validator proposer-selection divergence.**
  `block_producer.should_propose` previously called
  `ProofOfStake.select_proposer` (pre-VRF lottery seeded from parent
  randao_mix), while `validate_block` called the VRF-aware
  `Blockchain._selected_proposer_for_slot` (seeded from the lookahead
  block's mix, 32 blocks back). With 2 validators the two algorithms
  agreed ~50% of the time and disagreed the rest. `should_propose`
  now routes through `_selected_proposer_for_slot` so the producer
  and validator agree byte-for-byte on every (parent, round). Pinned
  with a regression test in `test_block_production.py` that walks 50
  slots in a 2-validator chain and asserts `should_propose` agrees
  with `_selected_proposer_for_slot` for every (entity, slot).

## [1.45.2] — 2026-04-29

Follow-up to 1.45.1.  That release fixed the receipt-page READ
path to consult durable on-disk sources, but the WRITE path was
silently broken: no proposer ever flushed in-memory attestations
onto chain, so the source the read path now consulted was empty
by construction.  Result was unchanged from before 1.45.1 — every
block produced before the most recent restart still showed
"0 attesters / awaiting finality" on https://messagechain.org.

### Fixed

- **Proposer now drains parent-block attestations into the next
  produced block.**  `_try_produce_block_sync` (server.py) and
  `_try_produce_block` (node.py) called `propose_block(...)`
  without `attestations=`, so every produced block carried zero
  attestations even though `validate_block_attestations` and the
  apply path already supported them (with the standing constraint
  that `att.block_hash == prev_hash` and `att.block_number ==
  block_number - 1`).  Both proposers now drain
  `self.blockchain.finality.attestations_for(tip.block_hash,
  tip.header.block_number)` and pass the result, capped at
  `MAX_ATTESTATIONS_PER_BLOCK`, into `propose_block`.  Adds
  `FinalityTracker.attestations_for(block_hash, block_number)` as
  the helper.  Historical blocks 1..N produced before this fix
  stay at 0 attesters forever — that data was never persisted
  and cannot be recovered — but every block produced after
  activation carries the attestations its peers cast in the prior
  block period, which is what the 1.45.1 read path was designed
  to surface.  Adds regression tests covering the helper
  (block-hash filter, height filter, dedupe, empty case) and the
  full proposer-drain → propose_block → add_block →
  durable_block_finality(post-restart) integration path.
  (a56a337)

## [1.45.1] — 2026-04-29

Bugfix release.  The receipt-page tx-status RPC was reading
attester counts and the finality verdict from the in-memory
`FinalityTracker`, which is rebuilt only for blocks observed
since the most recent restart.  After any node restart
(including a routine `upgrade`), every previously-included
block silently downgraded to "0 attesters / awaiting finality"
on https://messagechain.org, even when long-finalized on
chain.

### Fixed

- **Receipt-page finality now resolves from durable on-disk
  sources.**  A new `durable_block_finality` helper reads
  attester counts from block N+1's `attestations` list (the
  chain's permanent record of who attested to block N — the
  apply path rejects any attestation with
  `block_number != parent - 1`, so the successor block's list
  is complete by construction) and the finality verdict from
  the `finalized_blocks` table (which persists FinalityVote-
  driven finalization across restarts).  The in-memory tracker
  remains the fallback for the chain tip, where no successor
  block exists yet.  Both call sites
  (`Server._rpc_get_tx_status` and
  `Blockchain.get_tx_status_public`) delegate to the helper.
  Adds regression tests covering post-restart, tip-block-
  fallback, and DB-finalization-override paths.  (6e410f8,
  a9049c5)

## [1.45.0] — 2026-04-29

Multi-axis audit (UX / Security / Long-term / Value-prop / Economics)
against `origin/main` at 1.44.1 surfaced 47 findings; the cumulative
top-1 by severity × leverage × ROI lands here.  One new hard fork
(Tier 46) closes a structural authority-key defense gap that
predated the recent fix cadence: a hot-key compromise was, until
now, equivalent to a cold-key compromise.

### Security (consensus, gated by activation height)

- **Tier 46 — `SetAuthorityKey` rebind requires a cold-key
  counter-signature once an authority key is already installed.**
  Pre-fix, `Blockchain.validate_set_authority_key` verified the tx
  against `self.public_keys[entity_id]` (the hot signing key) only.
  An attacker with the hot key could broadcast
  `SetAuthorityKey(new_authority_key=ATTACKER_COLD)` and inherit
  unstake + emergency-revoke rights; Revoke is signed by
  `authority_keys[entity_id]` (now attacker-controlled), so the
  legitimate operator could no longer revoke their own compromised
  hot identity, and the attacker could sign Unstake to liquidate
  the entire bonded stake on the 7-day unbond.  The hot/cold split
  that the design document promises was not actually enforced.
  Tier 46 introduces an optional `cold_signature` field on
  `SetAuthorityKeyTransaction`: at and above
  `AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT = 5234` (riding +700
  cohort spacing above Tier 45's 4534), if `authority_keys[entity_id]`
  is already set, the tx must carry a valid signature under the
  currently-installed cold key over the same canonical bytes the
  hot key signs.  First-time install (no installed cold) and
  pre-fork rebind paths remain byte-identical for replay
  determinism — the new field is appended via a `0x01`-marker
  trailer (mirrors Tier 26 RevokeTransaction window pattern).
  `tx_hash` commits to the cold signature so it cannot be silently
  dropped by an intermediary.  CLI gains `--cold-key-path` on
  `set-authority-key`; `cmd_set_authority_key` detects rebind via
  RPC and routes through the new helper, with a clear error when
  `--cold-key-path` is missing on a rebind.  Adversary defended:
  validator collusion / coerced operator (PRIMARY).  Tests:
  `tests/test_authority_key_rebind_cold_signature.py` — 11 tests
  covering activation-height pinning, pre-fork acceptance,
  post-fork first-install acceptance, post-fork rebind hot-only
  rejection, valid cold counter-sig acceptance, wrong/forged
  cold-sig rejection, binary + dict round-trip for both legacy
  and cold-signed forms, byte-identical legacy encoding.  Source:
  `2b83b6e` (audit fix #1, merged via `5f91070`).

### Operator notes

- **One new activation height rides in this release.**  Tier 46 at
  `AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT = 5234` — well above
  current tip with comfortable runway.  All validators must
  upgrade to 1.45.0 before the runway closes.  Operators who
  currently rely on rebinding their authority key from the hot
  key alone must, at and above the activation height, have the
  cold private key available locally to sign the counter-sig.
  Pass `--cold-key-path <path>` to `messagechain set-authority-key`
  for the rebind flow; first-time install path is unchanged.
  Roll validators with `messagechain upgrade --yes`.

## [1.44.1] — 2026-04-29

Static-asset-only patch.  Public feed (`https://messagechain.org`)
quickstart-row CSS refactor + tagline edit.  No protocol, consensus,
or runtime change; validators serve the new HTML on next boot.

### UI

- **Quickstart steps render with uniform layout.**  Every step in
  the public feed's quickstart list now uses the same flex-row
  layout — number hangs to the left, button (or faucet `<details>`)
  fills the column width and lines up flush with the message cards
  below.  Previously only the "github / first-message" choice row
  was a flex row; the other steps were positioned via absolute
  number + left-padded button, so the button visually under-shot
  the column.  The `li.choice`-only flex rule is gone; flex is now
  the universal step layout.

- **Subhead tagline edit.**  Removed the "Suppression is slashable."
  fragment from the H1 subhead.  The remaining copy ("on-chain
  forever") carries the permanence promise without naming a specific
  enforcement mechanism that doesn't read cleanly to first-time
  visitors and isn't actionable from the landing page.

## [1.44.0] — 2026-04-29

Multi-axis audit (UX / Security / Long-term / Value-prop / Economics)
against `origin/main` at 1.43.1 surfaced 46 findings; the cumulative
top-3 by severity × leverage × ROI land here.  One new hard fork
(Tier 45) closes a continuously-bleeding economics defect on the
attester reward path; one no-fork security fix closes a silent-fork
primitive on the bad-state-root rollback path; one no-fork UX fix
unblocks the public faucet for every newcomer.

### Security (active immediately, no fork gate)

- **Snapshot/restore `reaction_state` and `archive_reward_pool` on
  bad-state-root rollback.**  `Blockchain._snapshot_memory_state`
  / `_restore_memory_snapshot` omitted two consensus-relevant
  mutable collections that `_apply_block_state` writes on every
  React-bearing or archive-duty block.  `self.reaction_state` is
  mixed into `compute_current_state_root` via
  `state_root_contribution()`; `self.archive_reward_pool` is mixed
  into the snapshot root.  A bad-state-root block was rolled back
  via `_restore_memory_snapshot` but both mutations leaked,
  opening a silent-fork primitive: a coerced proposer crafts a
  block with deliberately-wrong `state_root` whose apply path
  still runs `reaction_state.apply` on attacker-chosen React txs
  (or fires `archive_reward_pool` mutations).  The block is
  rejected, but in-memory state is now diverged from honest
  peers' replayed state — the next legitimate block's
  `compute_current_state_root` mixes in the diverged contribution
  and silently forks the chain at the next React-touching or
  archive-duty block.  Same defect class as the four-processor
  rollback fixes shipped 1.37.0–1.39.2 (non_response,
  bogus_rejection, censorship_pending, IL-processor, archive-duty
  miss/streak/first-active/active-snapshot); these two were
  simply missed from the structural sweep.  Pure in-memory
  rollback path; chaindb mirror runs only after the state-root
  check passes, so no fork or activation gate.  Adversary
  defended: validator collusion (PRIMARY).  Tests:
  `tests/test_reaction_state_rollback_snapshot.py` (new) +
  `tests/test_archive_reward_pool_rollback_snapshot.py` (new) —
  13 regression tests across the two files.  Source: `7ebe061`
  (audit fix #1, merged via `30b4217`).

### Changed (consensus, gated by activation height)

- **Tier 45 — per-validator attester reward cap retune from
  100 bps to 5000 bps post-activation.**  Pre-fix
  `PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH = 100` was
  sized for committees of size 128 (per-slot reward ≈ 0.05) but
  mainnet runs at committee size 2 (per-slot reward = 6 at
  BLOCK_REWARD=16).  Net effect: each validator hit the 12-token
  per-epoch cap by block ~3 of every 100-block epoch and burned
  ~5 tokens/block on the remaining 97 — **~79% of attester
  issuance evaporated every epoch under live mainnet
  conditions**.  Floor era (BLOCK_REWARD=4) is worse: per-slot=1,
  cap=3, burn rate ~97%.  Anchored "low steady perpetual
  inflation funds the security budget forever" was bleeding every
  block; the bootstrap-arc anchor (founder credibly secures the
  network solo while it has only a handful of nodes) was
  silently halved.  Tier 45 introduces a new constant
  `PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45 = 5000`
  and a height gate
  `PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT = 4534` (riding above
  Tier 44's 3834 with comfortable +700 cohort spacing above the
  current ~850 mainnet tip).  Post-activation cap = 600
  tokens/entity/epoch — well above expected per-validator
  earnings of ~500 at any committee size.  Pre-fork wire format
  byte-identical for replay determinism; the legacy 100-bps
  branch is preserved byte-for-byte.  Anchor protected: low
  steady perpetual inflation; honest-operator insurance;
  bootstrap-arc.  Tests:
  `tests/test_attester_cap_retune_tier45.py` — pre-fork
  byte-identical pin, post-fork retune assertion, activation
  ordering, constants visibility.  Source: `fe7a7bb` (audit fix
  #2, merged via `7ca9dec`).

### Fixed (UX / public funnel, no fork)

- **Public faucet `issue_challenge` and `try_drip` accept `mc1…`
  bech32 addresses in addition to 64-char hex.**  Pre-fix the
  faucet's server-side handlers and `feed.html`'s client-side
  regex hard-required hex form, but `messagechain account` and
  `messagechain generate-key` print `Address: mc1…` and
  explicitly tell users *"Share the 'Address' form when receiving
  funds — it has a built-in checksum."*  Net effect: every
  newcomer who lands on https://messagechain.org → CTA "Get
  starter tokens" → pastes the `mc1…` they were just told to
  share → gets bounced with `"Address must be exactly 64 hex
  characters."`  The mission's headline funnel ("post your first
  message") died at step 1 on the only public-facing surface.
  Fix decodes `mc1…` via the existing `decode_address` helper in
  `messagechain/identity/address.py` (no new bech32 codec —
  reuses the live one); checksum-failed `mc1…` returns a clear
  `"Invalid mc1 address (bad checksum)"` error.  `feed.html`
  placeholder updated to `"mc1… address (or 64-char
  entity_id)"` and the regex relaxed to accept either form;
  client passes the typed string to the server unchanged so the
  server is the single source of truth for address validity.
  Hex form continues to work (regression-tested).  Tests:
  `tests/test_faucet_accepts_mc1_address.py` — 7 new
  mc1-acceptance tests covering challenge issuance, drip,
  tampered-checksum rejection, and hex-form regression.  Source:
  `bce0481` (audit fix #3, merged via `e013741`).

### Operator notes

- **One new activation height rides in this release.**  Tier 45 at
  `PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT = 4534` — well above
  current tip with comfortable runway.  All validators must
  upgrade to 1.44.0 before the runway closes.  The rollback-leak
  fix and the faucet mc1 acceptance are active immediately on
  upgrade (no fork gate).  Roll validators with
  `messagechain upgrade --yes`.

## [1.43.1] — 2026-04-29

Multi-axis audit (UX / Security / Long-term / Value-prop / Economics)
against `origin/main` at 1.43.0 surfaced 48 findings; the cumulative
top-3 by severity × leverage × ROI land here.  All three are
no-fork hotfixes — one closes a live security regression on a
defense that landed last release, two close UX/funnel gaps that
made the headline censorship-resistance and validator-onboarding
guarantees unreachable from the default user surface.

### Security (active immediately, no fork gate)

- **RPC success-receipt path now drains the dedicated receipt
  bucket, not the rejection bucket.**  The `ReceiptBudgetTracker`
  shipped in 1.42.0 was bypassed entirely on the JSON-RPC surface:
  `Server._resolve_rpc_receipt_issuer` checked
  `rejection_budget_check(client_ip)` to gate success-path receipt
  issuance, while the HTTPS path correctly used
  `receipt_budget_check`.  Net effect: an attacker rotating across
  HTTPS+RPC drained both per-IP buckets, doubling the per-IP burst
  before the global cap fired, and the dedicated `_receipt_buckets`
  dict was dead code on the RPC surface.  Reopens the kill-switch
  the 1.42.0 cap was specifically built to close — a drained
  receipt subtree silently bricks the censorship-evidence
  pipeline.  Fix: one-line bucket swap in
  `Server._resolve_rpc_receipt_issuer`.  Adversary defended:
  validator collusion (PRIMARY anchored adversary).  Tests:
  `tests/test_rpc_receipt_budget_correct_bucket.py` (4 new TDD
  regression tests asserting the correct bucket is drained, silent
  downgrade fires when the receipt bucket is exhausted, the global
  cap still fires, and the rejection bucket stays untouched on the
  success path).  Source: `213cde8` (audit fix #1, merged via
  `aa170fb`).

### Fixed (CLI / UX, no fork)

- **`messagechain send` saves the SubmissionReceipt; not-found
  escalation hint points at the live `submit-evidence censorship
  --receipt` form.**  The headline censorship-evidence funnel was
  unreachable from the default `send` path: `cmd_send` read
  `tx_hash` and `fee` from the RPC response and dropped the
  signed `SubmissionReceipt` on the floor.  A user who later
  found their tx was censored had nothing to escalate with.
  Compounding, the receipt CLI's not-found hint
  (`_print_not_found_receipt`) pointed at the deprecated
  `submit-evidence --tx <hash>` form, which the live subcommand
  rejects as a stub demanding `--receipt <bundle.json>`.
  `cmd_send` now writes
  `~/.messagechain/receipts/<tx_hash>.json` (mkdir -p, JSON shape
  compatible with the live `submit-evidence censorship --receipt`
  parser, atomic-rename) and prints `receipt saved: <path>` on
  success.  `_print_not_found_receipt` now points the user at
  that exact file with the live subcommand form.  Surfaces the
  slashing-backed permanence guarantee at the default send
  surface; the chain-side Tier 30+ pipeline was already shipped.
  Tests: `tests/test_cli_send_saves_receipt.py` (round-trip
  verifies the saved bundle is loadable by the live
  `_load_receipt_bundle` helper) +
  `tests/test_cli_not_found_hint.py` (asserts the deprecated
  `--tx` form is gone).  Source: `73a4574` (audit fix #2, merged
  via `8048ca4`).

- **`messagechain stake` / `unstake` auto-fee no longer clamps to
  a stale 1000-token floor; install next-steps text uses live
  `get_validator_min_stake(tip)`.**  The chain admission floor
  for stake/unstake post-Tier 16 (MARKET_FEE_FLOOR_HEIGHT=623,
  long past on mainnet) is `max(MIN_FEE=100, MARKET_FEE_FLOOR=1)
  = 100`, but `cmd_stake` / `cmd_unstake` clamped the
  auto-computed fee to `MIN_FEE_POST_FLAT=1000`.  Net effect:
  the anchored Tier 29 *"1 faucet drip funds end-to-end validator
  stake"* flow (300 tokens = 200 staked + 100 fee) was broken at
  the CLI surface.  Every fresh validator following the README
  hit `Insufficient balance for staking + fee` because the CLI
  demanded a 1000-token fee on top of the 200-token stake.
  Compounding, `runtime/onboarding.py`'s on-host post-install
  next-steps text hardcoded
  `messagechain transfer --to {address} --amount 10000` and
  `messagechain stake --amount 10000`, contradicting the live
  `get_validator_min_stake(tip) = 200`.  Both lines now compute
  the live min-stake at install time so the on-host text agrees
  with the chain's actual rule.  Removed the redundant
  `MIN_FEE_POST_FLAT` clamp in `cmd_stake` / `cmd_unstake`
  (auto_fee already returns the correct floor of 100).  Tests:
  `tests/test_cli_stake_fee_floor.py` (new) +
  `tests/test_init_command.py` extension asserting the
  next-steps text reflects the live floor, not a hardcoded
  10000.  Source: `222ea80` (audit fix #3, merged via
  `d8cbb80`).

### Operator notes

- **No new activation heights, no fork runway constraint.**  All
  three fixes are active immediately on upgrade.  The fee-floor
  CLI fix is invisible on already-funded operators — the CLI just
  stops over-charging on stake/unstake.  Roll validators with
  `messagechain upgrade --yes`.

## [1.43.0] — 2026-04-29

Multi-axis audit (UX / Security / Long-term / Value-prop / Economics)
against `origin/main` at 1.42.0 surfaced 42 findings; the cumulative
top-3 by severity × leverage × ROI land here.  One new hard fork
(Tier 44) closes the largest remaining hole in the
censorship-evidence pipeline; one soft-fork extension under Tier 43's
existing activation height closes its sibling react-pool gap; one
no-fork CLI bugfix corrects an operator-facing leaf-usage indicator
that was 16× wrong on every status check.

### Changed (consensus, gated by activation height)

- **Tier 44 — `CensorshipEvidenceTx` carries a polymorphic
  receipted-tx field** covering Message / Transfer / React.  Pre-fix,
  `CensorshipEvidenceTx` hard-coded `MessageTransaction` in its wire
  format, but `submit_transaction_to_mempool` (Tier 1.34+) issues
  `SubmissionReceipt`s for all three receipted tx kinds.  Net effect:
  a coerced validator could issue a receipt for a Transfer or React
  (looks fully accountable on the wire) and silently drop the tx,
  with NO slashing path — the user holding the receipt could not
  package it, because `CensorshipEvidenceTx.from_bytes` /
  `.deserialize` called `MessageTransaction.from_bytes(...)` which
  fails on transfer/react payloads.  Receipts on transfer/react were
  slash-theatre; the CLAUDE.md "validator collusion" primary anchor
  + "transfer is a first-class, fully supported tx type" anchor were
  both half-violated.  Tier 44 introduces a single-byte kind tag
  (0=Message, 1=Transfer, 2=React) preceding the receipted-tx blob;
  the decoder dispatches to the appropriate `*Transaction.from_bytes`
  / `.deserialize`.  `CensorshipEvidenceProcessor.observe_block` now
  walks all three receipted-kind slots so a transfer-or-react
  inclusion correctly voids matching pending evidence, preventing
  mature-evidence slashes against validators whose tx WAS actually
  included as a transfer or react.  Activation at
  `CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT = 3834`, riding above
  Tier 43's 3134 with comfortable +700 cohort spacing above the
  current ~850 mainnet tip.  Pre-fork wire format byte-identical for
  replay determinism.  `messagechain submit-evidence censorship`
  CLI extended to read a `tx_kind` field from the receipt bundle,
  packing the correct kind into the new wire-format slot.  Adversary
  defended: validator collusion (PRIMARY).  Tests:
  `tests/test_censorship_evidence_polymorphic_tier44.py` (14 tests).

- **Tier 43 — forced-inclusion source-side gate now also covers
  `mempool.react_pool`.**  Tier 43 (1.42.0) wired stake / unstake /
  authority / governance + censorship-evidence pools as
  forced-inclusion sources, but reactions live in
  `mempool.react_pool` (separate from `pending`) and were NOT
  registered.  Block-side `_BLOCK_TX_LIST_ATTRS` already covered
  `react_transactions`, but attesters never pulled reacts into the
  forced set — so a colluding majority could still suppress
  arbitrarily-high-fpb React txs without slashable evidence.  This
  is the canonical CLAUDE.md threat-example — *"a corporation
  pressuring validators to suppress negative reviews of its
  products"* — on MessageChain, "negative reviews" are React
  vote-down txs (Tier 17 trust signal).  Fix adds an internal
  `_iter_react_pool_with_arrivals` helper mirroring the existing
  evidence-pool registration, with a sibling
  `_react_pool_arrival_heights` dict torn down on every removal
  path.  Per-entity-cap and Tier 37 same-entity entity-cap excuse
  semantics apply across the expanded source set via the existing
  `entity_id`/`voter_id` fallback in `_entity_id_of`.  **Soft fork
  under the existing `FORCED_INCLUSION_ALL_POOLS_HEIGHT = 3134`
  gate** — no new activation height; the registration expansion
  ships before Tier 43 activates.  Pre-activation behavior preserved
  byte-identically.  Adversary defended: validator collusion
  (PRIMARY).  Tests: `tests/test_forced_inclusion_react_pool.py`
  (new) + extensions to `tests/test_forced_inclusion_all_pools.py`.

### Fixed (CLI / operator-UX, no fork)

- **`messagechain status --entity` / `key-status` / `rotate-key`
  leaf-usage % now uses the per-entity `tree_height` from the chain
  rather than a hard-coded `1 << 16`.**  Validators run at
  `MERKLE_TREE_HEIGHT = 20` (1,048,576 leaves) but the status math
  was dividing by 65,536 — at 50% real capacity the operator saw
  `524288/65536 (800.0%) ROTATE NOW`.  Drove premature rotations
  (~90-min keygen + tx fee + leaf burn for the rotation itself) and
  trained operators to ignore the YELLOW/RED traffic light because
  it routinely blew past 100%.  Same class of bug at three sibling
  CLI sites; all three resolved through a new
  `_resolve_entity_tree_height()` helper that mirrors the
  already-correct path in `cmd_rotate_key_if_needed`.
  `Blockchain.get_entity_stats` now surfaces the per-entity
  `tree_height` (additive RPC field; absent for first-touch
  entities, which fall back to the personal-wallet default).
  Tests: `tests/test_cli_status_leaf_pct_per_entity_tree_height.py`
  (9 tests covering h=20 validator at 50%/85%, h=16 personal
  wallet, and first-touch fallback).

### Operator notes

- **One new activation height rides in this release.**  Tier 44 at
  `CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT = 3834` — well above
  current tip with comfortable runway.  All validators must upgrade
  to 1.43.0 before the runway closes.  The Tier 43 react_pool
  extension rides under the existing Tier 43 height (3134, also
  still in the future), so no second runway constraint.  The CLI
  leaf-usage fix is active immediately on upgrade (no fork gate).
  Roll validators with `messagechain upgrade --yes`.

## [1.42.0] — 2026-04-29

Multi-axis audit (UX / Security / Long-term / Value-prop / Economics)
against `origin/main` at 1.41.0 surfaced 48 findings; the cumulative
top-3 by severity × leverage × ROI land here.  One new hard fork plus
two no-fork hardenings against the censorship-evidence pipeline and the
wallet/CLI auto-fee path.

### Security (active immediately, no fork gate)

- **Default-success receipt issuance is now per-IP + global rate-capped
  via a dedicated `ReceiptBudgetTracker` bucket.**  Pre-fix, the
  HTTPS submission success path called `receipt_issuer.issue(tx_hash)`
  with NO budget consultation — only the opt-in
  `rejection_budget_check` / `ack_budget_check` paths gated against
  the global cap.  A drainer paying `MIN_FEE × 65k` floor-fee txs at
  the standard `SUBMISSION_RATE_LIMIT_PER_SEC` could exhaust the
  receipt subtree's WOTS+ leaves from a single /24 in minutes.  Once
  exhausted, `KeyPair.sign` raises `Key exhausted` (caught silently)
  and the validator can never issue another censorship-evidence
  receipt for the rest of that subtree's natural lifespan —
  neutralizing the only working remedy in the Tier 30→41 evidence
  stack.  Fix gates the success-path issuance through a new
  `_receipt_buckets` per-IP map + shared global cap (tunables
  `SUBMISSION_RECEIPT_RATE_LIMIT_PER_SEC = 0.1` and
  `SUBMISSION_RECEIPT_BURST = 5` in `messagechain/config.py`,
  matching the canonical pattern of every other submission-budget
  constant).  Fail-open semantics preserved: when the budget refuses,
  no leaf is consumed and the tx is still admitted with empty
  `receipt_hex`.  Adversary defended: validator collusion (PRIMARY).
  Tests: `tests/test_audit_critical_2026_04_28_r14.py`.

### Changed (consensus, gated by activation height)

- **Tier 43 — forced-inclusion source-side gate covers all tx pools.**
  Tier 34 (1.35.0) wired the *block-side* gate to walk every block
  tx-list field via the `_BLOCK_TX_LIST_ATTRS` registry, but the
  *mempool source* still only fed it from `mempool.pending` (Message
  + Transfer).  Server-local pools (`_pending_stake_txs`,
  `_pending_unstake_txs`, `_pending_authority_txs`,
  `_pending_governance_txs`) and the on-mempool censorship-evidence
  pool were not in `get_forced_inclusion_set`'s source.  Net effect:
  the CLAUDE.md "high-fpb tx cannot be suppressed without slashable
  evidence" anchor was honored only for Message and Transfer — a
  colluding proposer could silently drop the very
  `CensorshipEvidenceTx` filed against them, plus governance votes,
  unstake exits, stake-rebalances, etc., with zero slashable
  evidence.  Tier 43 closes this by extending the mempool's
  forced-inclusion source to consult registered external pools (a new
  registration surface on `Mempool` that the server uses to plug
  stake / unstake / authority / governance pools in) plus the
  on-mempool censorship-evidence pool.  Per-byte ranking and Tier 37's
  same-entity entity-cap excuse semantics apply across the expanded
  source set.  Activation at
  `FORCED_INCLUSION_ALL_POOLS_HEIGHT = 3134` (comfortable +734 cohort
  spacing above Tier 42's 2400; current tip ≈ 850).  Pre-fork
  behavior preserved byte-identically.  Adversary defended: validator
  collusion (PRIMARY), at the inclusion-rule abuse surface that Tier
  34 left half-closed.  Tests:
  `tests/test_forced_inclusion_all_pools.py` (15 tests).

### Changed (node-local, no fork)

- **Wallet/CLI auto-fee estimator now percentiles over fee-per-byte
  density, not absolute fees.**  Pre-fix `FeeEstimator.estimate_fee`
  percentiled `all_fees` directly, and `mempool_percentile_estimate`
  divided every observed fee by the *caller's quoting* `stored_size`
  then re-multiplied — divide-and-re-multiply cancel; result was a
  percentile of absolute fees, not densities, despite the docstring
  claim.  Worked example: mempool with 1×(5_000-byte tx @ fee 5_000,
  density 1/B) and 10×(50-byte txs @ fee 100, density 2/B) — true
  75th-pct fee/byte = 2/B; quoting a 100-byte tx should return ~200,
  but pre-fix returned either 100 or 5000 depending on the
  `stored_size`-cancel artifact.  Every wallet/CLI auto-fee call
  systematically mis-priced by the ratio of typical-tx-size to
  current-tx-size, directly violating the CLAUDE.md anchor "any
  wallet/CLI helper that picks a fee for the user computes a target
  fee-per-byte from current mempool conditions and multiplies by the
  tx's stored byte count."  Fix: `record_block_fees` now accepts
  `(fee, stored_size)` pairs (legacy bare-int still accepted with
  size=1 for back-compat); `estimate_fee` ranks densities and returns
  `percentile_density × quoting_stored_size`; server's
  `_rpc_estimate_fee` now passes the quoting tx's full
  `stored_bytes` (not just `message_bytes`) so non-message kinds also
  benefit from density-correct percentile pricing under pressure.
  All `rpc_call(..."estimate_fee"...)` CLI sites flow through the
  fixed path.  Tests: `tests/test_fee_estimator_density.py` (9 tests).

### Operator notes

- **One activation height rides in this release.**  Tier 43 at
  `FORCED_INCLUSION_ALL_POOLS_HEIGHT = 3134` — well above current tip
  with comfortable runway.  All validators must upgrade to 1.42.0
  before the runway closes.  The receipt-issuance cap and the
  fee-per-byte estimator fix are active immediately on upgrade (no
  fork gate).  Roll validators with `messagechain upgrade --yes`.

## [1.41.0] — 2026-04-28

Tier 42 hard fork retunes the smooth concave reward-curve constants
(peak / floor / curve-bend point).  The CLAUDE.md-anchored *shape*
of the curve (concave, monotonically diminishing per-unit yield,
asymptotic soft cap, no hard cap, strictly-increasing absolute reward,
concave absolute reward, pure-int) is preserved bit-for-bit — only the
tuning knobs change, per the explicit CLAUDE.md anchor that "exact
constants … are tuning knobs."

### Why

At today's mainnet bootstrap concentrations (2 validators ≈ 50%
each, stake_bps≈5000), the Tier 40 V1 constants
(PEAK=150 / FLOOR=40 / SCALE_BPS=300) put the multiplier at ~0.46×,
which means ~50–67% of the attester pool burns every block (integer-
rounding short of the pool at the `attester_tokens_paid<attester_pool`
branch in `inflation.mint_block_reward`).  That violates two CLAUDE.md
anchors at once:

  - **Bootstrap-arc anchor** (issuance is calibrated so the founder can
    credibly secure the network solo while it has only a handful of
    nodes): a multiplier that flattens to 0.40× at every realistic
    bootstrap concentration silently halves the founder's incentive
    against the schedule.
  - **"Low steady perpetual inflation funds the security budget
    forever"**: half-burning the attester pool every block is not the
    perpetual issuance the schedule was calibrated for.

The V1 curve-bend point (3% stake) sits below every realistic
bootstrap concentration, so a bootstrap-era validator effectively
earns at the asymptote rather than in the curve's working range.

### Tier 42 — Smooth-curve V2 retune (hard fork, height 2400)

- **`reward_curve_multiplier_v4(stake_bps)`** in
  `messagechain/economics/inflation.py`.  Same rational form as v3
  (anchored shape preserved); only the tuning knobs change:

      multiplier(s) = (FLOOR_V2·s + PEAK_V2·SCALE_V2) /
                      (MULT_DEN  · (SCALE_V2 + s))

- **Tuning constants in `messagechain/config.py`**:
  `REWARD_CURVE_SMOOTH_V2_PEAK_NUM = 130` (1.30× near-zero peak; was
  1.50× under V1), `REWARD_CURVE_SMOOTH_V2_FLOOR_NUM = 80` (0.80×
  asymptote; was 0.40× under V1),
  `REWARD_CURVE_SMOOTH_V2_SCALE_BPS = 1000` (curve-bend point at 10%
  stake — midpoint multiplier 1.05× at 10% stake; was 3% under V1).
  `MULT_DEN` shared with V1.
- **Resulting target shape** (multiplier at given stake share):

  | stake share | V1 (Tier 40) | V2 (Tier 42) |
  | ----------: | ----------:  | ----------:  |
  | near-zero   | 1.50×        | 1.30×        |
  |  5%  (500)  | 1.27×        | 1.13×        |
  | 10% (1000)  | 1.13×        | 1.05×        |
  | 25% (2500)  | 0.79×        | 0.94×        |
  | 50% (5000)  | 0.46×        | 0.88×        |

  At the bootstrap concentration the V2 multiplier is **~0.88×** — the
  attester pool now stays largely intact instead of half-burning every
  block.  Whales at very large concentrations still hit diminishing
  returns; the floor is just high enough to keep block-by-block burn
  from gating away the bulk of issuance during bootstrap.
- **Anchored shape preserved; only the tuning knobs change.**  Every
  shape invariant pinned for V1 (Tier 40) — concave, monotonically
  decreasing per-unit yield, floor strictly between 0 and peak, soft
  cap (asymptote never reached for any finite stake), strictly
  increasing absolute reward, concave absolute reward, pure-int
  determinism — is re-asserted on V2 in
  `tests/test_reward_curve_smooth_tier_v2.py`.
- **Activation: `REWARD_CURVE_SMOOTH_V2_HEIGHT = 2400`**, riding above
  Tier 41 (1640) with multi-day runway above the current ~840 mainnet
  tip.  Pre-activation: V1 (`reward_curve_multiplier_v3`) preserved
  byte-for-byte for replay determinism.
- **Dispatcher**: `mint_block_reward` and the `_apply_block_state` sim
  mirror in `core/blockchain.py` both gate on
  `REWARD_CURVE_SMOOTH_V2_HEIGHT`; pre-fork callers continue to invoke
  v3 / v2 / v1 in their respective height bands byte-for-byte.

### Tests

- New `tests/test_reward_curve_smooth_tier_v2.py` mirrors the
  `test_reward_curve_smooth_tier40.py` invariant suite on v4
  (activation ordering, target-shape table at canonical stake levels,
  monotonicity, asymptote-never-reached, midpoint-at-SCALE algebraic
  identity, absolute-reward strictly increasing + concave,
  `_NoFloatInt` pure-int determinism, pre-fork legacy byte-identical
  pin, dispatcher source-level wiring check).
- Existing `tests/test_reward_curve_smooth_tier40.py` continues to pin
  V1 byte-for-byte — V1 constants are unchanged.

## [1.40.0] — 2026-04-28

UX / value-prop release.  No consensus changes, no fork gate.  The
public web feed at messagechain.org rendered a list of messages
without any per-message permanence affordance — visually
indistinguishable from a generic social feed despite the chain's
defining property being slashing-backed permanence.  This release
makes the headline guarantee visible at the read surface.

### Added (UX / web feed)

- **Per-message "Permanent · verify" link** on every card on the
  live feed.  Each card links to `/r/<tx_hash>`, a new permanence-
  receipt page that renders inclusion proof + attester count +
  finality threshold and frames the message as "on-chain forever,
  suppression is slashable."
- **Chain-identity footer** on every page (feed, entity profile,
  receipt page).  Surfaces `chain_id`, short `genesis_hash`, and
  short `tip_hash` so a paranoid visitor on a hostile network can
  cross-check the rendered values against the README's pinned
  genesis hash without leaving the page.
- **Tier 25 community handle surfaced end-to-end.**
  `Blockchain.get_recent_messages` now includes the optional
  `community_id` field on each message dict.  The feed UI renders
  it as a `[handle]` chip; the CLI `read` listing renders it as
  `[handle]` after the timestamp.
- **`/v1/info` extended** with `genesis_hash`, `tip_hash`, and
  `state_root` (the data already comes back from
  `Blockchain.get_chain_info`; the public-feed endpoint just wasn't
  forwarding it).
- **`/v1/tx_status` JSON proxy** on the public-feed server,
  inclusion-only.  Same schema as the `_rpc_get_tx_status`
  "included" branch so the receipt-page UI consumes the same JSON
  whether it talks to the JSON-RPC port or the public-feed shim.
  Backed by a new `Blockchain.get_tx_status_public` helper.
- **`/r/<tx_hash>` static permanence-receipt page** mirroring the
  `/e/<entity_id>` pattern.  Renders inclusion proof, block hash,
  attesters, finality threshold flag, and a "Permanent / awaiting
  finality / not found" verdict line in plain language.

### Changed (UX / web feed)

- **Subhead rewrite** on the feed landing page and the README
  headline.  "A permanent, censorship-resistant ledger for human
  speech" reads as protocol jargon to a first-time visitor;
  "An uncensorable public square. Posts, replies, communities,
  votes — on-chain forever. Suppression is slashable." names the
  product before the property.

### Added (CLI)

- **`messagechain read` shows tx_hash, prev pointer, community
  chip, and vote totals** when present — pulling the same fields
  the web feed already had.  Pre-fix, the CLI listing dropped most
  of what the RPC was returning.
- **`messagechain read --community-id <handle>`** filters the
  listing client-side to a single Tier 25 community.
- **`messagechain read --by-address <hex|mc1...>`** filters the
  listing client-side to a single sender (accepts both bare hex and
  bech32 form).

## [1.39.2] — 2026-04-28

Defect-class bugfix: snapshot/restore symmetry for the archive-duty
in-memory state.  Same shape as the 1.37.0 evidence-collection fix
and the 1.39.0 inclusion-list-processor fix — purely closes an
in-memory leak on the bad-state-root rollback path.

### Security (active immediately, no fork gate)

- **Snapshot/restore archive-duty state on block-rollback.**
  `Blockchain._snapshot_memory_state` / `_restore_memory_snapshot`
  omitted the four mutable collections owned by the archive-duty
  subsystem: `validator_archive_misses`,
  `validator_archive_success_streak`,
  `validator_first_active_block`, and `archive_active_snapshot`.
  `_apply_archive_duty` mutates these every block — first-active
  stamps on every newly-observed-above-threshold validator, an
  `ActiveValidatorSnapshot` capture at every challenge block, a
  clear at every epoch close, and miss/streak deltas folded at
  every epoch close.  A bad-state-root block was rolled back via
  `_restore_memory_snapshot` but the archive-duty mutations leaked,
  opening three symmetric attacks: miss-counter poisoning (an
  attacker-bumped entry feeds a phantom withhold tier into the next
  reward payout), first-active poisoning (a brand-new validator's
  bootstrap-grace window anchored to an attacker-chosen height,
  exiting grace earlier or later than honest peers), and
  active-snapshot poisoning (a forged `ActiveValidatorSnapshot` is
  consumed at the next epoch close, producing miss updates the
  canonical chain never agreed to; the dual case clears a
  still-open canonical epoch).  These four fields ARE serialized
  into the on-disk state-snapshot blob, so cold-restart recovery
  was always correct — the gap was purely in-memory rollback.
  Mirrors the 1.39.0 fix for the inclusion-list processor and the
  1.37.0 fix for non_response / bogus_rejection processors.  Pure
  in-memory rollback path; chaindb mirror runs only after the
  state-root check passes, so no fork or activation gate.  Adds a
  structural symmetry guard test that catches the next defect of
  this class at CI time.

## [1.39.1] — 2026-04-29

Hotfix on top of 1.39.0.  The cold-load smoke test introduced in
1.38.2 passed `--service-user`'s default value
(`messagechain:messagechain`, a user:group spec for chown) verbatim
to `sudo -u`, which only accepts a bare user.  Every upgrade
attempt aborted at the smoke-test step with
`sudo: unknown user messagechain:messagechain` before the running
service was ever touched — net-correct from a downtime perspective
(service stays up, the abort is the smoke test doing its job),
but blocks every new release rollout until fixed.

### Fixed

- **`messagechain upgrade` strips the group portion from
  `--service-user` before invoking `sudo -u`** for the cold-load
  smoke test.  `chown` still receives the full `user:group` form
  (correct).  Adds a structural regression test asserting that
  the `sudo -u` slot in the smoke-test invocation never contains
  a `:` separator.

## [1.39.0] — 2026-04-28

Tier 41 hard fork closes the last known honest-acker mis-slash gap
in the non-response evidence pipeline, and the `submit-evidence`
CLI is wired end-to-end so the censorship-evidence path is live
from user surface through mempool to block inclusion.  Also a
defect-class bugfix on inclusion-list-processor rollback.

### Added (consensus — Tier 41 hard fork)

- **Tier 41 — ack-deadline GRACE defense on slash-decision
  comparator** (3858a01). Tier 39 closed the issuer-side ack
  backdating attack but introduced an asymmetry: validate-side
  tolerated `ACK_INCLUSION_GRACE` of slack on the inclusion height,
  but `NonResponseEvidenceProcessor.process` /
  `compute_post_state_root` mirror compared
  `ack_h <= earliest_obs + DEADLINE` with NO grace.  An honest
  acker landing one block past the bare deadline (because a
  colluding next-proposer dropped the ack for one block before
  the next honest proposer included it) was mis-slashed as
  "obligation not met" — a two-validator collusion (Q witnesses
  + 1 deadline-tip proposer) was enough to fabricate a non-response
  slash against an honest target.  Tier 41 widens the
  slash-decision comparator to
  `ack_h <= earliest_obs + DEADLINE + ACK_INCLUSION_GRACE`,
  restoring symmetry with the validate-side bound and mirroring
  the same change in `compute_post_state_root` so propose-time
  and apply-time non-response decisions stay byte-identical
  post-activation.  Activation:
  `ACK_DEADLINE_GRACE_DEFENSE_HEIGHT = 1640`, riding above Tier
  40 (1634) with comfortable runway above the current ~840
  mainnet tip.  Pre-activation: legacy comparator preserved
  byte-for-byte for replay determinism.

### Added (CLI / RPC — censorship evidence wired end-to-end)

- **`messagechain submit-evidence censorship --receipt
  <bundle.json>`** (5f836ec). Pre-fix the subcommand was a
  print-only stub; every Tier 30-35 hardening of the slashing
  apply paths shipped a back end whose user-facing entry point
  did not actually sign or submit a tx, defeating the
  censorship-evidence pipeline at the user surface.  The wired
  command reads a receipt-bundle (SubmissionReceipt + the
  receipted MessageTransaction), cross-checks via
  `get_tx_status` that the tx is NOT on chain, signs a
  `CensorshipEvidenceTx` through the personal-wallet keypair
  cache, and submits via the new `submit_censorship_evidence`
  RPC.  Auto-fee + auto-nonce + auto-discover-endpoint, same
  single-line invocation shape as `cmd_send` / `cmd_transfer`.
- **New server RPC `submit_censorship_evidence`** (5f836ec).
  Validates the tx via the live `validate_censorship_evidence_tx`
  gate, runs the cross-pool WOTS+ leaf-reuse check, and admits
  to the existing mempool censorship-evidence pool.
- **Block producer drains
  `mempool.censorship_evidence_pool`** (5f836ec) into proposed
  blocks and removes admitted evidence on success.  Without this
  drain, every submission would sit in the mempool unmineable.
- **`submit-evidence bogus-rejection` / `non-response`
  diagnostics** (5f836ec). Both subcommands now print clear
  "not yet wired" messages naming the consensus-layer module so
  the CLI surface always resolves to a real command (no more
  "Unknown command" from the receipt CLI's escalation hint).
  Legacy `--tx <hash>` invocation prints a migration message
  naming the new subcommand surface.

### Added (CLI / UX — first-command keygen tractable)

- **First-command keygen returns in seconds, not minutes**
  (451059e).  Three stacked wins: (1) personal-wallet default
  tree height drops from 20 (~1M leaves, ~90 min serial) to 16
  (~65k leaves, ~5 min serial); per-entity heights are stored on
  chain so different entities at different heights coexist, and
  validators stay at h=20 to amortize keygen across ~2 years of
  slot signing.  Fallback probes the legacy h=20 cache first so
  existing wallets keep their identity.  (2) `cmd_generate_key`
  prints the 24-word recovery phrase BEFORE running keygen and
  flushes stdout, so the user can back up the phrase during the
  keygen wait instead of staring at a silent progress bar.  (3)
  Parallel WOTS+ leaf derivation via `multiprocessing.Pool`,
  gated by `KEYGEN_PARALLEL_MIN_LEAVES = 16384` so small trees
  stay serial (subprocess-spawn overhead would dominate).
  `KEYGEN_WORKERS` env: `0`=auto (cap 8), `1`=serial, `N`=fixed.
  Stacked impact at h=16, 8 cores: first-command address arrives
  in <1 min instead of ~90 min.

### Fixed

- **Snapshot/restore inclusion-list-processor state on
  block-rollback** (96400dc). `Blockchain._snapshot_memory_state`
  / `_restore_memory_snapshot` omitted the four mutable
  collections owned by `inclusion_list_processor`
  (`active_lists`, `inclusions_seen`, `proposers_by_height`,
  `processed_violations`).  A bad-state-root block was rolled
  back via `_restore_memory_snapshot` but the IL-processor
  mutations leaked, opening two attacks: dedup poisoning (bumped
  `processed_violations` triple silently blocks honest
  resubmission of the same violation evidence), and
  `active_lists` poisoning (forged list registration persists
  past rollback, grounding phantom InclusionListViolation slashes
  against honest proposers).  Mirrors the 1.37.0 fix for
  non_response / bogus_rejection processors.  Pure in-memory
  rollback path; chaindb mirror runs only after the state-root
  check passes, so no fork or activation gate.  Adds a
  structural symmetry guard test that catches the next defect
  of this class at CI time.

## [1.38.2] — 2026-04-28

Operational hardening: the `upgrade` CLI now runs a cold-load
smoke test against the existing `chain.db` BEFORE stopping the
running service.  Catches the failure mode that took down
validator-1 during the 1.38.0 rollout (see 1.38.1 for context):
a wire-format slot whose activation height was crossed under an
older binary that lacked the slot, then encountered by a newer
decoder that expects it — invisible to the warm running service,
fatal on cold-load.

### Changed (operations)

- **`messagechain upgrade --yes`** now spawns a short-lived
  subprocess that imports the new code from the verified clone
  and attempts `Blockchain(db=ChainDB(...))` against the live
  data dir.  If the smoke test fails (or hangs >120s), the
  upgrade aborts with a clear diagnostic and the running
  service is left untouched.  Only after the smoke test passes
  does the CLI proceed to `systemctl stop`, backup, install,
  and post-restart health check.  Net effect: the previous
  failure mode (new binary can't read chain.db, but we only
  discover this AFTER the running service was stopped, leaving
  the operator to repair from the bak directory) cannot recur.
- The smoke test is read-only against `chain.db` and runs as
  the service user via `sudo -n -u <service_user>` so it
  exercises the same path the post-restart service will use.

## [1.38.1] — 2026-04-28

Hotfix release.  Re-runways the Tier 33–40 activation heights so an
existing chain that advanced past the original heights under an older
binary (specifically: 1.34.0, which contains Tiers 0–32 and was the
last version live-deployed on mainnet validators) can be upgraded
without crashing on cold-load.

### Why

The 1.38.0 cold-load attempt on validator-1 (mainnet, height ≈ 840)
crashed in `_decode_non_response_evidence_slot` with `Block blob
truncated mid-non_response_evidence_txs entry`.  Diagnosis: the chain
was produced entirely under 1.34.0, which lacks Tier 35's wire-format
slot.  When 1.38.0 cold-loaded those same blocks, its decoder saw
`block_number >= NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT (766)` and
tried to read a slot that was never encoded — interpreting the
trailing `declared_hash` bytes as a count + length-prefixed entries,
crashing on the (garbage) entry length.

The chain has been running honestly under 1.34.0's rules the whole
time; the activation heights for Tiers 33–40 simply passed without
the corresponding code being live on the network.

### Changed (consensus)

- **Tier 33 (NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT)**:
  762 → 1496.
- **Tier 34 (FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT)**: 764 → 1498.
- **Tier 35 (NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT)**: 766 → 1500.
  This is the wire-format slot whose missed activation crashed the
  1.38.0 cold-load.
- **Tier 36 (ATTESTER_DYNAMIC_COMMITTEE_HEIGHT)**: 768 → 1502.
- **Tier 37 (FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT)**: 800 → 1534.
- **Tier 38 (REWARD_CURVE_LARGE_BAND_HEIGHT)**: 801 → 1535.
- **Tier 39 (ACK_BACKDATING_DEFENSE_HEIGHT)**: 802 → 1536.
- **Tier 40 (REWARD_CURVE_SMOOTH_HEIGHT)**: 900 → 1634.  Already in
  the future, but moved to preserve the +734 spacing across the
  cohort and to satisfy the `Tier 40 > Tier 39` ordering assertion.

The +734 shift preserves every relative-ordering assertion in
`config.py`.  All `assert X_HEIGHT > Y_HEIGHT` checks that hold on
the original heights also hold on the shifted ones.

### Operator notes

- All validators must upgrade to 1.38.1.  The new heights give
  ~660 blocks of runway from the current tip (~840) to Tier 35's
  new activation at 1500 — comfortably more than a full cold-restart
  cycle of both validators.
- The 1.38.0 tag remains on GitHub for history, but **do not
  deploy 1.38.0 to a node whose chain.db has blocks past height
  766** — it will crash on cold-load.  1.38.1 obsoletes 1.38.0
  for any operator with a live chain.

## [1.38.0] — 2026-04-28

Two new hard forks plus a no-fork wallet UX pass, an internal state-
root refactor, and a feed-page restyle.  The headline anchor revision
is the reward-curve shape: from a piecewise sigmoid (small < middle >
large, large = saturating-linear) to a single smooth concave function
whose per-unit-stake yield diminishes monotonically from a peak at
near-zero stake toward a floor as stake grows large, asymptotically
approaching the floor without ever reaching it.  Replaces the entire
small/mid/baseline/saturating-tail piecewise machinery of Tiers 20+38
with one continuous rational function; preserves the "always earn
more for more stake" property (absolute reward strictly increasing and
concave in stake) while mitigating PoS's natural rich-get-richer drift
more aggressively.  Tier 39 closes a residual collusion path against
the Tier 35 silent-drop slashing arm before Tier 40 lands.

### Tier 39 — Submission-ack backdating defense (hard fork, height 802)

- A coerced target validator + colluding proposer could shift the
  `witness_ack_registry`'s recorded discharge height to any past
  block by signing an ack with `commit_height = earliest_obs - 1` and
  landing it at the late tip.  The non-response apply gate then read
  "obligation met" and skipped the slash — neutering Tier 35's
  silent-drop arm under two-validator collusion.  Adversary defended:
  validator collusion (the primary anchored adversary).
- Two complementary defenses ride at
  `ACK_BACKDATING_DEFENSE_HEIGHT = 802` (one above Tier 38):
  (a) bound `ack.commit_height` to
      `[block_height - (DEADLINE + ACK_INCLUSION_GRACE), block_height]`
      so an ack landing at the tip cannot point arbitrarily far back;
  (b) record `block.header.block_number` (the actual inclusion
      height) in the `witness_ack_registry` instead of
      `ack.commit_height`, removing issuer control over the deadline
      reference entirely.
- Pre-activation: byte-identical replay.  Tests:
  `tests/test_ack_backdating_defense.py` (6 tests).
- Source: `7821331` (audit top-3 branch, merged via `830209b`).

### Tier 40 — Smooth concave reward curve (hard fork, height 900)

- **`reward_curve_multiplier_v3(stake_bps)`** in
  `messagechain/economics/inflation.py`.  Pure-int rational form:

      multiplier(s) = (FLOOR_NUM·s + PEAK_NUM·SCALE) /
                      (MULT_DEN  · (SCALE + s))

  Properties (all derivable from the formula, asserted by
  `tests/test_reward_curve_smooth_tier40.py`): peak at stake_bps=0 is
  exactly PEAK_NUM/MULT_DEN; asymptote at stake_bps→∞ is FLOOR_NUM/
  MULT_DEN, never reached for any finite stake; multiplier strictly
  decreasing in stake_bps (no kinks, no flat region, no hump);
  absolute reward (= stake · multiplier) strictly increasing AND
  concave in stake (always pays more, but each marginal unit pays
  less — diminishing returns).
- **Tuning constants in `messagechain/config.py`**:
  `REWARD_CURVE_SMOOTH_PEAK_NUM = 150` (1.50x at near-zero stake),
  `REWARD_CURVE_SMOOTH_FLOOR_NUM = 40` (0.40x asymptote),
  `REWARD_CURVE_SMOOTH_MULT_DEN = 100`,
  `REWARD_CURVE_SMOOTH_SCALE_BPS = 300` (curve-bend point: at 3%
  stake the multiplier is exactly the midpoint between peak and
  floor, 0.95x; at 30% stake the multiplier is exactly 0.5x —
  algebraically equal to the old Tier 38 hard floor as a continuity
  sanity check, and the curve continues to compress past it instead
  of flat-lining).
- **Dispatcher in `mint_block_reward` and its sim mirror in
  `_apply_block_state`**: at heights >=
  `REWARD_CURVE_SMOOTH_HEIGHT (900)` swap in v3.  Pre-Tier-40 callers
  continue to invoke v2 (Tier 38) or v1 (Tier 20) byte-for-byte;
  replay determinism preserved across the entire fork ladder.
- **CLAUDE.md anchor rewritten** ("Stake concentration is softly
  capped via diminishing returns") to reflect the new shape.  The old
  shape (small < middle > large, large = linear cap) is retired; the
  new shape (concave, monotonically diminishing per-unit yield,
  asymptotic soft cap, no hard cap, no special small-end depression,
  no per-validator anti-sybil gate) is anchored.  Sybil-splitting a
  whale into many honest validators is recognized as desirable
  (decentralization-positive); operational infrastructure cost under
  each identity is the natural sybil tax.
- **Tests** (`tests/test_reward_curve_smooth_tier40.py`): activation
  ordering (40 > 38 > 20, also > 39), peak-at-zero, asymptote-never-reached
  across a dense stake-share grid, strict monotonic decrease at every
  consecutive grid pair, midpoint-at-SCALE algebraic identity,
  absolute-reward strictly-increasing, absolute-reward concavity (via
  non-increasing marginal-reward differences over an evenly-spaced
  triple), pure-int determinism (`_NoFloatInt` sentinel — helper
  must not coerce any input through `float()`), pre-fork v1/v2 byte-
  identical pinning (guards against accidental edits), dispatcher
  source-level wiring check (apply path + sim mirror both gate v3 on
  `REWARD_CURVE_SMOOTH_HEIGHT`).  103 subtest assertions in 2.1s.
- Source: `e7a0467` (merged via `1752736`).

### Changed (UX — wallet first-touch, no fork)

- **README first-touch path no longer pays full WOTS+ keygen on every
  command.**  `cmd_generate_key` now warms the personal-wallet cache;
  `cmd_verify_key` routes through the shared resolver;
  `cmd_balance` / `cmd_key_status` accept a read-only `--address` flag
  that skips key resolution entirely; `cmd_start --mine` consults the
  daemon's `_load_or_create_entity` cache.  Also fixes a stale
  `info --entity-id` printf in `cmd_bootstrap_seed` (the `info`
  subcommand doesn't accept that flag) — now points at
  `balance --address mc1...`.  Client-side only.  Tests:
  `tests/test_wallet_cache_first_commands.py` (5 tests).
- Source: `7821331` (merged via `830209b`).

### Changed (internal — state-root computation, no fork)

- **`compute_post_state_root_for_block(block)`** helper added.  The
  legacy 18-explicit-kwarg `compute_post_state_root` signature shipped
  two mainnet bugs already (1.29.x react-tx; the post-Tier-32 sim-vs-
  apply mirroring campaign).  The new helper reads tx lists via the
  canonical `_BLOCK_TX_LIST_ATTRS` registry — adding a new tx kind is
  now a one-line append.  Both call sites (`propose_block` +
  `add_block` pre-check) route through the helper; the legacy
  `compute_post_state_root` signature is kept for tests.  A
  structural-guard test pins the registry-walk pattern.  Byte-
  identical state-root output for every historical block; no fork
  required.  Tests:
  `tests/test_compute_post_state_root_registry.py` (5 tests).
- Source: `7821331` (merged via `830209b`).

### Changed (UI — public feed)

- **Feed call-to-action restyle** at `messagechain/static/feed.html`:
  bare green numbers (no inline labels); faucet element styled as a
  matching CTA tile with a caret affordance, lining up visually with
  the GitHub / first-message / run-a-node tiles.  Static asset only;
  no protocol or backend impact.
- Source: `0a80c7f` (merged via `9c63b75`).

### Operator notes

- **Two activation heights ride in this release.**  Tier 39 at
  `ACK_BACKDATING_DEFENSE_HEIGHT = 802` and Tier 40 at
  `REWARD_CURVE_SMOOTH_HEIGHT = 900`.  All validators must upgrade to
  1.38.0 within the runway window (current tip → 802).  Roll
  validators with `messagechain upgrade --yes`.

## [1.37.0] — 2026-04-28

Second multi-axis audit pass against current `origin/main` surfaced 41
findings; the cumulative top-3 by severity × leverage × ROI land here.
One no-fork security correctness fix and two new hard-fork tiers.

### Security (active immediately, no fork gate)

- **Block-rollback now snapshots the four evidence-tracking
  collections that `_apply_block_state` mutates.**  `_snapshot_memory_
  state` and `_restore_memory_snapshot` captured `_processed_evidence`
  but NOT `non_response_processor.processed`,
  `bogus_rejection_processor.processed`, `censorship_processor.pending`,
  or `witness_ack_registry`.  When a block failed the post-apply
  state_root check at `_append_block` and unwound via
  `_restore_memory_snapshot`, those four mutations stayed bumped — so
  a coerced/colluding proposer crafting a block with a valid evidence
  tx + a deliberately-wrong `state_root` could permanently poison the
  evidence-dedup state.  A later honest resubmission of the same
  evidence then hit `has_processed` (e.g. `non_response_evidence.py`'s
  dedup gate) and the slash never landed; same shape lets a
  rolled-back ack-registry insert silently kill any future
  NonResponseEvidenceTx whose `request_hash` matches.  The fix
  extends snapshot/restore to deep-copy the four collections (deepcopy
  for `censorship_processor.pending` since the values are mutable
  `_PendingEvidence` records; shallow `dict(...)` / `set(...)` for the
  rest).  No-fork: snapshot/restore is purely in-memory; chaindb
  mirror runs only after the state_root check passes, so historical
  replay is byte-identical.  Adversary defended: validator collusion
  (the primary anchored adversary).

### Changed (consensus, gated by activation height)

- **Tier 37 — forced-inclusion entity-cap excuse no longer counts
  same-entity lower-fpb txs toward the cap.**  Tier 34 (1.35.0) wired
  the forced-inclusion gate to walk every block tx-list field, but
  excuse #3 ("entity already at `MAX_TXS_PER_ENTITY_PER_BLOCK`")
  accepted a colluding proposer filling the quota with deliberately-
  cheap lower-fpb txs from a single victim entity at sequential
  nonces — and then "excusing" the higher-fpb forced tx of the same
  entity.  Because nonces must be sequential the forced tx IS the
  next one after the included ones, so it always fits structurally;
  the cap was an artifact of the proposer's own selection, not a real
  inclusion blocker.  Net effect: the CLAUDE.md "high-fpb tx cannot
  be suppressed without slashable evidence" anchor was bypassable
  with no slashing risk for the colluding proposer.  Tier 37
  tightens excuse #3: a same-entity block tx whose fee-per-byte is
  STRICTLY lower than the forced tx's fpb does not contribute to
  that forced tx's `entity_count` for the excuse calculation.  fpb
  comparison is integer cross-multiplication
  (`other_fee * ref_bytes < ref_fee * other_bytes`) — no float on
  the consensus path, mirroring the 1.35.0 honesty-curve cleanliness.
  Strict `<` (not `≤`) means same-fpb same-entity txs still count, so
  a proposer's right to choose among equal-density alternatives is
  preserved.  Activation at `FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT
  = 800`.  Pre-fork behavior preserved byte-identically.  Adversary
  defended: validator collusion (primary anchored adversary), at the
  inclusion-rule abuse surface.

- **Tier 38 — reward-curve large band saturates downward, restoring
  the anchored sigmoid shape.**  CLAUDE.md anchors a stake-reward
  shape where small < middle > large with large stakers earning at a
  STRICTLY LOWER per-unit-stake rate than mid-tier, so distributions
  compress upward over time and never ossify into permanent
  plutocracy.  The live curve was piecewise-constant 0.80 / 1.25 /
  1.00 — a 5% mid-tier validator and a 40% whale earned at the SAME
  per-token rate (1.0× both), missing the saturation property
  entirely.  Tier 38 adds a fourth band: the 0.80 / 1.25 / 1.00
  small/mid/flat-large bands stay byte-identical for stake share <
  15%, then between 15% and 30% the multiplier interpolates linearly
  from 1.00 down to a floor of 0.5 (50/100), and stays at 0.5 past
  30%.  Sample yield curve: 0.1%→0.80, 1%→1.25, 5%→1.00, 10%→1.00,
  15%→1.00, 20%→0.83, 25%→0.67, 30%→0.50, 40%→0.50.  Mid-vs-floor
  compression ratio is 2.5× (1.25 / 0.50) — large stakers still earn
  proportionally more in absolute tokens than smaller validators,
  still preferring 24/7 uptime, but no longer compounding their
  share at the same per-token rate as mid-tier.  All arithmetic is
  exact-rational integer (mirrors the 1.35.0 honesty-curve technique;
  pinned by a `_NoFloatInt` sentinel test).  Activation at
  `REWARD_CURVE_LARGE_BAND_HEIGHT = 801`.  Pre-fork behavior
  preserved byte-identically.  Anchor protected: stake-concentration
  cap (sigmoid shape) and the bootstrap→community handoff arc.

### Operator notes

- All validators must upgrade to 1.37.0 within the runway window
  (current tip → 800/801).  Tier 37 + Tier 38 ride one block apart;
  the in-memory snapshot/restore fix is active immediately on
  upgrade.  Roll validators with `messagechain upgrade --yes`.

## [1.36.0] — 2026-04-28

Multi-axis audit (UX / Security / Long-term / Value-prop / Economics)
surfaced 45 findings across origin/main at 1.35.0; the top-3 by
severity × leverage × ROI are landed in this release.  Two new hard
forks (Tier 35 + Tier 36) plus one hot consensus-correctness fix.

### Security (active immediately, no fork gate)

- **Matured censorship slash now refreshes the offender's state_tree
  leaf — closes a latent state_root-drift / chain-stall bug.**
  `_apply_censorship_slash` mutated `supply.staked[offender]` and
  `pending_unstakes` via `burn_slash_proportional` but never called
  `_touch_state({offender_id})`; the censorship evidence tx's
  `affected_entities()` returned only `{submitter_id}`, leaving no
  path that refreshed the offender's leaf when the offender wasn't
  also the proposer.  Net effect: when censorship matured with
  `offender ≠ proposer`, the proposer's signed `state_root` committed
  to the stale leaf while any peer recomputing from `supply.staked`
  produced a different root → block rejected → chain stall.  Fix:
  direct refresh at the apply site PLUS a structural guard inside
  `SupplyTracker.burn_slash_proportional` that takes an optional
  `blockchain=` kwarg and refreshes the offender leaf itself, so
  every existing call site (censorship, IL violation, bogus rejection,
  witness non-response) is covered AND no future caller can
  re-introduce the same gap.  No fork needed (no historical replay
  could have reached a divergent root without already being broken)
  (c22a7aa).
- **Proposer-side `compute_post_state_root` simulator now mirrors the
  apply path for ALL evidence kinds — closes silent
  proposer-self-rejection on bogus_rejection / censorship-mature /
  IL-violation slashes that have shipped curve-graded apply since
  Tier 30/31/32.**  Pre-fix the simulator burned a flat
  `CENSORSHIP_SLASH_BPS` against `staked` only on every evidence
  kind, while the apply path post-Tier-30/31/32 used the honesty
  curve and drained `(staked + pending_unstakes)`.  A proposer
  building a block carrying any of those evidence kinds since Tier
  32 activated would compute a sim root that diverged from the
  apply root and the block would self-reject.  Bogus_rejection
  evidence has been silently un-buildable from `propose_block` for
  the entire post-Tier-32 mainnet history; censorship-mature and
  IL-violation since their respective tier activations.  This fix
  replays byte-identically pre-fork on each path; post-fork the
  simulator routes through the same curve-graded computation as
  apply.  A shared `_sim_burn_slash_proportional_stake_delta` helper
  inside `compute_post_state_root` apportions burns against sim
  dicts and is reused at all four slash sites for the
  Tier-31/33/IL/Censorship pending-drain path (e07dcb7).

### Changed (consensus, gated by activation height)

- **Tier 35 — `NonResponseEvidenceTx` block slot wired in, closing
  a categorical bypass of the validator-collusion defense.**
  Audit finding #1.  Every prior NonResponseEvidenceTx admission /
  processor change shipped dead code: `Block` had no
  `non_response_evidence_txs` field, the canonical
  `_BLOCK_TX_LIST_ATTRS` registries didn't list it, and
  `_apply_block_state` never invoked `NonResponseEvidenceProcessor`.
  A coerced validator who silently dropped a witnessed POST could
  lose nothing — the entire silent-drop arm of censorship
  resistance was unprotected on mainnet.  Tier 35 wires the slot
  end-to-end: dataclass field on `Block`, slot in both `to_bytes` /
  `from_bytes` (gated on this height — pre-fork blocks emit zero
  bytes for the slot, byte-identical to historical encoding), entry
  in both forced-inclusion and Blockchain `_BLOCK_TX_LIST_ATTRS`
  registries (so Tier 34's multi-list gate sees forced NREs in
  their correct slot), and an apply loop in `_apply_block_state`
  that mirrors the bogus-rejection apply path exactly (Tier 32
  curve + Tier 33 pending-unstake drain via
  `burn_slash_proportional`).  Activation at
  `NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT = 766`.  Pre-fork replay
  byte-identical (c813cec, e07dcb7).

- **Tier 36 — dynamic attester committee shrinks below pool size,
  restoring floor-era validator P&L.**  Audit finding #3.  Tier 4's
  fixed 128-slot committee + integer pool division produced a
  silent zero-payout regime: at floor era (BLOCK_REWARD_FLOOR=4,
  proposer_share=1, attester_pool=3), `3 // 128 == 0` — every
  attester earned 0 from issuance forever once the floor binds (~year
  8 onward).  Even at genesis (`pool=12`) only the first 12 slots
  were paid; the remaining 116 burned (~90% leak of intended
  budget).  Two CLAUDE.md anchors violated at once: "validator
  profitability over decades" (issuance income → 0 forever) and
  "stake concentration is capped — sigmoid mid-tier compression
  band closes the gap fastest" (the 1.25× mid multiplier on a base
  of 0 is still 0; entire compression mechanism inert at floor era).
  Tier 36 fixes both with a dynamic committee: when `attester_pool
  < ATTESTER_COMMITTEE_TARGET_SIZE`, the caller shrinks
  `committee_size` to `min(target, pool)` so every paid slot
  receives ≥ 1 token.  Selection rule, randomness, stake-weighted
  blending, and the underlying inflation curve are unchanged —
  only the paid prefix length shrinks.  Liveness unchanged (every
  committee member still attests for finality; only payout
  eligibility changes).  Activation at
  `ATTESTER_DYNAMIC_COMMITTEE_HEIGHT = 768`.  Pre-fork replay
  byte-identical (e52f5a2).

### Operator notes

- All validators must upgrade to 1.36.0 within the runway window
  (current tip → 766).  Pre-1.36.0 nodes will continue to silently
  lose the witness-non-response slashing arm; will continue to
  self-reject any block they propose carrying a bogus_rejection /
  censorship-mature / IL-violation evidence tx; and will continue
  to burn the entire attester pool at floor era.  Roll validators
  with `messagechain upgrade --yes`.
- The censorship-slash `_touch_state` refresh and the
  `compute_post_state_root` evidence-mirror are active immediately
  on upgrade (no fork gate).  Both are correctness fixes against
  bugs that mask each other on the live 2-validator topology
  (offender == proposer in the censorship case; no propose_block
  path has been carrying bogus_rejection / IL evidence yet because
  it would self-reject) — but a third validator joining the network
  would have hit one of these on the first matured slash.

## [1.35.0] — 2026-04-28

Audit-driven security cluster — three findings landed together
because the upgrade window naturally couples the slashing-basis
extension (Tier 33) and the attester-side gate change (Tier 34) with
the consensus-determinism cleanup.

### Security (active immediately, no fork gate)

- **Honesty-curve severity is computed in pure integer arithmetic.**
  `slashing_severity` previously built `raw = base * escalation *
  float_relief` where `float_relief = HONEST_TRACK_THRESHOLD / track`,
  then truncated via `int(raw)`.  IEEE-754 division of small bounded
  integers is exact-rounded on every conformant platform, so in
  practice the float form was deterministic — but the function's
  output drives the slash percentage that mutates `staked` /
  `total_supply` (consensus state), and "in practice deterministic"
  is a weaker bar than the chain's permanent ledger demands.  Rewrites
  the relief as an exact rational `(num, den)` and computes
  `sev_int = (base * esc * num) // den` in pure integer arithmetic.
  Mathematically identical to the float form on the curve's input
  range — every existing honesty-curve test passes byte-identically —
  but auditably deterministic without depending on float semantics.
  Adds a determinism golden-table test pinning severity outputs across
  representative `(track_record, prior)` cells, plus a `_NoFloatInt`
  sentinel that proves the consensus hot-path never promotes any
  input through `float()` (catches accidental reintroduction of
  float relief in a future refactor).

### Changed (consensus, gated by activation height)

- **Tier 33 — non-response + bogus-rejection slashes drain
  `pending_unstakes`.** Tier 31 (1.34.0) widened the slash basis on
  `_apply_censorship_slash` and `process_inclusion_list_violation`
  from `staked` only to `(staked + pending_unstakes)`, closing the
  censor-then-unstake evasion.  Tier 32 (1.34.0 sibling) routed the
  witness-non-response and bogus-rejection apply paths through the
  honesty curve — but those two paths still drained `staked` only.
  Same evasion still worked: a coerced/colluding validator could
  silently drop a witnessed submission (or sign a forged
  REJECT_INVALID_SIG), immediately submit an unstake, and ride out the
  unbonding queue (EVIDENCE_MATURITY_BLOCKS ~ 2.7h vs UNBONDING_PERIOD
  > 14 days) with ≥ 90% of the would-be slashed stake intact.  Tier
  33 closes both, mirroring Tier 31 exactly: the apply path computes
  `sev_pct` via `slashing_severity` (always live by Tier 32) and
  applies via `supply.burn_slash_proportional(offender_id, sev_pct)`.
  Pre-Tier-33 paths preserved byte-for-byte.  Activation at
  `NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT = 762`.

- **Tier 34 — forced-inclusion gate covers all block tx-list
  fields.** `check_forced_inclusion` (the attester-enforced soft
  censorship-resistance gate) was scoped to message-only txs from day
  one: it built `included_hashes` from `block.transactions` only and
  accounted for byte budget via `len(tx.message)` (payload bytes,
  not stored bytes).  Two correctness gaps: (a) honest blocks placing
  a forced TransferTransaction in `block.transfer_transactions` had
  the legacy gate raise `AttributeError` on the path (production has
  not bitten because mainnet rarely keeps a transfer pending for
  FORCED_INCLUSION_WAIT_BLOCKS, but the trap was armed); (b) the
  CLAUDE.md "high-fpb tx cannot be suppressed without slashable
  evidence" anchor silently exempted every non-message tx kind from
  the gate — a colluding proposer dropping a forced transfer walked
  free.  Tier 34 closes both: post-fork the gate walks every known
  block tx-list field (`_BLOCK_TX_LIST_ATTRS` registry) and accounts
  for stored bytes via `len(ftx.to_bytes())` — the same axis the
  mempool's fee-per-byte ranking already uses.  Pre-fork: legacy
  message-only path preserved, but defensively filtered to message
  kinds at the top so the legacy AttributeError crash on transfers
  is avoided (liveness-safe).  Activation at
  `FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT = 764`.  Scope: covers tx
  kinds the consensus mempool already tracks (Message + Transfer);
  Stake / Unstake / Governance / Authority / React live in
  server-local pools today and require a follow-up architectural
  lift to bring them under the gate — Tier 34 is the prerequisite
  that makes the broader expansion mechanical (one tuple-extension +
  matching mempool surface).

### Operator notes

- All validators must upgrade to 1.35.0 within the runway window
  (current tip → 762).  Pre-1.35.0 nodes will continue to apply Tier
  31's pending-drain only on censorship + IL paths, missing the
  same protection on the witness-non-response and bogus-rejection
  paths; they will also continue to enforce the legacy
  message-only forced-inclusion check.  Roll validators with
  `messagechain upgrade --yes`.
- The honesty-curve integer-rewrite is active immediately on upgrade
  (no fork gate).  Outputs are byte-identical to the prior float
  form for every `(base, escalation, prior, track)` cell within the
  curve's input range, so historical replay is unchanged.

## [1.34.0] — 2026-04-28

### Fixed
- **Censorship & inclusion-list slashes now drain `pending_unstakes`
  too — closes the unstake-evasion attack on the validator-collusion
  defense (security).** Pre-fix, both `_apply_censorship_slash` and
  `process_inclusion_list_violation` computed the slash percentage
  against `staked` only and capped the burn at the post-unstake
  remainder.  `EVIDENCE_MATURITY_BLOCKS` (~16 blocks ~ 2.7h) is far
  shorter than `UNBONDING_PERIOD` (>14 days), so a coerced/colluding
  validator could censor a high-fee-per-byte tx, immediately submit
  an `unstake`, and ride out the unbonding queue with ≥90% of the
  would-be slashed stake intact — the protocol's anchored top-priority
  defense (validator collusion) was effectively gutted on mainnet.
  Both apply paths now scale severity (curve-graded percentage from
  Tier 30) against `staked + pending_unstakes` and drain
  proportionally from BOTH buckets, mirroring the canonical pattern
  at `validate_slash_transaction` and the equivocation-slash loop in
  `slash_validator()`.  The change is hard-fork gated on the new
  `CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT` (Tier 31, height 760) so
  pre-fork replay is byte-identical.  A new
  `SupplyTracker.burn_slash_proportional` helper centralizes the
  pure-burn proportional-drain shape so future slash paths can reuse
  it without reinventing the loop.

### Changed
- **Tier 30 sibling — honesty curve closes the last two flat-BPS
  soft-slash paths.**  Tier 30 (1.33.0) routed `_apply_censorship_slash`
  and `process_inclusion_list_violation` through the honesty curve,
  but two siblings kept burning flat BPS on first offense:
  `compute_non_response_slash_amount` /
  `NonResponseEvidenceProcessor.process` burned a flat
  `WITNESS_NON_RESPONSE_SLASH_BPS` (5%) on every silent-drop slash —
  a long-tenured validator dropping one witnessed submission under
  transient packet loss paid the same as a deliberate silent-drop
  censoring node.  `BogusRejectionProcessor.process` burned a flat
  `CENSORSHIP_SLASH_BPS` (10%) on every bogus REJECT_INVALID_SIG —
  a borderline rejection racing a fee-rule fork edge cost the same
  as deliberate forged-rejection censorship.  This fork adds
  `OffenseKind.WITNESS_NON_RESPONSE` and `OffenseKind.BOGUS_REJECTION`
  to the curve and routes both apply paths through `slashing_severity`
  with `Unambiguity.AMBIGUOUS` on first offense; subsequent offenses
  escalate via `slash_offense_counts`.  Gated on
  `HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT` (Tier 32, height 761);
  pre-fork behavior is byte-identical to legacy for replay determinism.
- **Personal-wallet keypair cache closes the 30-minute keygen cliff on
  the README's first-message walk-through.** Every `messagechain send`
  (and the five sibling spending commands -- `transfer`, `stake`,
  `unstake`, `set-authority-key`, `rotate-key`, plus `account`,
  `balance`, `propose`, `vote`, `react`, `key-status`,
  `emergency-revoke`, `set-receipt-subtree-root`, `bootstrap-seed`,
  `multi-submit`) used to call `Entity.create(private_key)`, which
  re-derives the 1,048,576-leaf WOTS+ Merkle tree from scratch on
  every invocation -- ~20-30 minutes per command on real hardware at
  the production tree height.  The validator daemon already had a
  working HMAC-keyed encrypted keypair cache; personal wallets just
  didn't use it.  Refactored the daemon's encode / decode helpers
  into the shared `messagechain.identity.keypair_cache` module and
  added a transparent personal-wallet path rooted at
  `~/.messagechain/wallet_cache/` -- same on-disk shape, same HMAC
  authentication, no flag required.  Cold first send writes the
  cache; warm subsequent sends are ~3000x faster (~11 ms vs ~35 s
  at test height=14; the speedup scales with `2^height`).  A stolen
  cache file alone is useless without the seed phrase (HMAC keyed
  on a domain-separated derivation of the private key).  Fixes the
  first-impression UX wedge that made the README's "send your first
  message" instruction unusable for newcomers.

## [1.33.0] — 2026-04-28

### Fixed
- **State-root sim mirrors inclusion-list mutations.** A block carrying
  a non-empty `inclusion_list` or any
  `inclusion_list_violation_evidence_txs` self-rejected at the post-
  apply state-root commitment check.  `process_inclusion_list_violation`
  slashed stake on the apply path and
  `_apply_inclusion_list_coverage_leak` drained stake from coverage-
  divergent attesters, but neither mutation was mirrored in
  `compute_post_state_root` — the proposer's committed root diverged
  from the validator-side post-apply root and any IL-bearing block
  errored "Invalid state_root — state commitment mismatch."  Threads
  both fields through `propose_block`, `consensus.create_block`, and
  the sim, with the sim mirroring the slash drain + coverage leak
  exactly.  Active immediately (no fork — block-validity rule was
  already broken; the fix is what makes IL-bearing blocks actually
  acceptable).
- **Mempool fee-per-byte ranking uses STORED bytes.** Pre-fix
  `_fee_per_byte` divided by `len(tx.message)`, which over-stated
  MessageTransaction density by ~50× (witness bytes invisible to the
  comparator) and collapsed non-message kinds (Transfer, Stake,
  Unstake, Governance, Authority, Slash, React) to absolute-fee
  ranking via the `getattr(tx, "message", b"")` fallback.  Switches
  to `len(tx.to_bytes())` with a per-tx_hash cache populated on
  insert and torn down on remove.  Active immediately — node-local
  ranking change, not consensus.

### Changed
- **Tier 30 — honest-operator insurance for soft-slash paths.**
  CLAUDE.md anchors "honest operators are insured against accidents";
  catastrophic burns are reserved for unambiguous, intentional
  violations.  Two soft-slash paths violated the anchor:
  `_apply_censorship_slash` burned a flat `CENSORSHIP_SLASH_BPS`
  (10%) without consulting the honesty curve, and
  `process_inclusion_list_violation` classified first offenses as
  `Unambiguity.UNAMBIGUOUS` (50%/100% slash on a single missed
  include — plausibly honest mempool churn).  Tier 30 routes both
  paths through `slashing_severity` with `Unambiguity.AMBIGUOUS` on
  first offense; subsequent offenses (read off
  `slash_offense_counts`, persisted from Tier 24) escalate via the
  existing curve mechanics.  Adds `OffenseKind.CENSORSHIP` to the
  honesty-curve enum and `HONESTY_CURVE_INSURANCE_HEIGHT = 756`
  (rides above Tier 29 with the standard runway buffer).  Pre-Tier-30
  behavior on both paths is byte-identical to legacy for historical
  replay determinism.

## [1.32.1] — 2026-04-28

### Docs
- **README — validator stake floor reflects Tier 28/29.** Bring the
  validator-stake number in `README.md` in line with the Tier 28
  drop from 10_000 to `FAUCET_DRIP` (300) and the Tier 29
  faucet-drip retune to 200. (942cec0, 5def863)
- **COMPARISON.md — keep stake-curve and content-cap framing at
  intent level.** Strip implementation-specific phrasing (exact
  curve constants, byte counts) so the public comparison stays
  durable across tuning changes; matches CLAUDE.md's "intent, not
  implementation" rule for public-facing docs. (9de1fcd, 55151da)

## [1.32.0] — 2026-04-28

### Changed
- **Hard fork sweep — Tier 24-29 activation heights compressed to
  750-755.** The long-runway tier schedule (`HONESTY_CURVE_RATE_HEIGHT`
  5000, `COMMUNITY_ID_HEIGHT` 8000, `REVOKE_TX_WINDOW_HEIGHT` 10000,
  `REACT_NO_SELF_MESSAGE_HEIGHT` 12000, `MIN_STAKE_FAUCET_DRIP_HEIGHT`
  14000, `VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT` 16000) is fast-forwarded
  to land back-to-back at 750/751/752/753/754/755 — immediately above
  the existing Tier 20-23 cluster (716-720). Mirrors the 1.26.0 sweep
  convention: one block per tier, monotone ordering, both validators
  upgrade in lockstep. Mainnet tip at cut was ~716, so the pack lands
  ~34 blocks ahead — buffer covers the rolling-upgrade window during
  which one validator keeps producing under old code while the other
  is being upgraded. Test fixtures that sampled fixed offsets past
  prior fork heights are tightened to mid-band of the relevant fork
  era so they don't accidentally cross into a later tier as gaps
  shrink. (f2fa300, 77698bd)

## [1.31.0] — 2026-04-28

### Changed
- **Tier 28 — validator min stake = one faucet drip.**
  `VALIDATOR_MIN_STAKE` drops from 10_000 to `FAUCET_DRIP` (300) at
  `MIN_STAKE_FAUCET_DRIP_HEIGHT = 14_000`. Tier 2's 10k floor turned
  permissionless validator entry into a capital wall; Tier 28 makes
  "minimum stake = one faucet grab" the new floor. Sybil cost
  collapses to ~one drip plus the faucet's per-/24 + PoW limits;
  slashing still bites proportionally. Pre-fork callers continue to
  see the legacy floor for replay determinism. The new constant is
  pinned to `FAUCET_DRIP` via a module-level assert so the two cannot
  drift. (55563b3, 4bef326)
- **Tier 29 — a single faucet drip funds a full validator
  end-to-end.** `VALIDATOR_REGISTRATION_BURN` drops to 0 and the
  stake floor drops from `FAUCET_DRIP` (300) to
  `FAUCET_DRIP - MIN_FEE` (200) so a 300-token drip covers stake
  (200) + fee (100) + burn (0) end-to-end. Closes the gap left by
  Tier 28 where `MIN_FEE` plus Tier 6's 10_000 registration burn
  meant a single drip couldn't actually fund a fresh validator.
  Activation at `VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT = 16_000`
  (rides above Tier 28). Pre-Tier-6 / Tier-6..Tier-29 / Tier-29+
  all return the right burn via `get_validator_registration_burn(height)`.
  (c306f5a, 0d0a1c0)

### Docs
- Add `COMPARISON.md` (vs Nostr / Arweave / DeSo). Linked from
  `README.md`. (6b08ae6)

## [1.30.2] — 2026-04-28

Cleanup-only.  Removes the temporary state_root diagnostic
logging blocks added in 1.29.1 and 1.29.2 from `_append_block`.
Their job (localizing the validator-side `compute_post_state_root`
missing `react_transactions=` kwarg) is done; the actual root
cause was fixed in 1.29.3.  Both rejection sites now return
`Invalid state_root — state commitment mismatch` directly, with
no per-leaf dump and no try/except diagnostic wrapper.

No consensus or behavioral change — these were `logger.warning`
side-effects only.

## [1.30.1] — 2026-04-27

Patch release.  Internal refactor that closes a latent dirty-set
scoping miss across several tx kinds, plus a homepage UX cleanup.
No consensus / state-root behavior change vs 1.30.0.

### Changed

- **Affected-entities sweep collapsed into a per-tx-class canonical
  registry** (29d6301, 15c2f07).  `_block_affected_entities` now
  walks a canonical `_BLOCK_TX_LIST_ATTRS` tuple and dispatches to a
  single `affected_entities() -> set[bytes]` method on each tx
  class, replacing the N hand-rolled per-kind branches that were
  the structural shape behind the 1.27/1.28/1.29 react-tx-stalls
  saga.  A structural-guard test walks every tx-like class in
  `messagechain/core`, `messagechain/consensus`, and
  `messagechain/governance` and asserts the method exists, so
  adding a new tx kind without registering it now fails loudly
  instead of silently mis-scoping `_persist_state` dirty sets.

### Fixed

- **Latent dirty-set scoping miss for several tx kinds** (29d6301).
  The legacy sweep silently omitted `governance_txs`,
  `finality_votes`, `custody_proofs`, `censorship_evidence_txs`,
  `bogus_rejection_evidence_txs`, and
  `inclusion_list_violation_evidence_txs` from
  `_block_affected_entities`, all of which DO mutate per-entity
  state on apply.  No state_root output change at any height
  (`compute_current_state_root` re-syncs ALL live entities via
  `_rebuild_state_tree`); the gap was a `_persist_state` dirty-set
  scoping concern only.  Picked up automatically by the new
  per-class registry.

### Changed (UX)

- **Homepage hero + entity-id lookup bar removed; replaced with a
  two-path next-step CTA** (ddd4bfa).  After the faucet section the
  page now offers "Send a message →" and "Run a node to earn
  tokens →" side-by-side, mirroring the funnel: get tokens → choose
  a path.  Poster ids in feed cards remain clickable for entity-
  profile navigation, so the standalone lookup bar was redundant.
  New `/gh/node` redirect deep-links to the README's "Run a
  validator" anchor for click-tracking parity with `/gh/start`.

## [1.30.0] — 2026-04-27

Minor release.  Adds the `messagechain react` CLI subcommand,
closes the symmetric proposer-side react leaf-advance bug, and
layers a global cap on top of the per-IP receipt-subtree gate to
defend the censorship-evidence framework against botnet /
IPv6-rotation drain.

### Added

- **`messagechain react` CLI subcommand** (aa64d6b).  Surfaces the
  existing Tier 17 `ReactTransaction` as a first-class CLI verb
  instead of hiding it behind `estimate-fee --tx-type react`.
  Mirrors `cmd_vote`: resolves the keyfile, fetches nonce +
  leaf-watermark, binds the persistent leaf cursor, auto-prices via
  the unified `auto_fee` helper, signs via
  `create_react_transaction`, and POSTs to `submit_react`.
  Pre-flight rejects malformed target hex and self-targeted
  user-trust votes before a WOTS+ leaf is consumed.

### Fixed

- **Proposer leaf-advance loop now includes `react_transactions`**
  (f118446).  Symmetric to the 1.29.3 validator-side fix.
  `propose_block`'s leaf-advance loop walked the proposer's own
  message / transfer / slash / governance / authority / stake /
  unstake txs but omitted react_transactions, so an honest
  proposer who signed a react then experienced a keypair reload
  (e.g. systemd restart) before the slot would compute
  `expected_proposer_leaf` against a stale watermark, reuse the
  same WOTS+ leaf in the header signature, and lose the slot to
  "Block contains duplicate WOTS+ leaf use".  ReactTransaction
  uses `voter_id` (not `entity_id`) for the signer, so the per-tx
  entity-id resolver also falls back to `voter_id`.

### Security

- **Receipt-subtree global cap layered on top of per-IP gate**
  (677c306).  The round-8 ReceiptBudgetTracker defends single-IP
  drain via a per-IP token bucket but admitted a botnet /
  IPv6-rotation drain: at `SUBMISSION_REJECTION_BURST=3` and
  `_max_tracked_ips=4096`, 4096 distinct IPs each got a fresh
  burst — 12,288 leaves drained in the burst alone, plus ~205/sec
  sustained.  The 65,536-leaf RECEIPT_SUBTREE drained in ~4-5
  minutes, after which every receipt / rejection / ack issuance
  silently broke until the operator rotated the on-chain subtree
  (~9 min keygen).  During that gap a colluding validator could
  ignore submissions with no chain-level evidence — defeating
  the censorship-evidence framework, the chain's primary defense
  against the primary anchored adversary (validator collusion).
  Now layered: per-IP first (fairness for honest opt-in clients),
  global second (`RECEIPT_GLOBAL_BURST=6_553`,
  `RECEIPT_GLOBAL_REFILL_PER_SEC=0.05` — sustained drain after
  burst depletion takes ~15 days to consume one full subtree, well
  above the ~22-day natural rotation cadence).  Atomic gate
  ordering: peek per-IP, peek global, consume both only on full
  pass — failures consume nothing, so attackers cannot probe
  global state by spending per-IP tokens.  Operator-visible
  warning logged at most once per minute when the global cap kicks
  in.  Shared bucket across HTTPS + RPC surfaces and across
  rejection + ack paths (per the cross-surface invariant).

## [1.29.3] — 2026-04-28

Critical consensus hotfix — `_append_block`'s pre-apply
state_root simulation was missing `react_transactions=` in its
`compute_post_state_root` call.  The proposer side
(`Blockchain.propose_block`) passes the react list so the sim
mirrors the voter's fee/nonce/leaf-watermark bumps and the
`reaction_state.choices` delta; the validator-side re-sim in
`_append_block` did not.  Result: proposer commits a state_root
computed WITH react TXs in scope, validator re-simulates WITHOUT
them, the two diverge, and any honest block carrying even one
react tx self-rejects at the pre-apply check with `Invalid
state_root — state commitment mismatch`.

This was the actual root cause behind the entire 1.27/1.28/1.29
react-TX-stalls-the-chain saga.  Pinpointed via the per-leaf
diagnostic added in 1.29.1/1.29.2 — the diagnostic showed
`committed=1fed22fc... simulated=9024cbb1... react=1
current_reaction_choices=0`, which is exactly the signature of
the validator sim seeing zero react TXs while the proposer's sim
saw one.

Fix is one kwarg.  No on-chain consequences for pre-fix history
(no react tx ever landed; the bug prevented it).

## [1.29.2] — 2026-04-28

Diagnostic-only.  Adds a pre-apply state_root mismatch diagnostic
in `_append_block` (the post-apply diagnostic from 1.29.1 doesn't
fire because the proposer's own `add_block` rejects at the
pre-apply simulation check before reaching the apply path).

## [1.29.1] — 2026-04-27

Diagnostic-only release.  Adds a per-leaf state diagnostic at the
`Invalid state_root — state commitment mismatch` rejection path so
the next mismatch logs the react voters' state_tree rows, balance,
nonce, leaf-watermarks, the proposer's row, and the reaction-state
contribution hash — pinpointing which sim/apply mutation is missing
without forcing another bisection.  No consensus-rule changes.

## [1.29.0] — 2026-04-27

Tier 27 hard fork — symmetric no-self-react rule.

ReactTransaction shipped at Tier 17 with an asymmetric self-vote
rule: self-trust votes were rejected (a free unbounded reputation
pump otherwise), but message-react votes on one's own messages were
allowed on the rationale that the per-tx fee was the spam tax.  That
rationale undersells the score's purpose — a vote signals external
reception, not author preference.  Allowing self-message-reacts lets
an author cheaply pump their own visibility wherever message_score
is consulted (sort order, "popular" feeds, any future reputation
derivative); a fee gates spam volume, not motivated self-promotion.

Tier 27 closes the asymmetry.  At/after `REACT_NO_SELF_MESSAGE_HEIGHT
= 12_000`, a ReactTx with `target_is_user=False` is rejected at the
admission layer when its `target` (a message tx_hash) resolves to a
MessageTransaction whose authoring `entity_id` equals `voter_id`.
Pre-activation blocks keep their original admission outcomes —
historical state must continue to apply under the rules in force
when each block was produced.

Implementation:
* `messagechain/config.py` — new `REACT_NO_SELF_MESSAGE_HEIGHT`
  constant + monotonicity assertion above `REVOKE_TX_WINDOW_HEIGHT`.
* `messagechain/storage/chaindb.py` — new `get_message_author`
  helper resolves `tx_hash → entity_id` via the existing
  `tx_locations` index + `get_block_by_number`; O(1) index lookup
  plus one block load per check, amortized through SQLite's row
  cache.  Returns None if the location is missing, the block load
  fails, or the in-block tx is not a MessageTransaction.  Threads
  `state` through so compact entity-ref blocks decode correctly.
* `messagechain/core/blockchain.py` — `validate_block` rejects a
  ReactTx whose voter authored its message target, gated on the
  activation height.
* `messagechain/network/submission_server.py` — mempool admission
  rejects matching submissions so they don't accumulate in the
  pool only to be filtered later.
* `server.py` — proposer pre-filters self-message-reacts pulled
  from the mempool before assembling a block, so a stale entry
  admitted pre-activation does not poison a post-activation block.
* `messagechain/core/reaction.py` — module + `create_react_transaction`
  docstrings updated to describe the symmetric rule and where each
  half of the check lives.

No new persisted state is introduced — message txs already carry
their authoring `entity_id`, so resolving authorship is read-only
against the existing `tx_locations` index.

## [1.28.6] — 2026-04-27

Critical consensus hotfix — companion to 1.28.5.  Same bug class
(state_root sim/apply divergence on a tx kind that wasn't fully
mirrored), this time on Tier 17 ReactTransaction.

`_block_affected_entities` was missing `block.react_transactions` in
its sweep.  The apply path's react-tx loop bumps the voter's nonce,
balance, and leaf_watermark via `pay_fee_with_burn` +
`_bump_watermark`, but the post-apply `_touch_state` call read its
voter list from `_block_affected_entities` — which never included
react voters — so the voter's state_tree row stayed at its
pre-block contents.  Meanwhile `compute_post_state_root` simulated
the same nonce/balance/watermark mutations into the sim dicts, then
built its tree commitment from those updated values.  Result: a
block with even one react tx self-rejected at the proposer with
`Invalid state_root — state commitment mismatch`.

Symptom on mainnet: chain stalled at h=687 with a UP react tx in
v1's mempool.  Same `state_root` rejection every 10 minutes; the
chain couldn't progress until the voter's row was added to the
touched set.

Fix is one loop in `_block_affected_entities`:

```python
for rtx in getattr(block, "react_transactions", []) or []:
    affected.add(rtx.voter_id)
```

No on-chain consequences for pre-fix history (no react tx ever
landed; the bug prevented it).  Pairs with the 1.28.5 fix for the
analogous v3-message-tx sender_pubkey omission.

## [1.28.5] — 2026-04-27

Critical consensus hotfix — `compute_post_state_root` was missing
the v3 first-send-pubkey install mirror in the message-transaction
loop, causing every block carrying a v3 MessageTransaction with
`sender_pubkey` set to be self-rejected by the proposer with
`Invalid state_root — state commitment mismatch`.

The transfer-tx sim has had this mirror since Tier 13 was wired
up (see `sim_public_keys[ttx.entity_id] = ttx.sender_pubkey` at
the transfer loop), but the message-tx sim never got the same
treatment.  Result: a fresh entity submitting its first message
(v3, `include_pubkey=True`) couldn't get its tx into a block.
Honest proposers built the block, simulated the post-state with
`sim_public_keys` un-updated, signed it with that stale state_root,
then rejected their own block when `_apply_block_state` actually
installed the pubkey and produced a different state_root.

Symptom on mainnet: chain stalled at h=678 with a v3 message tx
in mempool.  Every 10 minutes v1's proposer logged
`Failed to add proposed block: Invalid state_root — state
commitment mismatch`; the chain couldn't progress until the
mempool was drained or the bug was fixed.

Fix mirrors the transfer-tx pattern in `compute_post_state_root`:
on a v3 message tx with `sender_pubkey` set and the entity not yet
in `sim_public_keys`, install the pubkey into the sim dict before
the fee/burn/leaf-watermark mutations.  No on-chain consequences
for pre-fix history (no v3 message tx with `sender_pubkey` ever
landed; the bug prevented it from landing in the first place).

## [1.28.4] — 2026-04-27

Critical operational hotfix for submit-path lock contention.  The
1.28.3 to_thread fix moved the synchronous WOTS+ sign off the
asyncio event loop, but the underlying problem remained: every
`_rpc_submit_*` call passed `receipt_issuer=self.receipt_issuer`,
which forces a SubmissionReceipt to be signed using a leaf from
the receipt subtree.  That sign acquires a cross-process advisory
file lock with a 30-second timeout (`_LEAF_CURSOR_LOCK_TIMEOUT_S`).
On a node where the lock was held perpetually by the validator
process itself (`/proc/locks` showed `FLOCK ADVISORY WRITE` on
`receipt_leaf_index.json.lock`), every submit blocked the full
30 s before the receipt issuance gave up — long enough that
clients with a 10–30 s socket timeout always timed out.

**Receipt issuance is now opt-in.**  Submit handlers
(`_rpc_submit_transaction`, `_rpc_submit_transfer`,
`_rpc_submit_react`) skip the receipt subtree by default and
return immediately after the tx is admitted to the mempool.
Censorship-evidence clients that need a SubmissionReceipt can opt
in by passing `request_receipt: true` in the submission params.

No consensus impact, no wire-format change.  Default-path submits
go from 30 s+ timeouts to single-digit milliseconds.

## [1.28.3] — 2026-04-27

Critical operational hotfix.  Submit RPCs (`submit_transaction`,
`submit_transfer`, `submit_react`) now run inside `asyncio.to_thread`
so the WOTS+ sign + 30-second cross-process file-lock wait that
`receipt_issuer.issue()` performs no longer blocks the event loop.

Pre-fix, a single submit RPC could pin the entire asyncio event
loop for up to 30 seconds — every other handler (including
`get_chain_info`, peer message dispatch, block-production gossip)
froze in lockstep.  When a client retry-loop hit the natural ~10s
client socket timeout it would re-submit, queueing another sync
sign behind the first; the lock was held continuously and the
validator went globally unresponsive.  Symptom seen on mainnet:
v2's RPC stopped answering ~20 minutes after a 1.28.x rollout,
RPC port LISTEN but no completion, kernel `epoll_wait` never woke
up because the user-thread was busy in fcntl.flock retry loop.

The submit handlers themselves are unchanged; only the dispatch
site in `_process_rpc` is updated.  No consensus impact, no
wire-format change.  Test suite green (4270 / 21 skipped).

## [1.28.2] — 2026-04-27

Patch release.  **Pre-activation hard-fork wire-format revision for
Tier 25 `community_id`.**  No on-chain consequences (mainnet tip well
below the prior `COMMUNITY_ID_HEIGHT=6_000` activation; no v5 txs
exist yet), but the v5 layout shipped in 1.28.0 is REPLACED — operators
must upgrade to 1.28.2+ before the new activation height to avoid
parsing v5 blobs against the obsolete rule.

### Changed (consensus, pre-activation)

- **Tier 25 `community_id` redesigned from 16-byte opaque hash to
  short ASCII handle.**  v5 wire form is now `1B presence flag + 1B
  length + N bytes` (when set) where the payload is 1–32 bytes drawn
  from `[a-z0-9_-]` with first/last byte in `[a-z0-9]` (DNS-label
  style).  Rationale: an identifier needs zero-ambiguity semantics
  that the message-content validator does not provide — the prior
  opaque-hash design forced an off-chain `(hash → human name)`
  dictionary to be maintained by every client, and a permissive
  Unicode handle would have opened homoglyph-impersonation attacks
  (`art` (Latin) vs `аrt` (Cyrillic а) render identically).  Strict
  ASCII charset removes both problems and is asymmetrically
  reversible — a future tier can loosen the rule additively without
  breaking the wire format, but a permissive-then-tightened rule
  cannot be done without a new tx version.  Native-script community
  *names* live at L2/app layer (display name / icon / description),
  exactly like every successful identifier system (DNS, GitHub
  handles, Reddit subreddits, Twitter handles).  Anchored as a
  settled-design entry in CLAUDE.md.
- **`COMMUNITY_ID_HEIGHT` bumped 6_000 → 8_000** to widen the
  operator upgrade window for the wire-format revision.

### Operator upgrade

- All validators must be on 1.28.2+ before block 8_000.  No urgency
  at the time of release (mainnet tip well below 5_000); the
  `messagechain upgrade` CLI handles the rolling upgrade with
  health-check rollback.

## [1.28.1] — 2026-04-27

Patch release.  Closes the entire **floor-poisoning bug class** the
2026-04-27 chain-stall incident exposed.  1.28.0 mirrored the
specific (header, prev_block, wall-clock)-only validate_block rules
into a pre-sign helper, which fixed the round-cap path that wedged
the chain at height 671.  Hours later the chain wedged AGAIN at
height 672 via a state-root mismatch — same bug class, different
rule, not pre-sign-checkable.  This release durably closes the
window between ``record_block_sign`` and "block has been broadcast"
so any post-reserve rejection rolls back the floor.

### Security / correctness (active immediately, no fork gate)

- **Durable height-guard floor rollback on post-reserve rejection**
  (f6d8eea).  ``HeightSignGuard`` gains a per-role pending-reservation
  tracker plus a ``rollback_<role>_sign(height)`` API that durably
  restores the prior floor.  ``ProofOfStake.create_block`` wraps its
  post-reserve work (signing, RANDAO mix, block construction) in a
  try/except that rolls back on ANY exception before re-raising.
  Both production block-production paths
  (``server.py::_try_produce_block_sync`` and
  ``messagechain/network/node.py::_try_produce_block``) call
  ``rollback_block_sign`` when their own ``add_block`` rejects the
  candidate.  Net effect: the floor only ratchets when a block has
  ACTUALLY been accepted into the local chain — no more poisoning
  on state-root mismatch, byte-budget overflow, in-create_block
  exception, or any future rejection rule.

  Crash-window analysis (preserves the safe-failure-mode anchor):
  every interleaving of process kill between reserve and rollback
  leaves the on-disk floor at the higher value, refusing re-sign at
  that height — liveness loss for one block, NO equivocation.  The
  crash-restart double-sign guarantee is preserved end-to-end.

- **In-memory pending state does NOT survive restart.**  On process
  reload the on-disk floor is the only durable signal; a freshly-
  loaded guard cannot roll back a reservation that a previous
  process committed.  This closes a hypothetical attack where a
  malicious operator restart could "undo" a real signature by
  treating the post-restart pending dict as if it could undo
  pre-restart on-disk state.

### Operator notes

- No fork gate, no consensus impact, no migration step.  Roll
  validators with ``messagechain upgrade --yes``.
- This release is the durable fix for the floor-poisoning bug
  class.  After upgrade, any chain that was previously wedged on a
  poisoned floor will recover automatically on the next slot
  attempt at the next height (the proposer reads the canonical tip
  via fork-choice, advances past the poisoned floor, and produces).

## [1.28.0] — 2026-04-27

Minor release.  **Hard fork: Tier 25 — optional `community_id` on
`MessageTransaction`** (activates at `COMMUNITY_ID_HEIGHT = 6_000`).
Plus the root-cause fix for the chain-stall vector the 1.27.1 hotfix
unstuck, durability fixes for Tier 23/24 slash state, the
witness-auto-separation sweep wiring fix that completes the 1.27.0
default-on flip, a wallet-backup CLI surface, and a test-infra fix
for the leaf-cursor flake under xdist load.

### Added (consensus, gated by activation height)

- **Tier 25 — optional `community_id` on `MessageTransaction`**
  (306728d).  At `COMMUNITY_ID_HEIGHT=6000` an optional `community_id`
  field on the message wire format unlocks app-layer community
  tagging without changing the chain's permanence properties or the
  fee market.  Activation is `+1000` blocks above Tier 24 — disjoint
  from the slashing-curve subsystem so the only spacing constraint
  is the operator upgrade window.

### Security / correctness (active immediately, no fork gate)

- **Pre-sign local validation in `ProofOfStake.create_block`**
  (fce9148).  Root-cause fix for the live chain-stall incident at
  height 671 the 1.27.1 hotfix unstuck.  Pre-fix, the height-guard
  floor was reserved BEFORE local validation ran; when the network's
  downstream `validate_block` rejected a constructed block (round-
  cap, future-drift, MTP, timestamp-too-early), the floor was already
  durably advanced and every legitimate retry at the same height was
  refused as `HeightAlreadySignedError`.  Fix: a new
  `_local_pre_sign_validation` helper mirrors the
  (header, prev_block, wall-clock now)-only rejection rules from
  `validate_block`; if any reject, `create_block` raises a new
  `ProposerSkipSlotError` BEFORE the floor reservation.  Crash-restart
  equivocation guarantee preserved (the floor still ratchets BEFORE
  signing).  The pre-sign helper is gated on `ENFORCE_SLOT_TIMING` so
  the test-suite's synthetic-block-construction patterns keep working
  unchanged.  Same wedge cannot recur regardless of cap value.

- **`slash_offense_counts` persistence** (01f5dff).  The Tier 23/24
  honesty-curve and amnesty rules read `slash_offense_counts[entity]`
  to compute per-offense severity.  Pre-fix the counter lived only
  in memory: a validator restart, snapshot reload, or reorg reset
  every entity's count to 0, effectively granting amnesty on every
  bounce — defeating the "single-shot amnesty" anchor (one free
  AMBIGUOUS-evidence pass, then standard small severity).  Now
  durably persisted alongside other state in chaindb, restored on
  load, snapshotted with state-root commitments, and rolled forward/
  back in the same atomic transaction as the surrounding state on
  reorg.

### Operational

- **Witness auto-separation sweep wiring** (143208f).  The 1.27.0
  fork flipped `WITNESS_AUTO_SEPARATION_ENABLED` to True at
  `WITNESS_AUTO_SEPARATION_HEIGHT=3000`, but the sweep helper was
  never called by the finality advance path — so finalized blocks
  past `WITNESS_RETENTION_BLOCKS` had their inline WOTS+ signatures
  retained anyway.  This fix wires the sweep into every successful
  finality advance, materializing the storage savings the 1.27.0
  fork was supposed to deliver.

- **Block-production loop log levels** (fce9148).
  `ProposerSkipSlotError` (a working-as-designed slot skip) now
  logs at INFO; `HeightAlreadySignedError` (the same-height guard
  firing on crash-restart) now logs at WARNING.  Pre-fix both
  surfaced as `Block production iteration failed` ERROR alarms
  despite being the correct behavior.

### Wallet UX

- **`messagechain backup-wallet` CLI** (8d627cb).  New command and
  README guidance for capturing a portable wallet backup
  (private-key seed + chain-state-derived parameters) so an operator
  can restore the same WOTS+ identity on a new host without losing
  leaf-watermark continuity.  Operator-only feature; no consensus
  impact.

### Test infrastructure

- **`tests/conftest`: wipe `~/.messagechain/leaves/` per test**
  (2325f4f).  The 1.27.0 cross-process leaf-cursor lock made the
  CLI tests share an on-disk cursor across xdist workers; with
  `tree_height=4` (16 leaves) under the test conftest, parallel
  signing tests could exhaust the cursor and a later test's
  `load_leaf_index` would raise `ValueError: Corrupted leaf index
  file: next_leaf >= num_leaves`.  Wiping the per-test leaf-cursor
  directory in the fixture eliminates the shared-state interaction
  without weakening the production lock semantics.

### Operator notes

- Validators must upgrade to 1.28.0 within the runway window
  (current tip → 6000) to follow the Tier 25 fork.  Pre-1.28.0
  nodes will reject post-fork messages that carry a `community_id`
  field.
- The pre-sign-validation, slash-counter-persistence, and witness-
  sweep-wiring fixes are active immediately on upgrade.  Roll
  validators with `messagechain upgrade --yes`.

## [1.27.1] — 2026-04-27

Hotfix.  Raises `MAX_PROPOSER_FALLBACK_ROUNDS` from 5 → 100.

The original cap of 5 fallback rounds covered legitimate missed-slot
scenarios on a healthy chain.  During the 1.25.x → 1.26.x rollout a
series of regressions (mempool sort key on `TransferTransaction`, a
corrupted height-guard ratchet from earlier crash-restarts) left the
chain stalled for ~2 hours.  Round count grew to ~12 (one per 10-min
slot interval), and every recovery proposal was rejected with
"Proposer round N exceeds cap 5 — timestamp-skew slot hijacking
rejected".  The chain could not self-heal until the cap was lifted.

100 covers ~16 hours of stall and still bounds slot-rotation grinding
to a small constant — comfortably below the future-drift window's
worst-case abuse surface (`MAX_BLOCK_FUTURE_DRIFT = 120 s`).  No
consensus impact for healthy chains; only changes which blocks
honest fallback proposers are allowed to publish during a long
stall window.

## [1.27.0] — 2026-04-27

Minor release. **Hard fork: Tier 24 — track-record-aware slashing**
(activates at `HONESTY_CURVE_RATE_HEIGHT = 5000`) and **witness
auto-separation default-on** (activates at
`WITNESS_AUTO_SEPARATION_HEIGHT = 3000`). Plus a CRITICAL crypto
safety fix (active immediately, not gated): cross-process advisory
lock around the WOTS+ leaf-cursor advance to prevent concurrent
CLI invocations from reusing the same one-time leaf. Plus operator
UX: the long-defined post-block notify hook is now actually invoked,
and a node stuck on a same-height minority fork now auto-resyncs.

### Security (active immediately, not fork-gated)

- **WOTS+ leaf-cursor cross-process advisory file lock** (f41dfa2).
  Two concurrent CLI invocations on the same wallet (shell loop,
  retry-while-pending, two terminal panes) could each observe
  leaf=N on the on-disk cursor, both pass the per-process
  `_sign_lock`, both persist N+1, and both sign at leaf N — WOTS+
  leaf reuse mathematically reveals the leaf's private key,
  letting an attacker forge txs at that leaf (spend balance,
  rotate key, impersonate identity). Fix wraps the load → advance
  → persist sequence in `KeyPair.sign` with an exclusive advisory
  lock on a sibling `<leaf_index_path>.lock` file (`fcntl.flock`
  on POSIX, `msvcrt.locking` on Windows), released in `finally`
  even on persist failure / signature exception / KeyboardInterrupt.
  Acquire blocks up to 30s and then raises a clear
  `LeafCursorLockTimeoutError` naming the lock path.

### Added (consensus, gated by activation height)

- **Tier 24 — track-record-aware slashing severity** (878d07e).
  At `HONESTY_CURVE_RATE_HEIGHT=5000`:
  - **Honesty-curve RATE factor.** Tier 23 read `track_record` as
    pure VOLUME (good_blocks + good_attestations); Tier 24 reduces
    it by `BAD_PENALTY_WEIGHT × prior_offenses` (clamped ≥ 0).
    Long-tenured validators with many priors lose relief in
    proportion to bad volume; long-tenured + clean keeps full relief.
  - **Perfect-record AMNESTY** (the "low chance of getting penalized"
    anchor). AMBIGUOUS evidence + `track_record ≥ AMNESTY_TRACK_
    THRESHOLD` (default 1000) + zero priors → severity = 0, slash
    skipped entirely. Single-shot: `slash_offense_counts` is bumped
    even on the 0-severity outcome, so the next AMBIGUOUS incident
    sees prior=1 and falls back to standard small severity.
    UNAMBIGUOUS evidence is never amnestied.
  - **Inclusion-list slash routes through the honesty curve.**
    Pre-Tier-24, `process_inclusion_list_violation` bypassed
    `slashing_severity` and used a flat
    `INCLUSION_VIOLATION_SLASH_BPS` rate, contradicting the
    track-record-aware severity anchor for this evidence type.
    Post-Tier-24: routed through `slashing_severity` with
    `OffenseKind.INCLUSION_LIST_VIOLATION` +
    `Unambiguity.UNAMBIGUOUS`, so a long-tenured first offender
    hits `UNAMBIGUOUS_FIRST_PCT` (50%) instead of the flat rate,
    and repeat offenders hit 100%.

### Changed (consensus, gated by activation height)

- **Witness auto-separation default-on** (69cf7ca). At
  `WITNESS_AUTO_SEPARATION_HEIGHT=3000`, post-fork blocks past
  `WITNESS_RETENTION_BLOCKS` (200) of the finality horizon get
  their inline WOTS+ signatures stripped to the
  `block_witnesses.witness_data` side-table on each sweep. WOTS+
  signatures are ~73% of full-node block storage at saturation
  but only serve auditability after finalization — moving them
  off the hot block table keeps full-node storage broadly
  accessible (CLAUDE.md anchor) without changing any consensus
  output. Pre-fork blocks (`block_number <
  WITNESS_AUTO_SEPARATION_HEIGHT`) are NEVER stripped, even after
  the fork activates — replay determinism requires inline
  witnesses for blocks the chain committed to inline. Reassembly
  via `get_block_by_hash(..., include_witnesses=True)` remains
  available; nothing is deleted.

### Operational

- **Auto-resync from minority fork** (878d07e, network-only, no
  consensus impact). Pre-fix, the sync trigger fired only when
  `peer_height > our_height` — a node stuck on a same-height
  different-tip fork would never auto-recover. Adds
  `Node._minority_fork_likely()`: counts at-or-above peers
  reporting strictly-higher cumulative_weight; if a strict
  majority disagrees with us, kicks `start_sync` so ForkChoice
  picks the heavier chain on apply. Outlier defense: requires ≥ 2
  corroborating peers.
- **Post-block notify hook actually wired** (878d07e). The
  `runtime.notify` per-block hook was DEFINED but never CALLED.
  `Node._after_block_added()` is now invoked from each successful
  `add_block` site (3 sites in `node.py`); short-circuits
  cheaply when notify is disabled in `onboard.toml`; swallows all
  exceptions so SMTP failures cannot affect consensus. Lazy
  import keeps stripped-down builds free of the notify dependency.

### Docs

- **README leads with permanence + slashable censorship resistance**
  (e67767f). Pulled the differentiator above the fold so a reader
  who skims only the first paragraph still gets the headline
  promise.

### Operator notes

- Validators must upgrade to 1.27.0 within the runway window
  (current tip → 3000 → 5000) to follow the witness-separation
  and Tier 24 hard forks. Pre-1.27.0 nodes will reject post-fork
  blocks they synchronize from upgraded peers (different witness
  layout / different slashing-severity output on inclusion-list
  violations).
- The crypto safety fix is active immediately; restart wallet
  processes after upgrading so the lock is honored.

## [1.26.1] — 2026-04-27

Hotfix.  `mempool._fee_per_byte` did `len(tx.message)` on every entry
in the pending pool.  `_rpc_submit_transfer` routes
`TransferTransaction` through the same `add_transaction` →
`mempool.pending` path, so any transfer in the mempool crashed
block production with `AttributeError: 'TransferTransaction' object
has no attribute 'message'`.  This was a latent bug — it only
surfaced once a transfer was actually submitted via RPC.  Fix
reads the payload via `getattr(tx, "message", b"")` so non-message
tx kinds collapse to absolute-fee ranking.  No consensus impact;
the broken path was a sort key in proposer block-build.

## [1.26.0] — 2026-04-27

### Hard fork — fast-forwarded ALL non-bootstrap activation heights

The mainnet has zero non-operator users at the moment, so we're
collapsing the entire forward-fork schedule into a tight cluster
just past the current tip (≈668).  Twenty-one separate Tier 1–23
activations that previously ranged from height 800 to 21,000 now
all activate within a single ~20-block window starting at 700.
Every fork that was scheduled past current tip is in this sweep
EXCEPT the bootstrap-related ones — `SEED_STAKE_CEILING_HEIGHT`,
`SEED_DIVESTMENT_RETUNE_HEIGHT`, `SEED_DIVESTMENT_REDIST_HEIGHT`,
`SEED_DIVESTMENT_START_HEIGHT`, `SEED_DIVESTMENT_END_HEIGHT`, and
`BOOTSTRAP_END_HEIGHT` are unchanged.  Replay determinism is
unaffected — the chain has not crossed any of the touched heights.

New activation heights (in original tier order):

- `FINALITY_VOTE_CAP_HEIGHT` 800 → **700** (Tier 1)
- `MIN_STAKE_RAISE_HEIGHT` 1000 → **701** (Tier 2)
- `LOTTERY_BOUNTY_RAISE_HEIGHT` 1100 → **702** (Tier 2)
- `TREASURY_CAP_TIGHTEN_HEIGHT` 1200 → **703** (Tier 1)
- `TREASURY_REBASE_HEIGHT` 1300 → **704** (Tier 3)
- `INTL_MESSAGE_HEIGHT` 1500 → **705** (Tier 12)
- `ATTESTER_REWARD_SPLIT_HEIGHT` 1700 → **706** (Tier 4)
- `ATTESTER_FEE_FUNDING_HEIGHT` 1800 → **707** (Tier 4)
- `FINALITY_REWARD_FROM_ISSUANCE_HEIGHT` 1900 → **708** (Tier 4)
- `ATTESTER_REWARD_CAP_HEIGHT` 2000 → **709** (Tier 4)
- `ATTESTER_CAP_FIX_HEIGHT` 2300 → **710** (Tier 4)
- `DEFLATION_FLOOR_HEIGHT` 2500 → **711** (Tier 5)
- `DEFLATION_FLOOR_V2_HEIGHT` 2600 → **712** (Tier 5)
- `VALIDATOR_REGISTRATION_BURN_HEIGHT` 2700 → **713** (Tier 6)
- `TIER_18_HEIGHT` 11000 → **714** (Tier 18)
- `PROPOSAL_FEE_TIER19_HEIGHT` 13000 → **715** (Tier 19)
- `SOFT_SLASH_HEIGHT` 15000 → **716** (Tier 20)
- `REWARD_CURVE_HEIGHT` 15000 → **717** (Tier 20)
- `PROPOSER_CAP_HALVING_HEIGHT` 17000 → **718** (Tier 21)
- `VOTER_REWARD_HEIGHT` 19000 → **719** (Tier 22)
- `HONESTY_CURVE_HEIGHT` 21000 → **720** (Tier 23)

### Test fixtures touched by the sweep

Several tests were originally written assuming hundreds of blocks
between adjacent fork heights.  With the schedule compressed,
those windows shrink to a single block; tests are updated minimally:

- `test_attester_cap_fix.py` uses a `_post_fix_epoch_start()`
  helper that ceiling-divides to the first epoch entirely past
  `ATTESTER_CAP_FIX_HEIGHT`, and mints at `epoch_start` instead of
  the raw activation height so the per-epoch tracker's reset
  doesn't fire mid-test.
- `test_attester_reward_cap.py` wraps the cap-burn test in a
  `_CapFixBypass` context manager that pins
  `ATTESTER_CAP_FIX_HEIGHT` far in the future, since the test
  exercises strictly PRE-fix behavior.
- `test_governance_h6_m5_fixes.py` and `test_governance_pipeline.py`
  bypass `TREASURY_CAP_TIGHTEN_HEIGHT`, `TREASURY_REBASE_HEIGHT`,
  `DEFLATION_FLOOR_HEIGHT`, `DEFLATION_FLOOR_V2_HEIGHT`,
  `PROPOSAL_FEE_TIER19_HEIGHT`, and `VOTER_REWARD_HEIGHT` for the
  test's duration — these tests exercise the legacy uncapped
  treasury-spend path and would be perturbed by the rebase-burn
  firing on the close block.
- `test_deflation_floor.py::test_supply_drops_back_below_floor_boost_resumes`
  pins both calls to `POST_ACTIVATION_HEIGHT` (V1) instead of
  `POST_ACTIVATION_HEIGHT + 1` (V2 territory) so V1 multiplier
  semantics are testable in the now-1-block V1-only window.
- `test_reward_curve_tier20.py` relaxes the runway lower bound
  from 2000 to 1 — runway is now an operations property of the
  release/upgrade flow, not an inter-fork height invariant.
- Canonical-height assertions in `test_lottery_bounty_raise.py`,
  `test_min_stake_raise.py`, `test_treasury_rebase.py`, and
  `test_treasury_cap_tightening.py` updated to the new values.

## [1.25.2] — 2026-04-27

UI release riding the live ReactTx + prev-pointer activation. No
consensus changes — static feed and entity-profile rendering only,
plus one parallel `daily_cap` cleanup the Tier 22 rework missed.

### Changed (UI, off-chain, active immediately)

- **Public feed: distinguish replies from multi-tx continuations.**
  A `prev` pointer chaining a message to the SAME entity's previous
  message is now rendered as `↪ continued from <hex>` with a
  3px accent-colored left-border bar on the card; cross-author
  references stay as `↳ in reply to <hex>` with the original styling.
  Lets readers tell at a glance whether they're seeing a thread or a
  long post split across multiple txs.
- **Public feed: explicit "in reply to" / "continued from" labels.**
  Replaces the bare `refs <hex>` text — the chevron alone wasn't a
  strong-enough signal that the link points to a referenced post.
- **/v1/info: rename `daily_cap` → `window_cap`.** Tier 22 (1.24.0)
  retired the daily cap on the faucet in favor of a 15-min rolling
  window, but `_serve_info` still emitted the old field name and
  would have 500'd whenever a UI client polled it with the faucet
  enabled — same class of bug as the 1.25.1 hotfix, this time on
  the public-feed handler instead of the startup log line.

## [1.25.1] — 2026-04-26

Hotfix for 1.25.0. The Tier 22 (1.24.0) faucet rework retired
`FaucetState.daily_cap` in favor of `window_cap`, but a leftover log
line in `server.py` still referenced the old attribute. Validators
running with `--faucet-keyfile` (the public-feed validator) crashed
on startup with `AttributeError: 'FaucetState' object has no
attribute 'daily_cap'`. Fix renames the log line to `window_cap`.

No consensus impact. Activation heights from 1.25.0 unchanged.

## [1.25.0] — 2026-04-26

### Hard fork — fast-forwarded Tier 2 + Tier 7 + Tier 13–17 activations

Coordinated multi-tier fork that pulls forward seven previously
distant activation heights into a tight near-future window so the
Tier 17 ReactTransaction feature can be exercised live on mainnet
without waiting ~58 days for the chain to grow into the original
schedule. The chain has not yet reached any of these forks (current
tip ~611), so pre-fork replay is unaffected.

New activation heights (strict ordering preserved):

- `FEE_INCLUDES_SIGNATURE_HEIGHT` 1200 → **615** (Tier 2)
- `FLAT_FEE_HEIGHT` 2800 → **616** (Tier 7)
- `VERSION_SIGNALING_HEIGHT` 3500 → **620** (Tier 13)
- `MESSAGE_TX_LENGTH_PREFIX_HEIGHT` 4500 → **621** (Tier 14)
- `GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT` 5000 → **622** (Tier 15)
- `MARKET_FEE_FLOOR_HEIGHT` 7000 → **623** (Tier 16)
- `REACT_TX_HEIGHT` 9000 → **624** (Tier 17)

Tier 18 (`TIER_18_HEIGHT = 11000`), Tier 19, Tier 20, Tier 21, and
Tier 22 are left at their original heights. After the rollout,
ReactTransaction admission opens at block 624 (`REACT_FEE_FLOOR = 10`
per-tx until Tier 18 collapses to MARKET_FEE_FLOOR=1).

### Test fixtures

- `tests/test_fee_includes_signature_height_env.py` updated to the
  new default (615) and a sub-FLAT_FEE_HEIGHT env override value
  (610) to satisfy the `FLAT_FEE_HEIGHT > FEE_INCLUDES_SIGNATURE_HEIGHT`
  invariant under the compressed window.

## [1.24.0] — 2026-04-26

Minor release. **Hard fork: Tier 22 — voter rewards on passed
proposals** (activates at `VOTER_REWARD_HEIGHT = 19000`). Plus a
faucet rate-limit retune and a web-UI prose trim — both
non-consensus, active immediately.

### Governance — Tier 22: voter rewards on passed proposals (activates block 19000)

Hard fork at `VOTER_REWARD_HEIGHT = 19000` (rides above Tier 21's 17000
with the established ~2000-block runway). Reward-aligned governance
participation without a rubber-stamp incentive.

- **Per-proposal escrow funded by a proposer surcharge.** Post-fork,
  every `ProposalTransaction` debits an additional
  `VOTER_REWARD_SURCHARGE = 50_000` from the proposer's balance on
  top of the regular tx fee. The surcharge is held in
  `ProposalState.voter_reward_pool` — debited from the proposer, not
  minted, not burned. Net inflation invariant is preserved because
  the tokens stay in circulation, just sequestered until close.
- **Pay-on-pass, retrospective only.** At proposal close, if
  `yes_weight × 3 > total_eligible × 2` (the existing supermajority
  rule, evaluated in live-weight mode like the H6 binding tally),
  the pool is distributed pro-rata-by-live-stake to YES voters whose
  `get_staked > 0` at close. Proposals that fail the threshold burn
  the entire pool. No-voters and slashed-out yes-voters get nothing.
  The asymmetry is intentional: rewarding both sides degenerates back
  into pay-for-participation, which incentivizes uninformed voting.
- **Whale cap.** A single yes-voter cannot collect more than
  `VOTER_REWARD_MAX_SHARE_BPS / 10_000 = 25%` of the pool, even if
  they hold all the yes-side stake. Excess from the cap burns
  deterministically. Without this cap, a 70%-stake validator captures
  ~70% of every reward and the system reduces to "validators tax
  proposers via a 2/3 rubber stamp on their own proposals."
- **Dust burns deterministically.** Integer-division remainder from
  pro-rata distribution burns rather than going to a "lucky voter" —
  every node agrees on the post-distribution state byte-for-byte.
- **Validation enforces fee + surcharge affordability.** Post-fork
  proposal admission requires the proposer's balance to cover both
  the tx fee and the surcharge; pre-fork validation is unchanged so
  historical replay is byte-identical.
- **Pre-fork proposals are no-ops.** Pre-fork-height proposals carry
  `voter_reward_pool = 0` and `finalize_voter_rewards` is a no-op for
  zero-pool proposals — replay through Tier 22 height does not
  perturb their state.

### Changed (off-chain, active immediately)

- **Faucet: 15-min rolling window cap replaces daily cap** (401d940).
  The public-feed faucet now meters per-IP requests over a 15-min
  rolling window instead of a calendar-day cap, smoothing out the
  abuse vector where one IP could exhaust the daily budget in
  seconds at midnight UTC.
- **Web UI: trim hero/faucet/footer prose; consolidate entity
  profile sections** (3e49408). Tightens the public-facing copy on
  https://messagechain.org and folds duplicated entity-profile
  sub-sections together. Cosmetic only — no API changes.

## [1.23.0] — 2026-04-26

Combined release rolling up everything since the 1.21.0 tag — the
1.22.0 metadata bump and Tier 21 reward-cap rework were prepared on
`origin/main` but never tagged, so this version folds Tier 20 (soft
equivocation slash), the fork-emergency detector, Tier 21
(halvings-aware proposer reward cap), and the seed-divestment
retune-v2 into a single coordinated release. Validators upgrading
from 1.21.0 land on 1.23.0 directly.

This is the first release covering Tier 20, Tier 21, and the
divestment retune; pre-fork chain history replays byte-identically
under all three forks.

### Consensus — Tier 20: soft equivocation slash (activates block 15000)

Hard fork at `SOFT_SLASH_HEIGHT = 15000` (rides above Tier 19's 13000
with a ~2000-block runway, ~14 days at 600 s/block). Honest-operator
survivability under accidental dual-sign.

- **Equivocation penalty drops from 100% to 5% per offense.** Any
  double-proposal / double-attestation / finality-double-vote
  evidence used to wipe 100% of the offender's stake + full
  bootstrap escrow + permanently ban via `slashed_validators`. That
  penalty matched a deliberate Byzantine attack but was catastrophic
  for the most common honest-operator failure mode (failover
  misconfig, restored backup with the old node still running,
  restart race). Post-fork the slash is partial —
  `SOFT_SLASH_PCT = 5` of stake + the same fraction of bootstrap
  escrow + the same fraction of any pending unstakes. The validator
  stays in the set with reduced stake; only `_processed_evidence`
  dedupes so the SAME piece of evidence cannot be applied twice.
- **Repeat-offender economics fall out without escalation logic.**
  Each new piece of evidence slashes 5% of what remains:
  `(1 - 0.05)^N` — 10 mistakes ≈ 40% loss, 50 ≈ 92%. Sustained
  misbehavior still approaches total loss; a single accident does
  not.
- **Pending unstakes scaled in place.** Each pending entry's amount
  is multiplied by `(1 - SOFT_SLASH_PCT/100)`; `release_block` is
  preserved so the unbonding schedule the offender originally chose
  is not extended by the slash. DB mirroring uses atomic
  clear-and-re-add so cold-booted nodes rehydrate the same shape.
- **Pre-fork path byte-identical.** `slash_validator(slash_pct=100)`
  takes the legacy full-wipe code path verbatim; `slash_all` with
  the same default does the same for escrow.

### Operations — fork-emergency detector + validator auto-halt

- Detector watches for unintentional fork conditions; validator
  auto-halts rather than continuing to mint on a divergent fork.
  Reduces operator damage when consensus splits unexpectedly.

### Consensus — Tier 21: halvings-aware proposer reward cap (activates block 17000)

Hard fork at `PROPOSER_CAP_HALVING_HEIGHT = 17000`.

- **Per-block proposer reward cap is now recomputed every block.**
  Previously computed once at module load as `BLOCK_REWARD * 1/4 = 4`
  tokens. Once halvings drove the actual issued reward down to
  `BLOCK_REWARD_FLOOR = 4`, the cap (still 4) equaled the entire
  block reward — so a single validator who proposes AND attests
  could sweep everything with no clawback. The anti-mega-staker
  mechanism silently turned off forever at floor era.
- Post-fork the cap is recomputed every block from the live
  `reward` returned by the issuance schedule, so the clawback ratio
  is preserved across halvings. Pre-fork blocks still apply the
  cached cap byte-for-byte for replay parity.

### Consensus — seed-divestment retune-v2 (parameter-only)

Tightens the non-discretionary founder-stake unwind so it starts
sooner and ends at a smaller floor — cleaner end-state for "secure
early on, democratize later on, leave the founder a meaningful but
non-controlling stake." Parameter-only (no schema bumps, no new
state, no apply-path or sim-path code edits). Both validators must
upgrade before `SEED_DIVESTMENT_RETUNE_HEIGHT = 1400`; current head
is well below that, so plenty of runway.

- `SEED_DIVESTMENT_START_HEIGHT`: 50_000 → **7_500** (~50 days at
  600s/block, down from ~10 months). The 4-year bleed window length
  (`END - START = 210_384` blocks) is preserved so the per-block
  divestment rate stays sane; only the start moves.
- `SEED_DIVESTMENT_END_HEIGHT` (derived): 260_384 → **217_884**.
- `SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE`: 20_000_000 →
  **10_000_000** (~14.3% of supply → ~7.1% of supply). End-state
  reads as "top holder, not controlling holder." Legacy 1M
  pre-RETUNE floor is unchanged byte-for-byte.
- `SEED_MAX_STAKE_CEILING` (derived from floor): 20M → **10M**.
  Existing seed stake above 10M (currently ~22.5M on v1) is
  grandfathered — the ceiling is enforced on `StakeTransaction`
  validation only, not on existing stake; divestment will drain v1
  to the new floor naturally over the bleed window.

End-state for the ~95M founder bootstrap shifts:

|                    | pre-retune    | post-retune     |
|--------------------|---------------:|---------------:|
| Founder retained   | 20M (~14.3%) | **10M (~7.1%)** |
| Burned             | 37.5M (~26.8%) | **42.5M (~30.4%)** |
| Lottery payouts    | 33.75M (~24.1%) | **38.25M (~27.3%)** |
| Treasury           | 3.75M (~2.7%) | **4.25M (~3.0%)** |

### Files (this release)

- `messagechain/config.py` — `SOFT_SLASH_HEIGHT`, `SOFT_SLASH_PCT`,
  `get_slash_pct`, `PROPOSER_CAP_HALVING_HEIGHT`, divestment
  parameter retune, ordering invariants.
- `messagechain/economics/inflation.py` — `slash_validator()` +
  proposer-cap recomputation gating.
- `messagechain/economics/escrow.py` — `slash_all()` partial-burn
  branch.
- `messagechain/core/blockchain.py` — slash apply paths gate on
  `get_slash_pct(height)`; comment updates for new divestment floor.
- `tests/test_soft_slash_fork.py`, `tests/test_seed_divestment*.py`,
  `tests/test_seed_stake_ceiling.py`, fork-emergency tests, Tier 21
  reward-cap tests.

## [1.21.0] — 2026-04-27

Minor release. **Hard fork: Tier 18 — unified fee market** (activates
at `TIER_18_HEIGHT = 11000`) and **Tier 19 — proposal fee tightening
+ per-byte surcharge** (activates at `PROPOSAL_FEE_TIER19_HEIGHT =
13000`). Plus one CRITICAL security fix from the round-13 audit
(active immediately, pre-Tier-17). Plus front-end features: entity
profile page (`/e/<id>`) + per-post vote indicator.

### Added (consensus, gated by activation height)

- **Tier 18 — unified fee market across Message + Transfer + React**
  (b3202e2). At `TIER_18_HEIGHT=11000` the per-block tx-count cap
  (`MAX_TXS_PER_BLOCK=45`) and total-bytes ceiling
  (`MAX_BLOCK_TOTAL_BYTES=300_000`) cover Message + Transfer +
  React jointly, and the EIP-1559 base-fee controller auctions all
  three kinds against each other. Closes the per-kind silos that
  let one tx type underprice the others under congestion.
- **Tier 19 — proposal fee tightening + per-byte surcharge**
  (cdf89d7). At `PROPOSAL_FEE_TIER19_HEIGHT=13000`:
  - title cap 400 → 200 bytes; description cap 20_000 → 2_000
    bytes (long-form rationale moves off-chain behind
    `reference_hash`).
  - flat fee 10_000 → 100_000.
  - new per-byte surcharge: 50 tokens/byte over title +
    description + reference_hash.
  - Total post-fork floor for a proposal of payload `p` bytes:
    `100_000 + 50·p`. At any p this exceeds the typical
    message floor by orders of magnitude — closes the inversion
    where a max-size proposal paid LESS per stored byte than a
    typical message.

### Security (round-13 audit)

- **`_persist_state` now full-flushes `reaction_choices` on
  post-reorg replay** (bf7f6aa). Pre-fix the per-block reaction
  flush only iterated `self.reaction_state._dirty_keys`, which
  contains ONLY the keys touched during the new fork's replay.
  Old-fork-only rows in chaindb's `reaction_choices` table were
  never DELETEd. After the next cold restart `_load_from_db`
  rehydrated the orphan vote, mixed it into
  `state_root_contribution()`, and the restarted node silently
  forked off peers that didn't restart on the next state-root
  computation. Round-12 fixed the FAILED-reorg path via
  `restore_state_snapshot`; this fix closes the SUCCESSFUL-reorg
  twin via a `full_flush` sentinel in `_persist_state`. New
  `ChainDB.clear_all_reaction_choices()` helper wipes the table
  inside the same SQL transaction as the subsequent re-INSERTs,
  atomic with the wipe. Steady-state per-block flush still uses
  the dirty-key optimization (O(K_touched), not O(N_total)).

### Added (frontend / RPC)

- **Entity profile page + RPC** (b2c3384). New `/v1/entity` JSON
  endpoint and `/e/<entity_id>` static page surface per-entity
  state.
- **Per-post vote indicator** (6b5155e). Public feed UI now shows
  per-post vote counts and renders `entity_id` as a clickable
  link to the new profile page.

### Operational

- Validators must upgrade to 1.21.0 within the runway window
  (current tip → 11_000 → 13_000) to follow the Tier 18 / Tier 19
  forks. Pre-1.21.0 nodes will reject blocks at/after activation
  height that violate the new fee-market or proposal-fee rules.
- The round-13 fix is active immediately — closes a state-root
  fork vector that activates the moment Tier 17
  (`REACT_TX_HEIGHT=9000`) is crossed plus any subsequent reorg.

## [1.20.0] — 2026-04-26

Minor release. **Two CRITICAL Tier 17 wiring fixes from the round-12
audit.** Hard fork: `STATE_SNAPSHOT_VERSION 20 → 21` (additive
section for `reaction_choices`; pre-v21 snapshot blobs are rejected
by the strict version check). Plus a fee-coherence improvement.

Neither round-12 critical is exploitable today (Tier 17 activates at
`REACT_TX_HEIGHT = 9000`, current tip ~590), but both MUST land
before activation block 9000 or first-touch turns into key
compromise / state-sync hard break. **All mainnet operators should
upgrade ASAP.**

### Security (round-12 audit)

- **`ReactTransaction` now enforces WOTS+ leaf-watermark + in-block
  leaf-collision sweep + cross-pool dedupe** (3dd5ff0). Three layers
  of leaf-reuse defense were missing on the new react path:
  - `_validate_react_tx_in_block` admitted any `leaf_index`,
    including one already past the voter's `leaf_watermarks[]`.
    Mirror the message / transfer / stake / governance gate.
  - The block-level `_check_leaf` sweep iterated every other tx
    kind but NOT `block.react_transactions` — two same-leaf signed
    payloads in the same block (e.g. Transfer at leaf N + React at
    leaf N from the same voter) bypassed dedup, both applied, the
    WOTS+ leaf secret was publicly leaked from the two signatures.
  - `Server._check_leaf_across_all_pools` didn't scan
    `mempool.react_pool`; `_rpc_submit_react` skipped both the
    cross-pool check and the per-entity watermark gate at admission.
  - Two distinct signed payloads under the same WOTS+ leaf trivially
    leak enough one-time-key material for any observer to forge
    arbitrary signatures under that leaf — including a
    `TransferTransaction` draining the voter's full balance and
    stake. Once `REACT_TX_HEIGHT` activates, any wallet bug or
    backup-restore that regresses `_next_leaf` (per
    `reference_test_wallets.md` workflow) and submits
    `transfer-then-react` hands the network a leaf-reuse pair.
- **`ReactionState` ground-truth `choices` map now in snapshot +
  chaindb save/restore symmetry** (3dd5ff0). Pre-fix:
  - `state_snapshot.serialize_state` didn't extract
    `reaction_choices`; `_TAG_REACTION_CHOICES` didn't exist;
    `encode_snapshot` / `decode_snapshot` didn't write/read it;
    `compute_state_root` committed zero reaction data.
  - `_install_state_snapshot` left `self.reaction_state` as the
    default empty `ReactionState()` after install.
  - `chaindb.save_state_snapshot` didn't capture
    `reaction_choices`; `restore_state_snapshot` didn't wipe /
    re-insert.
  - Once `REACT_TX_HEIGHT` activates and the first vote lands, every
    checkpoint-bootstrapped node would FAIL the install-time
    root-equality check (synced node computes
    `state_root_contribution()` over empty reactions; canonical
    header committed root over real reactions) — **state-sync
    becomes IMPOSSIBLE** post-activation. Reorg across a
    React-bearing block leaves orphan-fork rows on disk → cold
    restart silently forks. Same defect class as the round-2
    `entity_id_to_index`, round-4 `key_rotation_last_height`, and
    round-7 `receipt_subtree_roots` mirror leaks.
  - **Fix.** Bump `STATE_SNAPSHOT_VERSION 20 → 21`. Add
    `_TAG_REACTION_CHOICES` Merkle section + leaf builder.
    `serialize_state` extracts `blockchain.reaction_state.choices`.
    `_install_state_snapshot` rebuilds `ReactionState` from the
    snapshot map AND mirrors entries to chaindb.
    `chaindb.save_state_snapshot` captures `reaction_choices`;
    `restore_state_snapshot` wipes the table and re-INSERTs inside
    the same SQL transaction (mirrors round-8 pattern).

### Changed

- **Mempool fee-coherence: size-aware estimator, best-fit fill,
  flat `MARKET_FEE_FLOOR`** (9ce9cdb). Mempool block-fill selection
  now uses a size-aware fee-per-byte estimator and best-fit
  packing; protocol-level `MARKET_FEE_FLOOR` enforced flatly across
  all tx kinds at admission.

### Notes

- The `STATE_SNAPSHOT_VERSION` bump is a wire-format break: a
  v1.20+ node cannot decode a v20 snapshot blob (and vice versa).
  Live operators do not currently bootstrap via checkpoint, so this
  is forward-only — re-bake any archived snapshots on the upgraded
  code.
- No CLI / RPC behavior change for honest operators on the
  steady-state path (Tier 17 still activates at height 9000;
  honest validators don't trigger the leaf-reuse class).

## [1.19.1] — 2026-04-26

Patch release. **CRITICAL upgrade-blocking fix.** 1.19.0 shipped
with a wire-format regression that crashed any node attempting to
load existing on-disk blocks: Tier 17 added `react_transactions` to
`Block.from_bytes` UNCONDITIONALLY, but every block already on disk
pre-1.19.0 was serialized without that field. The decoder ran off
the end of the blob inside `_load_from_db` on first startup,
systemd entered a crash-loop, and the upgrade CLI's auto-rollback
could not recover (the stale-import path predates the deeper
crash, so the verifier never noticed). validator-1 was taken down
mid-roll on 2026-04-26 and required manual rollback to the
pre-1.19.0 backup; validator-2 was untouched per the runbook
"never both at once" rule. **No node should run 1.19.0.**

### Fixed

- **`Block.from_bytes` end-of-blob shim for pre-Tier-17 blobs**
  (2864118). Detect `len(data) - off == 32` (only the trailing
  `declared_hash` remaining) and treat `react_transactions` as
  `[]` without consuming bytes. Pre-Tier-17 blobs are a strict
  prefix of post-Tier-17 blobs up to the new field, so the shim
  cleanly distinguishes the two cases. Post-Tier-17 blobs (which
  carry at least 4 bytes for the u32 count + 32 bytes for the
  hash) decode normally.
- Includes regression test
  (`tests/test_react_tx_block_backward_compat.py`) that builds a
  real Block, strips the empty-react u32 to simulate a pre-Tier-17
  on-disk blob, and asserts decode succeeds.

### Upgrade path

- Validators that already hit the 1.19.0 crash and rolled back to
  1.18.0 (or earlier) should upgrade directly to 1.19.1 — the
  pre-Tier-17 blob shim makes the upgrade safe regardless of
  starting version.
- The 1.19.0 tag remains in git history (signed and immutable, per
  release policy) but should NOT be installed by anyone.

## [1.19.0] — 2026-04-26

Minor release. **Hard fork: Tier 17 — `ReactTransaction` (user-trust
+ message-react votes).** Activates at `REACT_TX_HEIGHT = 9000`
(~14 days runway above Tier 16 at height 7000). Plus one CRITICAL
security fix from the round-11 audit.

### Added (consensus, gated by activation height)

- **`ReactTransaction` — first-class on-chain reaction tx type**
  (2fb5e86, aa6899b). Activates at `REACT_TX_HEIGHT = 9000`. Lets
  any registered entity cast (a) a `react` vote on a specific
  `MessageTransaction.tx_hash` (e.g. like / dislike / report) or
  (b) a `trust` vote on another entity's `entity_id` (e.g.
  trust / distrust / mute). Both vote types share the same
  WOTS+-signed wire format and pay the standard signature-aware
  fee floor; reactions ride the message-tx storage budget the
  same way every other signed payload does (no special
  per-reaction subsidy or surcharge). Pre-activation a v1
  ReactTransaction is rejected at admission; post-activation it's
  the canonical user-trust + message-react primitive.
  - **State commitment.** A new `ReactionState` aggregator tracks
    per-target reaction counts (per `tx_hash` for message reacts;
    per `entity_id` for trust votes); apply-time mutations are
    committed to the snapshot root via the same per-block flush
    discipline as every other consensus-visible field.
  - **Block-pipeline integration.** `Block.react_transactions`
    rides alongside the existing per-type tx lists; admission gates
    + apply ordering mirror `MessageTransaction` (fee burn + leaf
    watermark + nonce ratchet, all routed through the round-9
    add_block transaction wrap so apply-time mutations roll back
    cleanly on a state-root mismatch).

### Security (round-11 audit)

- **`FinalityDoubleVoteEvidence` slash now uses multi-key candidate
  verification** (cf4340c). Pre-fix the FinalityDoubleVote branch
  of `Blockchain.validate_slash_transaction` resolved ONE pubkey at
  `vote_a.signed_at_height` and called
  `verify_finality_double_vote_evidence(ev, K_old)` — checking
  BOTH votes against ONE pubkey. An equivocator who signed vote_a
  with K_old at height N, submitted a `KeyRotationTransaction` at
  N + `KEY_ROTATION_COOLDOWN_BLOCKS=144`, then signed vote_b with
  K_new at N+200 (within the
  `FINALITY_VOTE_MAX_AGE_BLOCKS=1000` window targeting the same
  checkpoint) bypassed the slash: K_old verified vote_a but
  vote_b's K_new signature failed → "Invalid evidence: vote_b
  signature is invalid", slash dismissed, **equivocator keeps
  stake**. Cooldown (144) << vote-age window (1000), so the
  rotation comfortably fits inside the same target's vote window
  and the bypass is trivial for any rotating validator.
  - **Fix.** Mirror the multi-key shape of
    `verify_attestation_slashing_evidence` (Round 6): drop the
    single-key shortcut and enumerate the offender's full
    `key_history` (+ current pubkey) as candidates. Verify each
    vote independently against ANY candidate. Every candidate is
    one the offender legitimately published on-chain (each
    rotation step is signed by the prior key), so matching ANY
    candidate is proof the offender produced the signature —
    attacker cannot exploit the candidate set to forge evidence.
  - This is **distinct** from the carried-over "multi-key resolver
    doesn't bind to evidence_height" item — that concerns
    *over-acceptance* in the multi-key path; this is the
    symmetric *under-acceptance* hole in the still-single-key
    FinalityDoubleVote branch.

### Operational

- Validators must upgrade to 1.19.0 within the runway window
  (7000 → 9000) to follow the Tier 17 fork. Pre-1.19.0 nodes will
  reject blocks at/after height 9000 that carry
  `ReactTransaction`s.
- The round-11 security fix is active immediately (pre-Tier-17),
  so all mainnet operators should upgrade promptly to close the
  finality-vote slash-evasion window.

## [1.18.0] — 2026-04-26

Minor release. **Hard fork: Tier 16 — market-driven fee floor.**
Activates at `MARKET_FEE_FLOOR_HEIGHT = 7000` (~14 days runway above
Tier 15 at height 5000).

### Changed (consensus, gated by activation height)

- **`MARKET_FEE_FLOOR = 1` retires the linear-in-stored-bytes fee
  floor.** At/after `MARKET_FEE_FLOOR_HEIGHT`, the protocol-level fee
  floor for `MessageTransaction`s collapses to a flat 1 token,
  regardless of message size, prev-pointer presence, or witness size.
  The linear formula
  (`BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE × len`) is retained
  only as a replay rule for blocks in `[BLOCK_BYTES_RAISE_HEIGHT,
  MARKET_FEE_FLOOR_HEIGHT)`. Pre-fork heights replay under the rule
  current at their height (legacy quadratic, flat
  `MIN_FEE_POST_FLAT`, or one of the two linear variants) — historical
  blocks validate unchanged.

  Rationale: the linear floor was doing two jobs — keep zero-fee txs
  out of the mempool, and discipline long-message bloat by per-byte
  pricing. Only the first is the floor's job. Bloat discipline is
  already delivered by `MAX_BLOCK_MESSAGE_BYTES` (a hard byte ceiling
  per block, ~6.5 MB/day at full utilization regardless of fee paid)
  and EIP-1559 base fee dynamics (which automatically price the
  marginal byte under congestion). Setting the floor to 1 — not 0 —
  preserves the no-free-tx invariant without the protocol trying to
  set the equilibrium price.
- **EIP-1559 base-fee lower bound drops from `MIN_FEE` (=100) to
  `MARKET_FEE_FLOOR` (=1) at/after `MARKET_FEE_FLOOR_HEIGHT`.** Base
  fee can now decay to 1 token during quiet periods, then ratchet up
  via the existing 12.5%-per-over-target-block dynamics under
  congestion. Upper cap stays absolute (`MIN_FEE × MAX_BASE_FEE_MULTIPLIER`
  = 1_000_000) — it bounds pathological pricing in absolute tokens,
  not as a multiple of the floor.
- **`enforce_signature_aware_min_fee` protocol baseline drops to
  `MARKET_FEE_FLOOR` for all non-message tx types at/after
  activation.** Type-specific surcharges (`NEW_ACCOUNT_FEE`,
  `GOVERNANCE_PROPOSAL_FEE`, `KEY_ROTATION_FEE`, etc.) are
  unaffected — they price externalities specific to those tx types
  (permanent state entry, binding governance vote, key rotation) and
  remain the binding floor for those tx types in practice.

### Operational

- Validators must upgrade to 1.18.0 within the runway window
  (5000 → 7000) to follow the fork. Pre-1.18.0 nodes will reject
  blocks at/after height 7000 that carry messages priced below the
  pre-Tier-16 linear floor.

### Security (round-10 audit)

- **Governance-tx gossip handler now verifies signatures before
  admitting** (b991720). Pre-fix the `kind=="governance"` branch of
  `Server._handle_announce_pending_tx` admitted forged
  `ProposalTransaction` / `VoteTransaction` /
  `TreasurySpendTransaction` after checking only that
  `signer_id in public_keys`. An unauthenticated peer could craft a
  tx with any registered entity's id as `proposer_id` / `voter_id`
  and the validator would admit it to `_pending_governance_txs` and
  rebroadcast. When the validator next became proposer it packed
  the forged tx into its block; `validate_block` then rejected the
  entire block at `_validate_governance_tx_in_block` (sig fails) —
  the proposer wasted its slot, produced no block, and accrued
  inactivity-leak / archive-miss penalties. Sustained flood across
  rotated peers prevents block production indefinitely on a
  2-validator chain. The fix routes admission through the existing
  in-tree `Blockchain._validate_governance_tx` helper — the same
  verifier `_validate_governance_tx_in_block` already trusts at
  consensus-time validation. Mirrors the verify-before-admit pattern
  of the sibling `stake` / `unstake` / `authority` branches; this
  was the lone gap.

## [1.17.1] — 2026-04-26

Patch release. ONE CRITICAL silent-fork fix from the round-9 audit
pass against the post-v1.17.0 chain state. **All mainnet operators
should upgrade ASAP** — every node that processed a state-root-
rejected block since the chain went live is exposed on its next cold
restart.

### Security

- **`add_block` now wraps apply + state-root verify + persist in a
  single chaindb transaction** (f28c872). Pre-fix multiple apply-time
  helpers eagerly committed to chaindb BEFORE the per-block
  transaction opened — `_record_key_history` /
  `apply_key_rotation` (set_public_key, set_leaf_watermark,
  set_key_rotation_count, set_key_rotation_last_height, plus an
  explicit `db.flush_state()`), `apply_revoke_transaction`
  (set_revoked + flush_state), and the first-spend pubkey installs
  in transfer-with-burn / message-tx apply paths (set_public_key).
  A block whose `state_root` mismatched got rolled back in-memory by
  `_restore_memory_snapshot`, but the disk mirror kept the
  rejected-block writes. A subsequent cold restart rehydrated the
  phantom rows and silently forked off the canonical chain.
  - **Concrete exploit**: a staked proposer crafts a block carrying
    a self-targeted `KeyRotationTransaction(new_public_key=
    PK_attacker)` plus a deliberately wrong `state_root`. The
    simulated-root pre-check skips slash-bearing blocks, so any
    block including a slash tx reaches apply unconditionally. Apply
    eagerly writes `(height, PK_attacker)` to `key_history` and
    `PK_attacker` to `public_keys`; state-root verify fails;
    in-memory rolls back; disk keeps the writes. Cold restart
    on any node that processed the block then resolves PK_attacker
    via `_public_key_at_height` for any block the entity signs and
    rejects pre-rotation slash evidence as having an invalid
    signature → silent fork at the slash block, plus a slashing
    escape for any equivocator who can land such a block.
  - **Fix shape**: in `add_block`, every chaindb write inside
    `_apply_block_state` now rides the outer txn via the chaindb's
    `_txn_depth` nesting (inner `begin_transaction` at depth>0 is a
    no-op; inner `_maybe_commit` at depth>0 is a no-op; only the
    outer commits or rolls back). On state-root mismatch we
    `rollback_transaction` to undo all eager DB writes alongside
    the existing `_restore_memory_snapshot`. Same defect-class fix
    as round-7's `_record_receipt_subtree_root` deferral, but
    applied at the apply-loop boundary so it covers ALL current
    AND future eager writers without per-helper plumbing changes.
- **Belt-and-suspenders cleanup** (f28c872):
  - `_record_key_history` no longer eager-writes; `_persist_state`
    gains a key_history flush loop after the existing past-roots
    loop.
  - `apply_key_rotation` no longer eager-writes; relies on
    `_persist_state`'s pre-existing `public_keys` /
    `leaf_watermarks` / `key_rotation_counts` /
    `key_rotation_last_height` flush loops.
  - `db.flush_state()` is now depth-aware (routes through
    `_maybe_commit`) so any helper invoked inside the outer wrap
    cannot prematurely commit the outer txn and partially defeat
    the fix. Outside any wrap (cold-start bootstrap, standalone
    tests) it still commits immediately.

### Notes

- No on-chain schema bump (no `STATE_SNAPSHOT_VERSION` change).
- No CLI / RPC behavior change for honest operators on the
  steady-state path.
- Mainnet validators have restarted multiple times during the
  recent 1.14→1.17 release sequence, so the exposure was real:
  the next restart on a node that had ever processed a bad-state-
  root block could have triggered the fork. Roll both validators
  promptly.

## [1.17.0] — 2026-04-26

Minor release. Two CRITICAL silent-fork fixes from the round-8 audit
pass against the post-v1.16.0 chain state. Both are state-sync /
cold-restart hazards: a node bootstrapped from a checkpoint snapshot
or restarted after a failed reorg ended up with empty maps that the
warm cluster relied on for evidence verification. **All mainnet
operators should upgrade ASAP** — once Fix #1 is in place, freshly
bootstrapped validators will correctly verify slash evidence at
pre-rotation heights.

Hard fork: `STATE_SNAPSHOT_VERSION 19 → 20`. Adds the new
`key_history` section (per-entity rotation history) to the
state-snapshot wire format and snapshot-root commitment. Pre-v20
snapshots can no longer be decoded; the in-memory `setdefault` to an
empty `key_history` is preserved for hand-built snapshot dicts in
tests, but the binary decoder is strict.

### Security

- **`key_history` now lives in the state snapshot** (04d2548). Pre-fix
  the snapshot did not encode `key_history` at all. State-synced nodes
  bootstrapping from a checkpoint started with `self.key_history = {}`
  for every entity, so `_public_key_at_height` fell back to the
  CURRENT pubkey for any rotated entity. Slash evidence whose signing
  height predated the rotation verified against the wrong key on the
  synced node — slash rejected, while warm nodes admitted — silent
  fork at the slash block. Adds:
  - `_TAG_KEY_HISTORY` (`khist`) section with a custom
    `(eid, height, pk)` leaf builder so the snapshot root commits to
    every rotation tuple
  - `_encode_key_history` / `_decode_key_history` with deterministic
    outer-by-eid + inner-by-(height, pk) sort order
  - `serialize_state` extracts `blockchain.key_history`
  - `_install_state_snapshot` installs the dict AND mirrors entries
    into chaindb's `key_history` table so cold restart on the synced
    node rehydrates from disk
- **chaindb save/restore symmetry on receipt-subtree + key-rotation-
  cooldown mirror tables** (04d2548). Pre-fix `save_state_snapshot`
  did NOT capture `receipt_subtree_roots`,
  `past_receipt_subtree_roots`, or `key_rotation_last_height`, but
  `restore_state_snapshot` DELETEd all three. The reorg-failure path
  in blockchain.py called `restore_state_snapshot` then returned
  without `_persist_state` — in the post-restore window a process
  exit (operator restart, OOM, SIGKILL) cold-restarted the node into
  empty mirrors. After the round-7 forged-receipt fix an empty
  `receipt_subtree_roots` makes LEGITIMATE `CensorshipEvidence`
  rejected on the cold-restarted node while warm nodes admit —
  silent fork. The fix:
  - `save_state_snapshot` includes the three missing keys
  - `restore_state_snapshot` adds three INSERT loops that re-populate
    from the snapshot dict atomically inside the same transaction
    that ran the DELETEs
  - belt-and-suspenders: the reorg-failure path now calls
    `_persist_state` after `_reset_state` + replay so future fields
    added to one side without the other still resync before the next
    block.

### Notes

- `STATE_SNAPSHOT_VERSION` bump is a wire-format break: a v1.17+ node
  cannot decode a v19 snapshot blob. Live operators do not currently
  bootstrap via checkpoint, so this is forward-only — re-bake any
  archived snapshots on the upgraded code.
- No new CLI commands, no new RPC methods, no behavior change for
  honest operators on the steady-state path. The fixes are purely
  "make state-sync and post-reorg-crash recovery actually work."

## [1.16.0] — 2026-04-26

Minor release. Four CRITICAL security fixes from the round-7 audit
pass against the post-v1.15.0 chain state. **All mainnet operators
should upgrade ASAP** — Fix #1 below directly exposes live validators
to a one-tx slash for the price of `MIN_FEE` until they upgrade.

### Security

- **Forged-receipt slashing of unonboarded validators closed**
  (135de3c). `validate_censorship_evidence_tx` and
  `validate_bogus_rejection_evidence_tx` no longer short-circuit the
  receipt-root admissibility gate when the offender has never
  installed a `SetReceiptSubtreeRoot`. Pre-fix the gate
  `if tx.offender_id in self.receipt_subtree_roots and not
  receipt_root_admissible(...)` skipped entirely for unonboarded
  victims, letting an attacker generate their own receipt subtree,
  sign a `SubmissionReceipt` purporting to be from the victim under
  an attacker-controlled root, wrap it in a `CensorshipEvidenceTx`,
  and slash the victim for `CENSORSHIP_SLASH_BPS` of stake at the
  price of `MIN_FEE`. Both live mainnet validators were exposed
  (neither has run their initial `SetReceiptSubtreeRoot` onboarding).
  The gate now defers to `receipt_root_admissible` unconditionally;
  that helper already returns `False` for offenders with no anchor
  of trust.
- **`_record_receipt_subtree_root` chaindb-write rollback safety**
  (135de3c). Pre-fix the helper called `db.set_receipt_subtree_root`
  and `db.add_past_receipt_subtree_root` synchronously at apply time,
  BEFORE the per-block SQL transaction opened in
  `_apply_block_state`. A bad-state-root block whose apply mutated
  the maps got rolled back in-memory by `_restore_memory_snapshot`,
  but the chaindb mirror kept the rejected-block writes — a cold
  restart then rehydrated the corrupted mirror and silently forked
  off the canonical chain. Writes are now deferred to
  `_persist_state`, which runs inside the per-block transaction
  wrapper for crash atomicity.
- **`_install_state_snapshot` installs `past_receipt_subtree_roots`**
  (135de3c). v19 made the historical-roots dict load-bearing for
  evidence admission AND committed it to the snapshot root, but the
  install path was never updated. State-synced (checkpoint-
  bootstrapped) nodes started with the dict empty and silently
  forked off the warm cluster on the first contested
  `CensorshipEvidence` under a rotated-away root. Install now
  mirrors the same shape as the live-roots assignment.
- **`FinalityVote.signed_at_height` bounded by
  `[target_block_number, current_height]`** (135de3c).
  `_validate_finality_votes` now rejects any vote whose
  `signed_at_height` exceeds the block being assembled (signer
  claims a tip they hadn't seen) or precedes the vote's target
  (signer predates the block they commit to). Pre-fix the field
  was unconstrained: the slash-evidence pipeline keys the TTL gate
  on `signed_at_height`, so an equivocator who picked a far-past
  value drove the TTL check past expiry the moment the votes landed
   — their double-vote was no longer slashable.

### Notes

- Pure security release. No new CLI commands, no new RPC methods,
  no `STATE_SNAPSHOT_VERSION` bump (no on-chain schema change), no
  behavior change for honest operators.
- The `FinalityVote.signed_at_height` bound is technically a
  consensus-rule tightening (a previously-valid block carrying an
  out-of-bounds vote would now be rejected). Honest validators
  produce votes with `signed_at_height` equal to the chain tip at
  signing time, so historical replay is unaffected. Roll both
  validators promptly to keep the rule uniformly enforced.

## [1.15.0] — 2026-04-26

Minor release. Three CRITICAL security fixes — all the same root
cause: the v1.14.0 `past_receipt_subtree_roots` defense (rotation
no longer wipes outstanding evidence) had three integration gaps
that effectively disabled the fix in production. **All mainnet
operators should upgrade ASAP** — the v1.14.0 release notes told
operators that rotation no longer wipes evidence; this release is
what actually makes that true.

Hard fork: `STATE_SNAPSHOT_VERSION 18 → 19`. Adds the new
`past_receipt_subtree_roots` section to the state-snapshot root
commitment. Pre-v19 snapshots are upgraded via a `setdefault` to an
empty history (no prior rotations to preserve), so a v18→v19
upgrade is seamless. Two state-synced nodes that observed different
rotation histories now correctly produce different state roots
instead of agreeing on root but disagreeing on which receipts are
admissible.

### Security

- **Block-apply path now routes through `_record_receipt_subtree_root`**
  (cd80604). Pre-fix `_apply_authority_tx` inlined the live-root
  overwrite and bypassed the helper that appends the OLD root to
  `past_receipt_subtree_roots`. The standalone
  `apply_set_receipt_subtree_root` method (which DOES use the
  helper) was dead production code — only tests called it. Net
  result: the v1.14.0 rotation-evidence-wipe defense was a no-op
  on mainnet. A coerced validator who issued thousands of receipts
  under R1 could publish ONE cold-key `SetReceiptSubtreeRoot(R2)`
  in a block; on every honest peer replaying that block, R1
  receipts became permanently inadmissible.
- **`_snapshot_memory_state` / `_restore_memory_snapshot` now
  capture `receipt_subtree_roots` + `past_receipt_subtree_roots`**
  (cd80604). Pre-fix a bad-state-root block whose apply path
  mutated the live map got caught by the post-apply state_root
  check and rolled back, but the snapshot didn't include these
  fields → in-memory map kept the rejected-block mutations.
  Combined with the chaindb mirror write that already landed
  during apply, the corruption persisted across restart.
- **`past_receipt_subtree_roots` now committed to the state-
  snapshot root** (cd80604). New `_TAG_PAST_RECEIPT_ROOT` section
  with deterministic `(eid, root)` leaf builder, encoder/decoder
  pair, and `serialize_state` extraction. Two state-synced nodes
  that observed different rotation histories now produce different
  state roots — closes the silent-fork window where they agreed on
  root but disagreed on `receipt_root_admissible`.

### Notes

- The `STATE_SNAPSHOT_VERSION` bump means a v1.15+ node MUST be
  used to validate v19 snapshots. v18 snapshots remain readable
  on v1.15+ via the upgrade-path `setdefault` to an empty
  `past_receipt_subtree_roots` map.
- No new CLI commands, no new RPC methods, no behavior change for
  honest operators. The fix is purely "make the v1.14.0 defense
  actually run."

## [1.14.0] — 2026-04-26

Minor release. Eleven critical security audit fixes across rounds 4
and 5. Closes the censorship-evidence pipeline end-to-end on both
HTTPS and RPC ingress, defeats a coerced-validator evidence-wipe via
`SetReceiptSubtreeRoot` rotation, plus several consensus-safety + DoS
holes. **All mainnet operators should upgrade ASAP** — five of these
issues directly target the headline structural defense against
validator collusion.

### Security

- **Wire `receipt_issuer` into `SubmissionServer`** (a6fd35e, fdcf83e).
  Pre-fix the public HTTPS submission endpoint never issued
  SubmissionReceipts / Acks / Rejections — the entire censorship-
  evidence pipeline was silently dead since the endpoint shipped. A
  coerced validator could admit-and-drop honest user submissions
  with zero on-chain accountability.
- **Wire `WitnessObservationStore` into `SubmissionServer`** (a6fd35e).
  Without it, the `obs_ok` ack-issuance gate short-circuits to True
  for any 32-byte `X-MC-Witnessed-Submission` header, letting a
  botnet drain the 65k-leaf receipt subtree in hours via the per-IP
  ack budget alone.
- **Route `_rpc_submit_transaction` through the receipt-issuer
  helper** (a6fd35e). Pre-fix the RPC submission path bypassed
  receipt issuance entirely. RPC submissions now return a `receipt`
  field clients can weaponize as `CensorshipEvidenceTx`.
- **`receipt_subtree_roots` reorg leak** (a6fd35e). Same defect class
  as the round-2 `entity_id_to_index` and round-4
  `key_rotation_last_height` leaks. `_reset_state` now clears the
  in-memory map; `restore_state_snapshot` `DELETE`s the chaindb
  mirror.
- **Receipt-subtree-root rotation no longer wipes outstanding
  evidence** (a6fd35e). New `past_receipt_subtree_roots` history per
  entity — receipt validation accepts the current root OR any
  historical root the entity ever installed. Pre-fix a coerced
  validator could pre-emptively erase every in-flight evidence
  receipt with one cold-key `SetReceiptSubtreeRoot` tx. New
  `past_receipt_subtree_roots` chaindb table mirrors the history.
- **Slashed-this-block validators excluded from finality**
  (a6fd35e). Pre-fix a coordinated proposer could push a target
  block over 2/3 finalization using stake that consensus had already
  declared malicious in the same block. `_apply_finality_votes` and
  the matching `compute_post_state_root` sim path now pre-filter
  survivors against `slashed_validators`.
- **Empty-entries inclusion list rejects non-empty
  `quorum_attestation`** (a6fd35e). Pre-fix the empty-entries
  shortcut returned OK before signature-verifying any quorum-
  attestation report — a proposer could attach arbitrarily large
  unverified garbage at zero fee.
- **Governance v1 admission rejected post-Tier-15 activation**
  (a6fd35e). Pre-fix both v1 and v2 of the SAME logical proposal
  text could exist concurrently (different tx_hashes → different
  proposal_ids), splitting honest votes; for `TreasurySpend`, both
  could clear 2/3 and double-debit the treasury. Post-fork
  (height ≥ `GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT=5000`), v1 admission
  is rejected. Historical v1 blocks still replay.
- **`KeyPair.sign` thread-safety** (fdcf83e). Concurrent calls
  could both observe the same `_next_leaf` before either advanced
  it, producing two WOTS+ signatures over different message hashes
  under the same one-time leaf — mathematically reveals the leaf's
  WOTS+ private key. New `_sign_lock` (threading.Lock) wraps the
  read-modify-write of `_next_leaf` (including persist-before-sign
  disk write).
- **`key_rotation_last_height` reorg leak** (fdcf83e).
  `restore_state_snapshot` now `DELETE FROM key_rotation_last_height`.
- **30-second socket read timeout on `_SubmissionHandler` and
  `_FeedHandler`** (a6fd35e). Closes a slow-loris vector — pre-fix
  a single attacker could pin thousands of validator threads.

### Notes

- The `past_receipt_subtree_roots` table is added by
  `CREATE TABLE IF NOT EXISTS` so a downgrade-then-upgrade cycle is
  safe.
- Validators on this version expose a new `receipt` field in the
  `submit_transaction` RPC response; older clients ignore unknown
  JSON keys, so this is a forward-compatible additive change.

## [1.13.0] — 2026-04-26

Minor release. Adds an engagement-signal beacon to the public feed
viewer: a one-shot `GET /beacon/scroll` the homepage's JS fires the
first time a visitor scrolls past the initial fold. Pairs visitor
IPs with reader-depth in the access log so operators can tell who
actually read past the first screen of messages. Cosmetic; no
protocol or consensus impact.

### Added

- **`GET /beacon/scroll` on `PublicFeedServer`** — 204 response, no
  body, `Cache-Control: no-store`. The homepage now ships a small
  scroll listener that fires this exactly once per page load when
  `window.scrollY` exceeds one viewport. The listener detaches
  itself after firing.

## [1.12.0] — 2026-04-25

Minor release.  Hard fork: compress the bootstrap-window fork
schedule (Tier 1-7) from the original 50_000-98_000 height range
into 600-2800.  Pulls SEED_DIVESTMENT_START_HEIGHT forward from
105_192 (~2 years) to 50_000 (~1 year).  No new consensus
mechanisms; every fork in this release is a parameter change the
schedule had already committed to.

### Why compress

The original schedule's wide spacing existed to give independent
operators 1-2 years of upgrade runway between forks.  With the
network in its bootstrap phase (one operator running both validators,
no external validators), that runway is artificial -- you're
upgrade-coordinating with yourself, and every additional block of
"future fork waiting to land" is unfinished business carried across
releases.  Pulling Tier 1-7 to the 600-2800 window gets the chain
into its steady-state parameters now, so future audits and validator
onboarding land against the final rule set instead of a partially-
activated transitional one.

### Compressed heights

Tier 1 (UNBONDING extension, FINALITY_VOTE cap, SEED_STAKE ceiling,
TREASURY_CAP tightening): 50_000-56_000 -> 600-1200.

Tier 2 (MIN_STAKE raise, LOTTERY_BOUNTY raise, FEE_INCLUDES_SIGNATURE):
60_000-64_000 -> 1000-1200.

Tier 3 (TREASURY_REBASE -33M burn, SEED_DIVESTMENT retune+redist):
68_000-74_000 -> 1300, 1400, 1600.

Tier 4 (ATTESTER reward split, fee funding, finality reward, cap, fix):
78_000-86_000 -> 1700-2300.

Tier 5 (DEFLATION_FLOOR v1+v2): 90_000-92_000 -> 2500-2600.

Tier 6 (VALIDATOR_REGISTRATION burn): 96_000 -> 2700.

Tier 7 (FLAT_FEE): 98_000 -> 2800.

All existing ordering asserts in `messagechain/config.py` are
preserved.  TREASURY_CAP_TIGHTEN_HEIGHT (1200) is placed after the
typical GOVERNANCE_VOTING_WINDOW close (~1014) so existing
treasury-spend tests with small treasuries don't trip the new
0.1%-per-epoch + 5%-annual caps; ATTESTER_REWARD_CAP_HEIGHT (2000)
and ATTESTER_CAP_FIX_HEIGHT (2300) are spaced 300 blocks apart
(vs. the original 2000) to preserve the [CAP, FIX) test window.

### Seed divestment pull-forward

`SEED_DIVESTMENT_START_HEIGHT`: was 105_192 (= BOOTSTRAP_END_HEIGHT,
~2 years from launch).  Now 50_000 (~1 year).  The 4-year bleed-
window duration (END - START = 210_384 blocks) is preserved, so the
per-block divestment rate is unchanged; only the start is pulled
forward.

`SEED_DIVESTMENT_END_HEIGHT`: 315_576 -> 260_384 (= 50_000 + 210_384).

This is the largest economically-significant change in the release.
By the end of the bleed (height ~260_384, ~5 years from launch), the
founder bond drops from the genesis 95M to a 20M floor, with the
delta burned 95% / treasury 5% / lottery (after redist fork) 45%/5%/50%
per the existing post-redist params.  Pulling the start forward by
one year compresses the runway to credible decentralization without
touching the bleed mechanics.  Why one year and not less: the audit
credibility win comes when the founder stake is no longer the
supermajority of stake, which requires external validators to exist;
starting the bleed before plausibly any external validator can exist
just burns tokens into a one-operator network.

### Activation runway

Lowest new fork height is 600.  Current tip ~451 at release time, so
~150 blocks (~25 hours at 600s/block) of upgrade runway.  Standard
`messagechain upgrade` on both validators picks up the new constants
on restart; pre-fork blocks continue to validate under the legacy
parameters at every height below the new activation, so historical
replay is byte-preserved.

## [1.11.0] — 2026-04-25

Minor release.  Hard fork (Tier 13, audit finding #2) plus an
operator feature.  Lays the wire-format groundwork for upgrade
signaling so future forks can refuse to cross their activation
height until enough validators have upgraded -- without that, a
single missed upgrade silently partitions the chain.  Also adds an
offline pre-sign workflow for the existing emergency-revoke
kill-switch.

### Added — Tier 13 hard fork (validator version signaling)

- **`BlockHeader.validator_version` (V2 wire format).**
  At/after `VERSION_SIGNALING_HEIGHT = 3500`, blocks serialize
  under `BLOCK_SERIALIZATION_VERSION_V2` carrying a uint16
  `validator_version` field stamping the proposer's running
  release.  Pre-activation blocks remain V1 (no field), and the
  V1 codec is preserved end-to-end so the entire pre-fork chain
  history hashes byte-for-byte identically under new code -- no
  migration step, no re-hashing, no surprise prev-hash drift.
  V1 and V2 are both accepted indefinitely so historical blocks
  always replay cleanly.  (`messagechain/core/block.py`,
  `messagechain/config.py`)
- **`messagechain/consensus/validator_versions.py` registry.**
  Append-only mapping from uint16 -> (release_tag, notes).
  `CURRENT_VALIDATOR_VERSION = 1` for this release; future
  releases bump and append.  Reserved value 0 = UNSIGNALLED, used
  for pre-Fork-1 historical blocks; consumers MUST treat it as
  "no signal" and never as "matches any version" so a downgrade
  attack can't bypass future activation gates by zeroing the
  field.
- **Block producer stamps `CURRENT_VALIDATOR_VERSION` post-
  activation.**  Pre-activation blocks default to UNSIGNALLED so
  the V1 layout is preserved.  `BlockHeader._ser_version_for_height`
  is the single point of truth: every codec path
  (signable_data, to_bytes, from_bytes, the Block envelope's
  leading-byte stamp) reads from it, so the in-memory
  representation can serialize cleanly under either format.
  (`messagechain/consensus/pos.py`)

This fork ITSELF has no consensus-rule consumer of the new field
-- it only makes the field appear on the wire.  Fork 2 (the
active-set liveness fallback, audit finding #1) will land in a
follow-up release and consume it as its activation gate.  Two
separate forks is the deliberate sequencing: activating a
liveness-recovery fork using the same heights-only deployment
mechanism that put liveness at risk would be reckless; fork-1
ships first, fork-2 ships behind the gate.

### Added — Offline emergency-revoke pre-sign workflow

- **`messagechain emergency-revoke --print-only`.** Builds and
  signs a revoke locally with the cold key, prints serialized
  hex on stdout, makes ZERO RPC calls.  Intended for an
  air-gapped machine: pre-sign once while the cold key is
  available, store the bytes offline (paper QR + encrypted USB
  in two physical locations), broadcast later under duress.
  Default fee in this mode is 10x `MIN_FEE_POST_FLAT` so a
  single fork worth of governance fee inflation does not strand
  the saved bytes.  `--fee` overrides.
- **`messagechain broadcast-revoke --hex <bytes> | --file <path>`.**
  Companion on the network-attached side.  Parses the saved
  hex (whitespace-tolerant, so a printed page with newlines
  works), confirms target entity + fee + tx hash, then submits
  via the existing `emergency_revoke` RPC.  No cold key
  required at broadcast time -- the bytes are already signed.

The protocol's `RevokeTransaction` was designed for this
workflow from day one (nonce-free, no expiration; see the
module docstring) -- only the CLI was missing.  Now closed.

### Deployment

Activation height `VERSION_SIGNALING_HEIGHT = 3500` sits well
above the live tip (~451 at release time), giving operators
~20 days of runway to upgrade without protection from this very
gate (which doesn't exist yet).  Manual coordination is the
mitigation for fork-1 itself; future forks use the gate.

Both validators MUST be on 1.11.0 before block 3500 or they
will silently diverge there: blocks produced post-activation
under V2 wire format are rejected by older code as "trailing
bytes," which presents as a fork.  See the design doc in the
operator runbook for the full rollout sequence.

### Changed

- `BLOCK_SERIALIZATION_VERSION` is now `2` (was `1`); both V1
  and V2 are in `_ACCEPTED_BLOCK_SERIALIZATION_VERSIONS` so
  old-format blocks still decode cleanly.

## [1.10.0] — 2026-04-25

Minor release.  Hard fork (Tier 12) opens the chain to non-English
speech.  Closes the largest mission/mechanism mismatch in the project:
the public framing pitches MessageChain as a censorship-resistant
ledger for dissidents and coerced-speech contexts, but the protocol
rejected every codepoint outside printable ASCII (32-126), shutting
out the bulk of the world's writing systems.

### Added -- Tier 12 hard fork

- **`MessageTransaction` plaintext rule, post-INTL_MESSAGE_HEIGHT.**
  At/after `INTL_MESSAGE_HEIGHT = 1500`, message plaintexts are NFC-
  normalized UTF-8 whose codepoints fall under Unicode General_Category
  L*/M*/N*/P*/Zs (letters, marks, numbers, punctuation, space), plus a
  narrow allowlist of two format characters required for script
  shaping: U+200C ZWNJ and U+200D ZWJ.  Bidi override / isolate
  characters (U+202A-U+202E, U+2066-U+2069) are explicitly rejected
  as spoofing vectors.  All `S*` (symbols including emoji, math glyphs,
  currency), `C*` outside the ZWJ/ZWNJ allowlist (controls,
  surrogates, private-use, unassigned, other format chars), and Zl/Zp
  separators are rejected.  Pre-activation: legacy printable-ASCII rule
  (32-126) unchanged so historical blocks replay deterministically.
  (`messagechain/core/transaction.py`, `messagechain/config.py`)
- **Why categories, not a script allowlist.**  The L/M/N/P/Zs
  whitelist is structural -- "characters that are letters, marks,
  numbers, punctuation, or space" -- and has no political knob.  A
  "popular scripts" allowlist would force a discretionary admission
  rule (which scripts count?  who decides when Tibetan or Burmese
  qualifies?), and the project's audience is disproportionately
  small-population languages in coerced-speech contexts that any such
  cutoff would strand.  Future Unicode scripts land in L/M/N
  automatically and become valid without a config change.
- **Coverage, by speaker count.**  Every modern living language with
  >=10M speakers is covered: Latin (English, Spanish, French, German,
  Vietnamese, Polish, Turkish, Indonesian, Swahili, Filipino, ...),
  Cyrillic (Russian, Ukrainian, Bulgarian, Serbian, Kazakh, ...),
  Arabic (Arabic, Persian, Urdu, Pashto, Uyghur, ...), CJK (Mandarin,
  Cantonese, Japanese, Korean), Indic (Hindi, Bengali, Tamil, Telugu,
  Marathi, Gujarati, Kannada, Malayalam, Sinhala, Punjabi, Nepali),
  Southeast Asian (Thai, Lao, Khmer, Burmese), plus Greek, Hebrew,
  Armenian, Georgian, Amharic, Tigrinya, Tibetan.
- **Storage cap unchanged in numerator, semantically shifted in
  denominator.**  `MAX_MESSAGE_CHARS = 1024` still binds, but post-fork
  it caps UTF-8-encoded plaintext bytes (1024 bytes) rather than ASCII
  characters.  English users still get ~1024 chars; Cyrillic / Greek /
  Hebrew users get ~512; CJK users get ~341.  Each pays
  `BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * len(stored)` -- the
  fee market already prices stored bytes, so bloat discipline is
  unchanged across regimes.
- **NFC normalization required (not auto-applied).**  Without this
  rule "café" encoded as U+00E9 vs U+0065+U+0301 would yield two
  distinct tx_hashes for the same visible message, breaking dedup,
  prev-pointer references, and feed-equality checks.  The chain
  rejects non-NFC input rather than silently normalizing -- determinism
  + replay sanity outweigh client-side convenience.

### Changed

- **`messagechain send` pre-flight check is now UTF-8-aware.**
  Replaces the pre-1.10.0 ASCII-only diagnostic that named em-dash /
  smart-quotes / ellipsis as "common culprits."  Post-fork those are
  legitimate punctuation (P* category) and the friendly diagnostic
  shifts to byte-cap overruns -- the only failure mode the CLI can
  pre-empt locally without a chain round-trip.
- **`MessageTransaction.deserialize` and `to_dict` now use UTF-8.**
  Byte-identical to the legacy ascii-encode path for ASCII-only
  plaintexts; correctly carries multi-byte sequences for post-fork
  messages.

### Deployment

- `INTL_MESSAGE_HEIGHT = 1500` is well above the live tip (~451 at
  release time), giving operators ~7 days of upgrade runway before
  the fork point -- substantially longer than the ~100-minute runways
  used for Tier 8-11.  This is a UX-visible change for every wallet
  and reader client, not just operators, so the wider window lets
  third-party tooling catch up.
- No operator action beyond the standard `messagechain upgrade`.  The
  validator binary picks up the new validation function on restart;
  pre-fork blocks continue to validate under the legacy ASCII rule
  through height 1499 and v1/v2 message wire formats keep working
  unchanged at all heights.

## [1.9.0] — 2026-04-26

Minor release. Hard fork (Tier 11) plus an opt-in operator feature.
Two structurally-correct fixes for the cold-start gap that the 1.8.x
faucet exposed: the chain itself now lets fresh wallets post their
first message in one tx, and the faucet now uses client-side
proof-of-work instead of pure rate-limiting so Tor / privacy users
stay first-class.

### Added — Tier 11 hard fork

- **`MessageTransaction.sender_pubkey` (v3 txs).**
  At/after `FIRST_SEND_PUBKEY_HEIGHT = 500`, message txs may carry
  an optional 32-byte `sender_pubkey` field.  When the sender's
  entity_id is not yet on chain, the field is required and is
  installed in `chain.public_keys` on apply.  Mirrors
  `TransferTransaction.sender_pubkey` exactly so messaging works
  for receive-to-exist wallets in one round-trip instead of
  needing a transfer-first dance to install the pubkey.  Closes
  the asymmetry where the faucet could fund a wallet but the
  recipient still couldn't post a first message until they did
  some other on-chain action.  Backwards-compatible: v1 / v2 txs
  remain valid; v3 is rejected pre-activation; activation gate is
  enforced at every validation entry point (mempool admit,
  validate_block, validate_block_signatures).
  (`messagechain/core/transaction.py`,
  `messagechain/core/blockchain.py`, `messagechain/config.py`)
- **`messagechain send` auto-attaches `sender_pubkey` on first send.**
  Probes the chain for the sender's pubkey via `get_entity`; when
  not registered AND past `FIRST_SEND_PUBKEY_HEIGHT`, sets
  `include_pubkey=True` so the chain installs on apply.  User
  experiences "get tokens, then send" as two CLI invocations
  instead of three.

### Added — Faucet PoW gate

- **`GET /faucet/challenge?address=<hex>`** mints a per-address
  challenge: 16 random seed bytes + difficulty + 10-min TTL.
- **`POST /faucet`** now requires `{address, challenge_seed, nonce}`.
  Server verifies that `sha256(seed || nonce_be_8 || address)` has
  at least `FAUCET_POW_BITS = 22` leading zero bits.  Average ~5s
  on desktop, ~15s on mobile in pure-JS sha256.  Per-/24 IP cooldown
  and daily aggregate cap remain as defense-in-depth.  Replay-
  protected: each challenge consumed atomically on use.  Address-
  bound: a nonce solving the challenge for address A cannot be used
  for address B.
- **No CAPTCHA dependency.**  Pure-JS sha256 in a WebWorker.  Tor
  and privacy users pay CPU, not credentials.  No third-party
  scripts on the public feed page.
- **Why PoW vs CAPTCHA**: the project's no-external-deps memory
  rules out Google/hCaptcha, and CAPTCHAs are actively hostile to
  Tor users (the censorship-resistance audience).  Per-address
  PoW makes bulk Sybil farming uneconomical (each new address
  costs the attacker the same CPU time as an honest user); the
  daily cap caps the operator's worst-case daily exposure.
  (`messagechain/network/faucet.py`,
  `messagechain/network/public_feed_server.py`,
  `messagechain/static/feed.html`)

### Changed

- **`messagechain send` "Unknown entity" hint** now points users at
  the public faucet URL and explains the Tier 11 auto-include flow:
  "get tokens at messagechain.org, wait one block, retry."  The
  bootstrap step list is now 3 items, not the awkward 4-step
  "transfer-first then message" workaround that 1.8.x described.
- **Per-address one-shot rate limit** is unchanged but the failure
  path is no longer reachable via cheap address-spam: the PoW
  consumes ~5s of attacker CPU per probe.

### Deployment

- Activation height `FIRST_SEND_PUBKEY_HEIGHT = 500` is well above
  the live tip (~451 at release time), giving operators ~10
  blocks (~100 minutes) of runway to upgrade before the fork
  point.  Validators on 1.8.x keep producing pre-Tier-11 blocks
  through height 500; v3 txs land starting at 501.
- The faucet PoW change is operator-side and takes effect
  immediately on validator restart -- no fork dependency.

## [1.8.2] — 2026-04-26

Patch release. Fixes the threadsafe-relay gap exposed by the 1.8.1
faucet drip path. No consensus changes.

### Fixed

- **`_rpc_submit_transfer` and `_rpc_submit_transaction` now schedule
  their gossip-relay task safely from any thread.** The two handlers
  previously called `asyncio.create_task(self._relay_tx_inv(...))`
  directly, which only works inside the main event loop's thread.
  When invoked from the public-feed faucet's worker pool (a thread
  outside asyncio), the call raised `RuntimeError: no running event
  loop` AFTER the mempool had already accepted the tx. The handler
  caught the exception and returned `{"ok": false, "error": "Internal
  error"}` -- so the faucet UI looked broken even though the drip
  tx was sitting in mempool waiting for the next block. Worse, on
  retry the cold-key would advance to the next leaf and a SECOND
  conflicting tx would land in mempool. The new
  `Server._schedule_coro_threadsafe` helper detects whether it's
  inside the main loop and dispatches via `create_task` or
  `run_coroutine_threadsafe` accordingly. (server.py)
- **`Server._main_loop`** captured at `start()` so cross-thread
  callers have a stable reference to the asyncio loop without
  having to chase `get_event_loop()` (which is deprecated and
  thread-local in 3.12+).

## [1.8.1] — 2026-04-25

Patch release. Fixes the faucet drip fee so transfers to brand-new
recipients (which is every recipient, by design) actually land. No
consensus changes.

### Fixed

- **Faucet now pays `MIN_FEE_POST_FLAT + NEW_ACCOUNT_FEE` per drip.**
  The 1.8.0 wiring hardcoded `fee=MIN_FEE_POST_FLAT=1000`, but the
  chain charges a `NEW_ACCOUNT_FEE=1000` surcharge on top of the
  base floor when the recipient has no on-chain history yet.  Faucet
  recipients are by definition brand-new wallets (a fresh user's
  first contact with the chain), so every drip hit
  `Transfer to brand-new recipient requires fee >= 1100; got 1000`
  and bounced.  The chain rejection was clean (no funds moved, no
  rate-limit slot consumed -- per the
  test_submit_failure_does_not_consume_quota guard) but the user-
  facing behavior was still "faucet returns an error every time."
  Now: fee = 1000 + 1000 = 2100 per drip.  At
  FAUCET_DRIP=1000, each drip costs the faucet 3100 tokens
  (1000 sent + 2100 fee), so a 200,000-token reserve covers ~64
  drips before refill -- just over a day at the daily cap.

## [1.8.0] — 2026-04-25

Minor release. Closes the receive-to-exist cold-start gap with an
opt-in operator-funded faucet on the public feed server. Pure
addition: no consensus changes; default-off so existing operators
get identical behavior.

### Added

- **Cold-start funding faucet (`POST /faucet`).**
  When the validator is launched with `--faucet-keyfile <path>` and
  `--public-feed-port` is set, the public feed exposes a JSON POST
  endpoint at `/faucet` that drips a fixed `FAUCET_DRIP=1000` tokens
  to the requested address. Three rate-limit layers stack: per-/24
  IP cooldown (24h), per-address one-shot (in-memory for the process
  lifetime), and a global daily cap (`FAUCET_DAILY_CAP=50`). Closes
  the receive-to-exist gap that made fresh wallets unable to send
  their first message without an out-of-band token transfer -- the
  dominant cold-start failure documented during the 2026-04-25
  submit-UX probe. (`messagechain/network/faucet.py`,
  `messagechain/network/public_feed_server.py`,
  `server.py:_build_faucet`)
- **"Get starter tokens" UI on `messagechain.org`.**
  Collapsible section above the live feed with an address input,
  one-line bootstrap explanation, and a "Get tokens" button that
  POSTs `/faucet`. Hidden when the validator does not advertise
  `faucet_enabled=true` on `/v1/info`. Counter shows remaining
  drips today so a visitor sees the daily cap state at a glance.
  (`messagechain/static/feed.html`)
- **`/v1/info.faucet`** block: when the faucet is enabled the info
  endpoint reports `{drip_amount, daily_cap, remaining_today}` so
  the UI does not need a separate roundtrip and operator dashboards
  can poll the cap counter.
- **`scripts/generate_faucet_key.py`** mirrors the cold-authority
  generator: produces a tree_height=16 wallet key, prints the public
  key on stdout, pushes private material straight to GCP Secret
  Manager via stdin (no filesystem touch).

### Operator workflow

1. `python scripts/generate_faucet_key.py <project> mc-faucet-key`
   -> records the printed pubkey.
2. Update the validator deploy script to fetch the secret to
   `/dev/shm/mc-faucet-key` (raw 64-char hex, mode 0400) at boot
   and pass `--faucet-keyfile /dev/shm/mc-faucet-key` to `server.py`.
3. Restart the validator (cold keygen ~10-20 min the first time;
   warm restarts hit the keypair cache).
4. From any wallet with sufficient balance, transfer the desired
   runway: `messagechain transfer --to <faucet-pubkey>
   --amount <N>`. A common starting allocation is
   `FAUCET_DRIP * 200 = 200,000` tokens (~4 days at peak cap).
5. Verify: `curl -X POST -H 'Content-Type: application/json'
   -d '{"address":"<test-entity-id>"}' https://messagechain.org/faucet`.

## [1.7.7] — 2026-04-25

Patch release. Closes the five submit-side UX gaps surfaced during
the 2026-04-25 first-ever-user-message probe and the v2 receipt-
subtree-root registration debug. No consensus changes; CLI-only.

### Fixed

- **`messagechain send` auto-fee was rejected by the chain.** The
  CLI computed `local_min` under the live LINEAR rule and passed it
  to `create_transaction`, but did not thread `current_height`, so
  `create_transaction` fell back to the legacy quadratic floor and
  rejected fees that the chain would have accepted at LINEAR. Net
  effect on mainnet (LINEAR_FEE_HEIGHT=300, tip~432): every fresh
  user with auto-fee hit `Fee must be at least 323 ...` and bounced.
  Pass `target_height` through; client-side floor now matches the
  on-chain rule.
- **`messagechain send` non-ASCII messages now produce a friendly
  diagnostic, not a Python traceback.** Pasting from a word
  processor (smart-quotes, em-dash, ellipsis) used to surface
  `UnicodeEncodeError: 'ascii' codec can't encode character ...`
  with the call stack. Now: clean error naming the offending
  character + codepoint + position, with a list of common culprits.
- **`Unknown entity -- must register first` now explains the
  receive-to-exist model.** A fresh wallet trying to send its first
  message gets rejected because it has no on-chain history to fund
  the fee. Pre-1.7.7 the CLI surfaced a bare `Failed: ...` with no
  next step, so users assumed the chain was broken. The CLI now
  detects this specific error and prints the bootstrap path: ask an
  existing token holder to send a small transfer to the user's
  address, then retry.
- **`messagechain set-receipt-subtree-root` now exposes a
  `--cold-leaf N` flag and surfaces the leaf used after signing.**
  Cold-key leaf state is not tracked on chain (see
  `apply_set_receipt_subtree_root`), so successive invocations with
  the default leaf 0 produce different messages signed at the same
  WOTS+ leaf -- a leaf-reuse violation the chain rejects. Operators
  must self-track; the post-signing output now says "Cold leaf: N
  (BURNED)" + "NEXT TIME pass --cold-leaf N+1". Discovered while
  registering validator-2's receipt root on 2026-04-25 -- worked
  around manually; now first-class.
- **`messagechain set-receipt-subtree-root` `--server` mismatch
  error now points at the workaround.** When the operator targets
  a peer validator (broadcasting through a node other than the one
  being registered), the local-root fetch returns the peer's own
  entity_id and the safety check fired with no actionable next
  step. Now: explains the cross-validator submission case and tells
  the operator to pass `--root <hex>` (with a pointer to the boot-
  log line where the root is printed).

## [1.7.6] — 2026-04-25

Patch release. Adds an outbound-click redirect on the public feed
viewer so operators can count how many people click through to the
GitHub repo from `https://messagechain.org`. Cosmetic; no protocol
or consensus impact.

### Added

- **`GET /gh` on `PublicFeedServer`** — 302 redirect to
  `https://github.com/ben-arnao/MessageChain`. The homepage's
  `<a>github</a>` link now points here instead of straight at
  GitHub, so each click lands in the Caddy access log under a path
  the `mc-feed-stats` script can grep for and report alongside the
  feed-viewer headcount.

## [1.7.5] — 2026-04-25

Patch release. Closes the mempool-sweep gap that prevented
SetReceiptSubtreeRoot transactions from ever landing on chain
when the validator entity had a non-zero hot-key leaf watermark.
No consensus changes.

### Fixed

- **`_sweep_stale_pending_txs` now treats SetReceiptSubtreeRoot
  as cold-signed.** Observed on mainnet 2026-04-25 when registering
  validator-2's receipt-subtree root post cold-key promotion: the
  RPC accepted the tx into `_pending_authority_txs` (returning a
  tx_hash), but the sweep run immediately before each block
  proposal compared the cold key's leaf_index (single digits) against
  the validator entity's hot-key leaf_watermark (high triple digits
  after sustained block production), declared it "stale leaf reuse,"
  and dropped it before `propose_block` could pull it. The carve-out
  for cold-signed txs only listed `RevokeTransaction` and
  cold-promoted `UnstakeTransaction`; `SetReceiptSubtreeRootTransaction`
  fell through. Net effect: a hot/cold validator could never register
  its receipt-subtree root on-chain, which broke every receipt that
  validator would issue at evidence-admission time. Carve-out now
  covers `SetReceiptSubtreeRootTransaction` explicitly.

## [1.7.4] — 2026-04-25

Patch release. Adds the missing operator CLI for registering a
validator's receipt-subtree root from a cold key, plus the RPC the
CLI relies on. No consensus changes.

### Fixed

- **`messagechain set-receipt-subtree-root` exists.** After the cold-
  authority-key promotion landed on validator-2 on 2026-04-25, the
  boot-time receipt-subtree auto-submit detected the cold-key gap
  and printed an actionable warning telling the operator to run
  `client.py set-receipt-subtree-root`. That command did not exist
  in either `client.py` or the `messagechain` CLI. Net effect: v2's
  receipt-subtree root has sat unregistered since the promotion,
  which would have made every receipt issued by v2 fail at evidence-
  admission time and collapsed the censorship-evidence pipeline for
  any submitter routed through that node. The new CLI fetches the
  validator's local root via the new `get_local_receipt_root` RPC
  (no scraping it out of journald or cache files), signs the
  `SetReceiptSubtreeRoot` tx with the cold key, and broadcasts via
  `set_receipt_subtree_root`. Refuses to broadcast when the remote
  validator's entity_id does not match the cold key's, exits zero
  when the on-chain root already matches (idempotent re-runs), and
  supports `--root` + `--print-tx` for fully air-gapped sign-on-cold,
  broadcast-on-hot workflows.
- **Boot-time warning text now references the real command.** The
  warning in `_bootstrap_receipt_subtree` previously pointed at
  `client.py set-receipt-subtree-root`; updated to the correct
  `messagechain set-receipt-subtree-root` invocation with concrete
  arguments.

### Changed

- **Public feed header**: replaced the tagline with a bare GitHub
  link, dropping one line of chrome above the message stream.
  (e711d28, b9c09dd)

## [1.7.3] — 2026-04-25

Patch release. The `get_nonce` RPC now returns the mempool-aware
next nonce, matching what the submit-side validators
(`_rpc_submit_transaction`, `_rpc_stake`, `_rpc_unstake`,
`_rpc_set_authority_key`, etc.) gate on. Previously the read
path returned the chain-state nonce only while the write path
gated on `_get_pending_nonce_all_pools`, so a client that
fetched the nonce while a prior tx was still in mempool would
sign with a stale value and get rejected with `Invalid nonce:
expected N+1, got N` until the prior tx landed in a block
(~10 min per wedge). Observed on mainnet 2026-04-25 when
chaining a transfer immediately after a set-authority-key
submission. Read and write paths now share the same helper, so
the contract holds for any pool combination. Empty-mempool
behavior is unchanged. No consensus change.

## [1.7.2] — 2026-04-24

Patch release. `messagechain set-authority-key` and `messagechain
rotate-key` now use the daemon's cached WOTS+ keypair when invoked
with `--data-dir`, mirroring the existing fast-path in `cmd_stake`,
`cmd_unstake`, and `cmd_transfer`. Previously both commands called
`Entity.create(private_key)` unconditionally on every invocation,
regenerating the full Merkle tree from scratch — a 20-30 minute
operation at production `tree_height=20` (1M leaves) that wedged
the CLI on a live validator host. Observed on mainnet 2026-04-24
when promoting a cold authority key to separate withdrawal
authority from block-signing authority. New regression tests bind
all four authority-gated CLI flows (stake / unstake /
set-authority-key / rotate-key) to the same cached-entity contract
so the next addition can't silently regress. Also adds
`scripts/generate_cold_authority_key.py`, an operator utility that
generates a cold authority key and pipes the secret material
directly to GCP Secret Manager via stdin (private material never
touches disk). No consensus change.

## [1.7.1] — 2026-04-24

Patch release. Display-only bugfix in `messagechain stake` and
`messagechain unstake`: the CLI attempted to print
`result['staked']` and `result['balance']` on successful
submission, but the RPC handlers return `{entity_id, tx_hash,
status}` — raising `KeyError` and exiting 1 even though the tx
had already been queued for inclusion. Operators saw the
exception and reasonably assumed the submission failed. The fix
prints `tx_hash` and `status` from the real response and adds a
regression test that exercises both commands against the actual
server contract so the next contract shift fails at test time
rather than silently on mainnet. No consensus change; operators
can upgrade at their convenience, but should upgrade before
driving the next stake/unstake so the CLI exits cleanly.

## [1.7.0] — 2026-04-24

Minor release. Extends the WOTS+ leaf-reuse gate to evidence txs
and custody proofs so every hot-key-signed tx type enforces the
same single-use-leaf invariant. Consensus-affecting: block-
validity rules are stricter and the state-root simulator gains a
new watermark bump for admitted custody proofs — requires all
validators to upgrade before producing blocks with the new
transaction flavors.

### Security

- **Round-4 defense-in-depth: evidence-tx + custody-proof WOTS+
  leaf-reuse gate.** Previously, every other hot-key-signed tx
  type (message, transfer, stake, governance, attestation,
  finality vote, authority) enforced the `leaf_index >=
  leaf_watermarks[submitter_id]` gate at both per-tx validation
  and the block-level `_check_leaf` dedupe. Evidence txs
  (censorship, bogus-rejection, inclusion-list violation,
  non-response) and custody proofs skipped both gates. A
  malicious submitter could sign a MessageTx +
  CensorshipEvidenceTx at the same `leaf_index` in one block (or
  across blocks) and leak the one-time WOTS+ secret by publishing
  two signatures under the same private material. Damage stopped
  at submitter self-compromise — the ratcheted watermark elsewhere
  keeps the leaked leaf unusable for any future tx — so this was
  not critical, but closing it here keeps the invariant uniform
  across tx types and insures against future refactors that could
  make leaf-leak actually exploitable. The block-level
  `_check_leaf` loop now iterates evidence txs and custody proofs
  (hot-key leaf namespace keyed by `submitter_id` / `prover_id`);
  each evidence validator gains the watermark check;
  `_apply_archive_rewards` bumps the watermark for every admitted
  custody-proof prover with an on-chain pubkey; the state-root
  simulator mirrors the bump so sim and apply stay in lockstep.
  Custody proofs from hobbyist-archivist provers without on-chain
  pubkeys are exempt (no prior leaf to collide with). (15d5539)

### Changed

- **Public feed: `refs` spans are now clickable anchors.** Each
  message card on https://messagechain.org now carries
  `id="tx-<full_hash>"` so a prev-pointer row can link to its
  target via URL fragment. When the referenced tx is in the
  current feed window, the ref span is an `<a href="#tx-<hash>">`
  that scrolls to and highlights the target card (CSS `:target` +
  keyframe flash). When the reference points at a tx older than
  the last LIMIT messages, the link is marked `.missing` (muted
  color, `pointer-events: none`) so users can see the reference
  exists but know it's out of view rather than clicking a dead
  link. README also surfaces `messagechain send --prev <tx_hash>`
  in the wallet CLI-reference block. (276e294)

### Fixed

- **Test hygiene: deterministic slot-0 proposer in
  `TestAckForgeryRejected`.** The ack-forgery regression suite
  added in 1.6.0 gave `self.proposer` and `self.target` equal
  stake, so the PoS slot-0 election was a coin flip against
  genesis-timestamp entropy — `test_legitimate_ack_accepted_and_
  commit_height_honored` flaked ~50% of the time. Proposer stake
  is now `VALIDATOR_MIN_STAKE * 1000` (vs. target's ×10) so the
  election is reliably deterministic. No production code change.

## [1.6.1] — 2026-04-24

Patch release. Fixes the `messagechain upgrade` CLI ordering bug
that bricked validator-1 during the 1.5.2 -> 1.6.0 rollout and
required a manual backup-directory restore before the service could
come back up. No consensus changes.

### Fixed

- **`messagechain upgrade` ordering: clone + verify now run BEFORE
  the live install is moved to backup.** The 1.5.x CLI moved
  `/opt/messagechain` to a `.bak-*` directory and THEN invoked
  `_upgrade_verify_tag_signature`, which lazily imports
  `messagechain.release_signers` from sys.path. With the install
  directory already gone, the import raised `ModuleNotFoundError`
  and the upgrade aborted with the service stopped and no live
  install — leaving the operator to `mv .bak-* /opt/messagechain`
  by hand. Fixed by reordering: clone to `/tmp`, verify against the
  still-in-place install's pinned signer list, stop the service,
  move the install to backup, copy the verified clone into place.
  Failure in clone or verify now leaves the prior binary running
  and untouched (zero downtime on rejected upgrades). Regression
  test asserts the ordering invariant.

## [1.6.0] — 2026-04-24

Minor release. Ships the **Tier 10 `prev` pointer** feature and pulls
the remaining bootstrap-era fork schedule forward so the feature can
be exercised end-to-end on the live chain within hours rather than
months. Consensus-breaking: requires all validators to upgrade before
the earliest activation height.

### Added

- **`prev` pointer on message transactions.** Optional single 32-byte
  `tx_hash` reference to a prior on-chain message, forming a
  protocol-agnostic single-linked list — apps can render the
  relationship as a reply, a chained long-form document, a citation,
  etc. The field is opt-in via tx `version=2`; `version=1` remains
  valid for prev-less messages.
- **Strict-prev validation.** When set, `prev` must resolve to a
  `MessageTransaction` already included in a strictly earlier
  persisted block. Self-reference, forward reference, and dangling
  reference are all rejected at the validation boundary.
- **ChainDB `tx_locations` index (schema v3).** Maps every message
  `tx_hash` to its `(block_height, tx_index)` for O(1) strict-prev
  resolution. One-shot migration `migrate_schema_v2_to_v3` walks
  persisted blocks to backfill; non-destructive, idempotent. The
  `messagechain migrate-chain-db` CLI now cascades v1 → v2 → v3 in a
  single invocation. `messagechain upgrade` runs migrations
  automatically.
- **`messagechain send --prev <tx_hash>`** CLI flag. Adds 33 stored
  bytes (1B presence flag + 32B hash) to the fee basis, priced at
  the live per-stored-byte rate. Pointer bytes do NOT count against
  `MAX_MESSAGE_CHARS` — the full 1024-char text budget stays intact.
- **Public feed (messagechain.org) surfaces `prev`.** `/v1/latest`
  JSON includes a `prev` hex field when a message carries a pointer;
  `feed.html` renders a `↳ refs <tx_hash_short>` row above the
  message text. Absent pre-fork and for prev-less post-fork messages.

### Changed (consensus)

- **Fork schedule pulled forward** so live operator testing is
  viable within the current bootstrap-era chain height:
  `LINEAR_FEE_HEIGHT` 4_300 → 300, `BLOCK_BYTES_RAISE_HEIGHT`
  4_500 → 350, `PREV_POINTER_HEIGHT` 6_000 → 400. All three forks
  activate in sequence within ~24 hours at the current block cadence.
  Validators MUST run 1.6.0 before the earliest activation height
  (300); an older binary at height ≥ 300 diverges consensus.

### Security

- No new security findings. Field-level tamper resistance on `prev`
  is covered by the standard signature commitment: the field is
  part of `_signable_data` at `version >= 2`, so flipping "no prev
  ↔ prev set" or swapping a `prev` value after signing invalidates
  the signature.

## [1.5.2] — 2026-04-24

Patch release. Bundles a security audit rollup with a P2P
maintenance-loop fix. No consensus changes.

### Security

- **C1 — validator-collusion censorship escape.**
  `BogusRejectionProcessor.process()` and its state-root simulator
  re-verified the embedded message tx without threading
  `current_height`, so at LINEAR-era heights `verify_transaction`
  fell back to the legacy quadratic fee rule. Low-fee txs that
  were valid under consensus but below the legacy floor were
  dismissed as "honest rejection," letting a lying validator
  escape slashing and successfully censor the message — directly
  defeating the stated primary-threat defense. Thread
  `block_height` through both paths and through mempool RBF.
  Regression test exercises the LINEAR-era gap window end to end.
  (ebde4d1)
- **C2 — supply-chain RCE in `messagechain upgrade`.** The
  upgrade CLI cloned and installed any `vX.Y.Z-mainnet` tag as
  root without verifying the tag's signature against an
  authoritative key. Now pins the release signer's SSH pubkey in
  `messagechain/release_signers.py` and runs `git tag -v` with
  `gpg.ssh.allowedSignersFile` pointed at that pinned list after
  clone, before the copytree swap. On verification failure:
  discard the clone, restore the backup, exit non-zero. The
  allowed-signers file is binary-local so a repo-level compromise
  cannot rotate the trust anchor. (ebde4d1)
- **C3 — fee-rule height threading in CLI send.**
  `calculate_min_fee` was called without `current_height`, so CLI
  users overpaid ~5–10× on short messages under the live LINEAR
  rule and low-fee dissident submissions were silently rejected
  client-side even though the chain would have accepted them.
  Thread tip+1 through the fee estimator; add an optional
  `current_height` arg to mempool RBF for consistent dispatch.
  (ebde4d1)

### Fixed

- **Maintenance loop now entity-aware.** After the 1.5.1
  entity-dedup rollout, the lower-entity side of each pair kept
  logging `p2p dedup: closing duplicate inbound session` every 30
  seconds. Root cause: the maintenance tick was keyed on
  `(host, listen_port)` and didn't recognize an inbound session
  from the same remote (keyed by the peer's ephemeral source
  port) as "already peered," so it re-dialed the seed every
  interval and each redial completed TLS+handshake just to be
  closed by the dedup. Now stores the remote's advertised listen
  port from the HANDSHAKE payload on `Peer.advertised_port`; the
  maintenance tick skips a seed `(host, port)` when any live,
  handshook peer already advertises that exact endpoint.
  Cosmetic at n=2, but the churn went quadratic as the validator
  set grew. (81298fb, a16a347)

## [1.5.1] — 2026-04-24

Patch release — P2P session dedup. No consensus changes.

### Fixed

- **Entity-level peer session dedup.** When two validators dialed
  each other simultaneously, each ended up with two live sockets to
  the same remote entity (one inbound on an ephemeral source port
  plus one outbound to the remote's listen port). The existing
  address-level dial dedup (keyed on `host:port`) couldn't catch
  this because the two sockets had genuinely different `host:port`
  tuples. Add a symmetric post-handshake tiebreaker — keep the
  session where the LOWER entity_id is the outbound dialer. Both
  ends apply the same rule against the same id pair, so both ends
  close the same TCP connection and the network converges to one
  session per peer pair. Observed on live mainnet after 1.5.0
  rollout; does not affect consensus or message delivery, only peer
  bookkeeping and metric honesty. (62eeabd, 18083cb)

## [1.5.0] — 2026-04-24

Minor release — validator operator onboarding automation plus a P2P
security hardening. No consensus changes.

### Added

- **Validator onboarding pack**: `messagechain init` / `doctor` /
  `config` / `rotate-if-needed` CLI surface, plus
  `scripts/install-validator.sh` for a one-command fresh-host install.
  Covers keyfile + hot-key generation, systemd unit install, seed
  configuration, reachability checks, and routine key rotation.
  (32ddfa7, bb1a91d, adc80b7, 7ee590e)
- **CLI reference** documents the full onboarding surface
  (`init`, `doctor`, `config`, `upgrade`, `rotate-if-needed`). (7ee590e)

### Security

- P2P handshake now gates on `CHAIN_ID` in addition to `genesis_hash`
  (defense-in-depth — an attacker flipping either field is rejected
  before the handshake completes). (35c7f7f)

### Fixed

- `install-validator.sh` clones the repo as root then chowns to the
  `messagechain` user, instead of attempting the clone as the
  unprivileged user against a root-owned target. (51ddf29)
- `init` now chowns `/etc/messagechain/*` to the `messagechain` user
  after writing, so the service user can read its own config. (6bd1445)
- Escape backticks in `install-validator.sh` progress echo so shell
  expansion doesn't garble output on some terminals. (1da5c30)
- `upgrade` runs as root end-to-end (fixes file-permission failures on
  validator hosts); `rotate` accepts `--yes` to skip the interactive
  prompt for automation; defer WOTS+ Merkle tree build during `init`
  so onboarding doesn't block on key derivation; env-scoped config
  lookup in `doctor` with actionable hint text. (91fbc0a, e3e9fcd)
- Drop duplicate `test_upgrade_command.py` left over after rebase. (8ce0ad7)

### Tests

- Cover `init`, `doctor`, `upgrade`, `rotate`, seeds, reachability,
  and config commands end-to-end. (bb1a91d)

## [1.4.0] — 2026-04-24

Minor release — **consensus-breaking hard fork**. Pulls the Tier 8
(linear-in-stored-bytes fees + 1024-char cap raise) and Tier 9
(throughput raise) activation heights forward into the bootstrap
window so the cap raise is testable on a realistic timeline with
the current two-validator network.

### Changed (consensus)

- `LINEAR_FEE_HEIGHT`: **100,000 → 4,300**. The linear formula
  (`BASE_TX_FEE + FEE_PER_STORED_BYTE × stored_bytes`) and the
  `MAX_MESSAGE_CHARS` raise to 1024 now activate ~28 days (nominal
  10-min blocks) after release instead of ~2 years.
- `BLOCK_BYTES_RAISE_HEIGHT`: **102,000 → 4,500**. Follows Tier 8
  immediately, same per-byte floor and tx-per-block bumps as before.
- **Tier 7 (`FLAT_FEE_HEIGHT = 98,000`) retired.** The flat-fee
  intermediate is superseded by Tier 8 at a lower height — in
  `calculate_min_fee` the LINEAR branch is checked first, so at height
  98,000 the linear rule is already in force and the flat floor
  never activates. The constant is kept for code-path audit clarity.
- The Tier-2 `FEE_INCLUDES_SIGNATURE_HEIGHT = 64,000` sig-aware
  quadratic rule is similarly unreachable for `MessageTransaction`
  (Tier 8 precedes it). Non-MessageTx tx types (transfer / stake /
  governance / etc.) still traverse the sig-aware branch via
  `enforce_signature_aware_min_fee`.

### Fixed

- `verify_transaction` now delegates fee-floor selection to
  `calculate_min_fee` (single source of truth) instead of branching
  on each gate locally. Previously, at heights in
  `[LINEAR_FEE_HEIGHT, FEE_INCLUDES_SIGNATURE_HEIGHT)` the verifier
  fell through to the legacy quadratic rule while `calculate_min_fee`
  had already routed to linear — the two disagreed. Unified. Only
  surfaces under compressed schedules where LINEAR precedes FLAT.

### Upgrade notes

Consensus-breaking. Both validators MUST upgrade before height
4,300 (~28 days from release at nominal pace). The two-validator
bootstrap set makes coordination trivial; re-tighten the
50,000-block runway rule in CLAUDE.md once the validator set grows.

## [1.3.1] — 2026-04-24

Patch release — P2P handshake symmetry for peer observability.

### Fixed

- The inbound side of the P2P handshake now echoes its own `HANDSHAKE`
  back to the dialer, so the dialer's `Peer` record populates with the
  peer's `entity_id`, `chain_height`, and `version`. Before this,
  outbound peers on `messagechain peers` output showed `Entity: (none)`,
  `Height: 0`, and `Version: unknown` indefinitely. Chain sync was
  unaffected (it runs off the inbound path) — this was an observability
  fix, not a liveness fix. Applied to both the `Server` runtime
  (`server.py`) and the `Node` class (`messagechain/network/node.py`).

### Added

- `Peer.handshake_sent` flag (`messagechain/network/peer.py`) — guards
  the new echo against re-firing on a reconnecting peer and is set on
  outbound at dial time for symmetry.

## [1.3.0] — 2026-04-24

Minor release — fork-skew halt semantics. An out-of-date binary now
halts cleanly with an actionable operator message instead of rejecting
post-fork blocks as "invalid" and spamming peer-ban state.

### Added

- `MAX_SUPPORTED_BLOCK_VERSION` config constant (currently 1). A
  future hard fork that changes consensus semantics bumps this to 2+;
  `messagechain upgrade` installs the binary that understands it.
- `BinaryOutOfDateError` (`messagechain/core/blockchain.py`) — a
  distinct exception class (sibling to `ChainIntegrityError`) raised
  by `validate_block` when a block carries a version newer than this
  binary understands. Semantically: "the network has moved past my
  binary" — NOT "the chain is broken" and NOT "the block is malicious".
- `server.py` installs an asyncio loop-level exception handler that
  converts `BinaryOutOfDateError` from any task into a clean
  `os._exit(42)` with a single clear journald entry:
  `BINARY OUT OF DATE -- HALTING: Block at height N has version V,
  but this binary supports up to W. Run \`messagechain upgrade\``.
  Systemd's `StartLimitBurst=5` turns the repeated exit into a
  failed-unit state, which is exactly the operator signal we want.

### Changed

- `Blockchain.validate_block` no longer treats unknown-version blocks
  as soft rejections. A `version > MAX_SUPPORTED_BLOCK_VERSION` now
  raises `BinaryOutOfDateError` (halt). A `version < 1` (malformed
  input, not fork-skew) remains a regular `(False, reason)` rejection
  so peer-ban machinery fires normally.

### Operator UX

No action needed to adopt 1.3.0 — the halt path only fires when a
future fork activates. When that happens on an old binary:

1. The unit exits with code 42 and journald records
   `BINARY OUT OF DATE -- HALTING`.
2. Systemd tries 5 restarts, hits `StartLimitBurst`, marks the unit
   failed.
3. Operator sees the failed unit, runs `messagechain upgrade --yes`.
4. New binary boots, accepts the blocks that the old one couldn't,
   catches up via normal P2P sync.

Previously, the old binary would spin instead of halting — rejecting
every post-fork block as "invalid block", ban-scoring every peer that
relayed one, and silently losing proposal slots to inactivity
slashing. 1.3.0 turns that failure mode into a fast, loud, actionable
halt.

## [1.2.2] — 2026-04-24

Patch release — fixes `messagechain upgrade` default tag resolution so
it actually finds the latest release with zero flags.

### Fixed

- `messagechain upgrade` (no `--tag`) previously queried the GitHub
  *Releases* API, which only returns tags that were explicitly
  published as GitHub Release objects via the Releases UI. This
  repo publishes by pushing git tags directly, so the Releases API
  returned the one-and-only pre-existing Release (v1.0.0-mainnet)
  and the command would attempt a downgrade. Now the resolver hits
  the git-tags API (`/repos/{owner}/{repo}/tags`), filters to
  canonical `vX.Y.Z-mainnet` tags, and picks the highest by semver
  triple — not lexicographic order, so `v1.10.0-mainnet` correctly
  ranks above `v1.9.0-mainnet`.

## [1.2.1] — 2026-04-24

Version-bump-only release. No behavior changes; cut to exercise the
`messagechain upgrade` command end-to-end on live mainnet validators.
Safe no-op rollout.

## [1.2.0] — 2026-04-24

Minor release — operator ergonomics. Adds a one-shot `messagechain upgrade`
command and surfaces peer binary versions in the `peers` table.

### Added

- `messagechain upgrade [--tag vX.Y.Z-mainnet]` — stops the validator
  service, backs up the install dir, fetches the release tag, swaps in
  the new code, runs `migrate-chain-db` (idempotent), restarts the
  service, polls local RPC status, and rolls back to the backup on
  health-check failure. Replaces the 20-line bash procedure we were
  running by hand. `--no-rollback` keeps the new code even on health
  failure. Defaults: install-dir `/opt/messagechain`, data-dir
  `/var/lib/messagechain`, service `messagechain-validator`.
- Peer binary versions now flow through the P2P handshake. `peers`
  output gains a **Version** column; peers running ≤1.1.1 show as
  `unknown` (they didn't advertise a version before this release).

### Changed

- Runtime `__version__` bumped 1.0.0 → 1.2.0. The 1.0.0 constant had
  drifted stale across 1.0.1, 1.0.2, 1.1.0, and 1.1.1 releases;
  1.2.0 resumes correct versioning and is advertised in handshakes
  from now on.

## [1.1.1] — 2026-04-24

Patch release — fixes a regression in the schema v1→v2 migration
introduced alongside the six cold-restart persistence surfaces. Any
operator running 1.1.0 and attempting `migrate-chain-db` on a chain.db
that contains blocks referencing non-genesis entities (i.e. any live
chain past block 0) would hit:

    ValueError: entity ref uses unknown index N (state lacks mapping)

and abort before stamping schema_version to 2.

### Fixed

- `migrate_schema_v1_to_v2` now pre-seeds the rebuilt Blockchain's
  `entity_id_to_index` / `entity_index_to_id` maps from the v1 DB's
  `entity_indices` table before the replay loop. Compact entity-refs
  in persisted blocks now decode correctly through
  `get_block_by_number`. Verified end-to-end against a live mainnet
  v1 chain.db (183 blocks replayed cleanly).

## [1.1.0] — 2026-04-24

Minor release — two sequential hard forks activate inside the bootstrap
window. Coordinated validator-binary upgrade required before the first
activation height (100,000). Current tip is well below the activation
window; operators have ample runway to roll the upgrade.

### Added

- **Tier 8 (`LINEAR_FEE_HEIGHT = 100_000`)** — retires the flat per-tx
  floor in favor of a linear-in-stored-bytes formula
  `fee_floor = BASE_TX_FEE + FEE_PER_STORED_BYTE * len(stored)`.
  Longer messages pay proportionally for the bytes they pin to
  permanent state. Pre-fork replay paths (flat floor, legacy
  quadratic) keep their semantics so historical blocks validate
  unchanged.
- **Tier 8 cap raises** — `MAX_MESSAGE_CHARS` 280 → 1024 (short-post
  scale, not document scale) and `MAX_BLOCK_MESSAGE_BYTES`
  10,000 → 15,000.
- **Tier 9 (`BLOCK_BYTES_RAISE_HEIGHT = 102_000`)** — per-block
  throughput raise: `MAX_BLOCK_MESSAGE_BYTES` 15,000 → 45,000,
  `MAX_TXS_PER_BLOCK` 20 → 45, `MAX_BLOCK_SIG_COST` 100 → 250.
  Per-message cap unchanged. Targets ~24 GB/yr on-disk chain growth
  at 100-validator saturation. Attestation overhead dominates total
  size at that scale; future ceiling raises live in a sig-aggregation
  fork, not in byte caps.
- **Tier 9 economic retune** — `FEE_PER_STORED_BYTE` 1 → 3 at fork
  height (preserves bloat discipline under the wider byte budget);
  `TARGET_BLOCK_SIZE` 10 → 22 at fork height (~50% of the new
  `MAX_TXS_PER_BLOCK` for EIP-1559 base-fee targeting).

### Operator action required

- All honest validators must run 1.1.0 (or later) before block
  height 100,000. An older binary past that height will reject
  valid post-fork blocks and halt — losing its slot and bleeding
  stake to inactivity penalties until upgraded.

## [1.0.2] — 2026-04-23

Patch release — ship validator-2 in the default seed list so fresh
clients bootstrap against both validators instead of one.

### Changed

- `SEED_NODES` and `CLIENT_SEED_ENDPOINTS` in `messagechain/config.py`
  now include both validator-1 (35.237.211.12) and validator-2
  (35.231.82.12). A fresh install — `messagechain send "hi"` or
  `python server.py --mine` with no flags — connects to either
  validator automatically. Users keep full `--seed` / `--server`
  override.

## [1.0.1] — 2026-04-23

Patch release — operator ergonomics + gossip correctness. No consensus
or chain-state changes; no hard fork needed. Safe to roll in-place on
a running validator via a systemd restart.

### Added

- `reserve_leaf` RPC on `server.py`. Atomic WOTS+ leaf reservation for
  CLI signers co-resident with the validator daemon: eliminates the
  window in which an operator `messagechain transfer` and a
  block-producer `sign()` pick the same leaf and leak the private key.
- Global `--data-dir` flag on the CLI. When set, `transfer`, `stake`,
  and `send` load the daemon's on-disk keypair cache (skipping the
  multi-minute WOTS+ keygen) and call `reserve_leaf` for the signing
  leaf (collision-free with block production).
- `_load_key_from_file(..., accept_raw_hex=True)` opt-in parser. The
  CLI now accepts the daemon-side 64-char raw-hex keyfile when
  `--data-dir` is present, so the operator keyfile the validator unit
  consumes is directly usable for CLI signing.

### Fixed

- ANNOUNCE_TX gossip for `TransferTransaction` payloads. The handler
  previously only deserialized `MessageTransaction`, so a transfer
  gossiped from a peer was rejected as `invalid_tx_data` and never
  reached the block producer. Dispatch now reads the `type`
  discriminator in the serialized dict and routes to the matching
  validator.

## [1.0.0] — 2026-04-22

Initial mainnet release. Current chain minted 2026-04-22 after several
bootstrap-window re-mints; see the `_MAINNET_GENESIS_HASH` history
block in `messagechain/config.py` for the full list of abandoned
genesis hashes that preceded the current pin.

### Chain facts

- Network: `mainnet`, chain ID `messagechain-v1`
- Genesis block-0 hash: `4eeb9edaadb42f1a460e95919bc667a3173c4a84aa9b5488da040ac7a1c054f6`
- Block cadence: 10 minutes
- Genesis supply: 140M, fully allocated at block 0 (founder 100M +
  treasury 40M). Additional tokens enter circulation via block
  rewards (inflationary, perpetual low-rate issuance) — they are NOT
  pre-minted into genesis. See `GENESIS_SUPPLY` in
  `messagechain/config.py` for the pinned value and rationale.

### Added

- PoS consensus with attestation-based finality, slashing, and unbonding.
- WOTS+ quantum-resistant signatures with version-tagged crypto agility.
- Key rotation, governance, authenticated registration.
- Flat per-tx fee market (activates at height 98,000).
- Twelve scheduled hard forks through the bootstrap window (see
  `CLAUDE.md` for the canonical activation heights).
- CLI: `generate-key`, `verify-key`, `send`, `read`, `estimate-fee`,
  `stake`, `unstake`, `rotate`, `set-authority-key`.
- Zero runtime dependencies outside the Python stdlib.
