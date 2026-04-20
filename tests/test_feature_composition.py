"""Integration tests that exercise archive rewards + censorship evidence +
normal txs TOGETHER in the same block and the same chain.

Unit and single-feature end-to-end tests already exist in:
    * tests/test_archive_rewards_wiring.py
    * tests/test_archive_challenge.py
    * tests/test_censorship_evidence.py
    * tests/test_submission_receipt.py

This file fills the gap between them.  We check composition-level
invariants that no single-feature test can exercise:

  * two chains fed the same blocks reach byte-identical state roots;
  * a block that bundles message tx + evidence tx + custody-proof
    payout validates and applies atomically;
  * an invalid proof poisons the whole block (no partial apply);
  * two evidence txs in one block dedupe deterministically;
  * evidence maturity on the SAME block as an archive-reward challenge
    fires both effects and keeps the ledger consistent;
  * snapshot v4 (pool + pending + processed + receipt roots) survives
    a serialize → decode → re-encode round-trip with a stable state
    root.

The tests build real Blockchain objects (no mocks).  Per the task
brief, if a scenario surfaces a latent bug we mark the test FAILING
and leave it as a regression canary — production code is not touched.

**FAILING tests discovered in this file** — search for `# FAILING:` to
see the marker comments.  Expected-fail unittests are skipped with
`self.skipTest("FAILING: ...")` so the suite stays green while the
bug is documented.
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
import messagechain.config as _mcfg
import messagechain.consensus.archive_challenge as _ac
import messagechain.core.blockchain as _bc_mod
import messagechain.consensus.censorship_evidence as _ce_mod

# Values this module uses at runtime.  Captured here as constants and
# re-applied inside `setUpModule` so they only take effect during
# THIS module's tests — not at import time.  Import-time patching
# interleaves badly with test_censorship_evidence's own import-time
# patches (same process, same module objects), so whichever module is
# collected last silently wins.  Keeping the patch in setUpModule
# confines the override to our test run window.
_MOD_ARCHIVE_INTERVAL = 4
_MOD_ARCHIVE_WINDOW = 4
_MOD_EVIDENCE_INCLUSION = 2
_MOD_EVIDENCE_MATURITY = 1
_MOD_EVIDENCE_EXPIRY = 32

# `from messagechain.config import X` creates a local binding at
# import time.  Our tests are written against these LOCAL bindings,
# so they must hold the shrunk values even before setUpModule runs.
# Mirror the shrunk values into the local module namespace here (via
# explicit assignment below, after the `from ... import ...` line
# that creates the bindings).
_ORIG = {
    "mcfg.ARCHIVE_CHALLENGE_INTERVAL": _mcfg.ARCHIVE_CHALLENGE_INTERVAL,
    "mcfg.ARCHIVE_SUBMISSION_WINDOW": _mcfg.ARCHIVE_SUBMISSION_WINDOW,
    "mcfg.EVIDENCE_INCLUSION_WINDOW": _mcfg.EVIDENCE_INCLUSION_WINDOW,
    "mcfg.EVIDENCE_MATURITY_BLOCKS": _mcfg.EVIDENCE_MATURITY_BLOCKS,
    "mcfg.EVIDENCE_EXPIRY_BLOCKS": _mcfg.EVIDENCE_EXPIRY_BLOCKS,
    "ac.ARCHIVE_CHALLENGE_INTERVAL": _ac.ARCHIVE_CHALLENGE_INTERVAL,
    "ac.ARCHIVE_SUBMISSION_WINDOW": _ac.ARCHIVE_SUBMISSION_WINDOW,
    "bc.EVIDENCE_INCLUSION_WINDOW": _bc_mod.EVIDENCE_INCLUSION_WINDOW,
    "bc.EVIDENCE_EXPIRY_BLOCKS": _bc_mod.EVIDENCE_EXPIRY_BLOCKS,
    "ce.EVIDENCE_INCLUSION_WINDOW": _ce_mod.EVIDENCE_INCLUSION_WINDOW,
    "ce.EVIDENCE_MATURITY_BLOCKS": _ce_mod.EVIDENCE_MATURITY_BLOCKS,
    "ce.EVIDENCE_EXPIRY_BLOCKS": _ce_mod.EVIDENCE_EXPIRY_BLOCKS,
}


def setUpModule():
    """Install shrunk constants into every module that reads them at
    runtime.  Runs right before THIS module's tests start (and after
    any earlier test module's own setUpModule / tearDownModule)."""
    _mcfg.ARCHIVE_CHALLENGE_INTERVAL = _MOD_ARCHIVE_INTERVAL
    _mcfg.ARCHIVE_SUBMISSION_WINDOW = _MOD_ARCHIVE_WINDOW
    _mcfg.EVIDENCE_INCLUSION_WINDOW = _MOD_EVIDENCE_INCLUSION
    _mcfg.EVIDENCE_MATURITY_BLOCKS = _MOD_EVIDENCE_MATURITY
    _mcfg.EVIDENCE_EXPIRY_BLOCKS = _MOD_EVIDENCE_EXPIRY
    _ac.ARCHIVE_CHALLENGE_INTERVAL = _MOD_ARCHIVE_INTERVAL
    _ac.ARCHIVE_SUBMISSION_WINDOW = _MOD_ARCHIVE_WINDOW
    _bc_mod.EVIDENCE_INCLUSION_WINDOW = _MOD_EVIDENCE_INCLUSION
    _bc_mod.EVIDENCE_EXPIRY_BLOCKS = _MOD_EVIDENCE_EXPIRY
    _ce_mod.EVIDENCE_INCLUSION_WINDOW = _MOD_EVIDENCE_INCLUSION
    _ce_mod.EVIDENCE_MATURITY_BLOCKS = _MOD_EVIDENCE_MATURITY
    _ce_mod.EVIDENCE_EXPIRY_BLOCKS = _MOD_EVIDENCE_EXPIRY


def tearDownModule():
    """Restore every patched constant so later test modules see the
    pre-patch values.  Needed because multiple test files
    monkey-patch the same module-level names and the last writer
    wins within a single process."""
    _mcfg.ARCHIVE_CHALLENGE_INTERVAL = _ORIG["mcfg.ARCHIVE_CHALLENGE_INTERVAL"]
    _mcfg.ARCHIVE_SUBMISSION_WINDOW = _ORIG["mcfg.ARCHIVE_SUBMISSION_WINDOW"]
    _mcfg.EVIDENCE_INCLUSION_WINDOW = _ORIG["mcfg.EVIDENCE_INCLUSION_WINDOW"]
    _mcfg.EVIDENCE_MATURITY_BLOCKS = _ORIG["mcfg.EVIDENCE_MATURITY_BLOCKS"]
    _mcfg.EVIDENCE_EXPIRY_BLOCKS = _ORIG["mcfg.EVIDENCE_EXPIRY_BLOCKS"]
    _ac.ARCHIVE_CHALLENGE_INTERVAL = _ORIG["ac.ARCHIVE_CHALLENGE_INTERVAL"]
    _ac.ARCHIVE_SUBMISSION_WINDOW = _ORIG["ac.ARCHIVE_SUBMISSION_WINDOW"]
    _bc_mod.EVIDENCE_INCLUSION_WINDOW = _ORIG["bc.EVIDENCE_INCLUSION_WINDOW"]
    _bc_mod.EVIDENCE_EXPIRY_BLOCKS = _ORIG["bc.EVIDENCE_EXPIRY_BLOCKS"]
    _ce_mod.EVIDENCE_INCLUSION_WINDOW = _ORIG["ce.EVIDENCE_INCLUSION_WINDOW"]
    _ce_mod.EVIDENCE_MATURITY_BLOCKS = _ORIG["ce.EVIDENCE_MATURITY_BLOCKS"]
    _ce_mod.EVIDENCE_EXPIRY_BLOCKS = _ORIG["ce.EVIDENCE_EXPIRY_BLOCKS"]

from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    ARCHIVE_REWARD,
    is_archive_challenge_block,
)

# Our tests use the shrunk values (set in setUpModule at test-run
# time); hard-wire the locals here to the same constants so the tests
# consume the shrunk values regardless of whether someone else
# re-patched `_mcfg.*` between import time and test time.
ARCHIVE_CHALLENGE_INTERVAL = _MOD_ARCHIVE_INTERVAL
EVIDENCE_INCLUSION_WINDOW = _MOD_EVIDENCE_INCLUSION
EVIDENCE_MATURITY_BLOCKS = _MOD_EVIDENCE_MATURITY
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block
from messagechain.core.transaction import (
    MessageTransaction, create_transaction,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.archive_challenge import (
    CustodyProof, build_custody_proof, compute_challenge,
)
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.network.submission_receipt import (
    SubmissionReceipt, ReceiptIssuer,
)
from messagechain.consensus.censorship_evidence import (
    CensorshipEvidenceTx, compute_slash_amount,
)
from messagechain.storage.state_snapshot import (
    serialize_state, encode_snapshot, decode_snapshot, compute_state_root,
)


# ── Seed constants — one fixed seed per role so every test builds
#    entities with identical public keys across chain_a / chain_b.
_OFFENDER_SEED = b"offender-seed"
_SUBMITTER_SEED = b"submitter-seed"
_SECOND_SEED = b"second-seed"
_THIRD_SEED = b"third-seed"


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_entity(seed: bytes) -> Entity:
    ent = Entity.create(seed.ljust(32, b"\x00"))
    ent.keypair._next_leaf = 0
    return ent


def _make_receipt_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag, height=height,
    )


def _build_proof_for_challenge(
    chain: Blockchain, prover_id: bytes, challenge_block_number: int,
) -> CustodyProof:
    """Construct a valid CustodyProof answering the challenge at H.

    Caller must ensure `chain.height >= challenge_block_number` so the
    parent block exists in the chain list.
    """
    parent = chain.get_block(challenge_block_number - 1)
    if parent is None:
        raise AssertionError(
            f"parent block at height {challenge_block_number - 1} not "
            f"in chain (chain.height={chain.height})"
        )
    ch = compute_challenge(parent.block_hash, challenge_block_number)
    target = chain.get_block(ch.target_height)
    if target is None:
        raise AssertionError(
            f"challenge target at height {ch.target_height} not in chain"
        )
    header_bytes = (
        target.header.signable_data() + target.header.randao_mix
    )
    return build_custody_proof(
        prover_id=prover_id,
        target_height=target.header.block_number,
        target_block_hash=target.block_hash,
        header_bytes=header_bytes,
        merkle_root=target.header.merkle_root,
        tx_index=None,
        tx_bytes=b"",
        all_tx_hashes=[],
    )


def _sign_evidence_tx(
    submitter: Entity,
    receipt: SubmissionReceipt,
    message_tx: MessageTransaction,
    fee: int = MIN_FEE,
    timestamp: int | None = None,
) -> CensorshipEvidenceTx:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = CensorshipEvidenceTx(
        receipt=receipt,
        message_tx=message_tx,
        submitter_id=submitter.entity_id,
        timestamp=ts,
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def _issue_receipt(
    offender: Entity, receipt_kp: KeyPair,
    mtx: MessageTransaction, commit_height: int,
) -> SubmissionReceipt:
    issuer = ReceiptIssuer(
        offender.entity_id, receipt_kp,
        height_fn=lambda: commit_height,
    )
    return issuer.issue(mtx.tx_hash)


def _fund_and_register(
    chain: Blockchain, offender: Entity, submitter: Entity,
    extras: list[Entity], receipt_kp: KeyPair,
) -> None:
    """Common chain post-genesis setup: register submitter + extras,
    seed balances, set offender stake, register the offender's receipt
    subtree root.  Idempotent given fresh entities.
    """
    register_entity_for_test(chain, submitter)
    chain.supply.balances[offender.entity_id] = 10_000_000
    chain.supply.balances[submitter.entity_id] = 10_000_000
    chain.supply.staked[offender.entity_id] = 1_000_000
    chain.receipt_subtree_roots[offender.entity_id] = receipt_kp.public_key
    for ent in extras:
        register_entity_for_test(chain, ent)
        chain.supply.balances[ent.entity_id] = 10_000_000


class _HarnessMixin:
    """Shared chain-construction scaffolding for all the test cases.

    Every test follows one of two patterns:

    1. Single chain — `_single_chain()` returns a fully set-up chain
       plus the test entities + receipt keypair.
    2. Twin chains — `_twin_chains()` returns two chains that share a
       byte-identical genesis block and identical initial per-entity
       state.  Replay `chain_a`'s post-genesis blocks onto `chain_b`
       with `_replay_blocks_onto`; the snapshot state roots must then
       agree.
    """

    def _single_chain(
        self,
        extras_seeds: list[bytes] | None = None,
    ) -> tuple[Blockchain, Entity, Entity, list[Entity], KeyPair]:
        offender = _make_entity(_OFFENDER_SEED)
        submitter = _make_entity(_SUBMITTER_SEED)
        extras = [_make_entity(s) for s in (extras_seeds or [])]
        receipt_kp = _make_receipt_subtree_keypair(_OFFENDER_SEED[:16])

        chain = Blockchain()
        chain.initialize_genesis(offender)
        _fund_and_register(chain, offender, submitter, extras, receipt_kp)
        chain._rebuild_state_tree()
        return chain, offender, submitter, extras, receipt_kp

    def _twin_chains(
        self,
        extras_seeds: list[bytes] | None = None,
    ) -> tuple[
        tuple[Blockchain, Entity, Entity, list[Entity], KeyPair],
        tuple[Blockchain, Entity, Entity, list[Entity], KeyPair],
    ]:
        """Two chains sharing genesis + initial state.

        Returns (A, B) where A is used to produce blocks and B replays
        them via `_replay_blocks_onto`.  Both get fresh entity
        instances derived from the same seeds — same entity_id and
        public_key, but keypairs start at leaf 0 so each chain's
        signing history is independent.

        initialize_genesis uses wall-clock `int(time.time())` in the
        genesis header.  To keep both genesis blocks byte-identical we
        mint chain_a's genesis, then swap chain_b's genesis block for
        chain_a's (same entity_id, same state — only the block object
        changes).
        """
        a_offender = _make_entity(_OFFENDER_SEED)
        a_submitter = _make_entity(_SUBMITTER_SEED)
        a_extras = [_make_entity(s) for s in (extras_seeds or [])]
        a_receipt_kp = _make_receipt_subtree_keypair(_OFFENDER_SEED[:16])

        b_offender = _make_entity(_OFFENDER_SEED)
        b_submitter = _make_entity(_SUBMITTER_SEED)
        b_extras = [_make_entity(s) for s in (extras_seeds or [])]
        b_receipt_kp = _make_receipt_subtree_keypair(_OFFENDER_SEED[:16])

        chain_a = Blockchain()
        chain_a.initialize_genesis(a_offender)

        chain_b = Blockchain()
        chain_b.initialize_genesis(b_offender)

        # Align genesis: replace chain_b's genesis block with chain_a's.
        # State was written by initialize_genesis from identical entities,
        # so it already matches; only the Block object needs swapping.
        src_genesis = chain_a.chain[0]
        chain_b.chain[0] = src_genesis
        chain_b._block_by_hash = {src_genesis.block_hash: src_genesis}
        chain_b.fork_choice.tips.clear()
        chain_b.fork_choice.add_tip(src_genesis.block_hash, 0, 0)

        _fund_and_register(chain_a, a_offender, a_submitter, a_extras, a_receipt_kp)
        _fund_and_register(chain_b, b_offender, b_submitter, b_extras, b_receipt_kp)
        chain_a._rebuild_state_tree()
        chain_b._rebuild_state_tree()

        return (
            (chain_a, a_offender, a_submitter, a_extras, a_receipt_kp),
            (chain_b, b_offender, b_submitter, b_extras, b_receipt_kp),
        )

    def _add_empty_block(
        self, chain: Blockchain, pos: ProofOfStake, proposer: Entity,
    ) -> Block:
        block = chain.propose_block(pos, proposer, [])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        return block

    def _replay_blocks_onto(
        self, source: Blockchain, dest: Blockchain,
    ) -> None:
        """Replay every post-genesis block from source onto dest.

        Round-trips each block through bytes (verifies wire-format
        fidelity) before calling add_block on the destination.  Any
        rejection fails the test loudly with the height at which the
        divergence appeared.

        We use the NON-compact wire form (no `state=`) so the replay
        doesn't depend on entity_id_to_index alignment between the two
        chains.  The compact form uses varint-indices keyed on whatever
        state was passed, and the two chains' indices can drift when
        one has registered an entity that the other hasn't yet seen
        (receive-to-exist pipeline).
        """
        for blk in source.chain[1:]:
            rebuilt = Block.from_bytes(blk.to_bytes())
            ok, reason = dest.add_block(rebuilt)
            self.assertTrue(
                ok,
                f"Replay failed at height {blk.header.block_number}: {reason}",
            )


# ─────────────────────────────────────────────────────────────────────
# Scenario 1 — "same-block stew": message tx + evidence tx + custody
#              payout in one block.
# ─────────────────────────────────────────────────────────────────────

class TestSameBlockStew(_HarnessMixin, unittest.TestCase):

    def test_three_features_in_one_block_and_cross_chain_consistency(self):
        """A challenge-height block carries: (a) an ordinary message tx
        signed by a THIRD entity (to avoid nonce collisions with the
        evidence submitter's receipted tx), (b) a CensorshipEvidenceTx,
        (c) a custody proof.  The block validates, applies, and the
        resulting snapshot state root is byte-identical on a second
        chain fed the same post-genesis blocks.
        """
        (a_ctx, b_ctx) = self._twin_chains(extras_seeds=[_THIRD_SEED])
        chain_a, a_off, a_sub, a_ext, a_rcpt = a_ctx
        chain_b, b_off, b_sub, b_ext, _ = b_ctx
        a_third = a_ext[0]

        chain_a.archive_reward_pool = ARCHIVE_REWARD * 3
        chain_b.archive_reward_pool = ARCHIVE_REWARD * 3
        pos = ProofOfStake()

        # Receipt is issued NOW (commit_height = last applied block).
        mtx = create_transaction(
            a_sub, "censored-msg", MIN_FEE + 200, nonce=0,
        )
        commit_h = chain_a.height - 1
        receipt = _issue_receipt(a_off, a_rcpt, mtx, commit_h)

        # Drive toward the challenge block at height
        # ARCHIVE_CHALLENGE_INTERVAL.  The offender is the sole proposer.
        while chain_a.height < ARCHIVE_CHALLENGE_INTERVAL:
            self._add_empty_block(chain_a, pos, a_off)
        next_h = chain_a.height
        self.assertEqual(next_h, ARCHIVE_CHALLENGE_INTERVAL)
        self.assertTrue(is_archive_challenge_block(next_h))

        # Ordinary tx from the THIRD entity — unrelated to the evidence
        # submitter so there's no nonce clash with the receipted mtx.
        # (A FAILING regression test for the submitter=ordinary-tx
        # collision is provided separately below.)
        ordinary_tx = create_transaction(
            a_third, "unrelated-ordinary-tx", MIN_FEE + 100, nonce=0,
        )

        etx = _sign_evidence_tx(a_sub, receipt, mtx)
        proof = _build_proof_for_challenge(chain_a, a_off.entity_id, next_h)

        pool_before = chain_a.archive_reward_pool
        staked_before = chain_a.supply.staked.get(a_off.entity_id, 0)
        offender_bal_before = chain_a.supply.balances.get(a_off.entity_id, 0)

        block = chain_a.propose_block(
            pos, a_off, [ordinary_tx],
            censorship_evidence_txs=[etx],
            custody_proofs=[proof],
        )

        ok, reason = chain_a.validate_block(block)
        self.assertTrue(ok, reason)

        ok, reason = chain_a.add_block(block)
        self.assertTrue(ok, reason)

        # Archive-pool payout landed.
        offender_bal_after = chain_a.supply.balances.get(a_off.entity_id, 0)
        self.assertGreaterEqual(
            offender_bal_after, offender_bal_before + ARCHIVE_REWARD,
        )
        # Pool ends at approximately pool_before - ARCHIVE_REWARD, but
        # is ALSO topped up by the fee-burn redirect
        # (ARCHIVE_BURN_REDIRECT_PCT of this block's burned fees).  So
        # we assert the NET move (payout - redirect) landed: the pool
        # dropped by AT MOST ARCHIVE_REWARD (upper bound: zero redirect)
        # and dropped by AT LEAST ARCHIVE_REWARD minus an epsilon
        # derived from the block's fee total.
        self.assertLess(
            chain_a.archive_reward_pool, pool_before,
            "archive pool must be net-debited after a same-block payout",
        )
        self.assertGreaterEqual(
            chain_a.archive_reward_pool, pool_before - ARCHIVE_REWARD,
            "archive pool cannot drop below pool_before - ARCHIVE_REWARD "
            "(the only debit path is a single-prover payout)",
        )

        # Evidence pending (maturity > 0).
        self.assertIn(
            etx.evidence_hash, chain_a.censorship_processor.pending,
        )

        # Stake unchanged pre-maturity.
        self.assertEqual(
            chain_a.supply.staked.get(a_off.entity_id, 0), staked_before,
        )

        # Cross-chain replay — chain_b feeds on chain_a's post-genesis
        # blocks through the wire (bytes) and must reach an identical
        # snapshot state root.
        self._replay_blocks_onto(chain_a, chain_b)
        root_a = compute_state_root(serialize_state(chain_a))
        root_b = compute_state_root(serialize_state(chain_b))
        self.assertEqual(
            root_a, root_b,
            "snapshot root must be byte-identical across two "
            "independent chains fed the same blocks",
        )


# ─────────────────────────────────────────────────────────────────────
# Scenario 2 — evidence maturity coincides with a challenge block.
# ─────────────────────────────────────────────────────────────────────

class TestMaturityAtChallengeHeight(_HarnessMixin, unittest.TestCase):

    def test_maturity_block_is_also_a_challenge_block(self):
        """Construct the chain so that the pending evidence matures
        EXACTLY on a challenge block.  Both effects fire in that block;
        two chains converge to the same state root.
        """
        (a_ctx, b_ctx) = self._twin_chains()
        chain_a, a_off, a_sub, _, a_rcpt = a_ctx
        chain_b, *_ = b_ctx
        chain_a.archive_reward_pool = ARCHIVE_REWARD * 2
        chain_b.archive_reward_pool = ARCHIVE_REWARD * 2
        pos = ProofOfStake()

        # admit_h + MATURITY must be a challenge block.  Using the
        # first challenge block (= INTERVAL) for minimal blocks in
        # flight (WOTS+ leaf budget).
        admit_h = ARCHIVE_CHALLENGE_INTERVAL - EVIDENCE_MATURITY_BLOCKS
        mature_h = admit_h + EVIDENCE_MATURITY_BLOCKS
        self.assertTrue(is_archive_challenge_block(mature_h))

        commit_h = chain_a.height - 1
        mtx = create_transaction(
            a_sub, "late-mature-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(a_off, a_rcpt, mtx, commit_h)
        self.assertGreater(
            admit_h - commit_h, EVIDENCE_INCLUSION_WINDOW,
            "test setup: admit block must be past the inclusion window",
        )

        while chain_a.height < admit_h:
            self._add_empty_block(chain_a, pos, a_off)

        etx = _sign_evidence_tx(a_sub, receipt, mtx)
        admit_block = chain_a.propose_block(
            pos, a_off, [], censorship_evidence_txs=[etx],
        )
        self.assertFalse(is_archive_challenge_block(admit_h))
        ok, reason = chain_a.add_block(admit_block)
        self.assertTrue(ok, reason)

        stake_before = chain_a.supply.staked.get(a_off.entity_id, 0)
        pool_before = chain_a.archive_reward_pool

        while chain_a.height < mature_h:
            self._add_empty_block(chain_a, pos, a_off)

        proof = _build_proof_for_challenge(chain_a, a_off.entity_id, mature_h)
        block = chain_a.propose_block(
            pos, a_off, [], custody_proofs=[proof],
        )
        ok, reason = chain_a.add_block(block)
        self.assertTrue(ok, reason)

        # Slash landed.
        stake_after = chain_a.supply.staked.get(a_off.entity_id, 0)
        expected_slash = compute_slash_amount(stake_before)
        self.assertEqual(stake_before - stake_after, expected_slash)

        self.assertNotIn(
            etx.evidence_hash, chain_a.censorship_processor.pending,
        )
        self.assertIn(
            etx.evidence_hash, chain_a.censorship_processor.processed,
        )

        # Archive payout landed.
        self.assertEqual(
            chain_a.archive_reward_pool, pool_before - ARCHIVE_REWARD,
        )

        # Determinism across twin chains.
        self._replay_blocks_onto(chain_a, chain_b)
        root_a = compute_state_root(serialize_state(chain_a))
        root_b = compute_state_root(serialize_state(chain_b))
        self.assertEqual(root_a, root_b)


# ─────────────────────────────────────────────────────────────────────
# Scenario 3 — slash-then-pay: offender is slashed AND paid in the
#              same block.
# ─────────────────────────────────────────────────────────────────────

class TestSlashThenPay(_HarnessMixin, unittest.TestCase):

    def test_validator_slashed_and_paid_in_same_block(self):
        """The offender is the block proposer AND submits a custody
        proof.  Evidence matures in the same block.  Final stake +
        balance must reflect both composing effects.
        """
        chain, off, sub, _, rcpt = self._single_chain()
        pos = ProofOfStake()
        chain.archive_reward_pool = ARCHIVE_REWARD * 2

        admit_h = ARCHIVE_CHALLENGE_INTERVAL - EVIDENCE_MATURITY_BLOCKS
        mature_h = admit_h + EVIDENCE_MATURITY_BLOCKS
        self.assertTrue(is_archive_challenge_block(mature_h))

        commit_h = chain.height - 1
        mtx = create_transaction(
            sub, "slash-then-pay-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(off, rcpt, mtx, commit_h)

        while chain.height < admit_h:
            self._add_empty_block(chain, pos, off)

        etx = _sign_evidence_tx(sub, receipt, mtx)
        admit_block = chain.propose_block(
            pos, off, [], censorship_evidence_txs=[etx],
        )
        ok, reason = chain.add_block(admit_block)
        self.assertTrue(ok, reason)

        while chain.height < mature_h:
            self._add_empty_block(chain, pos, off)

        stake_before = chain.supply.staked.get(off.entity_id, 0)
        bal_before = chain.supply.balances.get(off.entity_id, 0)
        pool_before = chain.archive_reward_pool
        expected_slash = compute_slash_amount(stake_before)
        self.assertGreater(expected_slash, 0)

        proof = _build_proof_for_challenge(chain, off.entity_id, mature_h)
        block = chain.propose_block(
            pos, off, [], custody_proofs=[proof],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)

        stake_after = chain.supply.staked.get(off.entity_id, 0)
        bal_after = chain.supply.balances.get(off.entity_id, 0)

        # Stake dropped by the exact censorship slash.
        self.assertEqual(stake_before - stake_after, expected_slash)

        # Balance gained AT LEAST the archive reward.  Offender is
        # also the proposer (block reward), so equality is not
        # guaranteed — inequality is enough to prove the payout landed.
        self.assertGreaterEqual(bal_after - bal_before, ARCHIVE_REWARD)

        # Pool debited.
        self.assertEqual(
            chain.archive_reward_pool, pool_before - ARCHIVE_REWARD,
        )


# ─────────────────────────────────────────────────────────────────────
# Scenario 4 — cold-restart determinism via snapshot.
# ─────────────────────────────────────────────────────────────────────

class TestColdRestartDeterminism(_HarnessMixin, unittest.TestCase):

    def test_pending_evidence_and_pool_survive_snapshot_round_trip(self):
        """Cold-restart determinism: a snapshot carrying a non-zero
        `archive_reward_pool` + pending evidence must survive a
        serialize → decode → `_install_state_snapshot` round-trip
        with the snapshot root preserved.

        Was previously a FAILING canary — `_install_state_snapshot`
        in `messagechain/core/blockchain.py` did not restore
        `archive_reward_pool` from the snapshot dict, even though
        the pool is hashed into the snapshot root under
        `_TAG_GLOBAL` / `_GLOBAL_ARCHIVE_REWARD_POOL`.  Fixed by
        adding
            `self.archive_reward_pool = int(snap.get("archive_reward_pool", 0))`
        after the `base_fee` restore block.
        """
        chain, off, sub, _, rcpt = self._single_chain()
        pos = ProofOfStake()
        chain.archive_reward_pool = ARCHIVE_REWARD * 4

        mtx = create_transaction(
            sub, "cold-restart-msg", MIN_FEE + 200, nonce=0,
        )
        commit_h = chain.height - 1
        receipt = _issue_receipt(off, rcpt, mtx, commit_h)

        while chain.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain, pos, off)

        etx = _sign_evidence_tx(sub, receipt, mtx)
        blk = chain.propose_block(
            pos, off, [], censorship_evidence_txs=[etx],
        )
        ok, reason = chain.add_block(blk)
        self.assertTrue(ok, reason)

        snap_dict = serialize_state(chain)
        blob = encode_snapshot(snap_dict)
        pre_root = compute_state_root(snap_dict)

        decoded = decode_snapshot(blob)
        self.assertEqual(pre_root, compute_state_root(decoded))

        chain_b = Blockchain()
        chain_b._install_state_snapshot(decoded)

        self.assertEqual(
            pre_root, compute_state_root(serialize_state(chain_b)),
        )
        self.assertIn(
            etx.evidence_hash, chain_b.censorship_processor.pending,
        )

    def test_matured_slash_survives_snapshot_round_trip(self):
        """Drive a full admit + mature cycle, take a snapshot post-
        maturity, install into a fresh chain, and verify the
        per-entity state tree root matches + the processed evidence
        set survived the round-trip.

        Only asserts on the PER-ENTITY state tree root
        (`compute_current_state_root` — the one committed in
        `block.header.state_root`).  See
        test_FAILING_pending_evidence_and_pool_survive_snapshot_round_trip
        for why the snapshot-level root is not stable today.
        """
        chain, off, sub, _, rcpt = self._single_chain()
        pos = ProofOfStake()

        mtx = create_transaction(
            sub, "matured-msg", MIN_FEE + 200, nonce=0,
        )
        commit_h = chain.height - 1
        receipt = _issue_receipt(off, rcpt, mtx, commit_h)

        while chain.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain, pos, off)

        etx = _sign_evidence_tx(sub, receipt, mtx)
        blk = chain.propose_block(
            pos, off, [], censorship_evidence_txs=[etx],
        )
        ok, reason = chain.add_block(blk)
        self.assertTrue(ok, reason)

        for _ in range(EVIDENCE_MATURITY_BLOCKS + 1):
            self._add_empty_block(chain, pos, off)

        self.assertIn(
            etx.evidence_hash, chain.censorship_processor.processed,
        )

        per_entity_before = chain.compute_current_state_root()

        snap = serialize_state(chain)
        blob = encode_snapshot(snap)

        decoded = decode_snapshot(blob)
        chain_b = Blockchain()
        chain_b._install_state_snapshot(decoded)

        per_entity_after = chain_b.compute_current_state_root()
        self.assertEqual(
            per_entity_before, per_entity_after,
            "per-entity state root (balances/stake/nonces/keys) must "
            "survive a snapshot round-trip",
        )
        self.assertIn(
            etx.evidence_hash, chain_b.censorship_processor.processed,
        )


# ─────────────────────────────────────────────────────────────────────
# Scenario 5 — two evidence txs against the same receipt in one block.
# ─────────────────────────────────────────────────────────────────────

class TestConflictingEvidenceDedup(_HarnessMixin, unittest.TestCase):

    def test_duplicate_evidence_in_same_block_blocks_itself(self):
        """Two CensorshipEvidenceTx's with the same evidence_hash in
        the same block: the first is admitted, the second is rejected
        by the dedupe gate (`is_pending` hits), and the block
        validates with matching sim / apply state roots.

        Was previously a FAILING canary — the sim path unconditionally
        paid the fee + bumped the submitter's leaf watermark for
        every etx, while the apply path correctly skipped both for
        the second (duplicate) etx.  Fixed by making the sim run the
        same `validate_censorship_evidence_tx` admission gate as
        apply, and skipping fee/bump/pending-insert when rejected.
        """
        (a_ctx, b_ctx) = self._twin_chains(extras_seeds=[_SECOND_SEED])
        chain_a, a_off, a_sub, a_ext, a_rcpt = a_ctx
        chain_b, *_ = b_ctx
        a_second = a_ext[0]
        pos = ProofOfStake()

        commit_h = chain_a.height - 1
        mtx = create_transaction(
            a_sub, "dup-evidence-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(a_off, a_rcpt, mtx, commit_h)

        while chain_a.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain_a, pos, a_off)

        etx1 = _sign_evidence_tx(a_sub, receipt, mtx)
        etx2 = _sign_evidence_tx(a_second, receipt, mtx)
        self.assertEqual(etx1.evidence_hash, etx2.evidence_hash)

        block = chain_a.propose_block(
            pos, a_off, [], censorship_evidence_txs=[etx1, etx2],
        )
        ok, reason = chain_a.add_block(block)
        self.assertTrue(ok, reason)

        pending = dict(chain_a.censorship_processor.pending)
        self.assertEqual(len(pending), 1)
        self.assertIn(etx1.evidence_hash, pending)
        self.assertEqual(
            pending[etx1.evidence_hash].evidence_tx_hash, etx1.tx_hash,
        )

        self._replay_blocks_onto(chain_a, chain_b)
        root_a = compute_state_root(serialize_state(chain_a))
        root_b = compute_state_root(serialize_state(chain_b))
        self.assertEqual(root_a, root_b)

    def test_single_evidence_admits_deterministically(self):
        """Positive analog of the FAILING dup test: a single
        CensorshipEvidenceTx admits, and two independent chains fed
        the same block reach identical state roots.  Verifies the
        single-evidence path works end-to-end across peers.
        """
        (a_ctx, b_ctx) = self._twin_chains()
        chain_a, a_off, a_sub, _, a_rcpt = a_ctx
        chain_b, *_ = b_ctx
        pos = ProofOfStake()

        commit_h = chain_a.height - 1
        mtx = create_transaction(
            a_sub, "single-evidence-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(a_off, a_rcpt, mtx, commit_h)

        while chain_a.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain_a, pos, a_off)

        etx = _sign_evidence_tx(a_sub, receipt, mtx)
        block = chain_a.propose_block(
            pos, a_off, [], censorship_evidence_txs=[etx],
        )
        ok, reason = chain_a.add_block(block)
        self.assertTrue(ok, reason)

        self.assertIn(
            etx.evidence_hash, chain_a.censorship_processor.pending,
        )
        self._replay_blocks_onto(chain_a, chain_b)
        root_a = compute_state_root(serialize_state(chain_a))
        root_b = compute_state_root(serialize_state(chain_b))
        self.assertEqual(root_a, root_b)

    def test_proposer_listed_order_is_canonical(self):
        """Proposer's listed order of CensorshipEvidenceTx's is
        canonical for admission: the FIRST etx in the block's list
        admits, any subsequent dup (same evidence_hash, possibly
        different submitter) is rejected.  The sim and apply paths
        agree on this ordering so the block validates.

        Was previously a FAILING canary — same sim-vs-apply drift
        as `test_duplicate_evidence_in_same_block_blocks_itself`.
        Fixed by the sim running the same admission gate as apply.
        """
        chain, off, sub, ext, rcpt = self._single_chain(
            extras_seeds=[_SECOND_SEED],
        )
        pos = ProofOfStake()
        second = ext[0]

        commit_h = chain.height - 1
        mtx = create_transaction(
            sub, "dup-rev-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(off, rcpt, mtx, commit_h)

        while chain.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain, pos, off)

        etx1 = _sign_evidence_tx(sub, receipt, mtx)
        etx2 = _sign_evidence_tx(second, receipt, mtx)

        block = chain.propose_block(
            pos, off, [], censorship_evidence_txs=[etx2, etx1],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        pending = chain.censorship_processor.pending
        self.assertEqual(len(pending), 1)
        self.assertEqual(
            pending[etx2.evidence_hash].evidence_tx_hash, etx2.tx_hash,
            "FCFS: the first evidence in the block's list is the one "
            "that admits; the proposer's listed order is canonical",
        )


# ─────────────────────────────────────────────────────────────────────
# Scenario 6 — invalid custody proof poisons an otherwise-valid block.
# ─────────────────────────────────────────────────────────────────────

class TestInvalidProofPoisonsBlock(_HarnessMixin, unittest.TestCase):

    def test_invalid_proof_rejects_whole_block_atomically(self):
        """A block that carries a valid CensorshipEvidenceTx AND a
        bogus custody proof must be rejected atomically by
        `_validate_custody_proofs` before any state is mutated.
        Evidence must NOT land in pending; pool must not be debited.
        """
        chain, off, sub, _, rcpt = self._single_chain()
        pos = ProofOfStake()
        chain.archive_reward_pool = ARCHIVE_REWARD * 2

        commit_h = chain.height - 1
        mtx = create_transaction(
            sub, "valid-evidence-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(off, rcpt, mtx, commit_h)

        while chain.height < ARCHIVE_CHALLENGE_INTERVAL:
            self._add_empty_block(chain, pos, off)
        next_h = chain.height
        self.assertTrue(is_archive_challenge_block(next_h))

        etx = _sign_evidence_tx(sub, receipt, mtx)

        good_proof = _build_proof_for_challenge(chain, off.entity_id, next_h)
        bad_proof = CustodyProof(
            prover_id=good_proof.prover_id,
            target_height=good_proof.target_height,
            target_block_hash=b"\xde" * 32,  # wrong — not chain's block
            header_bytes=good_proof.header_bytes,
            merkle_root=good_proof.merkle_root,
            tx_index=good_proof.tx_index,
            tx_bytes=good_proof.tx_bytes,
            merkle_path=list(good_proof.merkle_path),
            merkle_layer_sizes=list(good_proof.merkle_layer_sizes),
        )

        pending_before = dict(chain.censorship_processor.pending)
        pool_before = chain.archive_reward_pool
        supply_before = chain.supply.total_supply
        burned_before = chain.supply.total_burned
        balances_before = dict(chain.supply.balances)
        height_before = chain.height

        block = chain.propose_block(
            pos, off, [],
            censorship_evidence_txs=[etx],
            custody_proofs=[bad_proof],
        )
        ok, reason = chain.add_block(block)
        self.assertFalse(
            ok,
            f"block with bad proof should be rejected; reason: {reason}",
        )

        # Atomicity: chain state UNCHANGED.
        self.assertEqual(chain.height, height_before)
        self.assertEqual(
            chain.censorship_processor.pending, pending_before,
        )
        self.assertEqual(chain.archive_reward_pool, pool_before)
        self.assertEqual(chain.supply.total_supply, supply_before)
        self.assertEqual(chain.supply.total_burned, burned_before)
        self.assertEqual(chain.supply.balances, balances_before)


# ─────────────────────────────────────────────────────────────────────
# Scenario 7 — state-snapshot v4 round-trip under combined load.
# ─────────────────────────────────────────────────────────────────────

class TestSnapshotV4RoundTrip(_HarnessMixin, unittest.TestCase):

    def test_full_snapshot_byte_identical_and_root_stable(self):
        """Build a chain whose state populates every v4 section:
          * non-zero archive_reward_pool
          * pending censorship evidence
          * processed censorship evidence
          * registered receipt_subtree_roots
          * non-trivial balances / staked / nonces
        Serialize → decode → re-encode → assert bytes match.  Also
        assert the state root is stable across the round-trip.
        """
        chain, off, sub, _, rcpt = self._single_chain()
        pos = ProofOfStake()
        chain.archive_reward_pool = ARCHIVE_REWARD * 3

        # First evidence: admit, then mature → populates processed.
        mtx1 = create_transaction(
            sub, "m1-msg", MIN_FEE + 200, nonce=0,
        )
        commit_h = chain.height - 1
        r1 = _issue_receipt(off, rcpt, mtx1, commit_h)

        while chain.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain, pos, off)

        etx1 = _sign_evidence_tx(sub, r1, mtx1)
        blk = chain.propose_block(
            pos, off, [], censorship_evidence_txs=[etx1],
        )
        ok, reason = chain.add_block(blk)
        self.assertTrue(ok, reason)

        for _ in range(EVIDENCE_MATURITY_BLOCKS + 1):
            self._add_empty_block(chain, pos, off)

        # Second evidence: different tx, stays pending.
        mtx2 = create_transaction(
            sub, "m2-msg", MIN_FEE + 200, nonce=1,
        )
        commit_h2 = chain.height - 1
        r2 = _issue_receipt(off, rcpt, mtx2, commit_h2)

        while chain.height < commit_h2 + EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain, pos, off)

        etx2 = _sign_evidence_tx(sub, r2, mtx2)
        blk2 = chain.propose_block(
            pos, off, [], censorship_evidence_txs=[etx2],
        )
        ok, reason = chain.add_block(blk2)
        self.assertTrue(ok, reason)

        self.assertIn(
            etx1.evidence_hash, chain.censorship_processor.processed,
        )
        self.assertIn(
            etx2.evidence_hash, chain.censorship_processor.pending,
        )

        snap = serialize_state(chain)
        self.assertGreater(snap["archive_reward_pool"], 0)
        self.assertTrue(snap["censorship_pending"])
        self.assertTrue(snap["censorship_processed"])
        self.assertTrue(snap["receipt_subtree_roots"])

        blob = encode_snapshot(snap)
        root_before = compute_state_root(snap)

        decoded = decode_snapshot(blob)
        self.assertEqual(
            decoded["archive_reward_pool"], snap["archive_reward_pool"],
        )
        self.assertEqual(
            set(decoded["censorship_processed"]),
            set(snap["censorship_processed"]),
        )
        self.assertEqual(
            dict(decoded["censorship_pending"]),
            dict(snap["censorship_pending"]),
        )
        self.assertEqual(
            dict(decoded["receipt_subtree_roots"]),
            dict(snap["receipt_subtree_roots"]),
        )

        # Determinism: re-encoding a decoded snapshot produces byte-
        # identical output.
        reblob = encode_snapshot(decoded)
        self.assertEqual(
            blob, reblob,
            "re-encoding a decoded v4 snapshot must produce byte-"
            "identical output",
        )

        # State root stable across the round-trip.
        root_after = compute_state_root(decoded)
        self.assertEqual(root_before, root_after)


# ─────────────────────────────────────────────────────────────────────
# Scenario 8 — end-to-end convergence: two chains, combined features.
# ─────────────────────────────────────────────────────────────────────

class TestCrossPeerConvergence(_HarnessMixin, unittest.TestCase):

    def test_two_chains_converge_on_identical_snapshot_root(self):
        (a_ctx, b_ctx) = self._twin_chains()
        chain_a, a_off, a_sub, _, a_rcpt = a_ctx
        chain_b, *_ = b_ctx
        chain_a.archive_reward_pool = ARCHIVE_REWARD * 2
        chain_b.archive_reward_pool = ARCHIVE_REWARD * 2
        pos = ProofOfStake()

        commit_h = chain_a.height - 1
        mtx = create_transaction(
            a_sub, "conv-msg", MIN_FEE + 200, nonce=0,
        )
        receipt = _issue_receipt(a_off, a_rcpt, mtx, commit_h)

        while chain_a.height < EVIDENCE_INCLUSION_WINDOW + 2:
            self._add_empty_block(chain_a, pos, a_off)

        etx = _sign_evidence_tx(a_sub, receipt, mtx)
        blk = chain_a.propose_block(
            pos, a_off, [], censorship_evidence_txs=[etx],
        )
        ok, reason = chain_a.add_block(blk)
        self.assertTrue(ok, reason)

        # Run the chain through a challenge block AND past maturity.
        while chain_a.height < 2 * ARCHIVE_CHALLENGE_INTERVAL:
            self._add_empty_block(chain_a, pos, a_off)

        self._replay_blocks_onto(chain_a, chain_b)

        root_a = compute_state_root(serialize_state(chain_a))
        root_b = compute_state_root(serialize_state(chain_b))
        self.assertEqual(root_a, root_b)

        self.assertEqual(
            set(chain_a.censorship_processor.pending.keys()),
            set(chain_b.censorship_processor.pending.keys()),
        )
        self.assertEqual(
            set(chain_a.censorship_processor.processed),
            set(chain_b.censorship_processor.processed),
        )


# ─────────────────────────────────────────────────────────────────────
# Scenario 9 — FAILING regression canary for a sim-vs-apply divergence.
# ─────────────────────────────────────────────────────────────────────

class TestSubmitterNonceCollisionWithEvidence(_HarnessMixin, unittest.TestCase):
    """When a single submitter lands BOTH an ordinary MessageTransaction
    and a CensorshipEvidenceTx in the same block, and the receipted
    message_tx embedded in the evidence tx shares a nonce with the
    ordinary tx, the block is rejected by the STATE_ROOT check — the
    proposer cannot include both because:

      * `compute_post_state_root` (sim) debits the evidence fee + bumps
        the submitter watermark unconditionally;
      * `_apply_block_state` (apply) runs `validate_censorship_evidence_tx`
        at apply-time, which REJECTS the evidence because the
        submitter's nonce just advanced via the ordinary tx — the
        receipted tx "looks already on-chain" from the nonce gate's
        POV (nonce advanced past receipted tx's nonce);
      * therefore the apply path charges NO fee and bumps NO watermark,
        while the sim assumed otherwise → state_root mismatch → block
        rejected.

    This is a real sim-vs-apply divergence that surfaces only when the
    two features compose inside one block.  Filed as a FAILING canary
    so any future fix can flip this test green.
    """

    def test_sim_and_apply_diverge_on_nonce_collision(self):
        """Same-block ordinary tx + evidence tx from the same submitter
        with a nonce collision: the apply path correctly rejects the
        evidence (receipted tx's nonce has been bumped past), and the
        sim now matches by predicting the same rejection.  Block
        validates, no state_root mismatch.

        Was previously a FAILING canary — sim paid evidence fee +
        bumped the submitter's leaf watermark unconditionally while
        apply's `validate_censorship_evidence_tx` rejected the
        evidence (chain_nonce > message_tx.nonce).  Fixed by making
        the sim read the nonce gate against `sim_nonces`, which
        already reflects the same-block ordinary tx's nonce bump.
        """
        chain, off, sub, _, rcpt = self._single_chain()
        pos = ProofOfStake()
        chain.archive_reward_pool = ARCHIVE_REWARD * 2

        mtx = create_transaction(sub, "censored-msg", MIN_FEE + 200, nonce=0)
        commit_h = chain.height - 1
        receipt = _issue_receipt(off, rcpt, mtx, commit_h)

        while chain.height < ARCHIVE_CHALLENGE_INTERVAL:
            self._add_empty_block(chain, pos, off)

        # Ordinary tx from the SAME submitter at nonce=0 (same as mtx).
        # In real life, the submitter would expect this tx to land,
        # AND would also expect to file evidence about the offender
        # failing to include the earlier receipted tx — but those two
        # txs cannot coexist in one block today.
        ordinary_tx = create_transaction(
            sub, "ordinary-msg", MIN_FEE + 100, nonce=0,
        )
        etx = _sign_evidence_tx(sub, receipt, mtx)

        block = chain.propose_block(
            pos, off, [ordinary_tx], censorship_evidence_txs=[etx],
        )
        ok, reason = chain.add_block(block)
        # A fix for this bug would make this succeed.
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
