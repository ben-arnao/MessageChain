"""Audit r37 #1 -- fork-path / orphan-path Tier-18 budget bypass.

Pre-fix: ``Blockchain.validate_block_standalone`` (the fork-path
validator dispatched from ``_handle_fork``) and the orphan-path pre-
validator inline in ``Blockchain.add_block`` (the structural check on
unknown-parent blocks before they enter the orphan pool) both:

  (a) compute ``total_tx_count = len(block.transactions) +
      len(block.transfer_transactions)``, OMITTING ``react_transactions``
      from the cross-kind tx-count cap that ``validate_block`` enforces
      post-Tier-18; and
  (b) cap only ``total_message_bytes`` (just the message payloads),
      NEVER the unified ``MAX_BLOCK_TOTAL_BYTES`` Tier-18 byte budget
      that ``validate_block`` enforces across (message + transfer +
      react) tx kinds combined.

The canonical-chain ``validate_block`` enforces both rules; the fork-
path and orphan-path validators do not.

Concrete attack: a colluding proposer mints a fork tip whose
``react_transactions`` count pushes the cross-kind total past
``MAX_TXS_PER_BLOCK``, OR whose serialized tx bytes (summed across
message + transfer + react) exceed ``MAX_BLOCK_TOTAL_BYTES``.  The
canonical-chain validator rejects such a block; ``validate_block_
standalone`` accepts it.  ``_handle_fork`` then stores the block in
``self._block_by_hash`` and registers it as a fork tip in
``self.fork_choice.tips``.  The fork tip can attract cumulative
weight, and ``_reorganize`` swaps the canonical chain to it -- now
the chain holds a block exceeding the unified Tier-18 byte budget
that every honest node tried to enforce on the linear-extension path.
The orphan-path bypass is structurally similar: an attacker spams
oversized orphan blocks (bloated react_transactions counts, oversized
unified bytes) and they all enter the orphan pool, defeating the
"pre-validate before storing to prevent garbage" hardening that
the orphan pre-validator was added for.

CLAUDE.md anchors at risk:
  * "Censorship resistance is a *collective decision*" -- the Tier-18
    budget IS the cross-kind market mechanism that prevents one tx
    kind from drowning out others; reorg-path divergence lets a
    colluding proposer escape it without producing slashable
    evidence.
  * "Minimize chain bloat & maximize storage efficiency" -- chain
    bloat is fought only through protocol-level levers (per-block
    byte budget being one); a reorg path that admits oversized
    blocks erodes the lever.

Same defect class as the unstake-release / cross-pool admission gaps
closed in audit rounds r12, r28, r31, r33 -- a security gate that's
correctly enforced on the canonical-chain path is silently absent
from a sibling block-entry path.

Soft fix: pure tightening of fork-acceptance and orphan-acceptance
rules.  Every block already in the canonical chain passes both gates
(they were enforced on the linear-extension path), so the legacy
canonical chain replays byte-identically.  Only adversarial fork
tips and bloated orphans are newly rejected.  No new tier, no new
wire format, no state-tree changes.
"""

from __future__ import annotations

import inspect
import unittest
from unittest.mock import MagicMock

from messagechain import config
from messagechain.core.blockchain import Blockchain


# ---------------------------------------------------------------------------
# Source pins -- these are the cheapest invariants to express, since both
# call sites are inline structural checks rather than helper methods.
# ---------------------------------------------------------------------------


class TestForkPathValidatorEnforcesTier18(unittest.TestCase):
    """Source pin: ``validate_block_standalone`` MUST mirror the
    Tier-18 unified-budget block from ``validate_block``: include
    ``react_transactions`` in the cross-kind tx count post-Tier-18,
    AND apply ``MAX_BLOCK_TOTAL_BYTES`` across (message + transfer +
    react) post-Tier-18.
    """

    def test_standalone_validator_includes_react_in_tx_count(self):
        src = inspect.getsource(Blockchain.validate_block_standalone)
        self.assertIn(
            "react_transactions", src,
            "validate_block_standalone must reference react_transactions "
            "for cross-kind tx-count enforcement post-Tier-18 -- without "
            "it, a fork tip with bloated react_transactions evades the "
            "MAX_TXS_PER_BLOCK cap on the fork-acceptance path",
        )
        self.assertIn(
            "TIER_18_HEIGHT", src,
            "validate_block_standalone must consult TIER_18_HEIGHT to "
            "gate the cross-kind tx-count and unified-byte rules at the "
            "same activation height the canonical-chain validator does",
        )

    def test_standalone_validator_enforces_unified_byte_budget(self):
        src = inspect.getsource(Blockchain.validate_block_standalone)
        self.assertIn(
            "MAX_BLOCK_TOTAL_BYTES", src,
            "validate_block_standalone must enforce the Tier-18 unified "
            "byte budget across (message + transfer + react) tx kinds; "
            "without it, a fork tip exceeding the budget is accepted on "
            "the fork-acceptance path while every honest node rejected "
            "the same content on the linear-extension path",
        )


class TestOrphanPathPrevalidatorEnforcesTier18(unittest.TestCase):
    """Source pin: the orphan-path pre-validator inline in
    ``Blockchain.add_block`` MUST also include react_transactions in
    the count cap and enforce MAX_BLOCK_TOTAL_BYTES post-Tier-18.

    The check is inline (not a separate helper), so we source-pin
    against ``add_block``'s text and assert the orphan-path block
    references all three constants and includes react_transactions
    in the count.
    """

    def test_add_block_orphan_path_references_tier_18(self):
        src = inspect.getsource(Blockchain.add_block)
        self.assertIn(
            "Orphan rejected", src,
            "sanity: add_block must contain the orphan pre-validator block",
        )
        # The orphan-pre-validator block must reference all three Tier-18
        # constants/fields; without these the bloat path is open.
        self.assertIn(
            "TIER_18_HEIGHT", src,
            "add_block orphan pre-validator must consult TIER_18_HEIGHT",
        )
        self.assertIn(
            "MAX_BLOCK_TOTAL_BYTES", src,
            "add_block orphan pre-validator must enforce "
            "MAX_BLOCK_TOTAL_BYTES",
        )
        self.assertIn(
            "react_transactions", src,
            "add_block orphan pre-validator must include "
            "react_transactions in the cross-kind tx count",
        )


# ---------------------------------------------------------------------------
# Behavioural tests on validate_block_standalone -- assert the validator
# reaches the count / byte gates and rejects bloated fork tips post-Tier-18.
# ---------------------------------------------------------------------------


def _mock_tx(stored_bytes: int = 50, entity_id: bytes = b"\x00" * 32, tag: int = 0):
    """Minimal tx object that satisfies the surface validate_block_
    standalone reads up to the Tier-18 gate.  No real signing -- the
    early checks (count + bytes) reject before signature work.
    """
    tx = MagicMock()
    tx.entity_id = entity_id
    tx.message = b""
    # Unique tx_hash per call (collision would trip the dup-tx check).
    tx.tx_hash = tag.to_bytes(4, "big") + b"\x00" * 28
    tx.signature.leaf_index = 0
    tx.to_bytes.return_value = b"\x00" * stored_bytes
    return tx


def _mock_block(
    block_number: int,
    prev_hash: bytes,
    transactions=None,
    transfer_transactions=None,
    react_transactions=None,
):
    """Minimal block whose attribute surface matches what the early
    validate_block_standalone checks read.
    """
    blk = MagicMock()
    blk.header.prev_hash = prev_hash
    blk.header.block_number = block_number
    blk.header.version = 1
    blk.header.hash_version = 1  # current SHA3 hash version
    blk.header.proposer_signature = None  # skip sig-version validation
    blk.header.timestamp = 10**9  # arbitrary, real-block-style timestamp
    blk.transactions = transactions or []
    blk.transfer_transactions = transfer_transactions or []
    blk.react_transactions = react_transactions or []
    # Empty consensus-vote / governance / authority lists so
    # _validate_block_list_counts passes vacuously.
    blk.attestations = []
    blk.validator_signatures = []
    blk.governance_txs = []
    blk.authority_txs = []
    blk.censorship_evidence_txs = []
    blk.block_hash = bytes((block_number & 0xFF,)) * 32
    return blk


class TestStandaloneRejectsBloatedReactCountPostTier18(unittest.TestCase):
    """Behavioural: post-Tier-18, a fork tip with
    ``len(transactions) + len(transfer_transactions) +
    len(react_transactions) > MAX_TXS_PER_BLOCK`` must be rejected.

    Pre-fix the validator only sums the first two; with bloated
    react_transactions the total slips past the cap.
    """

    def test_post_tier18_count_includes_react(self):
        bc = Blockchain()
        parent_hash = b"\xAA" * 32
        parent = _mock_block(
            block_number=config.TIER_18_HEIGHT, prev_hash=b"\xBB" * 32,
        )
        parent.block_hash = parent_hash

        # MAX_TXS_PER_BLOCK + 1 react_transactions, 0 message, 0 transfer.
        # Pre-fix: total_tx_count = 0 + 0 = 0 (passes).
        # Post-fix: total_tx_count = 0 + 0 + (cap+1) > cap (rejects).
        bloat = [
            _mock_tx(stored_bytes=50, tag=i)
            for i in range(config.MAX_TXS_PER_BLOCK + 1)
        ]
        block = _mock_block(
            block_number=config.TIER_18_HEIGHT + 1,
            prev_hash=parent_hash,
            react_transactions=bloat,
        )

        ok, reason = bc.validate_block_standalone(block, parent)
        self.assertFalse(
            ok,
            "post-Tier-18 fork tip with bloated react_transactions must "
            "be rejected on count -- pre-fix the standalone validator "
            "ignored react in the count and accepted the bloat",
        )
        self.assertIn(
            "Too many transactions", reason,
            f"expected count-cap rejection, got reason={reason!r}",
        )


class TestStandaloneRejectsBloatedUnifiedBytesPostTier18(unittest.TestCase):
    """Behavioural: post-Tier-18, a fork tip whose serialized bytes
    summed across (message + transfer + react) exceed
    ``MAX_BLOCK_TOTAL_BYTES`` must be rejected.

    Pre-fix the validator capped only ``total_message_bytes`` (a
    legacy, message-payload-only check); the unified ceiling was
    never enforced on the fork path.
    """

    def test_post_tier18_unified_byte_budget_enforced(self):
        bc = Blockchain()
        parent_hash = b"\xCC" * 32
        parent = _mock_block(
            block_number=config.TIER_18_HEIGHT, prev_hash=b"\xDD" * 32,
        )
        parent.block_hash = parent_hash

        # Use a tx count strictly UNDER MAX_TXS_PER_BLOCK (so the
        # count cap does not bind first), but each tx oversized
        # enough that the unified byte budget DOES bind.
        n_txs = max(1, config.MAX_TXS_PER_BLOCK - 5)  # leaves count headroom
        oversize_each = (config.MAX_BLOCK_TOTAL_BYTES // n_txs) + 10
        # n_txs * (MAX/n_txs + 10) bytes > MAX_BLOCK_TOTAL_BYTES
        bloat = [
            _mock_tx(stored_bytes=oversize_each, tag=i)
            for i in range(n_txs)
        ]
        block = _mock_block(
            block_number=config.TIER_18_HEIGHT + 1,
            prev_hash=parent_hash,
            react_transactions=bloat,
        )

        ok, reason = bc.validate_block_standalone(block, parent)
        self.assertFalse(
            ok,
            "post-Tier-18 fork tip exceeding MAX_BLOCK_TOTAL_BYTES "
            "must be rejected -- pre-fix the standalone validator "
            "had no unified-byte gate at all",
        )
        self.assertIn(
            "exceed", reason,
            f"expected byte-budget rejection, got reason={reason!r}",
        )


class TestStandalonePreTier18LegacyByteIdentity(unittest.TestCase):
    """Behavioural regression pin: PRE-Tier-18 blocks must still
    pass the legacy count check that does NOT include react.  This
    preserves byte-identical replay of the historical canonical
    chain through ``_handle_fork`` for blocks at heights below
    ``TIER_18_HEIGHT``.
    """

    def test_pre_tier18_react_does_not_count_against_cap(self):
        bc = Blockchain()
        parent_hash = b"\xEE" * 32
        parent = _mock_block(
            block_number=10, prev_hash=b"\xFF" * 32,
        )
        parent.block_hash = parent_hash

        # Bloat react_transactions PAST the cap, but at a pre-Tier-18
        # height.  Legacy rule: react isn't counted.  The block still
        # has zero msg+transfer txs so it should not be rejected on
        # the count axis.  (It may fail later checks like sig_cost,
        # but NOT on "Too many transactions".)
        bloat = [
            _mock_tx(stored_bytes=50, tag=i)
            for i in range(config.MAX_TXS_PER_BLOCK + 1)
        ]
        block = _mock_block(
            block_number=11,  # well below TIER_18_HEIGHT
            prev_hash=parent_hash,
            react_transactions=bloat,
        )

        ok, reason = bc.validate_block_standalone(block, parent)
        # Either accepted (unlikely, since later checks like sig_cost
        # may bite the mock) or rejected for some non-count reason --
        # but NOT for "Too many transactions" on the count axis.
        if not ok:
            self.assertNotIn(
                "Too many transactions", reason,
                f"pre-Tier-18 fork block must NOT be count-rejected on "
                f"react bloat (legacy byte-identity); got reason={reason!r}",
            )


# ---------------------------------------------------------------------------
# Pin against the activation constant ordering -- the gate must use
# the same TIER_18_HEIGHT the canonical validator uses, not a fresh
# ad-hoc constant that could drift out of sync.
# ---------------------------------------------------------------------------


class TestActivationHeightConstantIsShared(unittest.TestCase):
    def test_uses_canonical_tier_18_height(self):
        std_src = inspect.getsource(Blockchain.validate_block_standalone)
        canonical_src = inspect.getsource(Blockchain.validate_block)
        # Both validators must reference the same TIER_18_HEIGHT
        # symbol for the activation gate; a fresh constant would
        # invite future drift.
        self.assertIn("TIER_18_HEIGHT", canonical_src)
        self.assertIn("TIER_18_HEIGHT", std_src)
        add_block_src = inspect.getsource(Blockchain.add_block)
        self.assertIn("TIER_18_HEIGHT", add_block_src)


if __name__ == "__main__":
    unittest.main()
