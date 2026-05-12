"""Audit r51 — the production runtime ``server.Server`` is the
twin of ``messagechain.network.node.Node``, but the audit-r46 #1 and
audit-r50 #1 / #2 fixes only landed on ``Node``.  ``Server`` (which
``cli.py`` actually instantiates for the validator process) still
verified attestations / finality votes against the CURRENT key, read
LIVE ``supply.staked`` for the finality denominator, AND inserted into
``_seen_attestations`` BEFORE signature verification.

CLAUDE.md adversaries silently re-armed on the production path:

  * **Validator collusion (primary).**  Gossip-layer dedup poisoning
    suppresses honest attestations with no slashable evidence (r50 #1
    re-armed on Server).  Live-stake reads at the gossip-ingress
    finality update fork two honest peers' attested_stake totals on
    the same (validator_id, height, hash) key during stake-churn
    windows (r46 #1 re-armed on Server).
  * **Honest-operator insurance + crypto-agility.**  A rotated
    validator's pre-rotation finality votes (within the 1000-block
    ``FINALITY_VOTE_MAX_AGE_BLOCKS`` window, while the rotation
    cooldown is only 144 blocks) verify-fail under the new key,
    relayers take ``OFFENSE_INVALID_TX``, honest peers ban honest
    peers (r50 #2 re-armed on Server).

Abstraction fix: lift the exact chokepoint shape from Node into
Server.  The helpers (`Blockchain._verify_signer_at_height`,
`Blockchain.resolve_pinned_attestation_stake`) already exist; Server
must route through them.  These tests are structural mirrors of the
Node-side audit r46 #1 + r50 #1 + r50 #2 guards, asserted against
``server.Server`` source, so a future refactor cannot silently
re-introduce any of the three defect-shapes on the production path.
"""

from __future__ import annotations

import inspect
import unittest


class TestServerHandleAnnounceAttestationRoutesThroughHelpers(unittest.TestCase):
    """Structural: ``Server._handle_announce_attestation`` must:

      (a) call ``Blockchain._verify_signer_at_height`` for sig verify
          (r50 #2 — historical-key candidate set);
      (b) call ``Blockchain.resolve_pinned_attestation_stake`` for the
          finality denominator (r46 #1 — pinned-stake snapshot);
      (c) insert into ``_seen_attestations`` AFTER the verify call
          (r50 #1 — dedup-after-verify discipline).
    """

    def _src(self) -> str:
        from server import Server
        return inspect.getsource(Server._handle_announce_attestation)

    def test_attestation_handler_routes_through_verify_signer_at_height(self):
        src = self._src()
        self.assertNotIn(
            "verify_attestation(att, pk)", src,
            "Server._handle_announce_attestation must NOT verify with "
            "``pk = self.blockchain.public_keys[...]`` -- a rotated "
            "validator's in-flight attestation silently fails under "
            "the new key (audit r50 #2 re-armed on production path).",
        )
        self.assertIn(
            "_verify_signer_at_height", src,
            "Server._handle_announce_attestation must route signature "
            "verification through Blockchain._verify_signer_at_height "
            "with att.block_number — same chokepoint discipline as "
            "Node._handle_announce_attestation (audit r51).",
        )

    def test_attestation_handler_routes_through_pinned_stake_helper(self):
        src = self._src()
        self.assertNotIn(
            "supply.get_staked(att.validator_id)", src,
            "Server._handle_announce_attestation must NOT read "
            "``supply.get_staked(att.validator_id)`` (live stake) for "
            "the finality denominator — live stake forks two honest "
            "peers' attested_stake totals during stake-churn windows "
            "(audit r46 #1 re-armed on production path).",
        )
        self.assertNotIn(
            "sum(self.blockchain.supply.staked.values())", src,
            "Server._handle_announce_attestation must NOT read the "
            "live ``sum(supply.staked.values())`` for total_stake — "
            "this is the live-stake divergence trap (audit r46 #1).",
        )
        self.assertIn(
            "resolve_pinned_attestation_stake", src,
            "Server._handle_announce_attestation must route the stake "
            "denominator through "
            "Blockchain.resolve_pinned_attestation_stake — same "
            "chokepoint Node._handle_announce_attestation uses.",
        )

    def test_attestation_handler_inserts_dedup_after_verify(self):
        """The dedup membership CHECK is fine pre-verify (cheap gate
        skips expensive verification of already-accepted entries).
        What's not allowed is the INSERT before verify — a forged-sig
        attestation poisons the LRU and silently suppresses the
        genuine attestation arriving later (audit r50 #1).
        """
        src = self._src()
        membership_idx = src.find("att_key in self._seen_attestations")
        # Either direct verify or the r50 #2 chokepoint counts as
        # the verify site.
        verify_idx = -1
        for needle in ("_verify_signer_at_height(", "verify_attestation("):
            i = src.find(needle)
            if i >= 0 and (verify_idx < 0 or i < verify_idx):
                verify_idx = i
        insert_idx = src.find("_seen_attestations[att_key]")

        self.assertGreater(
            membership_idx, 0,
            "Handler must perform the dedup membership check via "
            "``att_key in self._seen_attestations`` (cheap early-return "
            "gate).",
        )
        self.assertGreater(
            verify_idx, 0,
            "Handler must call a signature-verify primitive.",
        )
        self.assertGreater(
            insert_idx, 0,
            "Handler must populate _seen_attestations via an "
            "assignment to _seen_attestations[att_key].",
        )
        self.assertLess(
            membership_idx, verify_idx,
            "Membership check should precede verify (cheap dedup gate "
            "skips expensive sig verification of already-seen entries).",
        )
        self.assertLess(
            verify_idx, insert_idx,
            "Server._handle_announce_attestation must perform the "
            "``_seen_attestations[att_key] = True`` INSERT AFTER "
            "signature verification.  Otherwise a forged-sig "
            "attestation poisons the dedup LRU and silently "
            "suppresses honest finality (audit r50 #1 re-armed on "
            "production path).",
        )


class TestServerHandleAnnounceFinalityVoteRoutesThroughHelpers(unittest.TestCase):
    """Structural: ``Server._handle_announce_finality_vote`` must
    route signature verification through
    ``Blockchain._verify_signer_at_height`` with the vote's
    ``signed_at_height`` (audit r50 #2).
    """

    def _src(self) -> str:
        from server import Server
        return inspect.getsource(Server._handle_announce_finality_vote)

    def test_finality_vote_handler_routes_through_verify_signer_at_height(self):
        src = self._src()
        self.assertNotIn(
            "verify_finality_vote(vote, pk)", src,
            "Server._handle_announce_finality_vote must NOT verify "
            "with the current key — a rotated validator's "
            "pre-rotation in-flight votes (the rotation cooldown is "
            "144 blocks; the vote-admission window is 1000) silently "
            "fail under the new key, the relayer takes "
            "OFFENSE_INVALID_TX, and honest peers ban each other "
            "(audit r50 #2 re-armed on production path).",
        )
        self.assertIn(
            "_verify_signer_at_height", src,
            "Server._handle_announce_finality_vote must route signature "
            "verification through Blockchain._verify_signer_at_height "
            "with vote.signed_at_height — same chokepoint discipline "
            "Node._handle_announce_finality_vote uses (audit r51).",
        )


class TestServerLocalAttestationPathRoutesThroughPinnedStake(unittest.TestCase):
    """Structural: ``Server._maybe_attest_accepted_block`` (the local
    broadcast path — this validator attesting a block it just
    accepted) must compute the finality denominator via the pinned
    snapshot, NOT live ``supply.staked``.

    Same defect class as ``_handle_announce_attestation``: the apply
    path (`Blockchain._process_attestations`) and the gossip-ingress
    path both already route through the pinned snapshot; the local
    broadcast path was the third writer to ``FinalityTracker.
    add_attestation`` still reading live state on Server.  All three
    must share the same denominator source or two honest peers will
    diverge during stake-churn windows (audit r46 #1).
    """

    def _src(self) -> str:
        from server import Server
        return inspect.getsource(Server._maybe_attest_accepted_block)

    def test_local_broadcast_routes_through_pinned_stake_helper(self):
        src = self._src()
        self.assertNotIn(
            "supply.get_staked(self.wallet_id)", src,
            "Server._maybe_attest_accepted_block must NOT read "
            "``supply.get_staked(self.wallet_id)`` (live stake) for "
            "its local finality update — three call sites that all "
            "feed FinalityTracker.add_attestation MUST share one "
            "denominator source, otherwise honest peers diverge on "
            "is_finalized() during stake-churn windows (audit r46 #1 "
            "re-armed on production local-broadcast path).",
        )
        self.assertNotIn(
            "sum(self.blockchain.supply.staked.values())", src,
            "Server._maybe_attest_accepted_block must NOT read the "
            "live ``sum(supply.staked.values())`` for total_stake — "
            "see Node._attest_block_if_allowed for the correct shape.",
        )
        self.assertIn(
            "resolve_pinned_attestation_stake", src,
            "Server._maybe_attest_accepted_block must route the local "
            "finality update through "
            "Blockchain.resolve_pinned_attestation_stake — same "
            "chokepoint Node._attest_block_if_allowed uses.",
        )


if __name__ == "__main__":
    unittest.main()
