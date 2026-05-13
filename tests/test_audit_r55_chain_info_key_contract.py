"""Audit r55 #3 -- ``Blockchain.get_chain_info()`` key-contract drift.

Two consumers (``cli.cmd_ping`` and
``LocalWalletServer._serve_v1_info``) hard-coded a key list that the
actual return shape does NOT match:

  * ``cmd_ping``'s ``interesting_keys`` filter requests ``best_hash``,
    ``validator_count``, ``block_number``, ``supply`` -- none of these
    are returned by ``get_chain_info``.  The README-promoted first-run
    sanity check (``messagechain ping``) therefore prints 3 fields
    where the documentation implies ~8.

  * ``LocalWalletServer._serve_v1_info`` proxies through the
    ``get_chain_info`` RPC and reads ``info.get("tip_hash")`` /
    ``info.get("last_block_timestamp")`` -- both keys are silently
    ``None``.  The wallet UI's Node tab renders ``Tip-hash`` /
    ``Last-block-ts`` as ``?`` on every session.

Both sites are parallel-shape: an assumed-key-set drifted from the
actual return shape of the producer.  The abstraction-over-symptom
fix has two halves:

  1. Producer-side: ``get_chain_info`` returns BOTH the legacy keys
     (``latest_block_hash`` / ``latest_block_timestamp`` -- preserved
     for any external API consumer that may have grown around them)
     AND the canonical /v1/info-contract keys (``tip_hash`` /
     ``last_block_timestamp`` -- what ``LocalWalletServer`` and
     ``PublicFeedServer`` both already emit).

  2. Consumer-side: ``cmd_ping``'s allowlist must be a subset of the
     producer's actual returned keys.  This test module is the
     constraint pin that ensures a future rename of a return key
     surfaces as an explicit broken test, not a silent partial
     output.
"""

from __future__ import annotations

import unittest


class TestGetChainInfoReturnShape(unittest.TestCase):
    """Producer-side contract: every key any documented consumer
    expects MUST be present in the return."""

    def _make_chain(self):
        from messagechain.core.blockchain import Blockchain
        # Default Blockchain with no in-memory chain -- get_chain_info
        # is safe at empty chain (latest fields default to None).
        return Blockchain()

    def test_returns_tip_hash_alias(self):
        """``tip_hash`` is the canonical /v1/info contract key.  The
        LocalWalletServer's /v1/info proxy reads it; the producer must
        emit it."""
        chain = self._make_chain()
        info = chain.get_chain_info()
        self.assertIn(
            "tip_hash", info,
            "get_chain_info() must emit ``tip_hash`` -- the canonical "
            "/v1/info contract key that LocalWalletServer's proxy "
            "reads.",
        )

    def test_returns_last_block_timestamp_alias(self):
        """``last_block_timestamp`` is the canonical /v1/info contract
        key (matches PublicFeedServer's emit name)."""
        chain = self._make_chain()
        info = chain.get_chain_info()
        self.assertIn(
            "last_block_timestamp", info,
            "get_chain_info() must emit ``last_block_timestamp`` -- "
            "the canonical /v1/info contract key that "
            "LocalWalletServer's proxy reads.",
        )

    def test_aliases_match_legacy_values_at_empty_chain(self):
        """At empty chain both aliased pairs are None.  At non-empty
        chain they MUST equal the legacy keys (no semantic divergence
        between alias and the canonical value)."""
        chain = self._make_chain()
        info = chain.get_chain_info()
        self.assertEqual(info.get("tip_hash"), info.get("latest_block_hash"))
        self.assertEqual(
            info.get("last_block_timestamp"),
            info.get("latest_block_timestamp"),
        )

    def test_legacy_keys_still_present(self):
        """Backward-compat: any external API consumer that grew around
        the legacy ``latest_*`` names continues to work.  Aliases are
        additive, never a rename-and-break."""
        chain = self._make_chain()
        info = chain.get_chain_info()
        self.assertIn("latest_block_hash", info)
        self.assertIn("latest_block_timestamp", info)


class TestCmdPingAllowlistMatchesProducer(unittest.TestCase):
    """Consumer-side constraint: ``cmd_ping``'s interesting_keys tuple
    must be a subset of ``Blockchain.get_chain_info()``'s return keys.
    A future rename surfaces as an explicit broken test, not a silent
    partial first-run output.
    """

    def test_cmd_ping_interesting_keys_is_subset_of_get_chain_info(self):
        from messagechain.core.blockchain import Blockchain
        # Read the cmd_ping source to pull out its allowlist.  The
        # function is short and the allowlist is a literal tuple, so
        # a structural source-grep is sufficient (and avoids invoking
        # the CLI plumbing for a pure-property check).
        from pathlib import Path
        import re
        cli_src = (
            Path(__file__).resolve().parent.parent / "messagechain" / "cli.py"
        ).read_text(encoding="utf-8")
        # Find the cmd_ping function body and extract its
        # ``interesting_keys = (...)`` literal.
        m = re.search(
            r"def\s+cmd_ping\s*\([^)]*\):.*?"
            r"interesting_keys\s*=\s*\((?P<keys>.*?)\)",
            cli_src, re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "Could not locate cmd_ping's ``interesting_keys`` tuple -- "
            "if the function was refactored, update this structural "
            "pin to match.",
        )
        # Parse the tuple literal.  Strings only; ignore commas/spaces.
        ping_keys = set(re.findall(r'"([^"]+)"', m.group("keys")))
        self.assertTrue(
            ping_keys,
            "cmd_ping's interesting_keys tuple parsed empty -- check "
            "the regex against the current source shape.",
        )

        # Producer side: pull the actual returned keys (at an empty
        # chain so we don't depend on stake / supply distribution).
        info = Blockchain().get_chain_info()
        producer_keys = set(info.keys())

        missing = ping_keys - producer_keys
        self.assertFalse(
            missing,
            f"cmd_ping's interesting_keys contains keys "
            f"get_chain_info() does NOT return: {sorted(missing)}.  "
            f"Either rename the allowlist entry to a key the producer "
            f"actually emits, or extend the producer.  Silent partial "
            f"output on the README-promoted `messagechain ping` is the "
            f"defect-class this pin is meant to catch.",
        )


class TestWalletV1InfoProxyKeyContract(unittest.TestCase):
    """The LocalWalletServer proxies the ``get_chain_info`` RPC into
    its /v1/info response.  Every key it reads from the proxied
    result MUST be a key the producer actually emits."""

    def test_local_wallet_server_v1_info_keys_subset_of_producer(self):
        from messagechain.core.blockchain import Blockchain
        from pathlib import Path
        import re

        # Grep the wallet server source for the /v1/info reshape's
        # ``info.get("...")`` reads on the proxied get_chain_info
        # result.
        src = (
            Path(__file__).resolve().parent.parent
            / "messagechain" / "network" / "local_wallet_server.py"
        ).read_text(encoding="utf-8")
        # Match the _serve_v1_info function and find every
        # ``info.get("key")`` inside its body.
        m = re.search(
            r"def\s+_serve_v1_info\s*\([^)]*\):.*?(?=\n    def\s+|\nclass\s+)",
            src, re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "Could not locate _serve_v1_info function in "
            "local_wallet_server.py -- update this pin if the function "
            "was renamed / restructured.",
        )
        body = m.group(0)
        proxy_reads = set(re.findall(r'info\.get\(\s*"([^"]+)"', body))
        self.assertTrue(
            proxy_reads,
            "_serve_v1_info parsed zero info.get() reads -- check the "
            "regex against the current source shape.",
        )

        info = Blockchain().get_chain_info()
        producer_keys = set(info.keys())

        missing = proxy_reads - producer_keys
        self.assertFalse(
            missing,
            f"LocalWalletServer._serve_v1_info reads keys "
            f"get_chain_info() does NOT return: {sorted(missing)}.  "
            f"Wallet UI Node tab renders these as ``?``.  Either add "
            f"the alias key to the producer, or fix the proxy to read "
            f"the actual return key.",
        )


class TestCmdPingPrintsSubstantialFirstRunOutput(unittest.TestCase):
    """End-to-end smoke pin: ``messagechain ping`` against a chain
    info dict must yield MORE than zero ``key: value`` lines for the
    fields a first-run user expects.  This catches the regression
    where every key in the allowlist drifts to a name the producer
    doesn't emit (the originating defect was 4 of 7 keys missing)."""

    def test_cmd_ping_emits_minimum_interesting_fields(self):
        from messagechain.core.blockchain import Blockchain
        # Compute the actual overlap; assert it's at least 4 fields.
        # The producer side returns ~12 keys, so an allowlist that
        # overlaps with fewer than 4 is almost certainly the silent-
        # rename defect.
        from pathlib import Path
        import re
        cli_src = (
            Path(__file__).resolve().parent.parent / "messagechain" / "cli.py"
        ).read_text(encoding="utf-8")
        m = re.search(
            r"def\s+cmd_ping\s*\([^)]*\):.*?"
            r"interesting_keys\s*=\s*\((?P<keys>.*?)\)",
            cli_src, re.DOTALL,
        )
        ping_keys = set(re.findall(r'"([^"]+)"', m.group("keys")))
        info = Blockchain().get_chain_info()
        overlap = ping_keys & set(info.keys())
        self.assertGreaterEqual(
            len(overlap), 4,
            f"cmd_ping's allowlist overlap with get_chain_info "
            f"return = {len(overlap)} ({sorted(overlap)}).  Below 4 "
            f"likely indicates the silent-rename defect: the "
            f"README-promoted first-run command lands flat for new "
            f"users.",
        )


if __name__ == "__main__":
    unittest.main()
