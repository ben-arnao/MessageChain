"""Audit r54 finding 3 -- ``send-multi`` strips reply/community/poll/vote.

Pre-fix the censorship-resistant fan-out path called
``create_transaction(entity, args.message, fee=int(fee), nonce=nonce,
include_pubkey=include_pubkey)`` with no ``prev`` / ``community_id``
/ ``poll_options`` / ``vote_target`` plumbed through, AND the
``send-multi`` subparser never registered those flags.  Every social-
primitive shipped on ``cmd_send`` since Tier 5 was invisible on
``send-multi``.

CLAUDE.md anchor at risk: collective censorship-resistance via fan-
out.  The dissident reaching for ``send-multi`` under pressure --
exactly the use case the escape hatch exists for -- could not reply
to a deleted-from-mainstream thread, post into a community, vote on
a politically-charged poll, or create a poll.  The most-likely-to-be-
suppressed message shapes were the only ones the suppression-
resistance path could not transmit.

Abstraction-over-symptom fix.  Two new helpers consumed by both
``cmd_send`` and ``cmd_send_multi_submit``:

  * ``_add_message_tx_flags(parser)`` -- registers --prev,
    --community-id, --poll-option, --vote-target on a subparser.
    Used by both ``send`` and ``send-multi`` so the flag surface is
    DRY -- adding a future social primitive flag adds it on both
    transports by construction.

  * ``_parse_message_tx_fields(args)`` -- returns the parsed
    ``(prev_bytes, community_id, poll_options, vote_target)`` tuple
    with the same validation cmd_send already did inline.  Mutually-
    exclusive checks and pre-flight diagnostics survive the move.
"""

from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch, MagicMock

import messagechain.cli as _cli


class SendMultiParserRegistersSocialFlags(unittest.TestCase):
    """Pin that the send-multi subparser accepts every social-primitive
    flag cmd_send already supports.  Without this, the dissident
    reaching for the censorship-escape hatch cannot reply / tag /
    poll / vote -- exactly the message shapes most likely to need
    fan-out delivery."""

    def setUp(self):
        # Build the real top-level parser; argparse-namespace is the
        # canonical source of args.
        self.parser = _cli.build_parser()

    def _parse_send_multi(self, extra_args):
        return self.parser.parse_args(
            ["send-multi", "hello"] + extra_args
            + ["--endpoint", "a:1", "--endpoint", "b:2", "--endpoint", "c:3"]
        )

    def test_send_multi_accepts_prev(self):
        ns = self._parse_send_multi([
            "--prev", "a" * 64,
        ])
        self.assertEqual(ns.prev, "a" * 64)

    def test_send_multi_accepts_community_id(self):
        ns = self._parse_send_multi([
            "--community-id", "mc-dev",
        ])
        self.assertEqual(ns.community_id, "mc-dev")

    def test_send_multi_accepts_poll_options(self):
        ns = self._parse_send_multi([
            "--poll-option", "Yes",
            "--poll-option", "No",
        ])
        self.assertEqual(ns.poll_options, ["Yes", "No"])

    def test_send_multi_accepts_vote_target(self):
        ns = self._parse_send_multi([
            "--vote-target", ("a" * 64) + ":1",
        ])
        self.assertEqual(ns.vote_target, ("a" * 64) + ":1")


class SharedFieldParserHelperExists(unittest.TestCase):
    """Pin the existence + shape of ``_parse_message_tx_fields``.
    Adding a new social primitive in the future MUST happen here, not
    duplicated in cmd_send and cmd_send_multi_submit."""

    def test_helper_is_defined(self):
        self.assertTrue(
            hasattr(_cli, "_parse_message_tx_fields"),
            "cli._parse_message_tx_fields must exist -- shared parser "
            "for prev / community_id / poll_options / vote_target",
        )

    def test_parser_helper_returns_four_tuple_when_empty(self):
        # No flags set: helper returns (None, None, None, None) -- the
        # legacy "bare message" shape.  Both cmd_send and
        # cmd_send_multi_submit consume this directly.
        ns = argparse.Namespace(
            prev=None, community_id=None,
            poll_options=[], vote_target=None,
        )
        result = _cli._parse_message_tx_fields(ns)
        self.assertEqual(result, (None, None, None, None))

    def test_parser_helper_parses_prev(self):
        ns = argparse.Namespace(
            prev="ab" * 32, community_id=None,
            poll_options=[], vote_target=None,
        )
        prev, cid, polls, vote = _cli._parse_message_tx_fields(ns)
        self.assertEqual(prev, bytes.fromhex("ab" * 32))
        self.assertEqual(cid, None)

    def test_parser_helper_normalizes_community_id(self):
        ns = argparse.Namespace(
            prev=None, community_id="MyCommunity",
            poll_options=[], vote_target=None,
        )
        prev, cid, polls, vote = _cli._parse_message_tx_fields(ns)
        # NFC + lowercased
        self.assertEqual(cid, "mycommunity")

    def test_parser_helper_parses_poll_options(self):
        ns = argparse.Namespace(
            prev=None, community_id=None,
            poll_options=["Yes", "No"], vote_target=None,
        )
        prev, cid, polls, vote = _cli._parse_message_tx_fields(ns)
        self.assertEqual(polls, ("Yes", "No"))

    def test_parser_helper_parses_vote_target(self):
        ns = argparse.Namespace(
            prev=None, community_id=None, poll_options=[],
            vote_target=("ab" * 32) + ":2",
        )
        prev, cid, polls, vote = _cli._parse_message_tx_fields(ns)
        self.assertEqual(vote, (bytes.fromhex("ab" * 32), 2))


class SendMultiThreadsFieldsToCreateTransaction(unittest.TestCase):
    """End-to-end pin: when `send-multi` is invoked with social-
    primitive flags, the resulting `create_transaction` call MUST
    receive them.  Pre-fix the kwargs dropped silently on the floor."""

    def test_create_transaction_receives_prev_community_poll_vote(self):
        # Patch the chain of RPC calls and signing operations so the
        # test exercises the field-threading without needing a live
        # server.
        captured_kwargs = {}

        def _fake_create_transaction(entity, message, **kwargs):
            captured_kwargs.update(kwargs)
            captured_kwargs["__message__"] = message
            return MagicMock(
                tx_hash=b"\x00" * 32, serialize=MagicMock(return_value=b""),
            )

        fake_resolve_private_key = MagicMock(return_value=b"\x01" * 32)
        fake_resolve_signing_entity = MagicMock(return_value=MagicMock(
            entity_id_hex="ab" * 32,
            entity_id=b"\xab" * 32,
            keypair=MagicMock(leaf_index_path=None),
        ))
        fake_resolve_signing_leaf = MagicMock(return_value=7)
        fake_resolve_fee_with_server_floor = MagicMock(
            return_value=(100, 1),
        )
        fake_should_include_pubkey = MagicMock(return_value=False)
        fake_rpc = MagicMock(return_value={
            "ok": True,
            "result": {
                "nonce": 0, "leaf_watermark": 0, "height": 100,
            },
        })

        # SubmitClient is the fan-out client.  Mock its constructor
        # and instance so we don't actually try to POST to anywhere.
        # ``min_successes`` is an int (used in a ``<`` compare at the
        # tail of cmd_send_multi_submit); set it explicitly so the
        # mock doesn't auto-attribute a MagicMock that breaks the
        # comparison.
        fake_client_instance = MagicMock()
        fake_client_instance.min_successes = 1
        fake_client_instance.submit.return_value = MagicMock(
            tx_hash=b"\x00" * 32, successes=3, receipts=[],
            elapsed_ms=10, rejections=[],
        )

        with patch.object(_cli, "_resolve_private_key", fake_resolve_private_key), \
             patch.object(_cli, "_resolve_signing_entity", fake_resolve_signing_entity), \
             patch.object(_cli, "_resolve_signing_leaf", fake_resolve_signing_leaf), \
             patch.object(_cli, "_resolve_fee_with_server_floor", fake_resolve_fee_with_server_floor), \
             patch.object(_cli, "_should_include_pubkey", fake_should_include_pubkey), \
             patch("client.rpc_call", fake_rpc), \
             patch(
                 "messagechain.core.transaction.create_transaction",
                 _fake_create_transaction,
             ), \
             patch(
                 "messagechain.network.submit_client.SubmitClient",
                 return_value=fake_client_instance,
             ), \
             patch(
                 "messagechain.network.submit_client.ValidatorEndpoint.parse",
                 side_effect=lambda s: MagicMock(host=s, port=1, insecure=False),
             ):
            args = argparse.Namespace(
                message="hello",
                endpoints=["a:1", "b:2", "c:3"],
                insecure=False, server=None, urgency="normal",
                nonce=None, leaf_index=None,
                min_successes=1, per_endpoint_timeout_s=10.0,
                receipts_dir=None, no_receipts=True,
                fee=100,
                keyfile=None, data_dir=None,
                # the social-primitive flags being threaded:
                prev="ab" * 32,
                community_id="mycommunity",
                poll_options=[],
                vote_target=None,
            )
            _cli.cmd_send_multi_submit(args)

        # The whole point of the fix: create_transaction MUST see the
        # threaded fields.
        self.assertEqual(
            captured_kwargs.get("prev"), bytes.fromhex("ab" * 32),
            "send-multi must thread --prev through to create_transaction "
            "(pre-fix it dropped the kwarg silently)",
        )
        self.assertEqual(
            captured_kwargs.get("community_id"), "mycommunity",
            "send-multi must thread --community-id through to "
            "create_transaction (pre-fix it dropped the kwarg silently)",
        )
        # poll_options + vote_target are None in this test scenario,
        # but the helper still routes them as kwargs (and the chain's
        # admission gate enforces mutual exclusion).  Confirm the keys
        # are present so a future call shape change doesn't silently
        # break either primitive.
        self.assertIn(
            "poll_options", captured_kwargs,
            "send-multi must pass poll_options kwarg (even when None)",
        )
        self.assertIn(
            "vote_target", captured_kwargs,
            "send-multi must pass vote_target kwarg (even when None)",
        )


if __name__ == "__main__":
    unittest.main()
