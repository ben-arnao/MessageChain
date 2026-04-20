"""Integer-timestamp invariant.

Block headers and every signable transaction type use `int(timestamp)`
inside `signable_data` — so the signature never covers sub-second bits.
The wire/storage format packs the timestamp as an 8-byte float.  If a
creation path stored a fractional timestamp, the signed-vs-wire
representations would carry different information: a peer on the relay
path could mutate the sub-second bits (signature still verifies because
int() truncates them) and produce a "different" block that hashes
identically.

Defense: enforce at CREATION time that every timestamp is an integer.
Existing blocks on chain (made before this enforcement) carry sub-
second bits but were never consensus-consequential because int()
truncation made them information-free.  Going forward, new blocks
carry zero-valued sub-seconds, making the mutation surface vacuous.
"""

from __future__ import annotations

import unittest

from messagechain.identity.identity import Entity
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.core.staking import (
    create_stake_transaction, create_unstake_transaction,
)
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.emergency_revoke import create_revoke_transaction
from messagechain.core.block import create_genesis_block


_KEY_A = b"integer-timestamp-test-entity-k!"
_KEY_B = b"integer-timestamp-other-key-val!"


class TestIntegerTimestamps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entity = Entity.create(_KEY_A, tree_height=4)
        cls.other = Entity.create(_KEY_B, tree_height=4)

    def _assert_integer(self, ts, what: str):
        self.assertEqual(
            ts, int(ts),
            f"{what} timestamp {ts!r} has sub-second bits — "
            f"violates integer-timestamp invariant",
        )

    def test_message_transaction(self):
        tx = create_transaction(self.entity, "hi", fee=1000, nonce=0)
        self._assert_integer(tx.timestamp, "MessageTransaction")

    def test_transfer_transaction(self):
        tx = create_transfer_transaction(
            self.entity, self.other.entity_id, amount=1, fee=100, nonce=0,
        )
        self._assert_integer(tx.timestamp, "TransferTransaction")

    def test_stake_transaction(self):
        tx = create_stake_transaction(self.entity, amount=100, fee=100, nonce=0)
        self._assert_integer(tx.timestamp, "StakeTransaction")

    def test_unstake_transaction(self):
        tx = create_unstake_transaction(self.entity, amount=100, fee=100, nonce=0)
        self._assert_integer(tx.timestamp, "UnstakeTransaction")

    def test_set_authority_key_transaction(self):
        tx = create_set_authority_key_transaction(
            self.entity, self.other.public_key, fee=100, nonce=0,
        )
        self._assert_integer(tx.timestamp, "SetAuthorityKeyTransaction")

    def test_revoke_transaction(self):
        tx = create_revoke_transaction(self.entity, fee=100)
        self._assert_integer(tx.timestamp, "RevokeTransaction")

    def test_block_header(self):
        block = create_genesis_block(self.entity)
        self._assert_integer(block.header.timestamp, "BlockHeader")


if __name__ == "__main__":
    unittest.main()
