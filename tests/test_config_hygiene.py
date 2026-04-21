"""Config hygiene tests.

Catch dead or drift-prone config constants before they confuse
auditors.  Keep narrow: only assert the *absence* of constants that
have been intentionally retired so a future copy-paste doesn't silently
resurrect them.
"""
import unittest

import messagechain.config as cfg


class DeadConstantRemovalTest(unittest.TestCase):
    """Constants that were audited dead and removed stay removed."""

    def test_receipt_merkle_tree_height_is_not_defined(self):
        # RECEIPT_MERKLE_TREE_HEIGHT was a dead 24-height receipt tree
        # that the iter-1 hardening audit found was never referenced.
        # The actual receipt subtree is RECEIPT_SUBTREE_HEIGHT (16).
        # If a future edit reintroduces it, auditors will again ask
        # "why does the chain define two receipt-tree heights?" — so
        # the name must stay gone, not silently come back.
        self.assertFalse(
            hasattr(cfg, "RECEIPT_MERKLE_TREE_HEIGHT"),
            "RECEIPT_MERKLE_TREE_HEIGHT was removed as dead code; "
            "use RECEIPT_SUBTREE_HEIGHT for receipt-signing tree sizing.",
        )

    def test_receipt_subtree_height_is_defined(self):
        # Sanity: the surviving constant is still present.  If someone
        # removes it by accident while cleaning up the dead twin, this
        # test catches it.
        self.assertTrue(hasattr(cfg, "RECEIPT_SUBTREE_HEIGHT"))
        self.assertIsInstance(cfg.RECEIPT_SUBTREE_HEIGHT, int)
        self.assertGreater(cfg.RECEIPT_SUBTREE_HEIGHT, 0)


if __name__ == "__main__":
    unittest.main()
