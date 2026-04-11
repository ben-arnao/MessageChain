"""Test package — patches config for fast test execution."""
import hashlib
import messagechain.config
from messagechain.config import HASH_ALGO

messagechain.config.MERKLE_TREE_HEIGHT = 4  # 16 leaves instead of 1M (production=20)
# Tests historically use 1-validator chains. The production threshold of 4
# would force every test to register 4 validators before exiting bootstrap;
# override here so existing tests that stake a single validator continue to
# work. Production keeps the safer threshold defined in config.py.
messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1


def register_entity_for_test(chain, entity):
    """Register an entity with a valid registration proof (test helper)."""
    msg = hashlib.new(HASH_ALGO, b"register" + entity.entity_id).digest()
    proof = entity.keypair.sign(msg)
    return chain.register_entity(entity.entity_id, entity.public_key, registration_proof=proof)