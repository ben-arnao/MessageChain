"""Test package — patches config for fast test execution."""
import hashlib
import messagechain.config
from messagechain.config import HASH_ALGO

messagechain.config.MERKLE_TREE_HEIGHT = 4  # 16 leaves instead of 1M (production=20)


def register_entity_for_test(chain, entity):
    """Register an entity with a valid registration proof (test helper)."""
    msg = hashlib.new(HASH_ALGO, b"register" + entity.entity_id).digest()
    proof = entity.keypair.sign(msg)
    return chain.register_entity(entity.entity_id, entity.public_key, registration_proof=proof)