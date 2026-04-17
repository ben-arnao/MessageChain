"""Test package — patches config for fast test execution."""
import hashlib
import messagechain.config
from messagechain.config import HASH_ALGO

messagechain.config.MERKLE_TREE_HEIGHT = 4  # 16 leaves instead of 1M (production=20)
# Tests historically use 1-validator chains. The production threshold would
# force every test to register N validators before finalization works;
# override here so existing tests that stake a single validator continue
# to work. Production keeps the safer threshold defined in config.py.
# Despite the name, this is the finality floor (see config comment) —
# the canonical bootstrap signal is Blockchain.bootstrap_progress.
messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1
# Tests produce many blocks rapidly with real wall-clock timestamps, so the
# slot-timing lower bound (block.timestamp >= parent + BLOCK_TIME_TARGET)
# must be disabled. The proposer-match check stays on — tests that stake
# validators must use the deterministically-selected proposer.
messagechain.config.ENFORCE_SLOT_TIMING = False
# Tests run in devnet mode — allow genesis creation without PINNED_GENESIS_HASH.
messagechain.config.DEVNET = True


def register_entity_for_test(chain, entity):
    """Register an entity with a valid registration proof (test helper)."""
    msg = hashlib.new(HASH_ALGO, b"register" + entity.entity_id).digest()
    proof = entity.keypair.sign(msg)
    return chain.register_entity(entity.entity_id, entity.public_key, registration_proof=proof)


def pick_selected_proposer(chain, entities):
    """Return the entity that will be selected as proposer for the next slot.

    Tests that stake multiple validators must use the deterministically-
    selected one, otherwise validate_block rejects the block with "Wrong
    proposer for slot". This helper picks the right entity from a list
    of candidates. If none are selected (bootstrap mode or no validator
    matches), falls back to the first entity.
    """
    latest = chain.get_latest_block()
    if latest is None:
        return entities[0]
    selected_id = chain._selected_proposer_for_slot(latest, round_number=0)
    if selected_id is None:
        return entities[0]
    for e in entities:
        if e.entity_id == selected_id:
            return e
    # Selected validator not in candidate list — fall back (test setup issue)
    return entities[0]