"""Bitcoin anchoring — external immutability proof via OP_RETURN.

Periodically commits MessageChain block hashes into Bitcoin, creating an
independent proof that survives even total MessageChain validator collusion.

This is an OPERATIONAL feature, not a consensus rule. MessageChain never
halts if Bitcoin is unavailable. Any validator can submit anchors; the
protocol does not require it.
"""
