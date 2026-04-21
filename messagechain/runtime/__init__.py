"""Shared runtime primitives for the MessageChain validator.

Houses logic that is identical across the two validator runtimes
(`server.Server` and `messagechain.network.node.Node`) so that a
hardening fix applied to the shared method only has to be edited
once.  See `messagechain/runtime/shared.py` for the mixin itself
and `docs/hardening-findings-47-56.md` "B-small" section for the
drift analysis that motivated the split.
"""
