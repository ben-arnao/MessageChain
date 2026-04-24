"""Shared runtime primitives for the MessageChain validator.

Houses logic that is identical across the two validator runtimes
(`server.Server` and `messagechain.network.node.Node`) so that a
hardening fix applied to the shared method only has to be edited
once.  See `messagechain/runtime/shared.py` for the mixin itself;
the drift analysis that motivated the split lived in a private
hardening-findings runbook and is now baked into the mixin's
per-method docstrings.
"""
