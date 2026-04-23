# Security Policy

MessageChain is a live blockchain. Consensus, signature, and staking bugs
can cause real loss. Please report them privately.

## Reporting a vulnerability

**Email:** arnaoben@gmail.com

**Do not open a public GitHub issue** for anything that could be exploited
against the live chain. That includes (non-exhaustive):

- Consensus bugs — anything that lets a single node fork, halt, or
  re-order the canonical chain.
- Signature or key-management flaws — WOTS+ leaf reuse, signature
  forgery, authority-key bypass, first-spend hijack.
- Staking / slashing exploits — ways to stake without locking, avoid
  slashing after provable misbehavior, or unbond faster than the
  protocol allows.
- Fee-market bypass — ways to include transactions below the
  protocol-required fee floor.
- State-root or receipt fraud — ways to produce a valid-looking block
  with an incorrect state root or fabricated receipts.
- RPC / node-local bugs that let a remote attacker crash or take
  control of a validator process.

What to include: a clear description, a reproduction (testnet or local
script preferred), and the commit hash / version affected.

## What happens next

- Acknowledgement within **72 hours**.
- Triage and a target fix timeline within **7 days**.
- Coordinated disclosure: we agree on a public-disclosure date after
  the fix ships and validators have had time to upgrade.

There is no paid bug bounty program yet. Credit in the release notes
and changelog is available on request.

## Out of scope

- Front-end / third-party apps built on top of MessageChain (report
  those to the app author).
- Social-engineering attacks against operators.
- Physical or infrastructure attacks against a specific validator
  host (that is the operator's responsibility, not the protocol's).

## Supported versions

Only the latest tagged release on `main` is supported. There are no
backports; security fixes ship as new releases and, when consensus
is affected, as coordinated hard forks.
