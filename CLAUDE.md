# CLAUDE.md

## Principles (in order of priority)

1. **Security** — The most important principle of this project. Never compromise on it.
2. **Message permanence & censorship resistance** — Every message included on-chain lasts forever. No pruning, no deletion, no expiration, no TTL on message content. No blocklists, no content-based admission rules, no discretionary suppression. If it's on-chain, it's there forever and no one can take it down.
3. **Simplicity** — Keep things simple and straightforward.
4. **Long-term thinking** — Design for durability on the scale of 100 to 1000+ years into the future.

## High-Priority Concerns

- **Minimize chain bloat & maximize storage efficiency.** Because every message is permanent, bloat is fought only through protocol-level levers: fees (ideally superlinear in size), strict size caps, canonical compression, witness/signature separation, and similar storage optimizations. Never fight bloat via pruning, TTLs, or deletion of ledger content.

## Design Trade-offs

- **Slow transactions and expensive fees are acceptable** if they combat ledger bloat, strengthen security, or preserve long-term node/validator incentives. Never optimize for speed or cheapness at the expense of these goals.

## Repo Hygiene

- **`docs/` and `deploy/` are git-ignored and local-only.** They hold operator/founder-facing content — launch checklists, runbooks referencing real infra, systemd units, launch scripts — that shouldn't be in the public repo. Public-facing documentation lives in `README.md`. Don't reintroduce either directory under a tracked path.

## Workflow

- **Test-driven development** — This is a TDD environment. Write tests first, then implement the code to make them pass.
- **Always commit and push when done with a task. Do not ask — just do it.** This is standing authorization.
- All tests must pass at all times. Run `python -m unittest discover tests/` to verify.
- **Parallel-friendly worktrees** — For any code changes, start a new *local* branch off the current branch and run in an isolated git worktree (use the Agent tool's `isolation: "worktree"` option, or `git worktree add` manually). This lets multiple agents work in parallel without stepping on each other. The branch and worktree stay local — do the work there, commit, then merge back into the parent branch and push *only the parent branch* to remote. Remote sees the same single-branch history it would have seen without worktrees; parallelism is purely a local concern.
- **Re-run tests after every merge.** Passing on the feature branch isn't enough — parallel branches can conflict semantically even when they merge cleanly. After merging back into the parent branch, run the full test suite again and only push if it passes.
