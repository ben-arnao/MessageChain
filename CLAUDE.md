# CLAUDE.md

## Principles (in order of priority)

1. **Security** — The most important principle of this project. Never compromise on it.
2. **Simplicity** — Keep things simple and straightforward.
3. **Long-term thinking** — Design for durability on the scale of 100 to 1000+ years into the future.

## Design Trade-offs

- **Slow transactions and expensive fees are acceptable** if they combat ledger bloat, strengthen security, or preserve long-term node/validator incentives. Never optimize for speed or cheapness at the expense of these goals.

## Workflow

- **Test-driven development** — This is a TDD environment. Write tests first, then implement the code to make them pass.
- **Always commit and push when done with a task. Do not ask — just do it.** This is standing authorization.
- All tests must pass at all times. Run `python -m unittest discover tests/` to verify.
- **Parallel-friendly worktrees** — For any code changes, start a new branch off the current branch and run in an isolated git worktree (use the Agent tool's `isolation: "worktree"` option, or `git worktree add` manually). This lets multiple agents work in parallel without stepping on each other. Do the work on the branch, commit there, push the branch, then merge back into the parent branch and push — same end result as working directly, just parallel-safe.
