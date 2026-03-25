# CLAUDE.md

## Principles (in order of priority)

1. **Security** — The most important principle of this project. Never compromise on it.
2. **Simplicity** — Keep things simple and straightforward.
3. **Long-term thinking** — Design for durability on the scale of 100 to 1000+ years into the future.

## Workflow

- **Test-driven development** — This is a TDD environment. Write tests first, then implement the code to make them pass.
- Always commit changes and push to remote when done with a task.
- All tests must pass at all times. Run `python -m unittest discover tests/` to verify.
