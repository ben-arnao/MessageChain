# Governance: expensive proposals, permanent record

> **The shape:** opening a proposal is deliberately expensive. Voters
> are paid out of the proposal fee, not out of broader supply. Most
> proposals are *advisory* — the chain records the tally forever, but
> doesn't auto-execute anything.

Governance on a permanent ledger is unusual. Whatever gets debated
stays on chain for as long as the chain runs. A vote that passed
99-to-1 in 2027 is still readable in 2127. A proposal someone tried
to slip past a sleepy validator set is still readable, with the
exact tally, forever. The cost of having an opinion on chain is the
same as the cost of having a message on chain: permanent and paid
for once.

## Why proposals are expensive

If proposals were cheap, you'd get spam — the same dynamic that
makes message fees non-zero applies here, but with even higher
stakes, because every operator in the network is implicitly being
asked to read and consider the proposal.

The fee is not a tax. Most of it flows directly to the voters who
do the work of evaluating the proposal. The proposer is paying the
people they're asking to consider their idea — that's the spam
gate.

## The numbers

- **Proposal fee:** 100,000 tokens flat + 50 tokens per byte of
  payload (title + description). A serious, well-described
  proposal costs more to file than a one-liner; a one-liner that's
  too thin to evaluate is rare for that reason.
- **Vote fee:** 100 tokens per vote tx.
- **Voting window:** 1,008 blocks ≈ **7 days** at 600 s/block.
- **Approval threshold:** strict supermajority — `yes_weight × 3 > total_eligible_weight × 2`,
  i.e. **more than 2/3 of total eligible stake** must vote YES.
  Stakers who don't vote count as "no" by silence.
- **Vote weight:** stake-based. Each voter's weight is their own
  staked balance at the proposal's snapshot block. Non-stakers
  have no voice (their tx is silently rejected). No delegation,
  no quadratic, no aging — just stake at snapshot.
- **Voter reward pool:** 50,000 tokens escrowed on top of the
  proposal fee (the proposer pays this).

## Who actually gets paid for voting

This is the part most people get wrong on first read. The protocol
**does not** pay every voter who shows up. It pays:

- **Only YES voters,** and only when the proposal **passes** the
  2/3 threshold.
- Pro-rata by their voting weight (stake at snapshot), with each
  voter's share **capped at 25%** of the pool.
- If the proposal **fails**, the entire 50,000-token pool **burns**.
  Nobody gets anything — neither YES voters nor NO voters. The fee
  is gone.
- If the cap or integer-division dust leaves a remainder, that
  remainder also burns rather than being refunded to the proposer.

This is stronger than a "majority bonus." It's a clean asymmetry:
backing a winner pays; backing a loser pays nothing; declining to
take a side pays nothing. The economic incentive points squarely
toward "show up and form an honest opinion when you think the
proposal is good." It's deliberately *not* a participation award.

If you're a NO voter who turns out to be on the winning side
(majority NO), you still receive nothing. The 50,000 tokens burn.
The protocol treats the absence of a passed proposal as the default
state of the world — no reward is owed for confirming the default.

## How operators find out about open proposals

Validators don't have to poll the chain. When you start your node
or run a CLI command, the runtime prints a banner if there are
**open proposals you haven't voted on yet** — something like:

```
[!] Governance: 2 open proposal(s) — your vote is needed
    Run `messagechain proposals` to review.
```

This is in-CLI / in-process only. There's no email, no push, no
external alerting. The chain doesn't know your contact details and
doesn't want to. If you want a louder notification surface (Slack,
PagerDuty, whatever), it's app-layer — wrap the `proposals` CLI in
your own monitoring.

## Binding vs. advisory

This is the most distinctive part of MessageChain governance.

- **General proposals** (`ProposalTransaction`) are **purely
  advisory**. The tally is computed and recorded permanently
  on-chain, but the protocol enforces nothing. If a proposal says
  "validators should adopt new behavior X," the chain doesn't
  reach out and reconfigure validators. Operators see the tally and
  decide.
- **Treasury spends** (`TreasurySpendTransaction`) are **binding**.
  If a 2/3 supermajority votes YES, the treasury transfer
  auto-executes at proposal close. No manual step.

Why have advisory proposals at all? Because the chain is the public
record of what was asked and how the network answered. If a design
choice was put to a vote, passed clearly, and then someone failed
to honor it — the evidence is on chain forever. You can point to
it. You can build social pressure on it. You can fork on it. The
chain doesn't need to enforce the outcome to make the outcome
matter.

That same property cuts the other way: if a proposal *fails*, the
tally is permanent too. A bad idea that got voted down stays voted
down on the public record, even decades later.

## What stays on chain forever

Both proposal txs and vote txs are stored in the permanent ledger
exactly like message txs. The in-memory tracker prunes closed
proposals from RAM after the voting window expires (so a node
running for 50 years isn't carrying 50,000 expired-proposal
objects in memory), but the underlying transactions and tallies
are recoverable from the chain at any time.

In other words: **the tally is permanent; the *index* is
ephemeral**. Nothing is lost; the chain just doesn't waste RAM
keeping closed proposals hot.

## Filing a proposal — the quick path

```bash
messagechain propose --title "Raise per-block byte budget to 60kB" \
    --description "Detailed rationale here..."
messagechain proposals       # list open proposals + tallies
messagechain vote --proposal <id> --yes
```

The CLI auto-prices the fee like any other tx — `--urgency high`
gets you in the next block, default targets ~3 blocks. You can
preview cost without sending using `messagechain estimate-fee
--tx-type proposal`.

## Design rationale, in short

Governance protocols generally fail at one of two extremes:
**plutocracy** (whales rubber-stamp anything) or **apathy** (nobody
votes, anything passes by default). MessageChain leans on three
levers to dodge both:

1. **High proposer cost** filters out spam and signals seriousness.
2. **Voter reward funded by the proposer**, not minted from broader
   supply, means proposers literally pay for the attention they ask
   for.
3. **Strict 2/3 threshold against total eligible weight** (not just
   against votes cast) means absentees count as "no" — apathy is
   a *defensive* default, not a vulnerability.

Combined: changing the chain is hard, but when it changes, the
record is unambiguous and forever.
