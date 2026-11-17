# Standard History Derivation v0: conformance vectors

These vectors exercise `spec/standard-history-v0.md` (`standard_history/1`,
`standard_history/2` and `standard_history/3`, cited as SH): the card (SH §4), the counting rules (SH §5) and the six card
properties (SH §6), including `counterparty_class` (SH §7) as the input that decides whether a
deal is counted. `vectors.json` holds the `/1` cases. `vectors-2.json` holds the `/2` cases: a
deal whose agreed amount the records do not give, counted in every total and in no band.
`vectors-3.json` holds the `/3` cases (SH §11): deals counted from their term rows in five lines,
`did_not_hold` split four ways, and the shelf log's coverage start.

## Derivation

`python/scripts/generate_standard_history_v0_vectors.py` writes every card and every expected
property by hand from SH §4 to §6. It imports no implementation. Each case gives the card and what
a verifier may hold beside it:

| Input | What it is | Needed by |
|---|---|---|
| `card` | the card, as a JSON value | every property |
| `policy` | the policy's two members (SH §5.1): `digest` and `window` | `window_from_policy` |
| `as_of` | the anchor's digest and time, and the stream's first checkpoint time; in `vectors-3.json` also `coverage_start_time`, the time of the shelf log's coverage start (SH §11.5) | `as_of`, `counts_recompute` |
| `deals` | every deal entry (SH §5.2; under `/3`, §11.2, with each row's result as of the anchor's time) the stream holds at the anchor, given only when coverage is shown and no payload member the mapping reads is withheld (SH §6 "Handing the material"; a vector cannot carry the proof, so `deals` stands for a complete handover) | `counts_recompute` |
| `derivation` | in `vectors-2.json` and `vectors-3.json` only: the token the request named, which the card is checked under (SH §6) | every property |

`counts_recompute` recomputes over the card's own `window`, so it needs the anchor and the deal entries but not the policy. A case without an input expects `NOT_CHECKED` for each property that needs it. `expected` gives
all six properties, whether the card is a standard card (SH §6), and the properties that `FAIL`.

The deal entries are abstract (SH §5.2): no record format is fixed here. Every digest is a label
digest, SHA-256 of a text string, for these vectors only.

## The cases

Positive: a person's card with a 3-month window, checked with every input, with the deal entries
left out, without the policy (the counts still recompute), and with nothing beside it; a node's card with window everything over the same deals;
the month-end clamp of SH §5.1; a window with no deal in it (`of` 0 recomputes `PASS` over complete coverage); and a window across a year end with
a sub-unit deal (a negative decade) and a zero amount (the band whose decade is null); and the decade of 1 msat, 1 sat, 250 sat and 1 BTC over Lightning and of
1 cent of USDC; and a window that starts before year 1.

Negative, each failing the properties its `expected.fails` lists: `percentage-fraction`,
`percentage-member`, `count-without-denominator`, `tallies-disagree`, `counted-shop-purchase`,
`window-not-in-policy` (the counts differ over the card's own window too), `window-not-in-policy-counts-match` (only `window_from_policy` fails), `counterparty-member`, `since-day`, `since-non-ascii-digits`,
`bands-unsorted`, `band-duplicate`, `band-empty`, `currency-free-text`, `node-person-class`,
`node-class-free-text`, `window-all-false`,
`class-missing-over`, `dispute-forum-total` and `other-anchor`.

In `vectors-2.json`, positive: `unpriced-counted` (two counted deals without an amount, one held
and one undecided: every total counts them, `unpriced` is 2 of 2, no band counts them, an unpriced
shop purchase is only `not_counted`, and an unpriced deal before the window counts nowhere), the same card without the deal entries (`unpriced-without-deals`) and with nothing
beside it (`unpriced-card-only`), and a `/2` card whose every deal has an amount
(`unpriced-none`). Negative: `unpriced-left-out`, `unpriced-in-band`, `unpriced-outside-outcomes`,
`v2-without-unpriced`, `unpriced-with-currency`, `v1-card-for-v2-request`,
`v2-card-for-v1-request` and `v1-card-with-unpriced`.

In `vectors-3.json`, positive: `lines-and-split` (every line and every part of the split; a deal
where `undecided` and `did_not_hold` both apply, counted `undecided`; a ruling not honoured that
wins over `undecided`; a deal left out for want of a witness time and a shop purchase, both
`not_counted`; two unpriced deals and a zero amount), `quiet-deals-later-anchor` (the same deals at
a later anchor with no new fact: one moves from `held_so_far` to `undecided`, another to `held`),
and the first card without the deal entries (`lines-without-shelf`) and with nothing beside it
(`lines-card-only`). Negative: `line-not-first`, `left-out-counted`, `split-not-the-line`,
`band-three-outcomes`, `no-coverage-start`, `coverage-start-before-since`,
`coverage-start-other-month`, `v2-card-for-v3-request` and `v3-card-for-v2-request`. A `/3` deal
entry carries row results, not the row statements and dates they are computed from: the rule that
computes them is EBL's (SH-11), whose own vectors test it.

## Gates

- `python/tests/test_standard_history_v0_vectors.py` runs every case through the Python
  reference, `agent_action_capsule.standard_history`, rebuilds each fully checked standard card
  from its inputs with `derive_card`, runs defective evaluators that must each disagree with a
  case, checks that a `/1` card cannot be built over an unpriced deal, that every pair of row
  results falls in exactly one `/3` line, and regenerates the directory twice, byte-identical.
- `go/standardhistory` runs every case through the Go package and rebuilds the same cards with
  `Derive`.

This README is the only hand-written file in the directory.
