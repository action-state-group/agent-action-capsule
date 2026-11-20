# Standard History Derivation v0: conformance vectors

These vectors exercise `spec/standard-history-v0.md` (`standard_history/1`,
`standard_history/2`, `standard_history/3` and `standard_history/4`, cited as SH): the card (SH §4), the counting rules (SH §5) and the six card
properties (SH §6), including `counterparty_class` (SH §7) as the input that decides whether a
deal is counted. `vectors.json` holds the `/1` cases. `vectors-2.json` holds the `/2` cases: a
deal whose agreed amount the records do not give, counted in every total and in no band.
`vectors-3.json` holds the `/3` cases (SH §11): deals counted from their term rows in the three
outcomes, the remedied and not-honoured counts, the deals not counted by reason, and the shelf
log's coverage start. `vectors-4.json` holds the `/4` cases (SH §12): `/3` with no deal left out
for want of a witness time.

## Derivation

`python/scripts/generate_standard_history_v0_vectors.py` writes every card and every expected
property by hand from SH §4 to §6. It imports no implementation. Each case gives the card and what
a verifier may hold beside it:

| Input | What it is | Needed by |
|---|---|---|
| `card` | the card, as a JSON value | every property |
| `policy` | the policy's two members (SH §5.1): `digest` and `window` | `window_from_policy` |
| `as_of` | the anchor's digest and time, and the stream's first checkpoint time; in `vectors-3.json` and `vectors-4.json` also `coverage_start_time`, the time of the shelf log's coverage start (SH §11.5) | `as_of`, `counts_recompute` |
| `deals` | every deal entry (SH §5.2; under `/3` and `/4`, §11.2, with each row's result as of the anchor's time) the stream holds at the anchor, given only when coverage is shown and no payload member the mapping reads is withheld (SH §6 "Handing the material"; a vector cannot carry the proof, so `deals` stands for a complete handover) | `counts_recompute` |
| `derivation` | in `vectors-2.json`, `vectors-3.json` and `vectors-4.json` only: the token the request named, which the card is checked under (SH §6) | every property |

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

In `vectors-3.json`, positive: `outcomes-from-rows` (every outcome; a final unmet row beside a row
in dispute, counted `did_not_hold`; an unmet row still in its contest window beside a row waiting on
a statement of not met, counted `undecided`; a ruling the holder did not honour, counted
`did_not_hold` before `undecided` and counted in `not_honoured`; a row not reached, counted
`undecided`, and one beside an unmet row, which stays `did_not_hold`; a deal where only the
counterparty failed, counted `held`; a remedy made without a ruling, counted remedied; a deal left
out for want of a witness time and a shop purchase that also carries `left_out`, `not_counted` under
one reason each; two unpriced deals and a zero amount), `quiet-deals-later-anchor` (the same deals
at a later anchor with no new fact: one moves from `undecided` to `held`), and the first card
without the deal entries (`outcomes-without-shelf`) and with nothing beside it
(`outcomes-card-only`). Negative: `outcome-not-first`, `dispute-hides-unmet`, `ruling-not-honoured-undecided`,
`other-side-did-not-hold`, `not-reached-left-out`, `not-reached-hides-unmet`, `left-out-counted`,
`local-times-dropped`, `refund-not-remedied`, `not-honoured-uncounted`,
`not-honoured-not-did-not-hold`, `remedied-and-not-honoured`, `remedied-not-did-not-hold`,
`not-counted-wrong-reason`,
`not-counted-not-the-window`, `outcomes-five-lines`, `band-five-lines`, `no-coverage-start`,
`coverage-start-before-since`, `coverage-start-other-month`, `anchor-before-coverage-start`,
`v2-card-for-v3-request` and `v3-card-for-v2-request`. A `/3` deal
entry carries row results, not the row statements and dates they are computed from: the rule that
computes them is EBL's (SH-11), whose own vectors test it.

In `vectors-4.json`, positive: `no-witness-time-counted` (`/3`'s shelf at the first anchor with
deal-311, whose agreement names a witness and whose records hold no time from it, and deal-315,
whose agreement names no witness, each counted with every row local and in `local_times`; the shop
purchase alone not counted), the same card without the deal entries
(`no-witness-time-without-shelf`) and with nothing beside it (`no-witness-time-card-only`).
Negative: `no-witness-time-left-out` and `no-witness-time-not-local` (`counts_recompute`),
`not-counted-member`, `v3-card-for-v4-request` and `v4-card-for-v3-request` (`card_form`).

## Gates

- `python/tests/test_standard_history_v0_vectors.py` runs every case through the Python
  reference, `agent_action_capsule.standard_history`, rebuilds each fully checked standard card
  from its inputs with `derive_card`, runs defective evaluators that must each disagree with a
  case, checks that a `/1` card cannot be built over an unpriced deal, that every pair of row
  results falls in exactly one `/3` line, that a `/4` entry refuses `left_out`, and regenerates the directory twice, byte-identical.
- `go/standardhistory` runs every case through the Go package and rebuilds the same cards with
  `Derive`.

This README is the only hand-written file in the directory.
