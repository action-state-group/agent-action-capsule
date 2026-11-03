# Standard History Derivation v0: conformance vectors

These vectors exercise `spec/standard-history-v0.md` (`standard_history/1` and
`standard_history/2`, cited as SH): the card (SH §4), the counting rules (SH §5) and the six card
properties (SH §6), including `counterparty_class` (SH §7) as the input that decides whether a
deal is counted. `vectors.json` holds the `/1` cases. `vectors-2.json` holds the `/2` cases: a
deal whose agreed amount the records do not give, counted in every total and in no band.

## Derivation

`python/scripts/generate_standard_history_v0_vectors.py` writes every card and every expected
property by hand from SH §4 to §6. It imports no implementation. Each case gives the card and what
a verifier may hold beside it:

| Input | What it is | Needed by |
|---|---|---|
| `card` | the card, as a JSON value | every property |
| `policy` | the policy's two members (SH §5.1): `digest` and `window` | `window_from_policy` |
| `as_of` | the anchor's digest and time, and the stream's first checkpoint time | `as_of`, `counts_recompute` |
| `deals` | every deal entry (SH §5.2) the stream holds at the anchor, given only when coverage is shown and no payload member the mapping reads is withheld (SH §6 "Handing the material"; a vector cannot carry the proof, so `deals` stands for a complete handover) | `counts_recompute` |
| `derivation` | in `vectors-2.json` only: the token the request named, which the card is checked under (SH §6) | every property |

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

## Gates

- `python/tests/test_standard_history_v0_vectors.py` runs every case through the Python
  reference, `agent_action_capsule.standard_history`, rebuilds each fully checked standard card
  from its inputs with `derive_card`, runs defective evaluators that must each disagree with a
  case, checks that a `/1` card cannot be built over an unpriced deal, and regenerates the
  directory twice, byte-identical.
- `go/standardhistory` runs every case through the Go package and rebuilds the same cards with
  `Derive`.

This README is the only hand-written file in the directory.
