# Standard History Derivation v0: conformance vectors

These vectors exercise `spec/standard-history-v0.md` (`standard_history/1`, cited as SH): the
card (SH §4), the counting rules (SH §5) and the six card properties (SH §6), including
`counterparty_class` (SH §7) as the input that decides whether a deal is counted.

## Derivation

`python/scripts/generate_standard_history_v0_vectors.py` writes every card and every expected
property by hand from SH §4 to §6. It imports no implementation. Each case gives the card and what
a verifier may hold beside it:

| Input | What it is | Needed by |
|---|---|---|
| `card` | the card, as a JSON value | every property |
| `policy` | the policy's two members (SH §5.1): `digest` and `window` | `window_from_policy`, `counts_recompute` |
| `as_of` | the anchor's digest and time, and the stream's first checkpoint time | `as_of`, `counts_recompute` |
| `deals` | every deal entry (SH §5.2) the stream holds at the anchor | `counts_recompute` |

A case without an input expects `NOT_CHECKED` for each property that needs it. `expected` gives
all six properties, whether the card is a standard card (SH §6), and the properties that `FAIL`.

The deal entries are abstract (SH §5.2): no record format is fixed here. Every digest is a label
digest, SHA-256 of a text string, for these vectors only.

## The cases

Positive: a person's card with a 3-month window, checked with every input, with the deal entries
left out, and with nothing beside it; a node's card with window everything over the same deals;
the month-end clamp of SH §5.1; a window with no deal in it; and a window across a year end with
a sub-unit deal (a negative decade) and a zero amount (the band whose decade is null); and the decade of 1 msat, 1 sat, 250 sat and 1 BTC over Lightning and of
1 cent of USDC; and a window that starts before year 1.

Negative, each failing the properties its `expected.fails` lists: `percentage-fraction`,
`percentage-member`, `count-without-denominator`, `tallies-disagree`, `counted-shop-purchase`,
`window-not-in-policy`, `counterparty-member`, `since-day`, `since-non-ascii-digits`,
`bands-unsorted`, `band-duplicate`, `band-empty`, `currency-free-text`, `node-person-class`,
`node-class-free-text`, `window-all-false`,
`class-missing-over`, `dispute-forum-total` and `other-anchor`.

## Gates

- `python/tests/test_standard_history_v0_vectors.py` runs every case through the Python
  reference, `agent_action_capsule.standard_history`, rebuilds each fully checked standard card
  from its inputs with `derive_card`, runs defective evaluators that must each disagree with a
  case, and regenerates the directory twice, byte-identical.
- `go/standardhistory` runs every case through the Go package and rebuilds the same cards with
  `Derive`.

This README is the only hand-written file in the directory.
