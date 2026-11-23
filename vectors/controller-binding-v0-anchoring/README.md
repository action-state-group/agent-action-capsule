# Controller binding v0: revocation against an attested time

These vectors exercise `spec/controller-binding-v0.md` (cited as CB) §5.2. For a record with an
attested time (the earliest time a third party attests it existed by), a revocation statement
counts only when, besides `revoked_at` ≤ the record's own time as in CB §5, its earliest anchor (a
time a third party attests the statement existed by) is not later than the record's attested time.
`revoked_at` alone is the revoking key holder's word, and either bound key may revoke. Without the
rule, a key holder could sign a revocation after a record was stamped, date it before the record,
and remove the binding's effect on it. The rule only adds a requirement: no statement counts that
CB §5 alone would not count (`revoked-between-signing-and-stamp`).

They complement `vectors/controller-binding-v0/`, which is unchanged: there no record has an
attested time, and CB §5 applies as before. `not-anchored-not-stamped`, `stamp-by-bound-key` and
`stamp-after-evaluation-time` show that here.

## Derivation

Each case is the pair of agreeing halves of `vectors/controller-binding-v0/`, under the two producer
keys, with one `same_controller_asserted` binding of those keys. It adds a revocation statement by
a bound key, **stamps** (time attestations over the halves) and **anchors** (time attestations over
the statement), each as the case needs them.

`python/scripts/generate_controller_binding_v0_anchoring_vectors.py` writes every file except this
README. It uses no repository implementation, and it states every expected status by hand from the
text of CB.

`python/tests/test_controller_binding_v0_anchoring_vectors.py` checks the corpus from the case
inputs alone, with the evaluator of `python/tests/test_controller_binding_v0_vectors.py` extended
by CB §5.2:

- It compares the evaluator's result with the case's whole `expected` block.
- It runs defective evaluators, each of which must disagree with at least one case.
- It regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

**Format fixed for these vectors only, not registered (CB §10.1, CB-10):**

| Format | What it is |
|---|---|
| time attestation | `attested_at`, `attester`, `subject`, `sig`: Ed25519 by `attester` over UTF-8 of JCS of the other members. A **stamp** when `subject` is the SHA-256 of a half's octets, an **anchor** when it is the SHA-256 of UTF-8 of JCS of a revocation statement (CB §5.2), so an anchor names a statement the same way whether it is delivered alone or in a list |

An attestation counts only when it verifies, its `attester` is in `pins.trust_policy.time_attesters`,
the attester is neither bound key, and `attested_at` is not later than `pins.evaluation_time`
(CB §5.2). A half's attested time is the earliest `attested_at` of its stamps that count.

## What each case pins

| Pin | Where |
|---|---|
| Trust roots | `pins.trust_policy`: as in `vectors/controller-binding-v0/`, plus `time_attesters`, the keys the using profile accepts for time attestations: the time attester key, and in `anchor-by-bound-key` and `stamp-by-bound-key` a bound key as well, so that only the bound-key rule refuses its attestation |
| Verification policy | `pins.verification_policy`: as in `vectors/controller-binding-v0/`, plus `attestation_methods_implemented` |
| Times asked about | `pins.times_asked`: each half's T is its `issued_at`; its attested time is the `attested_at` of its earliest stamp that counts, or none |
| Evaluation time | `pins.evaluation_time` |
| Inputs | `halves`, `binding`, and where the case needs them `revocations`, `stamps`, `anchors` and `revocation_list`, each as JSON octets given as text |

**All keys are test keys.** Each private key is the Ed25519 seed SHA-256 of the label in
`test_keys`. Never use one for anything else.

## Times

| Time | What it is |
|---|---|
| `2026-10-12T00:00:00Z` | `revoked_at` of the statement, before both halves |
| `2026-10-13T00:00:00Z` | an anchor before the stamps |
| `2026-10-15T00:00:20Z`, `00:00:21Z` | the halves' `issued_at` |
| `2026-10-15T00:01:00Z`, `00:02:00Z` | `revoked_at` and anchor between signing and stamping (`revoked-between-signing-and-stamp`) |
| `2026-10-15T00:05:00Z` | the stamps over the halves: each half's attested time |
| `2026-10-15T01:00:00Z` | `revoked_at` dated after the stamps (`revoked-at-after-the-stamp`) |
| `2026-10-16T00:00:00Z` | an anchor after the stamps |
| `2026-10-17T00:00:00Z` | a second, later stamp over each half (`earliest-stamp-counts`) |
| `2026-10-19T01:00:00Z` | the evaluation time E |
| `2026-10-20T00:00:00Z` | stamps dated after E (`stamp-after-evaluation-time`) |

## Expected values

`expected` holds what `vectors/controller-binding-v0/` holds, and in `binding`:

- `times`: for each half, in order, its T (`issued_at`), its `attested_at` and `attested_by` (the
  attester's key), both `null` when it has no attested time (CB §7 item 1);
- `revocation_counted_from`: when `controller_binding_revocation` is `FAIL`, the time the statement
  counts from: the later of `revoked_at` and its earliest anchor at an attested half, its
  `revoked_at` at another; otherwise `null`.

## Cases

| Case | Revocation | `issuer_independence` |
|---|---|---|
| `anchored-after-the-stamp` | dated before the halves, anchored after the stamps: does not count, `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `anchored-before-the-stamp` | dated before the halves, anchored before the stamps: `FAIL` from the anchor | `NOT_CHECKED` |
| `anchored-at-the-stamp` | anchored at the stamps' time: `FAIL` | `NOT_CHECKED` |
| `not-anchored-stamped` | no anchor, stamped halves: `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `not-anchored-not-stamped` | no anchor, no stamps: CB §5 unchanged, `FAIL` from `revoked_at` | `NOT_CHECKED` |
| `one-half-stamped` | no anchor; counts at the unstamped half's `issued_at`: `FAIL` | `NOT_CHECKED` |
| `revoked-between-signing-and-stamp` | dated after the halves, anchored before the stamps: `revoked_at` > T, `NOT_CHECKED`, as under CB §5 | `FAIL`: redundant, by the binding |
| `revoked-at-after-the-stamp` | anchored before the stamps, dated after them: `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `earliest-anchor-counts` | anchors after and before the stamps: `FAIL` from the earlier | `NOT_CHECKED` |
| `earliest-stamp-counts` | stamps before and after the only anchor: the earliest stamp is the attested time, `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `anchor-by-bound-key` | the anchor's attester is a bound key, accepted by the profile: no anchor, `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `anchor-attester-not-accepted` | the anchor's attester is not accepted: no anchor, `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `anchor-forged` | the anchor names the accepted attester, signed by another key: no anchor, `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `anchor-other-statement` | the anchor is over another statement: no anchor, `NOT_CHECKED` | `FAIL`: redundant, by the binding |
| `stamp-by-bound-key` | the stamps' attester is a bound key, accepted by the profile: no attested time, CB §5 unchanged, `FAIL` | `NOT_CHECKED` |
| `stamp-after-evaluation-time` | the stamps are dated after E: no attested time, CB §5 unchanged, `FAIL` | `NOT_CHECKED` |
| `complete-list-entry-anchored` | a list declared complete holds the statement, anchored before the stamps: `FAIL` from the anchor | `NOT_CHECKED` |
| `complete-list-entry-not-anchored` | a list declared complete holds the unanchored statement: it does not count, the declaration does, `PASS` | `FAIL`: redundant, by the binding |

## Not covered

- An anchor or stamp whose `attested_at` is not a time, or whose members are not exactly the four
  above. The evaluator ignores it as an attestation that does not verify; no case pins it.
- An anchor dated after E. It is ignored as a stamp dated after E is
  (`stamp-after-evaluation-time`), but no case pins it, since such an anchor could only count at a
  stamp dated after E as well.
- A revocation `revoked_at` exactly equal to a half's `issued_at`. CB §5 counts it (≤); no case in
  either set pins that boundary.
- A `bip340` revoking key. The anchor is over the statement's octets, whatever key signed it.
- A `composed/v1` `controller_binding` join. CB §8 asks about each root record's `timestamp` and
  names no attested time, so §5.2 does not change it.
