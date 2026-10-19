# Deal Reconcile Contract — v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft. It states one Evidence Contract, `ec:deal-reconcile@1`, that a `type: reconcile`
claim of an Evidence Result (`spec/evidence-result-v0.md` §4.1, cited here as RES) cites when two
books reconcile the two halves of a deal. It says how the six reconcile tallies are recomputed
from the two halves and the openings of their commitments. Where this document needs a rule that
no other document states, it lists it under [Open points](#9-open-points) (DR-1, DR-2, …).

A reconcile under this contract shows that two books committed to the same amount and the same
currency for a deal, and that each commitment opens to the text compared. It shows nothing about
whether the amount was paid, delivered or owed.

## Dependency boundary

**Owns:** the contract document and its two requirement ids (§3), the half members this contract
reads (§4), the opening carriage keyed by half (§5), the per-pairing states (§6), the tallies,
sufficiency, verdict and deal state of a claim that cites the contract (§7), and the rule that such
a claim cites no Close (§7.4).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| RES | `spec/evidence-result-v0.md` | the claim, the `type: reconcile` body (§4.1): `join_key`, `peer`, `period`, the six tallies, `state_of_record`; the sufficiency derivation (§4.1); evidence by digest only (§5) |
| PO | `spec/personal-agent-history-outcome-v0.md` | the deal commitment rule (§7): the construction `sha256-jcs-nonce256`, where an opening travels, who an opening is released to; the `openings` carriage (§11) |
| PC | `spec/presentation-contract-v0.md` | the commitment construction `sha256-jcs-nonce256` (§7.2) |
| EL | `draft-mih-agent-evidence-layer-00` | the six per-pairing states and "one half unavailable is not disagreement" ("Reconcile and Close") |
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the value conventions (§5.2), the as-transmitted rule (§5.1), the Evidence Contract prose (§11.3) |

**Does not define:** any deal record format, any book, any disclosure rule (PO §7 is the only
one), any normalization of amounts or currency codes (DR-1), any judgment over a reconcile as a
whole, or what a recipient should conclude from a claim.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from RES §1, PO §1 and EL are used unchanged. This document adds:

- **Deal:** one agreement between two parties, named by a deal id both parties record.
- **Half:** one party's record of a deal, held in that party's book.
- **Side A, side B:** side A is the book that produces the Result; side B is the book the claim
  names as `peer` (RES §4.1).
- **Field:** `amount` or `currency`, the two terms this contract compares.
- **Field opening:** the `{"nonce", "text"}` a field commitment is recomputed from (PO §7).

All values follow IP §5.2: digests are 64 lowercase hexadecimal characters and times are RFC 3339
UTC with `Z` and seconds precision.

## 2. What the contract is for

Two parties to a deal each record their half in their own book. Each half commits to the deal's
amount and currency without disclosing them. A reconcile joins the two books' halves on the deal
id and, for each field, decides whether the two halves agree. The commitments let each book keep
its terms out of anything it answers; the openings, released to the party that runs the
reconcile, let that party check both halves against the same text.

This is a reconcile of two halves, not a Close. Nothing is closed, acknowledged or rebutted, and
no Close record exists for a claim to cite (§7.4).

## 3. The contract document

The contract is this JSON value. It validates against the Evidence Contract v0 schema pinned as
EC in IP's Dependency boundary (IP §11.3); the vectors (§8) record that pin's SHA-256.

```json
{
  "id": "ec:deal-reconcile",
  "version": "1",
  "requirements": [
    {
      "id": "amount-commitment-matched",
      "profile": "outcome",
      "statement": "Both halves of the deal commit to the same amount, and each amount commitment opens to the text compared.",
      "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}
    },
    {
      "id": "currency-commitment-matched",
      "profile": "outcome",
      "statement": "Both halves of the deal commit to the same currency, and each currency commitment opens to the text compared.",
      "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}
    }
  ]
}
```

A claim that cites this contract carries `contract_ref` `"ec:deal-reconcile@1"` and
`requirement_ref` `"amount-commitment-matched"` or `"currency-commitment-matched"`. The
requirement names the field: `amount-commitment-matched` compares `amount`,
`currency-commitment-matched` compares `currency`.

Each half is a `producer_claim` (EL): its book's own statement of the terms. A reconcile under
this contract never upgrades either half to a fact of the other book.

## 4. The half

A half is a JSON object. This contract reads these members and ignores every other:

| Member | Presence | Value | Meaning |
|---|---|---|---|
| `deal_id` | REQUIRED | non-empty text | the deal; the join key |
| `book_id` | REQUIRED | non-empty text | the book that holds the half |
| `recorded_at` | REQUIRED | RFC 3339 time | when the book recorded the half |
| `commit_alg` | OPTIONAL | `"sha256-jcs-nonce256"` | the commitment construction (PO §7, PC §7.2) |
| `amount_commitment` | OPTIONAL | lowercase-hex SHA-256 | the commitment to the amount |
| `currency_commitment` | OPTIONAL | lowercase-hex SHA-256 | the commitment to the currency |

A field commitment is the lowercase-hex SHA-256 of UTF-8 of JCS of `{"nonce": N, "text": T}`,
exactly as PO §7 states for a deal commitment, with `T` the field's text. Each half commits to each
field with its own nonce, fresh for each half and each field, from a cryptographically secure random
source. The two halves' commitments to the same text therefore differ, and only the openings show
whether the texts are equal.

A half's digest is the SHA-256 of its octets as held (IP §5.1). How a half is signed, and how a
verifier checks its signature and its book, is the half's own format's matter; this contract reads
a half only after that format's checks pass.

## 5. Field openings

Field openings travel where PO §7 says an opening travels and under the same rule: in the History
or in an Evidence Bundle beside the answers, released only to the recipient the holder releases an
opening to, and never in an envelope, an artifact or a Result. This document adds no other
disclosure rule.

They are carried as one object, `field_openings`, beside PO §11's `openings`. Its members are half
digests; each value is an object whose members are field names (`amount`, `currency`) and whose
values are `{"nonce", "text"}`. A field with no opening is left out, and a half with no field
opening is left out.

```json
{"field_openings": {"<half digest>": {"amount": {"nonce": "<64 hex>", "text": "<amount text>"},
                                     "currency": {"nonce": "<64 hex>", "text": "<currency text>"}}}}
```

A field opening **opens** a half's field when the half carries `commit_alg`
`"sha256-jcs-nonce256"` and the field's commitment, and the opening's two members recompute that
commitment.

## 6. Per-pairing states

A reconcile is over one period `[start, end)` (RES §4.1). The halves in it are those whose
`recorded_at` lies in the period and whose `book_id` is side A's or side B's. They are grouped by
`deal_id`. For each requirement, each deal in the group gets exactly one state, decided by the
first rule that applies:

1. More than one half on either side names the deal: `UNRESOLVED`.
2. Side A holds a half and side B holds none: `A_ONLY`. Side B holds one and side A none:
   `B_ONLY`. One half unavailable is not disagreement (EL); neither is ever `CONFLICTING`.
3. Either half carries no `commit_alg` `"sha256-jcs-nonce256"`, or no commitment for the
   requirement's field, or no field opening for it is carried: `INSUFFICIENT`. The pairing lacks
   what this contract needs to compare it.
4. A field opening is carried for either half and does not open it (§5): `UNRESOLVED`. The text
   offered is not the text committed, so the comparison cannot be decided. A failed opening is
   never `MATCHED`, and it is never `CONFLICTING`: the other book has not disagreed with anything.
5. Both openings open their halves, and their `text` members are equal: `MATCHED`.
6. Both open, and their `text` members differ: `CONFLICTING`.

Texts are compared as JSON strings, code point by code point, with no normalization (DR-1).

## 7. The claim

### 7.1 Body

A claim that cites this contract has `type` `"reconcile"` and the RES §4.1 body with these values:

| Member | Value |
|---|---|
| `join_key` | `"deal_id"` |
| `peer` | side B's `book_id` |
| `period` | the period of §6 |
| `tallies` | for each of the six states, the number of deals §6 gives that state under the claim's requirement |
| `state_of_record` | `"none"`: neither book is the state of record for a deal's terms |

The tallies are recomputed, never asserted: a verifier holding the halves and the field openings
MUST recompute them by §6 and MUST fail the claim when any tally differs. The claim's `tier` is
`recomputed`.

### 7.2 Sufficiency and verdict

Sufficiency follows RES §4.1 from the two non-finding tallies: `insufficient` > 0 ⇒ `GAP`;
otherwise `unresolved` > 0 ⇒ `UNKNOWN`; otherwise `SATISFIED`.

The verdict is `not_evaluable` when sufficiency is not `SATISFIED`. When it is `SATISFIED`, the
verdict is `met` when `matched` > 0 and `a_only`, `b_only` and `conflicting` are all 0, and
`not_met` otherwise. The verdict is never a ratio of the tallies.

### 7.3 Evidence

The claim's `evidence` is the digest of every half in the reconcile (§6), sorted, by digest only
(RES §5). The Result carries no field opening and no field text. A recipient that holds the Result
but not the openings sees the tallies and the halves' digests, never the terms.

### 7.4 No cited Close

A claim that cites this contract reports on two halves, not on a Close. Its tallies are recomputed
from the halves and their field openings alone. It cites no Close, and the RES §4.1 reconcile body
has no member that would. A verifier or builder that requires a reconcile claim to cite a Close
MUST treat a claim whose `contract_ref` is exactly `"ec:deal-reconcile@1"` as needing none. That
exception is for this exact `contract_ref`: another version of this contract, or any other
contract, gets no exception from this document.

### 7.5 Deal state

For each deal in the reconcile, a verifier MAY report a deal state: `reconciled` when the deal's
state is `MATCHED` under both requirements, `not_reconciled` otherwise. The deal state is shown
with the deal. It is not a claim and it changes no tally.

## 8. Vectors

`vectors/deal-reconcile-v0/` holds the contract document (as `contract.document` and
`contract.document_jcs`), its `contract_ref` and digest, and two cases over one deal, each with
the two halves, the field openings, the expected per-pairing states, the six tallies per
requirement, the deal state and the expected Evidence Result:

| Case | What it shows | Sections |
|---|---|---|
| `pair-matched` | both halves commit to the same amount and currency, every field opening opens: both requirements `MATCHED`, tallies `matched` 1, sufficiency `SATISFIED`, verdict `met`, deal `reconciled` | §5, §6 rule 5, §7 |
| `amount-opening-fails` | side B's amount opening carries other text: amount `UNRESOLVED`, not `MATCHED` and not `CONFLICTING`; sufficiency `UNKNOWN`, verdict `not_evaluable`; currency still `MATCHED`; deal `not_reconciled` | §5, §6 rules 4 and 5, §7 |

`python/scripts/generate_deal_reconcile_v0_vectors.py` regenerates them. The amount and currency
texts are placeholders; the currency is the code reserved for testing.

## 9. Open points

- **DR-1.** Texts are compared exactly. Two books that write the same amount differently
  (`"100.0"`, `"100.00"`) reconcile as `CONFLICTING`. Whether a later version names a canonical
  text form for each field is open.
- **DR-2.** Rule 4 of §6 makes a failed opening `UNRESOLVED`. A failed opening could instead be
  read as evidence that does not support the comparison (`INSUFFICIENT`, sufficiency `GAP`). This
  version keeps a missing opening and a wrong one apart.
