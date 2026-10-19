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

**Owns:** the contract document and its two requirement ids (§3), the abstract half members this
contract reads and the shape of the mapping a profile declares onto them (§4), the opening carriage
keyed by half (§5), the per-pairing states and when a side's set counts as complete (§6), the tallies,
sufficiency, verdict and deal state of a claim that cites the contract (§7), and the rule that such
a claim cites no Close (§7.4).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| RES | `spec/evidence-result-v0.md` | the claim, the `type: reconcile` body (§4.1): `join_key`, `peer`, `period`, the six tallies, `state_of_record`; the sufficiency derivation (§4.1); evidence by digest only (§5) |
| PO | `spec/personal-agent-history-outcome-v0.md` | the deal commitment rule (§7): the construction `sha256-jcs-nonce256`, where an opening travels, who an opening is released to; the `openings` carriage (§11) |
| PC | `spec/presentation-contract-v0.md` | the commitment construction `sha256-jcs-nonce256` (§7.2) |
| EL | `draft-mih-agent-evidence-layer-00` | the six per-pairing states and "one half unavailable is not disagreement" ("Reconcile and Close") |
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the value conventions (§5.2), the as-transmitted rule (§5.1), the coverage declaration, its properties and what a verifier reports (§6.7.1 to §6.7.3), the Evidence Contract prose (§11.3) |

**Does not define:** any deal record format (a profile maps its own onto §4's members), any book,
any disclosure rule (PO §7 is the only one), any coverage check (IP §6.7 is the only one), any
normalization of amounts or currency codes (DR-1), any judgment over a reconcile as a whole, or
what a recipient should conclude from a claim.

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

### 4.1 Abstract members

This contract reads six abstract members of a half and ignores everything else in it:

| Member | Presence | Value | Meaning |
|---|---|---|---|
| `deal_id` | REQUIRED | non-empty text | the deal; the join key |
| `book_id` | REQUIRED | non-empty text | the book that holds the half |
| `recorded_at` | REQUIRED | RFC 3339 time | when the book recorded the half |
| `commit_alg` | OPTIONAL | `"sha256-jcs-nonce256"` | the commitment construction (PO §7, PC §7.2) |
| `amount_commitment` | OPTIONAL | lowercase-hex SHA-256 | the commitment to the amount |
| `currency_commitment` | OPTIONAL | lowercase-hex SHA-256 | the commitment to the currency |

These are names for what the contract needs, not member names a half must use. A half is held in
its own profile's format, and that profile fills each abstract member from a field of its half by
the mapping of §4.2.

A field commitment is the lowercase-hex SHA-256 of UTF-8 of JCS of `{"nonce": N, "text": T}`,
exactly as PO §7 states for a deal commitment, with `T` the field's text. Each half commits to each
field with its own nonce, fresh for each half and each field, from a cryptographically secure random
source. The two halves' commitments to the same text therefore differ, and only the openings show
whether the texts are equal.

A half's digest is the SHA-256 of its octets as held (IP §5.1). How a half is signed, and how a
verifier checks its signature and its book, is the half's own format's matter; this contract reads
a half only after that format's checks pass.

### 4.2 Half mapping

A profile whose halves a reconcile under this contract reads declares one **half mapping**. It is a
JSON object with exactly two members:

- `profile`: non-empty text, the name of the profile whose halves the mapping reads;
- `members`: an object with exactly the six members of §4.1, each a JSON Pointer (RFC 6901) into
  the half.

An abstract member's value is the value its pointer resolves to in the half. A pointer that
resolves to nothing leaves the member absent. A verifier reads each half through the mapping of
the profile that half is held under; two books may use different profiles and so different
mappings. When `deal_id`, `book_id` or `recorded_at` is absent or not of its §4.1 form, the half is
malformed and a verifier MUST fail the claim. When `commit_alg` or a commitment is absent or not of
its form, the half is read as carrying none (§6 rule 3).

Example: a profile whose half is
`{"book": …, "deal_ref": …, "recorded_at": …, "terms": {"alg": …, "amount": …, "currency": …}}`
declares

```json
{"profile": "example-half/0",
 "members": {"deal_id": "/deal_ref", "book_id": "/book", "recorded_at": "/recorded_at",
             "commit_alg": "/terms/alg", "amount_commitment": "/terms/amount",
             "currency_commitment": "/terms/currency"}}
```

The profile name and the half layout of the example are for the vectors (§8) only and are not
registered. A mapping states which fields of a half fill the abstract members. It does not by
itself show that a given format's fields hold field commitments built as §4.1 says; the profile
that declares it states that (DR-4).

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
`recorded_at` lies in the period and whose `book_id` is side A's or side B's (§4). They are grouped
by `deal_id`. For each requirement, each deal in the group gets exactly one state, decided by the
first rule that applies:

1. More than one half on either side names the deal: `UNRESOLVED`.
2. Side A holds a half and side B holds none: `A_ONLY` when side B's set is `COMPLETE` for the
   period (§6.1), `UNRESOLVED` when it is `UNDECIDED`, and `INSUFFICIENT` when it is `NOT_SHOWN`.
   Side B holds one and side A none: `B_ONLY`, `UNRESOLVED` or `INSUFFICIENT` by side A's set in
   the same way. `A_ONLY` states a fact about side B's book, that it holds no half of the deal in
   the period, and only a complete set shows that. Without one, a missing half may be one the book
   holds and did not show. One half unavailable is not disagreement (EL); no case of this rule is
   ever `CONFLICTING`.
3. Either half carries no `commit_alg` `"sha256-jcs-nonce256"`, or no commitment for the
   requirement's field, or no field opening for it is carried: `INSUFFICIENT`. The pairing lacks
   what this contract needs to compare it.
4. A field opening is carried for either half and does not open it (§5): `UNRESOLVED`. The text
   offered is not the text committed, so the comparison cannot be decided. A failed opening is
   never `MATCHED`, and it is never `CONFLICTING`: the other book has not disagreed with anything.
5. Either opening opens its half to empty text (`""`): `INSUFFICIENT`, also when both are empty.
   Empty text records no term. A book may commit a placeholder with a fresh nonce, so two empty
   texts are two absent terms, not an agreement. Two empty texts are never `MATCHED`.
6. Both openings open their halves to non-empty text: `MATCHED` when their `text` members are
   equal, and `CONFLICTING` when they differ.

Texts are compared as JSON strings, code point by code point, with no normalization (DR-1).

### 6.1 A complete set

A side's set of halves for the period is `COMPLETE`, `UNDECIDED` or `NOT_SHOWN`. It is decided by
the coverage declaration (IP §6.7.1) the reconcile is given for that side's `book_id` and that
period, and by the verifier's own IP §6.7.2 report of that declaration's coverage properties:

| Status | When |
|---|---|
| `COMPLETE` | the kind is `stream_interval` with `rule` `all_records`, or `source_authoritative`, and every coverage property that applies to the kind is `PASS` |
| `UNDECIDED` | the kind is one of those two, no property is `FAIL` or `NOT_PRESENT`, and one is `NOT_CHECKED` or `INCONCLUSIVE` |
| `NOT_SHOWN` | no declaration is given; the kind is `holder_selected`; a `stream_interval` declaration's `rule` is not `all_records`; or a property is `FAIL` or `NOT_PRESENT` |

This is IP §6.7.3 item 4 carried to the pairing. RES §4.1 derives a reconcile claim's sufficiency
from the `insufficient` and `unresolved` tallies only, so a set that IP would leave a
completeness requirement `INSUFFICIENT` on gives `INSUFFICIENT` pairings, and one that IP would
leave `UNKNOWN` on gives `UNRESOLVED` pairings. In this revision `coverage_declaration_commitment`
is always `NOT_CHECKED` (IP §6.7.2), so a `stream_interval` set is at best `UNDECIDED`, and
`A_ONLY` or `B_ONLY` comes only from a `source_authoritative` set (DR-5).

A verifier shows, beside every `A_ONLY` or `B_ONLY` deal, the declared kind and what its
completeness is relative to (IP §6.7.1, last column).

The declaration travels as IP §6.7 says, in the definition of the set it declares. It is given to
the reconcile beside the halves and the field openings, keyed by `book_id`, with the period it is
given for. This contract adds no coverage check of its own.

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
(RES §5). Its `presentation` is a `disclosure` carrier (RES §2) over the same digests, whose
`status` is `SATISFIED`, `UNKNOWN` or `INSUFFICIENT` as the sufficiency is `SATISFIED`, `UNKNOWN`
or `GAP`: a `GAP` here only ever comes from the `insufficient` tally. The Result carries no field opening, no field text and no coverage declaration (DR-3). A recipient that holds the Result
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
`contract.document_jcs`), its `contract_ref` and digest, the example half mapping of §4.2, and eight
cases over one deal. Each case carries its halves in the example layout, the half mapping of each
book, the field openings, side B's coverage where one is given, the expected opening statuses,
each side's §6.1 status, the per-pairing states, the six tallies per
requirement, the deal state and the expected Evidence Result:

| Case | What it shows | Sections |
|---|---|---|
| `pair-matched` | both halves commit to the same amount and currency, every field opening opens: both requirements `MATCHED`, tallies `matched` 1, sufficiency `SATISFIED`, verdict `met`, deal `reconciled` | §4.2, §5, §6 rule 6, §7 |
| `amount-opening-fails` | side B's amount opening carries other text: amount `UNRESOLVED`, not `MATCHED` and not `CONFLICTING`; sufficiency `UNKNOWN`, verdict `not_evaluable`; currency still `MATCHED`; deal `not_reconciled` | §5, §6 rules 4 and 6, §7 |
| `currency-texts-empty` | both currency openings open to empty text: currency `INSUFFICIENT`, not `MATCHED`; sufficiency `GAP`, verdict `not_evaluable`; amount `MATCHED`; deal `not_reconciled` | §6 rules 5 and 6, §7 |
| `a-only-peer-complete` | side B holds no half; its `source_authoritative` coverage is `PASS` on every property, so its set is `COMPLETE`: both requirements `A_ONLY`, sufficiency `SATISFIED`, verdict `not_met` | §6 rule 2, §6.1, §7 |
| `a-only-peer-commitment-not-checked` | side B holds no half; its `stream_interval` coverage is `PASS` but for `coverage_declaration_commitment` `NOT_CHECKED`, so its set is `UNDECIDED`: both requirements `UNRESOLVED`, sufficiency `UNKNOWN`, verdict `not_evaluable` | §6 rule 2, §6.1, §7 |
| `a-only-peer-not-declared` | side B holds no half and no coverage is given: both requirements `INSUFFICIENT`, sufficiency `GAP`, verdict `not_evaluable` | §6 rule 2, §6.1, §7 |
| `a-only-peer-holder-selected` | as above, with side B's coverage `holder_selected`: `INSUFFICIENT` | §6 rule 2, §6.1, §7 |
| `a-only-peer-coverage-fails` | as above, with side B's `stream_interval` coverage failing `coverage_declaration_population`: `INSUFFICIENT` | §6 rule 2, §6.1, §7 |

`python/scripts/generate_deal_reconcile_v0_vectors.py` regenerates them. The amount and currency
texts are placeholders; the currency is the code reserved for testing. The coverage properties are
given as a verifier reports them; the coverage declaration vectors of IP §6.7.6 check how they are
computed.

## 9. Open points

- **DR-1.** Texts are compared exactly. Two books that write the same amount differently
  (`"100.0"`, `"100.00"`) reconcile as `CONFLICTING`. Whether a later version names a canonical
  text form for each field is open.
- **DR-2.** Rule 4 of §6 makes a failed opening `UNRESOLVED`. A failed opening could instead be
  read as evidence that does not support the comparison (`INSUFFICIENT`, sufficiency `GAP`). This
  version keeps a missing opening and a wrong one apart.
- **DR-3.** An IP §6.7 interval is bounded by anchors, not times. Nothing signed in this revision
  says that a declared set is a book's whole set for a period of `recorded_at` times; §6.1 takes
  that association from what the reconcile is given. The Result also does not cite the definition
  a completeness was taken from. Whether a later version binds a declaration to a period, and cites
  it by digest in the claim's `evidence`, is open.
- **DR-4.** No profile's half has yet been confirmed to fill §4.1's members by a §4.2 mapping, with
  field commitments built as §4.1 says. Until a profile declares its mapping and states that, a
  reconcile of that profile's halves under this contract is not specified.
- **DR-5.** §6.1 gives `A_ONLY` and `B_ONLY` only over a set with every coverage property `PASS`,
  so in this revision a `stream_interval` set never gives them. The other reading takes IP §6.7.3
  item 3, which reports such a set as complete relative to the live set the holder opened, and
  gives `A_ONLY` from it. That reading would give a sufficiency of `SATISFIED` from a set whose
  live set no one checked against its anchor, which IP §6.7.3 item 4 rules out for a completeness
  requirement. When IP registers the material `coverage_declaration_commitment` needs, a
  `stream_interval` set can be `COMPLETE` with no change here.
