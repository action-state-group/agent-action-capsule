# Standard History Derivation, v0

**Status.** Informational, pre-Internet-Draft, kept in this repository beside the Personal-Agent
History Profile (`spec/personal-agent-history-profile-v0.md`, cited here as PH). It changes no
Internet-Draft, no part of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v0.md`, cited as IP) and no part of PH or its Outcome level. Where it needs
a rule that no other document states, it states the rule as its own and lists it under
[Open points](#10-open-points) (SH-1, SH-2, …).

This document defines three things:

- the derivation `standard_history/1` (§3 to §6): one signed card, as of one anchor, that counts
  the holder's deals in a window the holder's policy sets. It is recipient-free: every requester
  the holder answers gets the same bytes;
- the deal member `counterparty_class` (§7), which decides whether a deal is counted;
- the record kind `receipt_document` (§8): a document the holder holds, sealed by its digest.

A card is counts and nothing else. It never carries a name, an item, an amount, a counterparty,
a deal reference, a record digest or a ratio of two counts. Its only date is `since`, a year and
month (§4).

## Dependency boundary

**Owns:** the derivation token `standard_history/1` and its registry row (`spec/REGISTRY.md` §16),
the deal entry and the counting rules (§5), the card and its members (§4), the card properties
(§6), the member `counterparty_class` and its three values (§7), and the record kind
`receipt_document` (§8).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| ER | `draft-mih-agent-evidence-request` -00 | the `full_history` subject [ER §3.1], a derivation named by a registered token and its declared field set [ER "Derivation", "Derivation-Scoped Disclosure"] |
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the request and envelope (§6.1, §6.2), `anchor_inclusion` for a derivation (§6.2), the value conventions (§5.2), lifecycle statements and their issuers (§11.2), the per-property vocabulary (§7.1) |
| PH | `spec/personal-agent-history-profile-v0.md` | the holder, the holder key and the deal (§1, §2) |
| EL | `draft-mih-agent-evidence-layer` -00 | the record header, its `record_type` and its correlation identifier, the epistemic types |
| SR | `draft-mih-agent-settlement-records` -00 | the amount triple (`value`, `assetCode`, `assetScale`) ("Amounts"), the counterparty half citation ("Citations Between Legs") |
| RES | `spec/evidence-result-v0.md` | the claim verdict `met`, `not_met`, `not_evaluable`, `out_of_scope` (§4) and the grade `self-attested` (§1) |

**Interop profile revision.** This profile stays on `evidence-interop/0`: IP is
`spec/interop-profile-v0.md` as of commit `1456285979bd759b7828fd3ccc4a24296074e552`, which is
frozen, not `spec/interop-profile-v1.md` (`evidence-interop/1`). The IP sections it cites (§5.2,
§6.1, §6.2, §7.1, §11.2) are the same in `evidence-interop/1`, which changes only the ER pin, the
refusal reasons and their mapping (IP v1 P-65), and its requests name `evidence-interop/0`.
Re-pinning to `evidence-interop/1` is a revision of this profile.

**Does not define:** any record format of a deal, any disclosure policy format (it reads two
members of one, §5.1), who may receive a card, any trust policy, any ordering, score or grade of
holders, deals or counterparties, or what a recipient should conclude. It does not change
`history_card/1` [ER "The History Card"], the Basic level `personal_history_basic/1` or the
Outcome level `personal_history_outcome/1`.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from PH §1, IP §1 and ER §2 are used unchanged. This document adds:

- **Card:** the artifact of an answer under `standard_history/1` (§4).
- **Policy:** the holder's disclosure policy in force at the anchor, in whatever format the
  holder's host keeps it.
- **Window:** the span of deals a card counts, set by the policy (§5.1).
- **Deal entry:** the abstract facts about one deal that the counting rules read (§5.2).
- **Counted deal:** a deal in the window whose `counterparty_class` is not `shop_preauth` (§7).
- **Tally:** a card member that holds counts. Every tally carries its own denominator, `of`.

All values follow IP §5.2: digests are 64 lowercase hexadecimal characters and times are RFC 3339
UTC with `Z` and seconds precision.

## 2. What a card says

A card answers "how did this holder's deals go, recently?" without showing any deal. It counts
only the deals where the holder had to come through for the other party after the agreement:
pay afterwards, deliver, turn up, or describe it truthfully. A purchase whose payment was taken
up front, before anything else happened, is not counted (§7). Every count is shown beside the
total it is part of, so a reader sees "9 of 12", never "75%".

The holder key signs every card (the envelope, IP §6.2). That is the holder's statement of the
counts. A recipient checks the card's form and its denominators without any further evidence
(§6). It checks the window only against the policy (SH-9), and recomputes the counts only from
deal entries, which it holds only when the holder hands it the Results and records they are read
from (SH-3). Until then the window and the counts are the holder's statement, and a verifier
shows them as such.

## 3. The derivation

`standard_history/1` is a registered derivation token [ER "Derivation"; `spec/REGISTRY.md` §16].
A request for it is the IP request [IP §6.1] with:

- `subject` `{"full_history": null}` [ER §3.1]: the holder's stream;
- `coverage` `{"expected_pin": <the anchor>}`;
- `derivation` `"standard_history/1"`;
- `profile` `"evidence-interop/0"`.

The responder answers with an IP envelope [IP §6.2] whose `artifact` is UTF-8 of JCS of the card
(§4).

- **Recipient-free.** The token carries no recipient, and nothing in the card depends on who
  asked. The card is caller-invariant for (subject, anchor, derivation) [ER §5]: the policy, the
  deals and their entries are all read from the holder's book at the anchor.
- **Who is answered** is the holder's policy, not this document. A responder that declines a
  requester refuses `policy_declined` or `not_authorized` [IP §6.3].
- **Declared field set.** The card's members (§4). The card reveals no record, no record member
  and no record digest [ER "Derivation-Scoped Disclosure"].
- **Inclusion.** IP registers no verification-material kind for a derivation's artifact, so
  `anchor_inclusion` is `NOT_CHECKED` for a card [IP §6.2, P-13], as for PH §6.1. A card answer
  carries no `verification` member. The anchor's witness receipt travels beside the card as it
  does for `history_card/1`; checking it against the card is SH-4.

## 4. The card

A card is a JSON object with exactly these members, all REQUIRED:

| Member | Value |
|---|---|
| `derivation` | `"standard_history/1"` |
| `holder_kind` | `"person"` or `"node"`: the kind of holder the holder key answers for, as the holder's own controller declaration states it |
| `controller_class` | the class of that declaration: `"person_declared"` on a `person` card and `"node_declared"` on a `node` card, and no other value in `/1`. Finer classes of a node's declaration are SH-5 |
| `anchor` | the anchor the card is as of: equal to the envelope's `anchor.digest` |
| `since` | the year and month of the holder stream's first checkpoint, `YYYY-MM` |
| `window` | the policy's window (§5.1): `{"months": N}` with `N` a positive integer, or `{"all": true}` |
| `policy` | the digest of the policy in force at the anchor (§5.1) |
| `in_window` | tally: `of` (deals in the window), `counted`, `not_counted` |
| `class_missing` | tally: `of` (counted deals), `count` (counted deals that carry no `counterparty_class`) |
| `outcomes` | tally over counted deals: `of`, `held`, `did_not_hold`, `undecided` |
| `bands` | an array of band tallies (below) |
| `roles` | tally over counted deals: `of`, `provided`, `bought` |
| `happened` | tally over counted deals: `of`, `stamped_by_both`, `receipt_only`, `no_record` |
| `disputes` | `{"raised": D, "received": D}`, each `D` a dispute tally (below) |

**A band tally** is `{"currency", "decade", "of", "held", "did_not_hold", "undecided"}`: the
counted deals in one value band (§5.3), by outcome. `currency` is an SR `assetCode`: three
uppercase ASCII letters (an ISO 4217 alphabetic code, or `BTC`), or a CAIP-19 asset type
(`namespace:reference/asset_namespace:asset_reference`, each part in CAIP-19's character set and
length). `decade` is an integer, negative for amounts below one unit, or `null` for a zero amount.
`bands` holds one entry per band that has at least one counted deal, sorted by `currency` (code
point order), then by `decade`, the `null` band first.

**A dispute tally** is `{"of", "by_outcome", "by_forum"}`. `of` is the number of disputes.
`by_outcome` is `{"of", "open", "for", "against", "split", "no_finding", "withdrawn"}`, and
`by_forum` is `{"of", "auto", "network", "rail", "external"}` (§5.4).

**Counts.** Every number on a card is an integer of at most 2^53 - 1 in magnitude, and every
number but a band's `decade` is 0 or more. The card travels as JCS, which writes the number 75.0
as 75, so what counts is the value, not how it was written. A card never carries a ratio, a share,
a percentage, a mean or a score.

**Denominators.** Every tally carries `of`. In every tally but `class_missing`, the other counts
partition `of`: they sum to it. `class_missing.count` is at most its `of`. The tallies agree with
each other:

- `in_window.counted` equals `class_missing.of`, `outcomes.of`, `roles.of` and `happened.of`;
- the bands' `of` sum to `outcomes.of`, and for each outcome the bands' counts sum to that
  outcome's count;
- in each dispute tally, `by_outcome.of` and `by_forum.of` equal its `of`.

No other member is allowed in `/1`, at any level of the card. Any change to a member, a value
list or a counting rule is `/2`. Nothing is extended in place.

**Example** (members in JCS order):

```json
{"anchor": "<64 hex>", "bands": [{"currency": "USD", "decade": 1, "did_not_hold": 0, "held": 2, "of": 3, "undecided": 1}],
 "class_missing": {"count": 1, "of": 3}, "controller_class": "person_declared", "derivation": "standard_history/1",
 "disputes": {"raised": {"by_forum": {"auto": 0, "external": 0, "network": 0, "of": 0, "rail": 0},
                         "by_outcome": {"against": 0, "for": 0, "no_finding": 0, "of": 0, "open": 0, "split": 0, "withdrawn": 0}, "of": 0},
              "received": {"by_forum": {"auto": 0, "external": 0, "network": 0, "of": 0, "rail": 0},
                           "by_outcome": {"against": 0, "for": 0, "no_finding": 0, "of": 0, "open": 0, "split": 0, "withdrawn": 0}, "of": 0}},
 "happened": {"no_record": 0, "of": 3, "receipt_only": 1, "stamped_by_both": 2}, "holder_kind": "person",
 "in_window": {"counted": 3, "not_counted": 1, "of": 4}, "outcomes": {"did_not_hold": 0, "held": 2, "of": 3, "undecided": 1},
 "policy": "<64 hex>", "roles": {"bought": 1, "of": 3, "provided": 2}, "since": "2026-03", "window": {"months": 3}}
```

## 5. Counting

### 5.1 The policy and the window

The card reads two members of the policy in force at the anchor, through the policy's own format:

- its **digest**, the SHA-256 of the policy's octets as held, which the card carries as `policy`;
- its **window**: a number of months `N`, or everything.

The window ends at the anchor's time `T`, the time of the checkpoint the anchor names. For
`{"months": N}` it starts at `S`: the same time of day as `T`, on the same day of the month, `N`
calendar months before `T`; when that month has fewer days, on its last day. A deal is **in the
window** when its `agreed_at` (§5.2) is at or after `S` and at or before `T`. For `{"all": true}`
every deal whose `agreed_at` is at or before `T` is in the window, and so it is for
`{"months": N}` when `S` would fall before year 1, the first year an IP §5.2 time names. A
policy's `N` is a whole number: 3.0 is 3, as JCS writes it.

The card's `window` is the policy's window, exactly. A card with any other window is not a
standard card (§6 `window_from_policy`), whatever its counts. A holder who sends a wider window
to one requester sends a different disclosure, never a `standard_history/1` card (SH-6).

### 5.2 The deal entry

The counting rules read one deal entry per deal the holder's stream holds at the anchor. These
are names for what the rules need, not record members a deal must carry. A host fills them from
its own records (SH-2):

| Member | Presence | Value | Filled from |
|---|---|---|---|
| `deal` | REQUIRED | non-empty text | the deal reference (PH §1) |
| `agreed_at` | REQUIRED | RFC 3339 time | when the holder's book committed the deal's terms |
| `counterparty_class` | OPTIONAL | §7's three values | the deal's `counterparty_class` member (§7) |
| `role` | REQUIRED | `provided` or `bought` | `provided` when the holder sold or provided; `bought` when the holder paid |
| `amount` | REQUIRED | the SR amount triple | the deal's agreed amount [SR "Amounts"] |
| `outcome` | REQUIRED | `held`, `did_not_hold` or `undecided` | the verdict of the deal's outcome claim [RES §4]: `met` is `held`, `not_met` is `did_not_hold`, and anything else, a missing claim included, is `undecided` |
| `happened` | REQUIRED | `stamped_by_both`, `receipt_only` or `no_record` | §5.5 |
| `disputes` | REQUIRED | an array, possibly empty, of `{"side", "outcome", "forum"}` | §5.4 |

A deal entry is never disclosed by a card. A host MUST NOT fill a member from text it was not
given for that member: a deal it cannot classify is `undecided`, `no_record` or without
`counterparty_class`, never guessed.

### 5.3 Counted deals and value bands

- A deal in the window is **counted** unless its `counterparty_class` is `shop_preauth`. A deal
  without `counterparty_class` is counted, and also counted in `class_missing.count`.
- `in_window` counts every deal in the window: `counted`, and `not_counted` for those whose
  `counterparty_class` is `shop_preauth`.
- Every other tally counts counted deals only. A deal that is not counted adds nothing else to
  the card: not its outcome, its role, its band or its disputes.
- A counted deal's **value band** is (`currency`, `decade`): `currency` is its amount's
  `assetCode`, which MUST be of §4's form; `decade` is floor(log10(`value` / 10^`assetScale`)),
  computed exactly as the number of decimal digits of `value` minus `assetScale` minus one
  [SR "Amounts"]. So decade 0 is 1 to below 10 units, decade 1 is 10 to below 100, and decade -1
  is 0.1 to below 1: 250 satoshi (`value` `"250000"`, `assetScale` 11) is decade -6. A deal whose
  `value` is `"0"` is in its currency's band whose `decade` is `null`. A band shows the size of a
  deal to a power of ten, never its amount.

### 5.4 Disputes

Each entry of a deal's `disputes` is one dispute about a record of the deal: an IP §11.2
`disputes` statement whose target is a record of the deal.

- `side` is `raised` when the holder key issued the statement, and `received` otherwise.
- `outcome` is `open` while no resolution of it is held, and otherwise what the resolution
  found for the holder: `for`, `against`, `split`, `no_finding`, or `withdrawn` when the issuer
  withdrew it.
- `forum` is the class of the process that resolves it: `auto` (a rule the two parties agreed to
  in advance), `network` (a process the parties' network provides), `rail` (the payment rail's
  own dispute process) or `external` (anyone else). An open dispute is counted by the forum it
  was raised in.

A dispute tally counts the disputes of counted deals by `side`. Within it, `by_outcome` and
`by_forum` each count every dispute once. How a host reads `outcome` and `forum` from the
resolving process's statement is SH-7.

### 5.5 How it happened

`happened` says how strongly the holder's book shows that the deal took place:

- `stamped_by_both`: the holder's book holds the other party's half of the deal, cited with
  `citation_purpose` `counterparty_half` [SR "Citations Between Legs"; `spec/REGISTRY.md` §11],
  and that half's own checks accept it;
- `receipt_only`: it does not, and it holds the holder's own record that the deal took place,
  such as one of its settlement legs or a `receipt_document` (§8);
- `no_record`: neither.

`receipt_only` is never shown like `stamped_by_both`, and `no_record` is not a failure: one side's
record missing is not disagreement.

## 6. Card properties

A verifier reports these properties of a card, in the IP §7.1 vocabulary [SH-1]:

| Property | Check | Needs |
|---|---|---|
| `card_form` | the card carries exactly §4's members, at every level, with the values §4 fixes for each; `since` is `YYYY-MM` in ASCII digits; each `currency` is of §4's form; `bands` is sorted as §4 says, with no two entries for one band. It does not check that a tally carries `of`, or that a count is an integer | the card |
| `counts_integral` | every JSON number in the card, at every level, is an integer of at most 2^53 - 1 in magnitude, and 0 or more except a band's `decade` (§4 "Counts") | the card |
| `denominator` | every tally carries `of`; its counts partition `of` (for `class_missing`, `count` is at most `of`); every band's `of` is 1 or more; the tallies agree as §4 says. `NOT_CHECKED` when `card_form` or `counts_integral` is `FAIL` | the card |
| `window_from_policy` | the card's `window` equals the policy's window, and its `policy` the policy's digest. `NOT_CHECKED` without the policy | the policy's two members (§5.1) |
| `as_of` | the card's `anchor` equals the anchor the envelope names, and its `since` is the year and month of the stream's first checkpoint. `NOT_CHECKED` without the anchor | the anchor, its time, the first checkpoint's time |
| `counts_recompute` | every count of the card equals the count §5 derives from the deal entries, under the policy's window. `NOT_CHECKED` without the deal entries, the policy or the anchor, or when `card_form`, `counts_integral` or `denominator` is not `PASS` | the deal entries of every deal the stream holds at the anchor |

A card is a **standard card** when every property is `PASS` or `NOT_CHECKED`, and `card_form`,
`counts_integral` and `denominator` are `PASS`. A verifier that does not hold the deal entries
reports `counts_recompute` `NOT_CHECKED` and shows the counts as the holder's statement under the
holder key, not as recomputed. A property `FAIL` means the card is not a standard card: a
verifier shows none of its counts.

The card properties never change an envelope property or an IP §8 status. A card makes no outcome
claim for a requirement to meet, and a requirement is never `SATISFIED` from a card alone.

**What a verifier shows** for a standard card, in this order: that the counts cover counted deals
in the stated window, how many deals in it were not counted, and how many counted deals are
`undecided`; each count with its `of` on the same line; which checks ran and which did not,
including `anchor_inclusion` `NOT_CHECKED` and, without their inputs, `window_from_policy`,
`as_of` and `counts_recompute` `NOT_CHECKED`. It shows the bands grouped by `currency`, each
band with its own currency, and never merges bands of two currencies into one row or shows a band
in another currency: amounts in different assets are never equal or converted [SR "Amounts"
rule 4]. It shows no ratio of two counts, and it never ranks or grades the holder.

**Vectors.** `vectors/standard-history-v0/` holds positive cards, among them a window across a
year end, a sub-unit deal with a negative decade and a zero amount, and negatives each failing the
property named: a share stated as a fraction (`counts_integral`), a percentage member
(`card_form`), a count without its denominator (`denominator`), tallies that disagree
(`denominator`), a shop purchase counted (`counts_recompute`), a window not in the policy
(`window_from_policy`), a counterparty member (`card_form`), a free-text `currency`
and a free-text node `controller_class` (`card_form`), a `since` finer than a month or in other
digits (`card_form`), bands out of order or repeated (`card_form`), an empty band
(`denominator`), and another anchor (`as_of`), among others.

## 7. `counterparty_class`

`counterparty_class` is a deal-level member: what kind of party the holder dealt with, and so
whether the deal is counted (§5.3). Its value is one of:

| Value | Meaning | Counted |
|---|---|---|
| `person_agent` | the other party is a person, through their agent | yes |
| `business_agent` | the other party is a business, through its agent, and the holder still had to come through after the agreement | yes |
| `shop_preauth` | a purchase from a shop whose payment was authorized up front, before anything else happened | no |

- A deal's records carry `counterparty_class` on at most one record, as a top-level member of
  that record's payload. A host reads a deal whose records carry it on two or more records as
  lacking it.
- It is set by whatever recorded how the deal was paid, for example a payment adapter: a card
  pre-authorization is `shop_preauth`. A payment after the agreement, such as an invoice paid
  later, is not. Without it a deal is counted, and the card counts the deal in
  `class_missing.count`.
- It is the recording party's own statement. A verifier MUST NOT present it as checked by
  anyone else.
- Carrying it on a settlement terms leg needs a revision of SR, whose `settlement` member is a
  closed set (SH-8).

## 8. `receipt_document`

A `receipt_document` record seals, by digest, a document the holder holds about a deal: a
receipt the other party or a payment service sent by mail or through an application, for
example. It is a record kind: its record header's `record_type` is `"receipt_document"` [EL], and
its correlation identifier is the deal reference. Its payload has exactly these members:

| Member | Value |
|---|---|
| `document_digest` | the SHA-256 of the document's octets exactly as held, 64 lowercase hex characters |
| `media_type` | the document's media type, for example `"message/rfc822"` |

- The record never carries the document. The document stays with the holder.
- The record is the holder's statement that it held a document with that digest when the record
  was committed. A claim that rests on it alone has grade `self-attested` [RES §1]. Its
  `epistemic_type` is `producer_claim` [`spec/REGISTRY.md` §17].
- It makes "the holder's receipt only" checkable later: a holder who releases the document lets
  the recipient recompute `document_digest` and see that the record committed to it. That shows
  the document existed when the record was committed, not that what it says is true, and not
  that its issuer signed it. A signature the document carries (for example a mail signature) is
  checked, if at all, by the Outcome level's verifier-statement form
  (`spec/personal-agent-history-outcome-v0.md` §5.3), never by this record.
- A `receipt_document` record is not in PH §3's or the Outcome level's closed lists of record
  kinds, so a History at those levels never carries one. The card counts it only through
  `happened` (§5.5).

## 9. Security and privacy considerations

- **Counts only.** A card carries no deal, deal reference, record digest, amount, item or party,
  and no date but `since` (§4). `bands` shows a deal's size only to a power of ten, and only in
  aggregate. A `currency` is an asset code, never free text, but a CAIP-19 asset type names a
  token contract, and a token one business issued can name that business. Which deals a card
  counts, and so which asset codes it shows, is the holder's control through the policy.
- **The holder's levers.** The holder's own records set `counterparty_class` and the outcome
  claim. Marking a deal `shop_preauth` takes it out of every count but `in_window`, and never
  recording an outcome claim leaves it `undecided`. The card shows both, as
  `in_window.not_counted` and `outcomes.undecided`, and a verifier shows them (§6).
- **Small counts.** A card with few deals in a band, or one dispute, can still tell a recipient
  who knows one of the deals something about it. The window and the bands are the holder's
  control, through the policy.
- **Same bytes for every requester.** A card is recipient-free (§3): two requesters who compare
  their cards learn only that they asked the same holder at the same anchor. A recipient that does
  not hold the policy cannot check the window (§6 `window_from_policy` `NOT_CHECKED`), so a card
  with another window is then the holder's statement too.
- **The holder's statement.** The holder key signs the counts. Without deal entries a recipient
  cannot recompute them (§6). A valid signature never shows that the counts are right, only that
  the holder stated them.
- **No grading.** This document defines no score, grade, ratio or ordering, and a verifier that
  follows it shows none.

## 10. Open points

| # | Point |
|---|---|
| SH-1 | The card properties (§6) as properties in IP's vocabulary that are not IP §7.2 envelope properties and never enter the IP §8 mapping, as PH's PA-10. |
| SH-2 | Filling the deal entry (§5.2) from a host's records: which record gives `agreed_at`, `role` and `amount`, and which claim is a deal's outcome claim. A host profile states its mapping, as `spec/deal-reconcile-contract-v0.md` §4.2 does for a half. |
| SH-3 | Handing a recipient what `counts_recompute` needs: the Results and records the deal entries are read from, without disclosing more than the recipient may see. Until a carriage is defined, a recipient's verifier reports `counts_recompute` `NOT_CHECKED`. ER asks a derivation's result to be re-derivable by the requester; this revision meets that only with that material. |
| SH-4 | Checking the anchor's witness receipt against a card: needs a verification-material kind for a derivation's artifact (IP P-13), as PH's PA-13. |
| SH-5 | Finer `controller_class` values for a node's declaration, and the node's further counts, such as counts per tier of paired answers and of referee findings. This revision defines a `node` card with the same members as a `person` card. The further counts belong in a separate derivation token for nodes, so that `/1` stays the same for every holder. |
| SH-6 | A disclosure wider than the policy's window, sent to one requester at the holder's choice. It declares the IP §6.7 coverage kind `holder_selected` and is never a `standard_history/1` card. |
| SH-7 | Reading a dispute's `outcome` and `forum` (§5.4) from the resolving process's statement: IP §11.2.6's statuses (`open`, `upheld`, `dismissed`, `conflicting`) do not say for whom a resolution found, and IP names no forum. |
| SH-8 | Carrying `counterparty_class` in SR's terms leg, whose `settlement` member is closed in -00. Until a revision lists it, it is carried in another record of the deal (§7). |
| SH-9 | Handing a recipient the policy, or the two members of it the card reads (§5.1), so that `window_from_policy` can run. Until a carriage is defined, a recipient's verifier reports it `NOT_CHECKED`, and the window is the holder's statement. |
