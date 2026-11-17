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
  the holder answers gets the same bytes. Its revision `standard_history/2` counts, in the same
  card, the deals whose agreed amount the holder's records do not give (§4, §5.3); a card under
  `/1` cannot count them. Its revision `standard_history/3` (§11) counts the deals of a shelf log
  of book facts from each deal's term rows, in five outcome lines, and carries the coverage start
  of that shelf log; `/1` and `/2` are unchanged by it;
- the deal member `counterparty_class` (§7), which decides whether a deal is counted;
- the record kind `receipt_document` (§8): a document the holder holds, sealed by its digest.

A card is counts and nothing else. It never carries a name, an item, an amount, a counterparty,
a deal reference, a record digest or a ratio of two counts. Its only date is `since`, a year and
month (§4).

## Dependency boundary

**Owns:** the derivation tokens `standard_history/1`, `standard_history/2` and
`standard_history/3` and their registry rows (`spec/REGISTRY.md` §16),
the deal entry and the counting rules (§5, §11), the card and its members (§4, §11.6), the card
properties (§6, §11.7), the member `counterparty_class` and its three values (§7), and the record
kind `receipt_document` (§8).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| ER | `draft-mih-agent-evidence-request` -00 | the `full_history` subject [ER §3.1], a derivation named by a registered token and its declared field set [ER "Derivation", "Derivation-Scoped Disclosure"] |
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the request and envelope (§6.1, §6.2), `anchor_inclusion` for a derivation (§6.2), the value conventions (§5.2), lifecycle statements and their issuers (§11.2), the per-property vocabulary (§7.1) |
| IP1 | `spec/interop-profile-v1.md` (`evidence-interop/1`) | only the witness Receipt over an anchor, `cll-witness-receipt`, and its check `anchor_witnessed` (§6.2.2). The request and envelope stay `evidence-interop/0`'s |
| PH | `spec/personal-agent-history-profile-v0.md` | the holder, the holder key and the deal (§1, §2) |
| EL | `draft-mih-agent-evidence-layer` -00 | the record header, its `record_type` and its correlation identifier, the epistemic types |
| SR | `draft-mih-agent-settlement-records` -00 | the amount triple (`value`, `assetCode`, `assetScale`) ("Amounts"), the counterparty half citation ("Citations Between Legs") |
| RES | `spec/evidence-result-v0.md` | the claim verdict `met`, `not_met`, `not_evaluable`, `out_of_scope` (§4) and the grade `self-attested` (§1) |
| EB | `spec/draft-mih-zhang-agent-disclosure-bundle-02.md` (`evidence-bundle/v2`) | only the Bundle, its `records`, its `completeness` members (`missing`), the disclosure overlay ("Bundle-Level Disclosures"), the padding leaf ("Non-Record Leaves") and the interval coverage and per-record membership claims ("Completeness Claims and Log Membership"), as the carriage of the material `counts_recompute` needs (§6 "Handing the material") |
| HF | `spec/history-frame-v0.md` | the History frame: its rules (§4), its parameters (§3), and this derivation's counting table and wording pack (§5, §6.1) |
| SF | `spec/shelf-forms-v0.md` | `/3` only: the shelf log, its book facts and journal facts, the status value a fact commits to, the format-switch marker and the coverage start (§1, §3, §4.2), as the basis `/3` counts from (§11) |
| EBL | the evidencebook library, <https://github.com/action-state-group/evidencebook>, commit `a443a83a7f9dcf781b1a54ada98e37a286423ebe` | `/3` only: the rule that computes a term row's status (`rowstatus/rowstatus.go`, design §4.2 of evidencebook#461), whose results a `/3` deal entry carries (§11.2, SH-11), and the whole-shelf handover and its checks (`shelf_handover.go`; its design `docs/design/461-shelf-facts.md` §2.7), the material of `/3`'s `counts_recompute` (§11.7) |

**Interop profile revision.** This profile stays on `evidence-interop/0`: IP is
`spec/interop-profile-v0.md` as of commit `1456285979bd759b7828fd3ccc4a24296074e552`, which is
frozen, not `spec/interop-profile-v1.md` (`evidence-interop/1`). The IP sections it cites (§5.2,
§6.1, §6.2, §7.1, §11.2) are the same in `evidence-interop/1`, which changes only the ER pin, the
refusal reasons and their mapping (IP v1 P-65), and its requests name `evidence-interop/0`.
Re-pinning to `evidence-interop/1` is a revision of this profile. The one exception is the
witness Receipt beside a card (§3 "Inclusion"), which this profile takes from
`spec/interop-profile-v1.md` §6.2.2 (cited as IP1): it is checked over the anchor, outside any
request or envelope, so it changes neither.

**Does not define:** any record format of a deal, any disclosure policy format (it reads two
members of one, §5.1), who may receive a card, any trust policy, any ordering, score or grade of
holders, deals or counterparties, or what a recipient should conclude. It does not change
`history_card/1` [ER "The History Card"], the Basic level `personal_history_basic/1` or the
Outcome level `personal_history_outcome/1`.

## Instance of the History frame

`standard_history/1` and `standard_history/2` are instances of the History frame (HF), with the
same parameters. This section names their values; it changes no member, value, identifier or
vector of this document.

- **Parameters** (HF §3; the SH column of HF §6.1): `identification` `token`; `level`
  `recipient_free` (§3); `subject_form` `full_history`; `coverage_kind` `policy_window`, carried as
  `instance_text`: a card covers every deal of the holder's book at the anchor whose `agreed_at`
  is in the window the policy sets (§5.1), completeness is not asserted, and the card carries no
  coverage member; `aggregation` `window`; `answer_anchor` `any_checkpoint`; `streams` `one`;
  `embeds` `receipt_beside` (§3 "Inclusion": no `history_card/1` is carried); `stated_by`
  `responder` (§2); `claims` `none`;
  `interop_pin` `evidence-interop/0`; `non_recipient_refusal` `none`; `policy_digest`
  `policy_octets` (§5.1); `container` `none`.
- **Counting table:** `spec/history-frame/standard-history-1-table.json`, digest
  `31122b837d2bea44dd3f559ca90a69f666c146ebb3f1b4d9f7df1c1fd3d47c53`: the deal entry (§5.2), the
  card members and tallies (§4), the units deals and disputes, the card properties (§6), and the
  properties that may be `NOT_CHECKED`: `window_from_policy`, `as_of` and `counts_recompute`.
- **Wording pack:** `spec/history-frame/standard-history-1-pack.json`, digest
  `dcea1ee99942d0b4dc78b380b63f7854964d132925de18fdeb30b336e9877b74`: the display strings of §6
  "What a verifier shows".
- **`/3`'s parameters** are `/1`'s, all of them: SH's column of HF §6.1 holds for the three
  tokens. Its anchor is a shelf checkpoint, the checkpoint of one log (`streams` `one`), and the
  coverage start it carries (§11.5) is a card member, not a coverage kind: `coverage_kind` stays
  `policy_window`, carried as `instance_text`.
- **`/3`'s documents:** the counting table `spec/history-frame/standard-history-3-table.json`,
  digest `71e38ed61fbe928ff535aa851e4bc4f86bd7ee039a2a80707cb54a493340cc00`, and the wording pack `spec/history-frame/standard-history-3-pack.json`, digest
  `bd5f940e4b541d2a91fe7532cde65b3c94004f5958b2d3d573eaabcacf6f55ac` (§11).
- **`/2`'s documents:** the counting table `spec/history-frame/standard-history-2-table.json`,
  digest `c18c28b9830440fddb0d2963c6731da698b019d00606e3f3e4205dfb34c48a1a`, which adds to `/1`'s
  table the card member and tally `unpriced` (§4); and the wording pack
  `spec/history-frame/standard-history-2-pack.json`, digest
  `212fa32bf4a5193f4161ecc86059cf4b79bac9af183350a1800a05834797a564`, which adds the string that
  words it (§6).
- **Pinning.** Each token pins both of its documents' bytes (HF §5.4): any change to either of
  `/2`'s is a new token, and `/1`'s stay as they are; `standard_history/3` pins its own two
  documents (§11), and any change to either of them is a new token too. Where a document and this text
  disagree, HF §6.3 applies.
- **Frame rules.** One holder key per card (HF §4.1), envelope acceptance (HF §4.3), card
  properties outside the IP §8 mapping (HF §4.4), acceptance (HF §4.5: a standard card, §6), no
  score, grade, ratio or ordering (HF §4.6) and differencing (HF §4.8; §9 "Differencing") are the
  frame's, and this document states each again where it applies them. Composition only by an
  evidence-backed key link (HF §4.7) is the frame's rule, which this document did not state
  before: cards under two holder keys compose only by such a link, never by being shown together.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from PH §1, IP §1 and ER §2 are used unchanged. This document adds:

- **Card:** the artifact of an answer under `standard_history/1`, `standard_history/2` (§4) or
  `standard_history/3` (§11.6).
- **Policy:** the holder's disclosure policy in force at the anchor, in whatever format the
  holder's host keeps it.
- **Window:** the span of deals a card counts, set by the policy (§5.1).
- **Deal entry:** the abstract facts about one deal that the counting rules read (§5.2).
- **Counted deal:** a deal in the window whose `counterparty_class` is not `shop_preauth` (§7).
- **Unpriced deal:** under `/2`, a deal whose entry carries no `amount`, because the holder's
  records do not give the deal's agreed amount (§5.2).
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
deal entries, which it holds, shown complete, only when the holder hands it the records they are
read from (§6 "Handing the material"). Without them the counts are the holder's statement, and
without the policy so is the window; a verifier shows them as such, as the normal case and not as
a warning: the holder signed the counts, and recomputing them needs the whole stream.

## 3. The derivation

`standard_history/1`, `standard_history/2` and `standard_history/3` are registered derivation
tokens [ER "Derivation"; `spec/REGISTRY.md` §16]. A request for any of them is the IP request
[IP §6.1] with:

- `subject` `{"full_history": null}` [ER §3.1]: the holder's stream;
- `coverage` `{"expected_pin": <the anchor>}`;
- `derivation` `"standard_history/1"`, `"standard_history/2"` or `"standard_history/3"`;
- `profile` `"evidence-interop/0"`.

Everything §1 to §9 say of a card holds under `/1` and `/2` unless it names one, and under `/3`
as §11 says. A responder answers a request with a card of the token the request names, never of
another one. A
responder whose records do not give a deal's agreed amount cannot fill that deal's `/1` entry
(§5.2), so it cannot answer `/1`: it refuses the request with reason `no_such_subject` [IP §6.3,
ER "The Signed Refusal"]. It never leaves the deal out of a `/1` card, and it never fills an
amount it was not given; it can answer `/2`.

The responder answers with an IP envelope [IP §6.2] whose `artifact` is UTF-8 of JCS of the card
(§4).

- **Recipient-free.** The token carries no recipient, and nothing in the card depends on who
  asked. The card is caller-invariant for (subject, anchor, derivation) [ER §5]: the policy, the
  deals and their entries are all read from the holder's book at the anchor.
- **Who is answered** is the holder's policy, not this document. A responder that declines a
  requester refuses `policy_declined` or `not_authorized` [IP §6.3].
- **Declared field set.** The card's members (§4). The card reveals no record, no record member
  and no record digest [ER "Derivation-Scoped Disclosure"]. The material of §6 "Handing the
  material" is not part of this answer: it is handed to one recipient, under the holder's own
  disclosure policy, and the card's bytes are the same with or without it.
- **Inclusion.** IP registers no verification-material kind for a derivation's artifact, so
  `anchor_inclusion` is `NOT_CHECKED` for a card [IP §6.2, P-13], as for PH §6.1. A card answer
  carries no `verification` member. The anchor's witness Receipts travel beside the card, as for
  `history_card/1`, each a `cll-witness-receipt` [IP1 §6.2.2]. How they travel is the host's, as
  for the policy (SH-9). A verifier that holds them runs `anchor_witnessed` [IP1 §6.2.2] over the
  card's `anchor`. A Receipt covers the anchor, not the card, so `anchor_inclusion` stays
  `NOT_CHECKED` whatever it reports.

## 4. The card

A `/1` card is a JSON object with exactly these members, all REQUIRED. A `/2` card has exactly
the same members and `unpriced`, all REQUIRED:

| Member | Value |
|---|---|
| `derivation` | the token: `"standard_history/1"` or `"standard_history/2"` |
| `holder_kind` | `"person"` or `"node"`: the kind of holder the holder key answers for, as the holder's own controller declaration states it |
| `controller_class` | the class of that declaration: `"person_declared"` on a `person` card and `"node_declared"` on a `node` card, and no other value in `/1` or `/2`. Finer classes of a node's declaration are SH-5 |
| `anchor` | the anchor the card is as of: equal to the envelope's `anchor.digest` |
| `since` | the year and month of the holder stream's first checkpoint, `YYYY-MM` |
| `window` | the policy's window (§5.1): `{"months": N}` with `N` a positive integer, or `{"all": true}` |
| `policy` | the digest of the policy in force at the anchor (§5.1) |
| `in_window` | tally: `of` (deals in the window), `counted`, `not_counted` |
| `class_missing` | tally: `of` (counted deals), `count` (counted deals that carry no `counterparty_class`) |
| `outcomes` | tally over counted deals: `of`, `held`, `did_not_hold`, `undecided` |
| `bands` | an array of band tallies (below) |
| `unpriced` | `/2` only. Tally over counted unpriced deals: `of`, `held`, `did_not_hold`, `undecided` |
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
  outcome's count. On a `/2` card, the bands and `unpriced` together do: the bands' `of` and
  `unpriced.of` sum to `outcomes.of`, and for each outcome the bands' counts and `unpriced`'s
  count sum to that outcome's count;
- in each dispute tally, `by_outcome.of` and `by_forum.of` equal its `of`.

No other member is allowed in either token's card, at any level. Any change to a member, a value
list or a counting rule of `/2` is `/3`, and `/1` stays as it is. Nothing is extended in place.

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

The `/2` card over the same deals, none of them unpriced, has `derivation`
`"standard_history/2"` and also carries
`"unpriced": {"did_not_hold": 0, "held": 0, "of": 0, "undecided": 0}`.

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
to one requester sends a different disclosure, never a `standard_history/1` or `/2` card (SH-6).

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
| `amount` | REQUIRED in `/1`; OPTIONAL in `/2` | the SR amount triple | the deal's agreed amount [SR "Amounts"]. Under `/2`, absent when the holder's records do not give it |
| `outcome` | REQUIRED | `held`, `did_not_hold` or `undecided` | the verdict of the deal's outcome claim [RES §4]: `met` is `held`, `not_met` is `did_not_hold`, and anything else, a missing claim included, is `undecided` |
| `happened` | REQUIRED | `stamped_by_both`, `receipt_only` or `no_record` | §5.5 |
| `disputes` | REQUIRED | an array, possibly empty, of `{"side", "outcome", "forum"}` | §5.4 |

A deal entry is never disclosed by a card. A host MUST NOT fill a member from text it was not
given for that member: a deal it cannot classify is `undecided`, `no_record` or without
`counterparty_class`, never guessed. So too for `amount` under `/2`: a deal whose records do not
give its agreed amount has no `amount`, never an estimated or zero one, and a host whose records
give the amount fills it. A zero amount (`value` `"0"`) is an amount the records give, not a
missing one.

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
- Under `/2`, a counted unpriced deal is counted like any other counted deal: in `in_window`,
  `class_missing`, `outcomes`, `roles`, `happened` and its disputes. It has no value band: it is
  in `unpriced`, by its outcome, and in no band, not even a zero-amount band. A card carries no
  amount and no sum of amounts, so it adds to no sum either. A counted deal that is not unpriced
  is in its band and never in `unpriced`.

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

A verifier reports these properties of a card, in the IP §7.1 vocabulary [SH-1]. It checks a card
under the token the request named: a `/1` card answering a `/2` request, or a `/2` card answering
a `/1` request, fails `card_form`.

| Property | Check | Needs |
|---|---|---|
| `card_form` | the card carries exactly §4's members for the token, at every level, with the values §4 fixes for each; `since` is `YYYY-MM` in ASCII digits; each `currency` is of §4's form; `bands` is sorted as §4 says, with no two entries for one band. It does not check that a tally carries `of`, or that a count is an integer | the card |
| `counts_integral` | every JSON number in the card, at every level, is an integer of at most 2^53 - 1 in magnitude, and 0 or more except a band's `decade` (§4 "Counts") | the card |
| `denominator` | every tally carries `of`; its counts partition `of` (for `class_missing`, `count` is at most `of`); every band's `of` is 1 or more; the tallies agree as §4 says. `NOT_CHECKED` when `card_form` or `counts_integral` is `FAIL` | the card |
| `window_from_policy` | the card's `window` equals the policy's window, and its `policy` the policy's digest. `NOT_CHECKED` without the policy | the policy's two members (§5.1) |
| `as_of` | the card's `anchor` equals the anchor the envelope names, and its `since` is the year and month of the stream's first checkpoint. `NOT_CHECKED` without the anchor | the anchor, its time, the first checkpoint's time |
| `counts_recompute` | every count of the card equals the count §5 derives, over the card's own `window`, from the deal entries. `NOT_CHECKED` without the deal entries of every deal the stream holds at the anchor, shown complete (§6 "Handing the material"), or without the anchor, or when `card_form`, `counts_integral` or `denominator` is not `PASS`. It does not need the policy: whether the card's window is the policy's is `window_from_policy` | the deal entries of every deal the stream holds at the anchor, shown complete; the anchor's time |

A card is a **standard card** when every property is `PASS` or `NOT_CHECKED`, and `card_form`,
`counts_integral` and `denominator` are `PASS`: HF §4.5's rule, with `window_from_policy`, `as_of`
and `counts_recompute` as the properties that may be `NOT_CHECKED`. A verifier that does not hold the deal entries
reports `counts_recompute` `NOT_CHECKED` and shows the counts as the holder's statement under the
holder key, not as recomputed. A property `FAIL` means the card is not a standard card: a
verifier shows none of its counts.

The card properties never change an envelope property or an IP §8 status. A card makes no outcome
claim for a requirement to meet, and a requirement is never `SATISFIED` from a card alone.

**Handing the material (SH-3).** A holder that wants a recipient to recompute a card's counts
hands it `evidence-bundle/v2` Bundles [EB], one per log the anchor commits. This adds no member,
derivation or token, and it is not a disclosure of SH-6: it changes neither the card nor its
`coverage_kind`. Each Bundle's `records` are Capsules: the records the deal-entry mapping of the
host's profile reads (SH-2), including the sealed records whose payloads carry the Results, the
counterparty halves and the dispute statements. The holder includes only the records its own
disclosure policy lets this recipient have, a policy this document does not define; the recipient
learns nothing it may not already see. A Bundle's `root` is any record it carries and means
nothing here, and its `completeness.records_mode` is not read: it describes citation closure from
the `root`, not coverage.

The recipient's verifier forms the deal entries (§5.2) by the host profile's mapping and reports
which mapping it applied; with none for the card's host, `counts_recompute` is `NOT_CHECKED`. It
passes the deal entries to the check only when it has shown **coverage**:

- **(a)** the anchor's own log: every leaf from `seq` 1 to the anchor is a supplied record with
  its per-record membership established, or a `padding` leaf [EB "Non-Record Leaves"], none listed
  in `completeness.missing`, and the interval coverage claim established against the anchor [EB
  "Completeness Claims and Log Membership"], neither claim labelled `checkpoint_unverified`. A
  non-record leaf of any type but `padding` is not accepted: EB checks nothing further about it, so
  it could hide a deal record;
- **(b)** every other log the anchor commits, none excluded: the same, from `seq` 1 to the extent
  the anchor commits for it. A recipient cannot tell a log the mapping reads from one it does not
  unless it holds it. The set of committed logs must be in a form the recipient can check against
  the anchor. An anchor that commits its logs through a salted or sparse tree does not enumerate
  them, and this revision defines no disclosed form of that set (SH-10): for such an anchor
  coverage cannot be shown, and `counts_recompute` is `NOT_CHECKED`.

With coverage shown, a payload member the mapping reads that a Bundle withholds [EB "Bundle-Level
Disclosures"] still makes the result `NOT_CHECKED`: a missing input would otherwise read as
`undecided`, `no_record` or no `counterparty_class` (§5.2) and turn an honest card into a `FAIL`.
Otherwise the check runs: every count equal is `PASS`, any difference `FAIL`. A `FAIL` therefore
never comes from a partial handover, and the holder's own number of deals, `in_window.of`, is never
what shows completeness. A card with `in_window.of` 0 recomputes `PASS` over coverage with no deal
in it.

The consequence is stated plainly: `PASS` needs every record of every log the anchor commits, deal
records and others. A disclosure policy that shows a recipient only its own deals leaves
`counts_recompute` `NOT_CHECKED` for any holder with other deals; a verifier shows that as the
card's counts being the holder's statement (above), not as a defect of the card or the holder.

**What a verifier shows** for a standard card, in this order: that the counts cover counted deals
in the stated window, how many deals in it were not counted, and how many counted deals are
`undecided`; on a `/2` card, how many counted deals have no recorded amount and so are in no
band, as `unpriced.of` of `outcomes.of`; each count with its `of` on the same line; which checks ran and which did not,
including `anchor_inclusion` `NOT_CHECKED`, `anchor_witnessed` with its status, and, without
their inputs, `window_from_policy`, `as_of` and `counts_recompute` `NOT_CHECKED`. It shows the
bands grouped by `currency`, each band with its own currency, and never merges bands of two
currencies into one row or shows a band in another currency: amounts in different assets are never equal or converted [SR "Amounts"
rule 4]. It shows `unpriced` apart from the bands, never as a band, a currency or a zero amount. It shows no ratio of two counts, in figures, words or a graphic, but for the outcome bar
below, which draws the counts and is not itself a ratio; and it never ranks or grades the holder.

**The outcome bar.** A verifier MAY draw the `outcomes` tally's `held`, `did_not_hold` and
`undecided` counts as one bar (HF §4.6 "A count bar"): three segments, in that order, the lengths
of the three counts out of `of`, drawn with the three counts and each count's `of` shown beside
the bar, as above. `undecided` is drawn in a tone that is neither the colour of
`held` nor of `did_not_hold`. No other tally of the card is drawn as a bar, the bar never replaces
the counts, and a card whose `outcomes.of` is 0 has none. This display rule has no vector: a vector
checks a card's properties (§6), not how a verifier draws it.

**The witness line.** A witness Receipt covers the anchor, the snapshot the card states it is as
of, and not the card's counts (§3). A verifier that ran `anchor_witnessed` [IP1 §6.2.2] over the
card's `anchor`, with a witness policy the relying party set, and got `PASS` MAY say that the
snapshot was witnessed: at the anchor's witnessed time and by the witness IP1 §6.2.2 pairs with it,
named as the relying party's policy names it, or with no time when no passing Receipt has one. It
shows that a witness entered that anchor digest in its log, not that the anchor is a well-formed
checkpoint of the holder's log, nor that it is the anchor the envelope names; `as_of` checks that. It says so only of a standard card. It MUST NOT pair one
Receipt's time with another Receipt's witness, and it MUST NOT say or imply that the witness
checked, saw or confirmed the counts, the deals or the card: those stay the holder's statement
under the holder key. Otherwise, with a Receipt that came with the card, the verifier
MAY say that one came with it and that it was not checked, or say nothing about a witness; it
MUST NOT say that a witness saw, checked or witnessed the snapshot or the card.

**Vectors.** `vectors/standard-history-v0/` holds positive cards, among them a window across a
year end, a sub-unit deal with a negative decade and a zero amount, and negatives each failing the
property named: a share stated as a fraction (`counts_integral`), a percentage member
(`card_form`), a count without its denominator (`denominator`), tallies that disagree
(`denominator`), a shop purchase counted (`counts_recompute`), a window not in the policy
(`window_from_policy`), a counterparty member (`card_form`), a free-text `currency`
and a free-text node `controller_class` (`card_form`), a `since` finer than a month or in other
digits (`card_form`), bands out of order or repeated (`card_form`), an empty band
(`denominator`), and another anchor (`as_of`), among others. The `/1` cases are in `vectors.json`.
The `/2` cases are in `vectors-2.json`: a card with two unpriced deals of different outcomes,
which the totals count and no band does, and negatives each failing the property named: the
unpriced deals left out of every tally (`counts_recompute`), counted in a band (`counts_recompute`), counted in `unpriced`
but not in the outcomes (`denominator`), a `/2` card without `unpriced`, a `/1` card with it, a
`/1` card answering a `/2` request and the reverse (`card_form`), and `unpriced` with a currency
(`card_form`).

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
  aggregate. `unpriced` shows only how many counted deals have no recorded amount. A `currency` is an asset code, never free text, but a CAIP-19 asset type names a
  token contract, and a token one business issued can name that business. Which deals a card
  counts, and so which asset codes it shows, is the holder's control through the policy.
- **The holder's levers.** The holder's own records set `counterparty_class` and the outcome
  claim. Marking a deal `shop_preauth` takes it out of every count but `in_window`, and never
  recording an outcome claim leaves it `undecided`. The card shows both, as
  `in_window.not_counted` and `outcomes.undecided`, and a verifier shows them (§6). Under `/2`,
  never recording a deal's amount takes it out of the bands but not out of any other count: the
  card shows it as `unpriced`, and a verifier shows that too. Leaving out the amount never hides
  the deal, and `/1` gives a host no way to leave the deal out instead (§3).
- **Small counts.** A card with few deals in a band, or one dispute, can still tell a recipient
  who knows one of the deals something about it. The window and the bands are the holder's
  control, through the policy.
- **Differencing.** A card counts over a window that ends at any anchor, with no floor (§5.1).
  Two cards at consecutive anchors can be subtracted, and the difference can isolate one deal:
  a recipient that holds both learns about the deals that entered or left the window between
  them, even though each card alone shows deals only in aggregate. This document sets no floor
  and no period rule (HF-1). A holder key that also serves Standard Histories under
  `inference-service-history/0` serves no `standard_history/1` or `/2` card: a holder that serves both
  under the same key is out of conformance by ISH's text already
  (`spec/inference-service-history-profile-v0.md` §6.1 item 8; HF §4.8).
- **Same bytes for every requester.** A card is recipient-free (§3): two requesters who compare
  their cards learn only that they asked the same holder at the same anchor. A recipient that does
  not hold the policy cannot check the window (§6 `window_from_policy` `NOT_CHECKED`), so a card
  with another window is then the holder's statement too.
- **The holder's statement.** The holder key signs the counts. Without deal entries shown
  complete a recipient cannot recompute them (§6). A valid signature never shows that the counts are right, only that
  the holder stated them.
- **Handed material.** The Bundles of §6 "Handing the material" hold only records the holder's
  own policy lets this recipient have, so they disclose nothing beyond it. With the anchor's log in
  hand, whether a handover is partial or complete tells the recipient nothing the log sizes the
  anchor commits do not already show. The Bundles are per recipient and are not a
  `standard_history/1` answer.
- **No grading.** As HF §4.6: this document defines no score, grade, ratio or ordering, and a
  verifier that follows it shows none. The outcome bar §6 allows draws the same three counts; it is
  not a ratio and never a rate.

## 10. Open points

| # | Point |
|---|---|
| SH-1 | The card properties (§6) as properties in IP's vocabulary that are not IP §7.2 envelope properties and never enter the IP §8 mapping, as PH's PA-10. The History frame states this for every instance (HF §4.4). |
| SH-2 | Filling the deal entry (§5.2) from a host's records: which record gives `agreed_at`, `role` and `amount`, and which claim is a deal's outcome claim. A host profile states its mapping, as `spec/deal-reconcile-contract-v0.md` §4.2 does for a half. |
| SH-3 | Closed (§6 "Handing the material"): the carriage is one `evidence-bundle/v2` per log the anchor commits, and `counts_recompute` needs coverage shown. ER asks a derivation's result to be re-derivable by the requester; this revision meets that only with that material, and only where coverage can be shown (SH-10). |
| SH-4 | Closed for the anchor: a card's page checks the anchor's witness Receipts with `anchor_witnessed` (IP1 §6.2.2, §6 "The witness line"). Still open: a verification-material kind that proves a derivation's artifact against the anchor (IP P-13), as PH's PA-13, without which `anchor_inclusion` stays `NOT_CHECKED` and no Receipt says anything about a card's counts; and carrying the Receipts in the envelope's `verification` instead of beside the card. |
| SH-5 | Finer `controller_class` values for a node's declaration, and the node's further counts, such as counts per tier of paired answers and of referee findings. This revision defines a `node` card with the same members as a `person` card. The further counts belong in a separate derivation token for nodes, so that `/1` and `/2` stay the same for every holder. |
| SH-6 | A disclosure wider than the policy's window, sent to one requester at the holder's choice. It declares the IP §6.7 coverage kind `holder_selected` and is never a `standard_history/1` or `/2` card. |
| SH-7 | Reading a dispute's `outcome` and `forum` (§5.4) from the resolving process's statement: IP §11.2.6's statuses (`open`, `upheld`, `dismissed`, `conflicting`) do not say for whom a resolution found, and IP names no forum. |
| SH-8 | Carrying `counterparty_class` in SR's terms leg, whose `settlement` member is closed in -00. Until a revision lists it, it is carried in another record of the deal (§7). |
| SH-9 | Handing a recipient the policy, or the two members of it the card reads (§5.1), so that `window_from_policy` can run. Until a carriage is defined, a recipient's verifier reports it `NOT_CHECKED`, and the window is the holder's statement. |
| SH-10 | A disclosed, checkable form of the set of logs an anchor commits, for an anchor that commits them through a salted or sparse tree, such as a batching tree whose root is a parent log's entry. Without it, coverage (b) of §6 "Handing the material" cannot be shown for such an anchor, and `counts_recompute` stays `NOT_CHECKED`. |
| SH-11 | Restating, in this repository, the rule that computes a term row's status (§11.2). `/3` cites EBL's rule (`rowstatus/rowstatus.go` at the commit the dependency table pins) and does not restate it; until it is restated, a second implementation of a host computes row results to EBL's vectors (`testdata/row-status/`). |
| SH-12 | Counting the deals whose line rests on a row result computed from a record with no time (a local result, EBL `rowstatus` `Local`). `/3` carries no such count: a verifier shows a card whose anchor has no passing Receipt as unwitnessed (§11.8), and no count says how many of its rows are local. |
| SH-13 | A window membership rule that a reader without status openings can check, such as the first witnessed time of a book's first fact in place of `agreed_at`, with a check of a window alone instead of a whole shelf (the target design's proposal of 2026-11-16 for evidencebook#461, not adopted). `/3` keeps `agreed_at` (§5.1, §11.2). |
| SH-14 | The wire form of the whole-shelf handover `/3`'s `counts_recompute` reads (§11.7), as SF-7. Until it is defined, the handover is EBL's form, and a verifier that does not read it reports `counts_recompute` `NOT_CHECKED`. |

## 11. `standard_history/3`

`standard_history/3` counts the holder's deals in the window its policy sets, as `/2` does, from a
different source: each deal's term rows, read from the holder's shelf log of book facts [SF] as of
the anchor. Its card has `/2`'s members with three changes: the three outcomes become five lines
(§11.3), one of them, `did_not_hold`, is split four ways in a tally of its own (§11.4), and the card
carries the coverage start of the shelf log (§11.5). Everything §1 to §9 say of a `/2` card holds of
a `/3` card, `/2`'s rules wherever they name a token, except where this section says otherwise.
`/1` and `/2` are unchanged by it, in every member, value, rule, document and vector.

### 11.1 The anchor and the deals

- **The anchor** is a shelf checkpoint [SF §1] at or after the coverage start (§11.5). The
  holder's stream is its shelf log, and `since` is the year and month of the shelf log's first
  checkpoint, as §4 says of the stream.
- **The deals** are the books whose `book_id` appears in a book fact [SF §3.2] of the shelf log up
  to the anchor and whose status value the host's mapping reads as a deal (SH-2), each at its
  latest book fact up to the anchor. A journal fact [SF §3.3] is no deal, and neither is a book of
  profile `none`. A deal that has not started, whose book holds no agreement, has no deal entry and
  is in no tally.
- **As of the anchor's time.** Each deal's row results (§11.2) are computed as of `T`, the anchor's
  time, from the status value of its latest fact [SF §4.2]. A deal whose book has not changed since
  its last fact is counted by its rows' dates and `T`, so its line can change from one anchor to the
  next with no new fact.

### 11.2 The deal entry

A `/3` deal entry has `/2`'s members (§5.2), with `amount` OPTIONAL as under `/2`, except:

| Member | Presence | Value | Filled from |
|---|---|---|---|
| `outcome` | absent | | `/3` reads no outcome claim |
| `rows` | REQUIRED | a non-empty array of row results (below) | each term row of the deal, as of `T` |
| `left_out` | OPTIONAL | `"no_witness_time"` | present when the deal's agreement names witnesses and the holder holds no registration time from any of them for the deal's records (EBL `RecordTime`) |

A **row result** is `{"owed_by", "status", "value", "remedy"}`:

| Member | Presence | Value |
|---|---|---|
| `owed_by` | REQUIRED | `holder` when the holder owed the row, `counterparty` when the other side did |
| `status` | REQUIRED | one of the ten statuses of EBL's rule, below |
| `value` | exactly when `status` is `waiting`, `uncontested`, `agreed_so_far`, `agreed` or `ruled` | `met` or `not_met`: the value the status carries (for `ruled`, the ruling's) |
| `remedy` | exactly when `status` is `ruled` | `none`, `due`, `made` or `not_honoured`: the remedy the ruling ordered and its state |

The statuses, as EBL's rule computes them from both sides' statements on the row and its dates
(SH-11): `not_reached` (a date of the row hangs on a record whose time was not known by that
record's latest date), `not_due` (no statement, up to and including the due date), `no_statement`
(no statement after the due date), `waiting` (one side's statement, inside the contest window),
`uncontested` (one side's statement, after the window), `agreed_so_far` (both sides' statements the
same, inside the window), `agreed` (the same, after it), `in_disagreement` (the statements differ,
or the row's recomputed check failed), `in_dispute` (a dispute in time and not withdrawn, or two
conflicting final rulings) and `ruled` (the first final ruling of the adjudicator the agreement
names; its remedy `not_honoured` when the remedy's date passed without one).

A host fills each row result by that rule, from the status value of the deal's latest fact, as of
`T`. It MUST NOT fill a row result it did not compute by the rule, and a host that cannot compute a
row's result from what it holds cannot fill the deal's entry, so it cannot answer `/3`: it refuses
with reason `no_such_subject`, as §3 says of `/1`. It never leaves the deal or the row out. A deal is
**counted** under `/3` when it is in the window and neither its `counterparty_class` is
`shop_preauth` nor it carries `left_out`; `in_window.not_counted` counts both kinds of deal, and
§5.3's other rules hold unchanged.

### 11.3 The outcome lines

A counted deal falls in exactly one of five lines, the first in this order that applies:

| Line | When |
|---|---|
| `ruling_not_honoured` | a row is `ruled` with remedy `not_honoured` |
| `undecided` | a row is `in_disagreement`, `in_dispute`, `no_statement` or `not_reached`, or is `waiting` with value `not_met` |
| `did_not_hold` | a row is `agreed_so_far`, `agreed`, `uncontested` or `ruled` with value `not_met` |
| `held_so_far` | a row is `not_due`, or is `waiting` or `agreed_so_far` (with value `met`, since the lines above did not apply) |
| `held` | every row is `agreed`, `uncontested` or `ruled` with value `met` |

The lines cover every deal: a deal no line above `held` applies to has only rows that `held` names.
A `not_reached` row is `undecided`: its date can no longer be set, so whether it was met cannot be
decided, as §5.2 counts a deal it cannot classify.

### 11.4 The split of `did_not_hold`

A `did_not_hold` deal is in exactly one of four parts, the first in this order that applies. Its
**unmet rows** are the rows the line's condition names: `agreed_so_far`, `agreed`, `uncontested` or
`ruled`, with value `not_met`.

| Part | When |
|---|---|
| `not_remedied` | an unmet row is owed by the holder and is not `ruled`, or is `ruled` with remedy `none`: no remedy is made or ordered |
| `remedy_pending` | an unmet row is owed by the holder and is `ruled` with remedy `due` |
| `remedied` | the unmet rows owed by the holder, one or more, are all `ruled` with remedy `made` |
| `other_side` | every unmet row is owed by the counterparty |

### 11.5 The coverage start

The **coverage start** is the shelf checkpoint that ends the format switch's stamp [SF §3.6]: the
point from which the shelf log carries a fact for every change of every book. The card carries
`coverage_start`, the year and month of that checkpoint's time, `YYYY-MM`, never before `since`.
A shelf log whose first entry document is its marker has a coverage start in the month its facts
began; one migrated from an older form has `since` from its first checkpoint and its coverage start
at the migration.

The card claims nothing complete before the coverage start, whatever `since` says: the books held
at the switch are counted from the genesis facts the switch wrote for them, and what each held
before the switch is the holder's statement, unless a reader checks the tie of a genesis fact to an
older witnessed checkpoint (EBL design §2.7), which this document does not count.

### 11.6 The card

A `/3` card is a JSON object with exactly these members, all REQUIRED:

| Member | Value |
|---|---|
| `derivation` | `"standard_history/3"` |
| `holder_kind`, `controller_class`, `anchor`, `since`, `window`, `policy` | as §4 |
| `coverage_start` | the year and month of the coverage start (§11.5), `YYYY-MM` |
| `in_window` | tally: `of` (deals in the window), `counted`, `not_counted` (§11.2) |
| `class_missing` | as §4 |
| `outcomes` | tally over counted deals: `of`, `held`, `held_so_far`, `did_not_hold`, `undecided`, `ruling_not_honoured` (§11.3) |
| `did_not_hold` | tally over counted `did_not_hold` deals: `of`, `not_remedied`, `remedy_pending`, `remedied`, `other_side` (§11.4) |
| `bands` | an array of band tallies: `{"currency", "decade", "of"}` and the five lines, as §4 orders them |
| `unpriced` | tally over counted unpriced deals: `of` and the five lines |
| `roles`, `happened`, `disputes` | as §4 |

**Denominators.** §4's rules hold with the five lines in place of the three outcomes: the bands and
`unpriced` together partition `outcomes`, line by line. Also, `did_not_hold`'s parts partition its
`of`, and its `of` equals `outcomes.did_not_hold`.

No other member is allowed in a `/3` card, at any level. Any change to a member, a value list or a
counting rule of `/3` is a new token, and `/3` stays as it is.

**Example** (members in JCS order):

```json
{"anchor": "<64 hex>", "bands": [{"currency": "USD", "decade": 1, "did_not_hold": 1, "held": 1, "held_so_far": 1, "of": 3, "ruling_not_honoured": 0, "undecided": 0}],
 "class_missing": {"count": 0, "of": 3}, "controller_class": "person_declared", "coverage_start": "2026-11",
 "derivation": "standard_history/3",
 "did_not_hold": {"not_remedied": 0, "of": 1, "other_side": 1, "remedied": 0, "remedy_pending": 0},
 "disputes": {"raised": {"by_forum": {"auto": 0, "external": 0, "network": 0, "of": 0, "rail": 0},
                         "by_outcome": {"against": 0, "for": 0, "no_finding": 0, "of": 0, "open": 0, "split": 0, "withdrawn": 0}, "of": 0},
              "received": {"by_forum": {"auto": 0, "external": 0, "network": 0, "of": 0, "rail": 0},
                           "by_outcome": {"against": 0, "for": 0, "no_finding": 0, "of": 0, "open": 0, "split": 0, "withdrawn": 0}, "of": 0}},
 "happened": {"no_record": 0, "of": 3, "receipt_only": 1, "stamped_by_both": 2}, "holder_kind": "person",
 "in_window": {"counted": 3, "not_counted": 1, "of": 4},
 "outcomes": {"did_not_hold": 1, "held": 1, "held_so_far": 1, "of": 3, "ruling_not_honoured": 0, "undecided": 0},
 "policy": "<64 hex>", "roles": {"bought": 1, "of": 3, "provided": 2}, "since": "2026-03",
 "unpriced": {"did_not_hold": 0, "held": 0, "held_so_far": 0, "of": 0, "ruling_not_honoured": 0, "undecided": 0},
 "window": {"months": 3}}
```

### 11.7 Card properties

A verifier reports §6's six properties of a `/3` card, with these changes:

- **`card_form`** checks §11.6's members and values. `coverage_start` is `YYYY-MM` in ASCII digits
  and not before `since`. A `/3` card answering a `/1` or `/2` request, or a `/1` or `/2` card
  answering a `/3` request, fails `card_form`.
- **`denominator`** checks §11.6 "Denominators".
- **`as_of`** also checks that `coverage_start` is the year and month of the coverage start's
  time; it needs that time beside the anchor's and the first checkpoint's.
- **`counts_recompute`** checks every count against the count §11 derives, over the card's own
  window, from the deal entries of every deal of the shelf log at the anchor, shown complete. For
  `/3`, complete is shown by the whole-shelf handover (EBL design §2.7; SH-14), not by §6's
  Bundles: every shelf log entry up to the anchor, recomputing the anchor; every entry document
  after the marker, hashing to its entry; each book fact's status opening verifying against its
  commitment [SF §4.1]; each book checkpoint hashing to its fact; and the chain of each book's facts
  unbroken. A handover that passes these checks enumerates the books the anchor commits, so §6's
  coverage (b) and SH-10 do not arise for `/3`. The verifier forms each deal entry from the latest
  fact's status opening by the host's mapping (SH-2) and the row rule (§11.2), as of the anchor's
  time, and reports which mapping it applied; with none, or without the handover, or when the
  handover fails a check, `counts_recompute` is `NOT_CHECKED`. A book the card leaves out, or a
  book counted that the handover does not hold, makes the counts differ: `FAIL`.

The properties that may be `NOT_CHECKED` are `window_from_policy`, `as_of` and `counts_recompute`,
as under `/1` and `/2`.

**Unknown format.** A verifier that does not implement `/3`, given a `/3` card, reports its
`derivation` as unknown, checks no property of it and shows none of its counts: never `PASS`. A
`/3` verifier given a `/1` or `/2` card checks it as §6 says, under the token the request named.

### 11.8 What a verifier shows

For a standard `/3` card, §6 "What a verifier shows" holds, with the five lines in place of the
three outcomes and these additions:

- **The split.** `did_not_hold`'s four parts, each with its `of`, beside the `did_not_hold` line.
- **The coverage start.** That the counts are complete from `coverage_start` on, and that before it
  they are the deals the holder carried into its shelf log at the switch (§11.5).
- **The level reached.** Whether the counts were recomputed (`counts_recompute` `PASS`) or are the
  holder's statement, and, separately, whether the anchor was witnessed (`anchor_witnessed` `PASS`
  with a registration time) or not. A card whose anchor has no passing Receipt is shown as
  **unwitnessed**: a shelf with no witness is a supported default, and its card is still a standard
  card. A card neither recomputed nor witnessed is shown as checked for its form only. A Receipt
  says nothing of the counts (§6 "The witness line").

**The outcome bar.** A verifier MAY draw the `outcomes` tally as one bar (HF §4.6), with five
segments in the order `held`, `held_so_far`, `did_not_hold`, `undecided`, `ruling_not_honoured`,
under §6's rules for the bar. `undecided` and `held_so_far` are drawn in tones that are neither
`held`'s nor `did_not_hold`'s. The `did_not_hold` split is never drawn as a bar.

### 11.9 Security and privacy considerations

§9 holds for `/3`, and:

- **Finer lines.** Five lines and a split of four parts say more about each deal than three outcomes
  do. With few counted deals, a recipient who knows one deal can learn its line, such as a ruling
  the holder did not honour. The window and the bands remain the holder's control, through the
  policy.
- **A second date.** `coverage_start` is a year and month, as `since` is: it shows when the holder
  moved its shelf to book facts, and nothing of any deal.
- **The holder's levers.** Marking a deal `left_out` takes it out of every count but `in_window`, as
  `shop_preauth` does, and the card shows it as `in_window.not_counted`. Never stating on a row
  leaves it `no_statement` after its due date, so `undecided`, never `held`.
- **Differencing.** As §9. A holder key that serves Standard Histories under
  `inference-service-history/0` serves no `standard_history/3` card either, for the reason §9
  gives.
- **No grading.** As §9: the lines are counts, never a rate, and a verifier ranks no holder by them.

### 11.10 Vectors

`vectors/standard-history-v0/vectors-3.json` holds the `/3` cases, each naming its token in
`inputs.derivation`: a card over deals that fall in every line and every part of the split, with a
deal whose rows make two lines apply (the first wins), a deal left out without a witness time, an
unpriced deal and two bands; the same deals at a later anchor, where a deal with no new fact moves
from `held_so_far` to `held` and another from `held_so_far` to `undecided`; and negatives each
failing the property named: a deal counted in a later line than the first that applies
(`counts_recompute`), a deal left out counted (`counts_recompute`), a split that does not sum to the
`did_not_hold` line (`denominator`), a band that counts by three outcomes (`card_form`), a card
without `coverage_start` (`card_form`), a `coverage_start` before `since` (`card_form`), a
`coverage_start` that is not the coverage start's month (`as_of`), a `/2` card answering a `/3`
request and the reverse (`card_form`).
