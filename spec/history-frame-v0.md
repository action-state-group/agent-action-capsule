# History Frame, v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft, no part of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v0.md` and `spec/interop-profile-v1.md`, cited as IP), and no member, value,
identifier or digest of the four documents it frames. Its own rules are §3 to §6. The questions
it leaves open are listed under [Open points](#9-open-points) (HF-1, HF-2, …).

This document defines one **History frame**: the rules every History shares, a closed set of
**frame parameters**, and two documents each instance supplies, a **counting table** and a
**wording pack**. A History is an instance of the frame: it sets its values of the parameters and
pins one table and one pack. Four instances exist, each defined by its own document:

| Tag | Document | Instance identifier |
|---|---|---|
| SH | `spec/standard-history-v0.md` | `standard_history/1` |
| PH | `spec/personal-agent-history-profile-v0.md`, Basic level | `personal_history_basic/1` |
| PO | `spec/personal-agent-history-outcome-v0.md`, Outcome level | `personal_history_outcome/1` |
| ISH | `spec/inference-service-history-profile-v0.md`, Standard and Detailed levels | `inference-service-history/0` |

Restating them as instances moves no wire byte. Every request, envelope, card, artifact,
definition and refusal of the four is what its own document already says, and so is every
vector of theirs.

**The premise, narrowed.** A unified History was first described as one shared period policy, one
per-cell floor and complementary suppression. Those rules exist only in ISH (ISH §6). This
revision narrows that premise: aligned closed periods, answers only at period boundaries, the
floor and complementary suppression stay ISH's, as the value `periods` of the parameter
`aggregation` (§3). Only the frame is unified. Imposing the period rules on another instance
changes what its cards or Histories say, and would be a new version of that instance's
identifier, not a restatement (HF-1).

## Dependency boundary

**Owns:** the frame parameters and their values (§3), the frame rules (§4), the form of a counting
table and of a wording pack (§5), the pinning rule (§5.4), the instance table and the documents it
lists in `spec/history-frame/` (§6.1), the document properties (§6.2) and the precedence rule
(§6.3).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) and `spec/interop-profile-v1.md` (`evidence-interop/1`) | the envelope (§6.2), signed refusals (§6.3), recipient-specific disclosures (§6.5), the coverage declaration and issuer independence (§6.7), the per-property vocabulary (§7.1), the result mapping (§8.1), discovery (§11.4.3) |
| ER | `draft-mih-agent-evidence-request` | the `full_history` and `correlation` subject forms [ER §3.1], derivation by registered token or by definition digest [ER "Derivation"; ER §3.3], caller invariance [ER §5] |
| SH, PH, PO, ISH | the four instance documents above | each instance's members, values, identifiers, properties and vectors, unchanged |

**Interop profile revision.** The frame is pin-neutral. Each instance keeps the IP revision it
pins (§3 `interop_pin`): SH, PH and PO stay on `evidence-interop/0`, and ISH is written against
`evidence-interop/1` and serves `evidence-interop/0` per request. The IP sections this document
cites are the same in both revisions. Re-pinning an instance is a revision of that instance.

**Does not define:** any member, value, identifier or digest of an instance, any record format,
any trust policy, who may receive a History, any score, grade, ratio or ordering, or what a
recipient should conclude.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from IP §1 and ER §2 are used unchanged. This document adds:

- **Frame:** the rules of §4 and the parameters of §3.
- **Instance:** a History defined by one identifier (§6.1), with its values of the frame
  parameters (per level, for an instance with levels), one counting table and one wording pack.
- **Subject key:** the key that signs every envelope of a History: SH's and PH's holder key, ISH's
  node key.
- **Counting table:** an instance's document naming what it counts, from what, in which units,
  and which properties it reports (§5.2).
- **Wording pack:** an instance's document of display strings (§5.3).
- **History property:** a property an instance reports of a History, a card or a claim, beside
  the IP envelope properties.

## 2. What the frame decides

The frame decides what every History says the same way: one subject key, one anchor, how an
envelope is accepted, how a History property is read, that a count is never combined into a
figure, how two subjects compose, and when a non-recipient is refused with which token. An
instance decides only what its parameters, its counting table and its wording pack say. An
instance's document states the rules that carry out its own parameter values, such as ISH's period
rules under `aggregation` `periods`; it never adds a rule that contradicts §4 or that needs a
parameter or value §3 does not list. Such a behaviour is a revision of this frame, never an
instance's own extension of it.

## 3. Frame parameters

The frame parameters are exactly these, each with exactly the values listed. An instance sets, for
each parameter, one listed value, or a set of listed values where its document allows several (as
PO's `coverage_kind`), and nothing else. An instance with levels (ISH) sets its values per level;
its levels share one identifier, one counting table and one wording pack. A parameter or value not
listed here is a revision of this document.

| Parameter | Values | What it decides |
|---|---|---|
| `identification` | `token`: a registered derivation token [ER "Derivation"]; `definition_digest`: SHA-256 of UTF-8 of JCS of a definition document [ER §3.3; IP §6.5] | what the request's `derivation` carries |
| `level` | `recipient_free`: every admitted requester gets the same bytes [ER §5]; `recipient_specific`: one recipient, named in the definition [IP §6.5] | who may be answered, and whether §4.9 and §4.10 apply |
| `subject_form` | `full_history`, `correlation` [ER §3.1] | the subject each request names |
| `coverage_kind` | an IP §6.7.1 kind: `stream_interval` (with the `rule` the instance requires), `holder_selected` or `source_authoritative`; or `policy_window`, a frame value only, never an IP §6.7.1 kind and never carried in a `coverage_declaration`: the holder's own statement that the card covers the deals of its book at the anchor within the window its policy sets, with no completeness asserted under IP §6.7 | what the History is complete relative to (§4.12) |
| `coverage_carriage` | `instance_text`: stated by the instance's document, no member; `completeness`: the definition's `completeness` member; `definition`: the definition's `coverage_declaration`; `definition_and_artifact`: split between the definition and the artifact | where the coverage kind is carried |
| `aggregation` | `window`: counts over a window ending at the anchor; `per_deal`: one state or claim set per selected deal, no count across deals; `periods`: counts per aligned closed period, under a floor and complementary suppression (ISH §6); `per_exchange`: one entry per exchange shown | how what is shown is grouped |
| `answer_anchor` | `any_checkpoint`; `period_boundary`: only a checkpoint whose time is a period boundary | which anchors a History is answered at |
| `streams` | `one`; `witnessed_tick`: one stream, or several at one witnessed checkpoint tick (PH §2) | how many evidence streams one anchor covers |
| `embeds` | `none`; `receipt_beside`: no `history_card/1` is carried, and the anchor's witness receipt travels beside the answer (SH §3 "Inclusion"); `history_card/1`: embedded, byte-identical [ER §8.1] | what the answer carries of the stream's checkpoints and receipts |
| `stated_by` | `responder`: the counts are the subject key's statement; `verifier`: the verifier derives what is shown from what is carried | who states each count, and so how a verifier labels it |
| `claims` | `none`; `requirement_results`: source-checked claims with requirement results of the instance's own (§4.13) | whether a requirement can be `SATISFIED` from the History |
| `interop_pin` | `evidence-interop/0`; `evidence-interop/1`, with `evidence-interop/0` negotiated per request | which IP revision requests and envelopes name |
| `non_recipient_refusal` | `none` (a `recipient_free` instance); `not_authorized`; `policy_declined` (§4.9) | the token a non-recipient is refused with |
| `policy_digest` | `none`; `policy_octets`: SHA-256 of the policy's octets as held; `period_policy_jcs`: SHA-256 of UTF-8 of JCS of the `period_policy` member | how the policy a count is read under is named |
| `container` | `none`; `one_file`: a one-file History container (PH §8.2) | whether a holder may hand a History over as one file |

Two further inputs are not parameters but documents, pinned by digest (§5, §6.1): the counting
table and the wording pack. Which of an instance's properties may be `NOT_CHECKED` (§4.5) is a
member of its counting table.

## 4. Frame rules

Every instance follows these rules. An instance's document may state them again, citing this
section, and may add its own rules, but never one that contradicts these.

### 4.1 One subject key

The subject of a History is its subject key: the `responder` of every envelope in it [IP §6.2]. It
is not a person, an account, an operator or a machine, and a label attached to it is the key
holder's own statement. Every envelope of one History MUST name the same `responder`. Records
signed under two keys, including one subject's keys before and after a rotation, are two
Histories.

### 4.2 One anchor

A History is answered at one anchor: every request names it in `expected_pin`, and every envelope
in `anchor.digest` [IP §6.1, §6.2]. Which anchors an instance answers at is its `answer_anchor`
and `streams`.

### 4.3 Envelope acceptance

Each exchange is verified as IP §7.3 describes, with the requester's own retained request octets.
An envelope answering a History is accepted when `profile_version`, `envelope_signature`,
`responder_trust`, `issued_at_form`, `request_binding`, `subject_binding`, `artifact_digest` and
`anchor_match` are `PASS`, and `anchor_inclusion` is `NOT_CHECKED`: IP registers no
verification-material kind for a derivation's artifact (IP §6.2, P-13), so a History answer
carries no `verification` member and `verification_binding` is not required [IP §7.2].

### 4.4 History properties

History properties are reported in the IP §7.1 vocabulary. They are not IP §7.2 envelope
properties, they never change an envelope property or an IP §8 status, and they never enter the
IP §8 mapping.

### 4.5 Acceptance

A History, card or claim is accepted only when every History property its instance reports for
it is `PASS`, except that a property the instance's counting table lists in `may_be_not_checked`
(for a claim, `claim_may_be_not_checked`) may be `NOT_CHECKED`. Those are the properties that
need an input outside the answer, such as a policy or the deal entries, which a verifier may not
hold. A property `FAIL` means not accepted: a verifier shows no count of a History or card that
is not accepted, and a claim that is not accepted does not count. How a coverage property of
IP §6.7.2 acts is the instance's: one the instance lists among its History properties is one
(PO §8.2 lists `coverage_declaration_form`); otherwise it acts as IP §6.7.3 says, and as the
instance's acceptance rule adds (ISH §8 accepts no History with a coverage property `FAIL`).

### 4.6 Counts, and no score, grade, ratio or ordering

Every count is in exactly one unit, from the instance's counting table, and no count is in two
units. Where an instance carries a count as part of a total, such as an SH tally's `of`, the count
is shown beside that total: "9 of 12", never "75%". No figure adds counts beyond the totals the
instance's own counting rules define (SH's tallies, ISH's per-period unit total), so no figure
adds counts of different units or subjects; an instance may forbid more, as ISH §5.1 forbids a
figure across labels or periods.

No instance defines a score, a grade, a ratio, a rate, a share, a mean or an ordering of subjects,
deals, exchanges or counterparties, and a verifier that follows an instance shows and outputs
none. A History stays the subject key's statement, never a requester's conclusion about it.

**A count bar.** An instance may allow a verifier to draw the parts of one of its tallies as one
bar, the lengths of its segments the parts' counts out of the tally's `of`. The bar adds no figure:
each part is shown with its count and the tally's `of` as above, and the bar is not labelled, worded
or coloured as a rate, a share, a score or a grade, is not ordered to rank, and is never drawn
across two tallies. A segment's colour says which part it is, never how good. An instance that
does not allow a bar shows none.

### 4.7 Composition only by an evidence-backed key link

Histories under two subject keys, whether of one instance or of two, are separate subjects. They
compose only by an explicit, evidence-backed link between their keys, never by being shown
together, by sharing a label, or by both verifying.

### 4.8 Differencing

Two counts over overlapping intervals can be subtracted, and the difference can be one deal or
one exchange. ISH's period rules bound that for its own Standard level (ISH §6). The frame
restates ISH §6.1 item 8 as it stands, and does not extend it: a node that serves Standard
Histories under `inference-service-history/0` MUST NOT serve a `standard_history/1` card under the
same key, because two such cards at consecutive checkpoints could be subtracted to isolate one
exchange the periods protect. A subject key that serves both is out of conformance by ISH's text
already; SH states the same exposure for its own cards (SH §9 "Differencing").

### 4.9 Refusing a non-recipient

A `recipient_specific` instance answers only the recipient its definition names, after
authenticating it [IP §6.5 item 4]. It refuses any other requester with a signed refusal
[IP §6.3]:

- where the definition digest is a function of a published template and a candidate recipient
  alone, anyone can compute it: the refusal is `policy_declined`, and the instance gives the same
  token for a digest it does not hold, because `not_authorized` would tell the requester that a
  History for that recipient exists (ISH §8.4, the ISH Detailed level);
- where the digest also covers a selection the holder makes for one recipient (PH, PO), the
  refusal MAY be `not_authorized`, or `policy_declined` where the more specific token would
  disclose what the policy protects [IP §6.3]. Such a digest is not secret: deal references are
  carried in the clear and are the same in every History that includes the deal (PH §4.5). A
  party that knows a whole selection, such as an earlier recipient of it, can compute the digest
  for a candidate recipient, and a `not_authorized` refusal can then tell it that a History under
  that digest is held. PH keeps `not_authorized`, which its acceptance vector signs (PH §6.4); a
  holder for whom that disclosure matters refuses `policy_declined`, as PH §8.1 allows.

Under both IP revisions, `not_authorized`, `policy_declined` and `derivation_unsupported` map to
`WITHHELD`, sufficiency `GAP`, verdict `not_evaluable` [IP §8.1]. Every refusal of a non-recipient
therefore reads `WITHHELD`, whichever token it carries: the choice changes no result, only what
the token tells the requester.

### 4.10 Discovery

A discovery manifest never lists a `recipient_specific` definition, its identifier, its recipient
or its deal or exchange references [IP §11.4.3]. It MAY list a `recipient_free` instance's
identifier.

### 4.11 No label stronger than its evidence

An instance that labels counts or entries by the strength of their evidence (ISH §7.1, PO §5,
SH §5.5) MUST NOT show a label stronger than what its own rules derive. A valid envelope signature
never makes a label, and two signatures never show two parties [IP §6.7.4].

### 4.12 Coverage stated

Every instance states its coverage kind (§3 `coverage_kind`) and where it is carried
(`coverage_carriage`). A valid signature never implies completeness [IP §6.7], and a requirement
whose condition needs the History to be complete is never `SATISFIED` from a History that does
not establish it [IP §6.7.3 item 4].

### 4.13 Result mapping

With `anchor_inclusion` `NOT_CHECKED` (§4.3), a requirement a History answer is the only evidence
for maps to IP §8.1 row 4: status `UNKNOWN`, sufficiency `UNKNOWN`, verdict `not_evaluable`. An
instance whose `claims` is `none` never yields `met` or `not_met`. Only an instance whose `claims`
is `requirement_results` evaluates requirements beyond that, by its own rules over claims checked
against their own sources; IP §6.7.3 item 4 and IP §6.7.4 apply after those rules, unchanged.

## 5. Counting tables and wording packs

### 5.1 The documents

A counting table and a wording pack are JSON objects. Each carries:

| Member | Value |
|---|---|
| `document` | `"counting_table"` or `"wording_pack"` |
| `frame` | `"history-frame/0"` |
| `instance` | the instance identifier (§6.1) |

A document's **digest** is the SHA-256 of UTF-8 of JCS of the document, as 64 lowercase hex
characters. The documents carry no numbers and only ASCII member names. The documents of this
revision are in `spec/history-frame/`.

### 5.2 The counting table

A counting table carries, besides §5.1's members, what the instance's document fixes about what
is counted: the record kinds or inputs read, the definition members and fixed values where the
instance has a definition document, the tallies, cells or states, the units, the evidence labels
where the instance has them, and the History properties it reports, in report order. It carries
`may_be_not_checked` (§4.5), and, for an instance with claims, `claim_may_be_not_checked`. Its
other member names are the instance's own. A counting table restates the instance's text; it adds
no rule (§6.3).

### 5.3 The wording pack

A wording pack carries exactly §5.1's members, `language` (a BCP 47 tag; `"en"` for every pack of
this revision) and `strings`: a non-empty object whose members name display strings and whose
values are non-empty text strings.

- A pack holds only what a verifier shows in words. It never holds a string that a property
  checks. So no pack string equals a member name or value that the instance's counting table
  carries: ISH's labels `self_reported`, `peer_confirmed` and `corroborated`, a record kind, or a
  card value such as `stamped_by_both` are counting-table strings, never pack strings.
- No pack string shows a label stronger than its evidence (§4.11). A pack can only word what the
  instance derives; it never changes what is derived.
- A verifier MAY show a translation of the pinned pack into another language. A translation is
  not a pack: it is not pinned, binds nothing and is never offered in place of the pinned pack
  (§6.2 `pack_binding`). Whoever makes a translation keeps each string's meaning, never
  stronger than the string it translates; no property checks this. A property-checked value is
  shown as itself.

### 5.4 Pinning

Each instance identifier pins the bytes of its counting table and its wording pack immutably: the
files §6.1 lists, whose digests are the ones §6.1 lists. Any change to either file's bytes is a new
version of the instance identifier (`standard_history/2`, `personal_history_basic/2`,
`personal_history_outcome/2`, `inference-service-history/1`), with new documents and new
digests, listed by a revision of this document. Nothing is changed in place, including a change
that would leave a digest unchanged.

The digests are not members of any signed definition, card or artifact. A verifier is never
handed a table or a pack with an answer: it holds them by the instance identifier the answer
already signs (the token, the definition's `name`, or the definition's `profile`).

## 6. Instances

### 6.1 The instance table

| Parameter | SH | PH | PO | ISH Standard | ISH Detailed |
|---|---|---|---|---|---|
| `identification` | `token` (`standard_history/1`) | `definition_digest` | `definition_digest` | `definition_digest` | `definition_digest` |
| `level` | `recipient_free` | `recipient_specific` | `recipient_specific` | `recipient_free` | `recipient_specific` |
| `subject_form` | `full_history` | `correlation` | `correlation` | `full_history` | `full_history` |
| `coverage_kind` | `policy_window` | `holder_selected` | any IP §6.7.1 kind; `stream_interval` only with rule `all_records` | `stream_interval`, rule `all_records` | `holder_selected` |
| `coverage_carriage` | `instance_text` | `completeness` | `definition` | `definition_and_artifact` | `definition` |
| `aggregation` | `window` | `per_deal` | `per_deal` | `periods` | `per_exchange` |
| `answer_anchor` | `any_checkpoint` | `any_checkpoint` | `any_checkpoint` | `period_boundary` | `any_checkpoint` |
| `streams` | `one` | `witnessed_tick` | `witnessed_tick` | `one` | `one` |
| `embeds` | `receipt_beside` | `none` | `none` | `history_card/1` | `history_card/1` |
| `stated_by` | `responder` | `verifier` | `verifier` | `responder` | `verifier` |
| `claims` | `none` | `none` | `requirement_results` | `none` | `none` |
| `interop_pin` | `evidence-interop/0` | `evidence-interop/0` | `evidence-interop/0` | `evidence-interop/1` | `evidence-interop/1` |
| `non_recipient_refusal` | `none` | `not_authorized` | `not_authorized` | `none` | `policy_declined` |
| `policy_digest` | `policy_octets` | `none` | `none` | `period_policy_jcs` | `none` |
| `container` | `none` | `one_file` | `one_file` | `none` | `none` |

ISH's two levels share one identifier, one counting table and one wording pack. Each instance's
documents and digests:

| Instance | Counting table | Wording pack |
|---|---|---|
| `standard_history/1` | `spec/history-frame/standard-history-1-table.json`: `31122b837d2bea44dd3f559ca90a69f666c146ebb3f1b4d9f7df1c1fd3d47c53` | `spec/history-frame/standard-history-1-pack.json`: `dcea1ee99942d0b4dc78b380b63f7854964d132925de18fdeb30b336e9877b74` |
| `personal_history_basic/1` | `spec/history-frame/personal-history-basic-1-table.json`: `d7f17129d98f5b849c59fb4d906bc3e9c57ce13fe08d00433fbe09161125ebb1` | `spec/history-frame/personal-history-basic-1-pack.json`: `b3e4868affdaeede5eeadb0d909d4e4f665260d6a68a3c10896ab9a0abf6be60` |
| `personal_history_outcome/1` | `spec/history-frame/personal-history-outcome-1-table.json`: `a332d408c5ea2566b8f650769f92044c1b075c028cfcd64b112b626fc7b7e97c` | `spec/history-frame/personal-history-outcome-1-pack.json`: `00dce14b0bfdda0187b274727dd34d7b6a8bd5d5bf3884b934f6840604fc6d47` |
| `inference-service-history/0` | `spec/history-frame/inference-service-history-0-table.json`: `3307e6f1e58759aea656b3e84afa8e21b00a14a260e5cc11513c379eb92c7057` | `spec/history-frame/inference-service-history-0-pack.json`: `693ae7f8f259ec37bf9b177f6373c295d6a851abf359859e8e5a3e627d08ed82` |

This table names this repository's identifiers only. A host's own definition under an instance
(for example an ISH definition a host publishes, which conforms by its digest, ISH §4.1) is not an
instance of its own and is not listed here.

### 6.2 Document properties

A verifier that holds an instance's documents reports, in the IP §7.1 vocabulary:

| Property | Check |
|---|---|
| `table_binding` | the counting table's digest (§5.1) equals the one §6.1 lists for the instance |
| `pack_binding` | the wording pack's digest equals the one §6.1 lists for the instance |
| `pack_form` | the pack carries exactly §5.3's members, its `document`, `frame` and `instance` are its own, every string is a non-empty text, and no string equals a member name or value its counting table carries |

A document whose property is not `PASS` is not the instance's document. A verifier does not use it
to show an answer. The document properties never change an envelope property, a History property
or an IP §8 status.

### 6.3 Precedence

The instance's own document is the source of truth, and its counting table and wording pack
restate it. If a document and the instance's text disagree, the change that made them disagree is
in error, and is corrected before it merges; neither is read as overriding the other in a
released revision. Each instance's vector generator loads its documents, checks their digests
against §6.1 and §6.2, and asserts that each document equals, member for member, the one its own
constants and cases give: what it emits, and, for a member its vectors do not emit, the
instance's text as the generator states it. It also derives `may_be_not_checked` from the
properties that are `NOT_CHECKED` in its accepted cases. A disagreement stops the generator.

## 7. Vectors

`vectors/history-frame-v0/` holds, for each instance, its two documents with the digests §6.1
lists, and negatives each failing the properties named: a pack label made stronger, so a
mismatched pack digest (`pack_binding`); a translation offered as the pinned pack
(`pack_binding`); a table with a member added (`table_binding`); a pack carrying a
property-checked string (`pack_binding`, `pack_form`); and a pack naming another instance
(`pack_binding`, `pack_form`). `python/scripts/generate_history_frame_v0_vectors.py` generates them
and `python/tests/test_history_frame_v0_vectors.py` checks them.

The generators of `vectors/standard-history-v0/`, `vectors/personal-history-basic-v0/`,
`vectors/personal-history-outcome-v0/`, `vectors/inference-service-history-v0/` and
`vectors/inference-service-history-v0-interop-v1/` load the same documents through
`python/scripts/history_frame.py` (§6.3). Those sets are unchanged by this revision.

## 8. Security and privacy considerations

- **Differencing.** Counts that end at any anchor can be subtracted (§4.8). The period rules bound
  that for ISH's Standard level only. Another instance's exposure is stated by its own document
  (SH §9 "Differencing").
- **Packs change no check.** A wording pack words what an instance derives and never holds a
  string a property checks (§5.3), so a changed or translated pack cannot turn a failed or weaker
  result into a stronger one. A verifier that shows a translation still checks under the pinned
  documents.
- **Pinned, not carried.** The documents are bound by the instance identifier the answer signs
  (§5.4), not carried with it. A verifier that holds documents whose digests do not match §6.1
  holds other documents (§6.2), whatever they say.
- **No personal data.** The documents name members, values and display strings only. They carry
  no subject, deal, exchange, key or counterparty.
- **No grading.** This document defines no score, grade, ratio or ordering, and a verifier that
  follows it shows none (§4.6).

## 9. Open points

| # | Point |
|---|---|
| HF-1 | The period rules (aligned closed periods, boundary anchors, floor, complementary suppression) for an instance other than ISH. This revision keeps them as ISH's `aggregation` `periods`. A recipient-free deal History with a floor is a separate instance or `standard_history/2`, never a change to `/1`. |
| HF-2 | Table and pack digests as members of each signed definition. This revision binds them through the identifier (§5.4) so that no definition digest moves. Carrying them in a definition is a new version of each instance, and SH has no definition document to carry them. |
| HF-3 | The Python and Go references reading display strings from the wording packs. This revision changes no reference; the vector generators check the documents (§6.3). |
