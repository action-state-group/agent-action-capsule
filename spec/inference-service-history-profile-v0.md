# Inference-Service History Profile — v0

**Status.** Informational host profile, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft and no part of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v0.md`, cited here as IP). It is written against IP's request, envelope,
recipient-specific disclosure, coverage declaration, per-property status and result-mapping rules,
and uses them unchanged. Where it needs a rule IP does not state, it states the rule as its own and
lists it under [Open points](#13-open-points) (SH-1, SH-2, …).

A History under this profile shows what one node or service recorded about the exchanges it took
part in: how many it served and how many it requested, over which checkpoints, with which witness
receipts and referee verdicts, and which exchanges the other party's own signed half confirms. It
establishes nothing about the correctness of any answer, and it ranks no one.

This revision defines two History levels:

- the **Standard level**: the same bytes for every requester at one anchor. It embeds the
  `history_card/1` answer unchanged and carries counts per closed period, under the
  anti-differencing rules of §6;
- the **Detailed level**: a recipient-specific projection [IP §6.5] that carries the exchanges the
  node had with one recipient, each with the node's signed half and, where held, the other party's.

The personal-agent History profile (`spec/personal-agent-history-profile-v0.md`) is a sibling host
profile. The two families are separate subjects. They compose only by an explicit, evidence-backed
link between their keys, never by being shown together.

The Standard History derivation `standard_history/1` (`spec/standard-history-v0.md`) is a separate
derivation with its own purpose: one card that counts a holder's deals over a window ending at any
anchor, with no period floor. It is not this profile's Standard level, and this revision does not
reconcile the two. A node that serves this profile's Standard Histories serves no
`standard_history/1` card under the same key (§6.1 item 8). Their labels do not map onto each
other: `stamped_by_both` there is not `peer_confirmed` here. The two documents number their open
points (SH-n) independently.

## Dependency boundary

**Owns:** the frame of a definition document under this profile (§4.1), how its coverage
declaration is carried (§4.2), the members of each level (§4.3, §4.4), the units and labels a
History is counted and shown in (§5, §7), the period rules (§6), the artifact form (§8.2), the
History properties (§8.3) and what a verifier shows (§8.5).

**Uses unchanged:**

| Tag | Document | What this profile takes from it |
|---|---|---|
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the request (§6.1), the envelope and its signing input (§6.2), signed refusals (§6.3), recipient-specific disclosures as definition-digest derivations (§6.5), the coverage declaration, its properties and issuer independence (§6.7), the per-property statuses (§7), the result mapping (§8), the acceptance record and its session scope (§11.1), lifecycle statements (§11.2), carriage and discovery (§11.4) |
| ER | `draft-mih-agent-evidence-request` -01 | the `full_history` and `range` subject forms [ER §3.1], what a record carries [ER §3.1.1], derivation by definition digest [ER §3.3], the signed refusal [ER §4.2], caller invariance [ER §5], derivation-scoped disclosure [ER §8], the history card `history_card/1` [ER §8.1] |
| RES | `spec/evidence-result-v0.md` | claim, sufficiency and verdict |

Section numbers for ER are those of the rendered `.txt` of the -01 revision. IP pins ER -00;
every ER section cited here other than §3.1.1 has the same number in -00. A requirement
written `[IP §6.5]` is taken from IP; `[SH-n]` marks one this profile adds.

**Does not define:** any record format, any identity scheme, any trust policy, who may receive a
History, or what a recipient should conclude. It defines no figure that combines units, labels or
nodes, no score, and no ordering of nodes, providers or exchanges. Nothing in a History is an input
to routing or provider selection, and a verifier that follows this profile outputs none.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from IP §1 and ER §2 are used unchanged. This profile adds:

- **Node:** the service whose evidence stream a History reads.
- **Node key:** the key that signs every envelope of a History (§2).
- **Exchange:** one request and its answer between the node and another party.
- **Half:** one party's own signed record of an exchange. The node's half is in the node's
  stream; the other party's half is in that party's stream.
- **Peer:** the other party of an exchange, when it records a half of its own.
- **Period:** a closed, aligned time interval fixed by a period policy (§6.1).
- **Cell:** one count, in one unit, for one period, optionally for one value of a stated dimension.
- **Recipient:** at the Detailed level, the principal the definition names; the only requester
  answered under it.

## 2. Subject

The subject of a History is the **node key**: the `responder` key of every envelope in it
[IP §6.2]. It is not an operator, a person, a model or a machine. A label attached to the key is
the node's own statement and is never checked by this profile.

- Every envelope of one History MUST name the same `responder` [SH-1]. Records signed under two
  keys, including one node's keys before and after a rotation, are two Histories.
- Every request names the subject `{"full_history": null}` [ER §3.1]: a History reads the node's
  evidence stream up to the anchor. A request under a History definition with any other subject
  form is refused (§8.4).
- A History is answered at one anchor, a checkpoint of the node's stream, named in the request's
  `expected_pin` and the envelope's `anchor.digest` [IP §6.1, §6.2].
- Checkpoint continuity, a witness receipt or a valid signature never shows that the node ran a
  model, ran it correctly, or ran the model it names. A verifier MUST NOT present any of them as
  such.

## 3. Levels

| Level | Who may ask | Bytes | Carries |
|---|---|---|---|
| Standard | any requester the node's policy admits; every admitted requester gets the same bytes | the same for every requester at one (subject, anchor, derivation) [ER §5] | the history card; counts per closed period; optionally verdict counts |
| Detailed | only the recipient its definition names [IP §6.5 item 4] | the same for every request under its definition [IP §6.5 item 2] | the history card; the exchanges with the recipient, each with the node's half and the peer's half where held, and the session agreement each cites |

A Standard History has no member whose content depends on who asks. Peer halves, record bodies and
anything released to one counterparty belong to a Detailed History, which is a different
derivation with a different identifier, and is never presented as the Standard one [IP §6.5
item 3].

## 4. Disclosure identification

### 4.1 The definition document

A History is a derivation identified by the digest of its definition document: the 64-hex SHA-256
of UTF-8 of JCS of the document [ER §3.3; IP §6.5 item 1]. The request's `derivation` is that
digest. The definition's `name` is what people read, never what the wire carries, and is not sent
as a registered token.

IP leaves the member names of a definition document open (IP P-14). This profile does not fix one
definition. It fixes the **frame** every definition under it carries, so that a host's own
definition conforms to this profile by its digest [SH-2]:

| Member | Value |
|---|---|
| `profile` | `"inference-service-history/0"` |
| `name` | a text string of lowercase ASCII letters, digits and `_`, then `/` and a version number |
| `kind` | `"projection"` |
| `level` | `"standard"` or `"detailed"` |
| `embeds` | `["history_card/1"]` |
| `subjects` | `["full_history"]` |
| `members` | the closed list of members this definition may carry (below) |
| `reads` | the union of every member's `reads`, in member order, without duplicates: the declared field set [ER §8] |
| `excludes` | what the definition never reads, stated so a reviewer can check it. At the Standard level it MUST include `"requester identity"` |
| `coverage_declaration` | the coverage declaration (§4.2) |
| `period_policy` | Standard level only, REQUIRED: the period policy (§6.1) |
| `recipient` | Detailed level only, REQUIRED: the recipient's principal reference [ER §3.7; IP §6.5 item 1] |
| `spec` | the location of the host's human-readable account of this definition |

No other member is allowed. Each `members` entry is an object with:

- `name`: unique in the list;
- `required`: a boolean. `history_card` is present at both levels and is required;
- `derivation`: for an embedded derivation, its identifier. For `history_card` it is
  `"history_card/1"`;
- `reads`: the fields the member reads;
- `units`: a non-empty array of `{"where", "unit"}`, one entry per count the member carries,
  naming its unit from §5.1. No count is in two units;
- `claims`: OPTIONAL. Where the member carries a statement made by the node about something the
  node's log does not show, such as a model, hardware or an execution environment, it is
  `{"asserted_by", "label", "where"}`, `where` an array of locations, and a verifier shows each
  value at those locations under that label
  (§8.5).

Any change to a member, to `reads`, to the period policy or to the coverage declaration is a new
version, with a new definition and a new digest. Nothing is extended in place. A host's definition
whose digest is fixed before it carries `profile`, `coverage_declaration` and, at the Standard
level, `period_policy` does not conform to this profile, and conforms only as a new version that
carries them [SH-13].

### 4.2 Coverage declaration

Every definition carries `coverage_declaration` [IP §6.7]:

- **Standard:** `{"kind": "stream_interval", "rule": "all_records"}`. A Standard History is every
  record of the node's stream up to the anchor.
- **Detailed:** `{"kind": "holder_selected"}`. The node lists the exchanges it chose to show the
  recipient; completeness is not asserted [SH-9].

A Standard definition is answered at every anchor, so it cannot name one. IP §6.7 places the
whole declaration in the definition [IP P-58], and lets a host profile name another member *of
the definition* as the declaration; it does not provide for part of a declaration to be carried
in the artifact. This profile does that, as its own rule, and asks IP for it [SH-3]: a Standard
declaration is the definition's `coverage_declaration` together with the artifact's
`coverage_declaration` (§8.2), which repeats `kind` and `rule` and adds the members that depend on
the anchor. Each answer is its own set, read against its own artifact's members:

- `interval`: `{"from": null, "to": <the anchor digest>}`. A Standard History always starts at
  the beginning of the stream; an interval starting later is not provided for in this revision;
- `live_set`: one entry, `{"stream", "checkpoint", "start", "count"}`, where `stream` is the
  artifact's `evidence_stream`, `checkpoint` is the anchor digest, `start` is 0 and `count` is the
  log size at the anchor.

The coverage properties are IP §6.7.2's, read over that pair:

| Property | Standard | Detailed |
|---|---|---|
| `coverage_declaration_form` | the definition's member is exactly the value above, and the artifact's carries exactly `kind`, `rule`, `interval` and `live_set` in their forms, with `kind` and `rule` equal to the definition's | the definition's member is exactly `{"kind": "holder_selected"}` |
| `coverage_declaration_anchor` | `interval.to` equals the envelope's `anchor.digest`, and `interval.from` differs from it | not reported |
| `coverage_declaration_population` | `NOT_CHECKED`: a count carries no records to compare with `count` [SH-4] | not reported |
| `coverage_declaration_commitment` | `NOT_CHECKED`, as in IP §6.7.2 | not reported |

IP §6.7.2's population check compares the records carried with `count`. A counts member carries
no records, so read literally that check could only fail; this profile reports it `NOT_CHECKED`
instead, as its own rule [SH-4]. A verifier therefore never reports a Standard History as complete.
It reports the declared kind `stream_interval` over the node's stream at the anchor, and states
that completeness is not established because the counts were not checked against records. By IP
§6.7.3 item 4, no requirement whose condition needs completeness is `SATISFIED` from it.

### 4.3 The Standard level

| Member | Required | Content |
|---|---|---|
| `history_card` | yes | the `history_card/1` artifact for the same subject and anchor (§5.2) |
| counts | at least one | one or more members of period counts (§6), each declaring its units |
| verdict counts | no | referee verdicts about the node's own exchanges, under §5.3 |

The counts members' shapes are the host's. Their rules are §5 to §7, §10 and §5.3. The vectors fix
one shape for themselves only (§9).

### 4.4 The Detailed level

| Member | Required | Content |
|---|---|---|
| `history_card` | yes | as at the Standard level |
| `exchanges` | yes | one entry per exchange the node shows the recipient (§7.2) |

Every entry is an exchange between the node and the recipient: a node MUST NOT include an
exchange with any other party, or another party's half. A verifier cannot check this from the
artifact alone; the relying party's policy binds the recipient's principal reference to the keys
whose halves may appear.

The definition names its recipient, so a host does not write it into the node's evidence stream,
where other requesters could be served it. A request under it from any other requester is refused
(§8.4). Possessing the definition grants nothing.

## 5. Units and sources

### 5.1 Units

Every count states its unit, from this closed list [SH-5]:

| Unit | Counts |
|---|---|
| `exchanges_served` | exchanges in which the node's half records that it served |
| `exchanges_requested` | exchanges in which the node's half records that it requested |
| `exchanges_unattributed` | exchanges whose half records neither role, or both |
| `checkpoints` | checkpoints of the node's stream |
| `witness_receipts` | witness receipts over those checkpoints |
| `referee_verdicts` | referee verdicts, under §5.3 |
| `records` | records of the node's stream |

- A served exchange and a requested exchange are never counted together. No count is in two
  units, and no figure adds counts of different units, labels, nodes or periods.
- A count in `exchanges_served` reads no requester-identity field.
- There is no total across units, no rate, no ratio and no score.

### 5.2 Checkpoints and witness receipts

`checkpoints` and `witness_receipts` are not stated by the node. A verifier counts them in the
embedded history card:

- The embedded `history_card` MUST be byte-identical to the `history_card/1` artifact the node
  serves for the same subject and anchor. Because JCS is compositional, UTF-8 of JCS of the
  member equals that artifact's octets, and its SHA-256 equals the artifact's
  `history_card_digest` (§8.2). A requester that needs the card as a standalone artifact under its
  own envelope sends the direct `history_card/1` request at the same anchor and compares digests.
- The card's checkpoints run from the stream's first checkpoint to the anchor [ER §8.1]. A card
  that does not verify (a checkpoint not signed by the stream's log key, a consistency proof that
  does not chain, a receipt that does not cover its checkpoint) fails `history_card_content`.
- A receipt counts only after the verifier checks it, offline, under a witness key the relying
  party's policy configures. A receipt under a key the policy does not configure is shown and not counted,
  with that reason. A key accepted on first contact is labelled as such, apart from a configured
  key.
- A History whose card carries no receipt is shown as "no witness named", not as a failure.
- A witness receipt shows that a later rewrite of the checkpoint is detectable. It shows nothing
  about the records' content.

### 5.3 Referee verdicts

These are rules for the responder, applied under the node's own policy when it counts; a verdict
count is the node's statement and is labelled `self_reported`. Where the verdicts themselves are
carried, a verifier applies the same rules under the relying party's policy. A referee verdict
about one of the node's exchanges counts only when [SH-10]:

1. it is signed by the referee under a key the policy accepts;
2. it cites the request the node itself made of that referee, and the exact pair of halves it
   compares; and
3. the referee was eligible: the referee's own signed statement in the verdict names how it was
   selected, the referee is party to neither half, and it served the model and weights the two
   halves state.

Verdict counts stay four separate counts, `corroborated`, `contradicted`, `inconclusive` and
`not_comparable`, each in the unit `referee_verdicts`, with "not adjudicated" and its reason shown
apart and counted against no one. A verdict in a History is the node's held record of its own ask,
labelled with whose ask it was. A History carries no verdict about another node's exchanges. A
verdict says nothing about the node's other or later answers. Verdict counts at the Standard level
are period counts (§6), floor included.

## 6. Period counts

A count over a node's stream discloses cadence, volume and use. Two counts over overlapping
intervals can be subtracted, and the difference can be one exchange. So every count of exchanges,
verdicts or sessions a Standard History carries is a **period count**, under these rules, which
are REQUIRED of the responder [SH-7]. The history card's checkpoints and receipts are not period
counts: the card discloses each checkpoint's log size exactly (§12).

### 6.1 Periods

The definition's `period_policy` is a JSON object with exactly:

| Member | Value |
|---|---|
| `epoch` | a time |
| `length_s` | the period length in seconds, a positive integer, at least `min_length_s` |
| `min_length_s` | the minimum period length the policy allows, a positive integer |
| `floor` | the per-cell floor, a positive integer |
| `suppression` | `"complementary"` (§6.2) |

Period *k*, for any integer *k*, is the half-open interval [`epoch` + *k* · `length_s`,
`epoch` + (*k* + 1) · `length_s`).
A record is in a period by the time the node's stream committed it.

1. **Aligned.** A period count names a period of the policy, by its `from` and `to`, and no other
   interval.
2. **Closed.** A period is counted only when the anchor's checkpoint time is at or after its end.
   The period the anchor falls in is never counted. A Standard History is answered only at an
   anchor whose checkpoint time is a period boundary, `epoch` + *k* · `length_s` for an integer
   *k*; such a checkpoint commits only records of the periods before it. A request naming any other
   anchor is refused `policy_declined`, the same for every requester. A node serving Standard
   Histories therefore checkpoints its stream at the boundaries it answers at. The answer keeps the
   anchor's exact log size (§4.2, §12).
3. **Non-overlapping and complete.** A counts member lists its periods sorted by `from`, each
   once. It lists every closed period from the stream's first period to the anchor and leaves none
   out: the first is the period that holds the stream's first record, each later one starts where
   the one before it ends, and the last ends at the anchor. A period in which the node recorded
   nothing is listed too, its cells suppressed below the floor like any other (§6.2).
4. **Fixed once produced.** A period's cells are fixed when first produced. Every later answer, at
   any later anchor, carries that period with the same cells; it never drops it. A record
   committed later is never counted in an earlier period.
5. **No other interval.** A request for counts over any interval that is not a run of whole closed
   periods, such as a `range` subject [ER §3.1], is refused `policy_declined`, the same for every
   requester. This is IP §6.3's exception: the more specific `no_such_subject` would tell the
   requester which intervals the policy protects.
6. **One policy per node.** Every Standard definition a node serves uses the same `epoch` and
   `length_s`. Two definitions with offset or different periods could be subtracted from each
   other.
7. Each counts member names its policy by the digest of `period_policy` (SHA-256 of UTF-8 of JCS).
   A verifier shows the policy's `length_s` and `floor` beside the counts. This profile sets no
   minimum for either; whether a policy is strong enough is the relying party's judgement (SH-7).
8. **No `standard_history/1` beside it.** A node that serves Standard Histories under this profile
   MUST NOT serve a `standard_history/1` card (`spec/standard-history-v0.md`) under the same node
   key. That card counts over a window that ends at any anchor, with no floor, so two of its cards
   at consecutive checkpoints could be subtracted to isolate one exchange that these periods
   protect (§12).

### 6.2 Floor and complementary suppression

1. A cell whose value is below `floor` is **suppressed**: it is published with no value and the
   reason `below_floor`. A suppressed cell is never published with a value.
2. The floor applies per period and per cell, never only to the whole answer.
3. **Complementary suppression.** A cell whose value could be derived from published cells and
   totals is suppressed with them, with the reason `complementary`. At the least: where a unit's
   total for a period is published and exactly one of its dimension cells is suppressed, the
   smallest other dimension cell is suppressed too [SH-8].
4. A dimension value that names a model or other claim is the node's statement, declared in the
   member's `claims` (§4.1).

### 6.3 Period properties

Each is reported in the IP §7.1 vocabulary:

| Property | Check |
|---|---|
| `period_alignment` | every period of every counts member is aligned to the policy's epoch, has exactly the policy's length, is closed at the anchor, and starts at the end of the period before it; the first starts before the time of the card's first checkpoint that commits a record, and the last ends at the latest period boundary at or before the anchor (§6.1 item 3); the member names the policy's digest |
| `period_anchor` | the anchor's checkpoint time is a period boundary (§6.1 item 2) |
| `period_floor` | no published cell is below the floor, every suppressed cell has no value and the reason `below_floor` or `complementary`, and §6.2 item 3 holds |
| `period_fixed` | over two or more Histories under one definition held by one verifier, every period of a History is carried, with the same cells, by every History at a later anchor |

`period_fixed` is reported only by a verifier that holds two or more such Histories. A verifier
that holds one states that it was not checked.

## 7. Exchanges and labels

### 7.1 The three labels

Every count and every exchange entry carries a label. From weakest to strongest [SH-6]:

| Label | Means | Reached when |
|---|---|---|
| `self_reported` | the node's own log says so | always: every count, and every exchange without a confirming peer half |
| `peer_confirmed` | the other party's own signed half is held, verified under that party's key, and joined to the node's (what it does not show: §7.2) | §7.2 holds |
| `corroborated` | the two halves come from distinct controllers | `issuer_independence` is `PASS` [IP §6.7.4], which no verifier built from this revision reports |

A Standard History's counts are always `self_reported`. A count of exchanges with a peer half
held, stated by the node, is still the node's statement. An exchange is `peer_confirmed` only
where the halves themselves are carried, which is at the Detailed level, or where the requester
holds its own half of the exchange and checks it against the node's half by §7.2, outside this
profile's answers.

### 7.2 Peer confirmation

An `exchanges` entry carries:

| Member | Value |
|---|---|
| `client_nonce` | the reference that joins the two halves, bound into both |
| `half` | the node's half, as signed, `{"media_type", "octets_text"}` or `{"media_type", "octets_hex"}` |
| `peer_half` | OPTIONAL: the peer's half, as signed, in the same form |
| `unit` | `exchanges_served` or `exchanges_requested`, by the role the node's half records |
| `label` | the label the node claims for the entry |

The node's half MUST verify under the node key. An exchange is `peer_confirmed` only when:

1. `peer_half` is present and verifies under its producer's key;
2. that key is not the node key. Two halves under one key are "redundant, not corroborating", and
   `issuer_independence` is `FAIL` [IP §6.7.4];
3. the relying party's policy accepts that key as the peer's;
4. both halves carry the same `client_nonce`, the node's half cites the peer's half by its digest
   in the member ER §3.1.1 designates for the half's format (for the vectors' format, a
   `references` entry with `citation_purpose` `counterparty_half`), and the two halves record
   opposite roles. The digest is SHA-256 of the peer half's octets as carried. Halves joined by a
   time window, or by an identifier each side minted on its own, are not joined.

Otherwise the exchange is `self_reported`, shown as "one-sided" (no peer half), "redundant, not
corroborating" (item 2), "peer half not verified under a trusted key" (item 1 or 3) or "not
joinable" (item 4). None of these is a failure of the History. A one-sided exchange is shown as
one-sided, never as a failure.

A `peer_confirmed` pair has `issuer_independence` `NOT_CHECKED` and is shown as "peer-confirmed;
not corroborating (independence not established)" [IP §6.7.4]. Two keys never show two parties.

`peer_confirmed` shows that the peer signed its own half with the same client nonce, and that the
node's half cites it. The citation is one-way: the peer's half need not cite the node's, so a
`peer_confirmed` served exchange shows that the peer signed its request, not that it received or
recorded the answer [SH-6].

### 7.3 Never stronger than the evidence

A label MUST NOT be stronger than what §7.1 and §7.2 derive [SH-6]. The History property `labels`
is `FAIL` when any count is labelled other than `self_reported`, or when any exchange entry's label
is stronger than the label its halves support. A valid envelope signature never makes a label.

## 8. Answers and acceptance

A History is accepted when IP's verifier accepts its envelope (§8.1), every History property
passes (§8.3), and no coverage property (§4.2) is `FAIL`.

### 8.1 Interop properties

Each exchange is verified exactly as IP §7.3 describes, with the requester's own retained request
octets. An envelope answering under this profile is accepted when `profile_version`,
`envelope_signature`, `responder_trust`, `issued_at_form`, `request_binding`, `subject_binding`,
`artifact_digest` and `anchor_match` are `PASS`, and `anchor_inclusion` is `NOT_CHECKED`: IP
registers no verification-material kind for a derivation's artifact (IP §6.2, P-13), so a History
answer carries no `verification` member, and `verification_binding` is not required [IP §7.2].

The IP §8 mapping applies unchanged, and IP §6.7.3 item 4 after it. With `anchor_inclusion`
`NOT_CHECKED`, a requirement a History answer is the only evidence for maps to row 4: status
`UNKNOWN`, sufficiency `UNKNOWN`, verdict `not_evaluable` [IP §8.1; RES]. A History never yields
`met` or `not_met` in this revision.

### 8.2 The artifact

The artifact is UTF-8 of JCS of one JSON object:

| Member | Value |
|---|---|
| `anchor` | the resolved anchor digest, equal to the envelope's `anchor.digest` |
| `derivation` | the definition digest, equal to the envelope's `derivation` |
| `subject` | `{"full_history": null}`, equal to the envelope's `subject` |
| `evidence_stream` | the node's stream |
| `declared` | the names of the members this artifact carries, sorted, without duplicates: every required member, and only members the definition lists |
| `history_card` | the embedded card (§5.2) |
| `history_card_digest` | SHA-256 of UTF-8 of JCS of `history_card` |
| `coverage_declaration` | Standard level only: the anchor-dependent declaration of §4.2 |
| each declared member | its content |

A member is present if and only if `declared` names it. No other member is allowed. Which members
are declared depends only on (subject, anchor, definition), never on who asks or when. When a
required member cannot be served under the node's current policy, the History is refused whole,
never served with the member dropped.

### 8.3 History properties

Each is reported in the IP §7.1 vocabulary [SH-11 for the list]:

| Property | Levels | Check |
|---|---|---|
| `definition_form` | both | the definition carries exactly the members of §4.1 for its level, with the values §4.1 fixes, its `coverage_declaration` is §4.2's for its level, and `reads` is the union of its members' `reads` |
| `definition_binding` | both | the envelope's `derivation` equals the SHA-256 of UTF-8 of JCS of the definition the requester holds |
| `artifact_form` | both | the artifact is §8.2's object for the definition's level; at the Detailed level every entry's `half` verifies under the node key, names the entry's `client_nonce` and records a role |
| `history_card_content` | both | §5.2: the card's digest, its anchor, its checkpoints' signatures and order, and every receipt's coverage of its checkpoint |
| `units` | both | every count's unit is in §5.1 and is a unit its member declares; at the Detailed level each entry's unit is the one its half's role gives |
| `labels` | both | §7.3 |
| `period_alignment` | Standard | §6.3 |
| `period_anchor` | Standard | §6.3 |
| `period_floor` | Standard | §6.3 |

`period_fixed` (§6.3) is a property of two or more Histories, not of one. The History properties
are checked only over an envelope accepted under §8.1. When `definition_form` is `FAIL` only
`definition_binding` is reported beside it, and when `artifact_form` is `FAIL` none after it is. A History
property that is not `PASS` means the History is not accepted, whatever the envelope's statuses
are. A History property never changes an envelope property or an IP §8 status.

### 8.4 Refusals

The node refuses with a signed refusal [IP §6.3]:

- a request under a Standard definition naming any subject other than `full_history`, or any
  interval that is not a run of whole closed periods: `policy_declined`, the same for every
  requester (§6.1 item 5);
- a request under a Standard definition at an anchor whose checkpoint time is not a period
  boundary: `policy_declined`, the same for every requester (§6.1 item 2);
- a request under a Detailed definition with any subject other than `full_history`:
  `policy_declined`;
- a request under a Detailed definition from a requester other than its `recipient`, after
  authenticating it: `policy_declined` [IP §6.3, §6.5 item 4]. A Detailed definition is a template
  plus a recipient, so anyone can compute the digest for a candidate recipient; `not_authorized`
  would tell them the node holds a Detailed History for that party. The node gives the same token
  for a digest it does not hold, where it would otherwise answer `derivation_unsupported`;
- a History whose required member cannot be served: the refusal the member's own derivation
  would give, and never a History with the member dropped.

### 8.5 What a verifier shows

A verifier showing an accepted History shows, in this order:

1. that every count is the node's own statement unless labelled otherwise, that continuity,
   receipts and signatures never show execution (§2), the coverage kind and what completeness is
   relative to (§4.2), before any count;
2. each count with its unit, its label and its period, each in its own row; each suppressed cell
   with its reason; each `claims` value under its member's `label`, as the node's statement;
   the policy's `length_s` and `floor`;
3. the checkpoints and the witness receipts counted, and each receipt not counted with its reason,
   or "no witness named";
4. at the Detailed level, per exchange: the label derived, how it is shown (§7.2) and
   `issuer_independence` where reported, beside the label the node claimed;
5. which checks ran and which did not, including `anchor_inclusion`,
   `coverage_declaration_population` and `coverage_declaration_commitment` `NOT_CHECKED`, and
   `period_fixed` where it held one History;
6. the limits of §12.

It shows no figure that combines units, labels or periods, and no ordering of nodes.

## 9. Acceptance vectors (informative)

The vectors are in `vectors/inference-service-history-v0/`.
`python/scripts/generate_inference_service_history_v0_vectors.py` generates them, and
`python/tests/test_inference_service_history_v0_vectors.py` checks them: every request and reply
through IP's reference verifier, and the History properties with an evaluator of its own. They pin
trust, verification policy, contract and evaluation time as IP §11.5 does.

These formats are fixed for the vectors only and are not registered [SH-12]:

- the definitions `service_history_example/0` (Standard) and `service_history_detail_example/0`
  (Detailed);
- a history card `{anchor, derivation, evidence_stream, history, subject}`, whose `history`
  entries are `{checkpoint, receipts}`, whose checkpoints are `{key_id, log_size, root, timestamp, sig}` and whose
  receipts are `{checkpoint, witness, sig}`, each `sig` Ed25519 over UTF-8 of JCS of the other
  members. Roots are label digests and no consistency proof is carried, so the vectors do not
  check the card's consistency;
- a period counts member `period_counts`: `{"policy", "periods": [{"from", "to", "cells":
  [{"unit", "label", "dimension", "value", "suppressed"?}]}]}`, with `dimension` null on a unit's
  total;
- a half: `{client_nonce, committed_at, producer, role, references?, sig}`.

### 9.1 Standard level

One node checkpoints its stream at noon each day and at each midnight it answers at. Answered at
the checkpoint of midnight on 4 October, it served 19, 12 and 11 exchanges on three closed days, over two models it states, and
requested 4, 2 and 1. The served-only History counts the served ones, per model and in total; the
requested ones are in no cell. On the second day one model's 3 is below the floor of 5, so it is
suppressed, and the other model's cell with it, because the total is published.

### 9.2 Two anchors

The same definition answered at the next boundary, midnight on 5 October, carries the same three
earlier periods byte for byte, and 4 October now closed. A later answer that changes or drops an
earlier period fails `period_fixed`. The checkpoint at noon on 4 October lies
inside the open day: a Standard History is refused there, and one answered there fails
`period_anchor`.

### 9.3 Detailed level

The node shows one recipient five exchanges. Only the first is `peer_confirmed`. The others are one
exchange with no peer half, one whose "peer" half the node key signed, one whose halves carry
different client nonces, and one whose half cites no counterparty half. Each is honestly labelled
`self_reported`, and the History is accepted.

### 9.4 The cases

| Case | Expected |
|---|---|
| `standard-served-only` | accepted; every History property `PASS`; population and commitment `NOT_CHECKED`, completeness not established; 2 receipts counted, 1 not counted (witness key not configured) |
| `mutant-count-mixes-units` | `units` `FAIL`: a cell counting served and requested together, in the unregistered unit `exchanges` |
| `mutant-standard-count-labelled-peer-confirmed` | `labels` `FAIL` |
| `mutant-overlapping-period` | `period_alignment` `FAIL` |
| `mutant-duplicate-period` | `period_alignment` `FAIL`: one aligned period listed twice |
| `mutant-open-period` | `period_alignment` `FAIL`: the day the anchor falls in is counted |
| `mutant-answered-at-open-anchor` | `period_anchor` `FAIL`: answered at the checkpoint of noon on 4 October |
| `mutant-short-period` | `period_alignment` `FAIL` |
| `mutant-omitted-first-period` | `period_alignment` `FAIL`: 1 October, the stream's first period, left out |
| `mutant-omitted-period` | `period_alignment` `FAIL`: 2 October left out between 1 and 3 October |
| `mutant-cell-below-floor` | `period_floor` `FAIL` |
| `mutant-complementary-not-suppressed` | `period_floor` `FAIL` |
| `periods-fixed-across-anchors` | `period_fixed` `PASS` |
| `mutant-period-changed-across-anchors` | `period_fixed` `FAIL` |
| `mutant-period-dropped-across-anchors` | `period_fixed` `FAIL`: the later History drops 2 October |
| `refused-range-interval` | signed refusal `policy_declined` |
| `refused-range-interval-other-requester` | the same token, for a second requester |
| `refused-open-period-anchor` | signed refusal `policy_declined`: asked at the checkpoint of noon on 4 October |
| `refused-detailed-other-requester` | signed refusal `policy_declined` |
| `detailed-peer-confirmed` | accepted; one exchange `peer_confirmed` with `issuer_independence` `NOT_CHECKED`, four `self_reported` (one-sided, redundant, two not joinable) |
| `mutant-labelled-corroborated` | `labels` `FAIL`: two keys, no evidence about their controllers |
| `mutant-same-key-halves-labelled-peer-confirmed` | `labels` `FAIL`; the pair is redundant |
| `mutant-unjoined-halves-labelled-peer-confirmed` | `labels` `FAIL` |
| `mutant-uncited-halves-labelled-peer-confirmed` | `labels` `FAIL` |
| `mutant-one-sided-labelled-peer-confirmed` | `labels` `FAIL` |
| `mutant-untrusted-peer-labelled-peer-confirmed` | `labels` `FAIL` |

In every case whose envelope is answered, the IP §8 mapping of the recipient's requirement is
`UNKNOWN`/`not_evaluable` (§8.1).

## 10. Session agreements

One accepted record MAY cover a bounded session of exchanges, so that each exchange cites the
agreement instead of negotiating again. This profile uses IP §11.1 unchanged for it:

- the agreement is an IP acceptance record whose `transaction` names the session and whose
  `session` carries its window and the digests of its policy and terms [IP §11.1.3];
- an exchange is covered by the agreement only when its execution records, the node's half
  among them, cite the acceptance's record digest and every time held for it lies within the
  session window [IP §11.1.3];
- "accepted before the action" is shown only with ordering evidence [IP §11.1.5]. Without it a
  verifier shows "agreement present; ordering not established";
- acceptance is not authority to spend or to bind a principal [IP §11.1.6].

An agreement has one counterparty, so counts per agreement would publish per-counterparty data
to every requester. A Standard History therefore carries no session counts. A Detailed History
shows, per exchange, the agreement its node's half cites and whether the exchange is covered; an
exchange outside the session's window or bound is shown as not covered. These are rules for the
responder; a verifier applies them where the acceptance record is carried.

## 11. Carriage

Requests and replies are carried by any IP carriage (the native stream, HTTP, A2A or MCP), with
IP's rules unchanged [IP §11.4]. The canonical artifact for one (subject, anchor, derivation) is
the same octets whatever the requester, nonce or carriage [ER §5]; each envelope binds one request
[IP §6.2].

- A node advertises that it answers History requests only if its operator chooses to. A discovery
  manifest MAY list a Standard definition's identifier. It never lists a Detailed definition, its
  identifier or its recipient, and never per-exchange identifiers [IP §11.4.3].
- Whether a Standard History is answered to requesters with no prior exchange with the node is
  the node's policy. When the policy declines, the refusal is `policy_declined`, the same for
  every such requester.

## 12. Security and privacy considerations

- **Cadence and volume.** A history card discloses a stream's cadence and volume [ER §12]. Counts
  disclose use. §6 bounds what a sequence of this profile's answers reveals; it does not make one
  answer reveal nothing.
- **Differencing.** Aligned, closed, non-overlapping, fixed periods, one policy per node and the
  per-cell floor with complementary suppression stop two period counts being subtracted to isolate
  one exchange. They do not cover the history card: every checkpoint's log size is exact, with no
  floor. Answering only at period boundaries (§6.1 item 2) stops an answer showing the stream's
  size inside a period that is still open. It delays, and does not remove, the card's disclosure:
  a later answer's card carries every earlier checkpoint, including those inside a period, each
  with its exact log size. A requester who already knows all but one
  exchange of a cell can still learn the last; the floor limits, and does not remove, what such a
  requester learns.
- **Another derivation of the same stream.** §6 bounds only this profile's answers. A
  `standard_history/1` card counts the holder's deals over a window ending at any anchor, with no
  floor: two such cards under the node key, at consecutive checkpoints, differ by what was
  committed between them, which can be one exchange. §6.1 item 8 therefore forbids a node that
  serves this profile's Standard level to serve that card under the same key. A verifier sees a
  breach only when it holds both answers.
- **Self-reported counts.** Every count is the node's statement over its own stream. The History
  artifact is not itself logged or inclusion-checked: a changed or dropped closed period is caught
  only by `period_fixed`, by a verifier that holds two answers. The population check is
  `NOT_CHECKED` for counts (§4.2).
- **What one key proves.** Every envelope verifies under the node key. That shows the key signed
  the answer, not who operates it, and not that the node is independent of any peer.
- **Peer halves.** A peer half shows that the peer's key signed its record. It does not show the
  peer is independent of the node (§7.2). A Detailed History reveals the peer's half to the
  recipient; the node releases it only under the peer's and its own policy.
- **Claims stay claims.** A model name, weights digest, hardware or execution-environment claim is
  the node's statement, shown as such, and never "ran" or "verified".
- **No ordering.** This profile defines no figure that orders, grades or selects nodes, providers
  or exchanges, and a verifier that follows it shows none and outputs none to a routing decision.

## 13. Open points

| # | Point |
|---|---|
| SH-1 | One node key per History. Composing Histories across a key rotation needs a signed link between the two keys. |
| SH-2 | The definition frame (§4.1), which IP leaves open as P-14. If IP fixes common member names, a later version adopts them. |
| SH-3 | A Standard declaration split between the definition (`kind`, `rule`) and the artifact (`interval`, `live_set`), because one Standard definition is answered at every anchor (§4.2). |
| SH-4 | `coverage_declaration_population` `NOT_CHECKED` for counts, which carry no records (§4.2). IP §7.1 could also be read to give `NOT_PRESENT`, which IP §6.7.3 item 4 maps to `INSUFFICIENT`; either way no completeness requirement is `SATISFIED`. A count checkable against records needs a disclosure of the records, or a verification-material kind for counts. Relatedly, ER §3.3 asks that a derivation result come with what the requester needs to check its binding; a count has nothing of the kind in this revision. |
| SH-5 | The closed list of units (§5.1). The requirements' roles `conflict` and `unknown` are both counted in `exchanges_unattributed`; a later revision may split them. |
| SH-6 | The labels and the peer-confirmation join (§7). The join's citation member is ER §3.1.1's. The citation is one-way; a two-way join (the peer's half citing the node's) would let `peer_confirmed` show receipt of the answer. `corroborated` needs evidence of distinct controllers in a form IP does not register (IP P-60). |
| SH-7 | The period rules (§6.1): time-aligned periods, answers only at period boundaries, the refusal token, fixed cells, one policy per node, no `standard_history/1` card under the same key. No profile minimum for `length_s` or `floor` is set. The history card's exact log sizes are outside the period rules (§12). |
| SH-8 | Complementary suppression (§6.2 item 3) fixed only for one suppressed cell beside a published total; larger tables of dimensions need a fuller rule. |
| SH-9 | The Detailed level declares `holder_selected`. A Detailed History complete relative to the node's exchanges with the recipient needs the records in a form whose population can be checked. |
| SH-10 | Referee verdict eligibility (§5.3): the form of the referee's selection statement is not fixed here. |
| SH-11 | The History properties (§8.3, §6.3) as properties in IP's vocabulary that are not IP §7.2 envelope properties and never enter the IP §8 mapping. |
| SH-12 | The vector-only formats of §9. |
| SH-13 | A host's definition conforms by its digest (§4.1). A host definition fixed before it carries `profile`, `coverage_declaration` and `period_policy` conforms only as a new version. |
| SH-14 | No vectors in this revision for: verdict counts and session coverage (§5.3, §10); `definition_form`, `definition_binding`, `artifact_form`, `history_card_content`, `coverage_declaration_form` or `coverage_declaration_anchor` failing; a key accepted on first contact; a count that mixes units under a registered unit, which needs the records to detect; a node that also serves `standard_history/1` under its key (§6.1 item 8), which a verifier sees only when it holds answers of both. |
