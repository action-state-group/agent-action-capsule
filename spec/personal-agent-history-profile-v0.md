# Personal-Agent History Profile — v0

**Status.** Informational host profile, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft and no part of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v0.md`, cited here as IP). It is written against IP's request, envelope,
recipient-specific disclosure, per-property status and result-mapping rules, and uses them
unchanged. Where it needs a rule IP does not state, it states the rule as its own and lists it
under [Open points](#10-open-points) (PA-1, PA-2, …).

This revision defines one History level, the **Basic level**: a holder's selection of their own
deals, answered under one signing key, that shows which deals were selected, when each recorded
step was committed, and whether each recorded step completed or failed. It establishes no outcome
of any deal. Outcome claims with source labels are the Outcome level,
`personal_history_outcome/1`, defined in `spec/personal-agent-history-outcome-v0.md` (PA-9).

A sibling host profile covers inference-service histories (IP §6.5 is the common mechanism). The
two compose only by an explicit, evidence-backed link, never by being shown together.

## Dependency boundary

**Owns:** the Basic level's definition document and its member names (§4.1), the record kinds the
Basic level reveals (§3), the artifact form of its answers (§4.3), the History properties and
the acceptance rule (§6), the History container (§8.2), and the units a History is counted in (§5).

**Uses unchanged:**

| Tag | Document | What this profile takes from it |
|---|---|---|
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the request (§6.1), the envelope and its signing input (§6.2), recipient-specific disclosures as definition-digest derivations (§6.5), the per-property statuses and catalogue (§7), the result mapping (§8), lifecycle statements and issuer rules (§11.2), carriage and discovery (§11.4) |
| ER | `draft-mih-agent-evidence-request` -00 | the `correlation` and `exchange` subject forms [ER §3.1], derivation by definition digest [ER §3.3], caller invariance [ER §5], derivation-scoped disclosure [ER §8] |
| EL | `draft-mih-agent-evidence-layer` -00 | the record header and its members, the epistemic types |
| RES | `spec/evidence-result-v0.md` | claim, sufficiency and verdict |

Section numbers for ER and EL are those of the rendered `.txt` of the revision IP pins. A
requirement written `[IP §6.5]` is taken from IP; `[PA-n]` marks one this profile adds.

**Interop profile revision.** This profile stays on `evidence-interop/0`: IP is
`spec/interop-profile-v0.md` as of commit `1456285979bd759b7828fd3ccc4a24296074e552`, which is
frozen, not `spec/interop-profile-v1.md` (`evidence-interop/1`). `evidence-interop/1` adds two
refusal rows to the result mapping this profile applies (IP v1 §8.1), and the requests and envelopes
of its vectors name `evidence-interop/0` (§4.3). Re-pinning to `evidence-interop/1` is a revision of
this profile.

**Does not define:** any record format, any identity scheme, any trust policy, who may receive a
History, or what a recipient should conclude. It defines no figure that combines deals, records or
steps, and no ordering of deals, holders or counterparties.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from IP §1 and ER §2 are used unchanged. This profile adds:

- **Holder:** the party whose agent recorded the deals, and who selects which of them a recipient
  receives.
- **Holder key:** the key that signs every envelope of a History (§2).
- **Deal:** every record the holder's evidence stream holds under one correlation identifier.
- **Deal reference:** that correlation identifier.
- **Selection:** the set of deal references the holder picked for one recipient.
- **History:** the definition document (§4.1) and one answered exchange per selected deal.
- **Recipient:** the principal the definition names; the only requester answered under it.

## 2. Subject

The subject of a History is the **holder key**: the `responder` key of every envelope in it
[IP §6.2]. It is not a person, a name or an account. A label the holder attaches to the key is the
holder's own statement and is never checked by this profile.

- Every envelope of one History MUST name the same `responder` [PA-1]. A History over records
  signed under two keys, including one holder's keys before and after a rotation, is two Histories.
- One History MAY span several evidence streams held under the holder key, for example one stream
  per deal. Every record of one deal MUST be held in one stream. Each envelope answers one deal
  from that stream, and its artifact names the stream (§4.3) [PA-14].
- Every envelope of one History MUST be answered at one coverage anchor: every request names it
  in `expected_pin`, and every envelope in `anchor.digest` (§4.3, §6.2) [PA-14]. Where every
  selected deal is held in one stream, the anchor MAY be a checkpoint of that stream. Where the
  deals are held in two or more streams, it MUST be a **witnessed checkpoint tick**: one
  checkpoint of the holder's, countersigned by a witness, that commits to the checkpoint of each
  of those streams at that tick. Its digest is taken as for any checkpoint [IP §6.2.1], so a
  witness's countersignature does not change it. A deal's records "at the anchor" (§4.3) are then
  those its stream holds at the checkpoint the tick commits to.
- At the Basic level a verifier checks only that every envelope names the same anchor (§6.2
  `single_anchor`). It does not check that the anchor is witnessed, or that it commits to the
  stream an artifact names: like `anchor_inclusion` (§6.1), that needs verification material IP
  does not register (PA-13, PA-14). Both are among the checks a verifier shows as not run
  (§6.3 item 4).
- One anchor over several streams says nothing about which of their records a History includes.
  That is the History's coverage declaration [IP §6.7]. A History at the Basic level declares
  `holder_selected`: its definition's `completeness` `not_asserted` (§4.1) is that declaration, and
  the definition carries no `coverage_declaration` member [PA-15]. A History of the other two kinds,
  `stream_interval` (every record of the opened live set at the anchor) and `source_authoritative`
  (every deal a named external source lists), needs a definition that carries one. That is the
  Outcome level (`spec/personal-agent-history-outcome-v0.md` §3), not `/1`.
- The holder key answering is not evidence that the key's holder made the deals. The records'
  own signatures sit outside what the Basic level reveals (§9).

## 3. Record kinds

The Basic level reveals one thing about each record beyond its time: whether a step the holder's
agent recorded completed or failed. It carries that in the record header's `record_type` [EL],
from this closed list [PA-2]:

| `record_type` | Meaning |
|---|---|
| `step_completed` | a step of the deal that the holder's agent recorded as completed |
| `step_failed` | a step of the deal that the holder's agent recorded as failed |

- A host whose native records carry a step status elsewhere (for example an effect status on an
  action record) maps that status onto these two kinds when it writes the deal's records.
- `record_type` is open vocabulary in EL, so a host could write a type that names an item, a
  category or a counterparty. That is why the list is closed: a record of any other type MUST NOT
  be in a selected deal, and a verifier reports it as `record_kinds` `FAIL` (§6.2).
- A recorded completed step is not a completed sale, payment, delivery or receipt. It says that
  the holder's agent recorded a step as completed, and nothing about what the step was (§5).
- `epistemic_type` is revealed as the holder's agent recorded it. It is the holder's own label.
  A verifier MUST NOT present it as corroboration by anyone else.

## 4. Disclosure identification

A History at the Basic level is a **recipient-specific projection**: a derivation identified by
the digest of its definition [IP §6.5]. It is never the canonical Artifact of the underived
subject, and never presented as the answer to an Evidence Request for anything else
[IP §6.5 item 3].

### 4.1 The definition document

IP leaves the member names of a definition document open (IP P-14). This profile fixes them for
its derivation [PA-3]:

| Member | Value |
|---|---|
| `name` | `"personal_history_basic/1"`: what people read, not what the wire carries |
| `kind` | `"projection"` |
| `subject_form` | `"correlation"`: each request names one deal [ER §3.1] |
| `selection` | the deal references the holder picked: a non-empty array of non-empty text strings, sorted by code point, without duplicates |
| `reads` | exactly `["committed_at", "epistemic_type", "event_time_claim", "record_type"]`: the declared field set [ER §8] |
| `completeness` | `"not_asserted"`: the coverage kind `holder_selected` [IP §6.7.1; PA-15] |
| `recipient` | the recipient's principal reference [ER §3.7; IP §6.5 item 1] |

No other member is allowed in `/1`. Any change to a member, to `reads` or to the record kinds of
§3 is `/2`, with a new definition and a new digest. Nothing is extended in place.

### 4.2 The identifier

The request's `derivation` is the 64-hex SHA-256 of UTF-8 of JCS of the definition document
[ER §3.3; IP §6.5 item 1]. `personal_history_basic/1` is not a registered derivation token, and
is never sent as one.

What the identifier binds:

- **The recipient.** Two recipients give two identifiers even for the same selection
  [IP §6.5 item 1].
- **The selection.** Every envelope signs `derivation` [IP §6.2]. So each envelope is the holder
  key's signed statement of the whole selection, not only of the deal it answers. A deal added to
  or removed from the definition a recipient holds no longer matches what the holder signed.
- **The field set.** `reads` bounds what any answer under the identifier can reveal [ER §8].

The definition names its recipient, so a host does not write it into the holder's evidence
stream, where other requesters could be served it.

### 4.3 The answer

For each deal reference in `selection`, the recipient's request is the IP request [IP §6.1] with:

- `subject` `{"correlation": <deal reference>}`;
- `coverage` `{"expected_pin": <the anchor the History is answered at>}`;
- `derivation` the identifier of §4.2;
- `profile` `"evidence-interop/0"`.

The responder answers with an IP envelope [IP §6.2]. Its `artifact` is UTF-8 of JCS of [PA-4]:

| Member | Value |
|---|---|
| `anchor` | the resolved anchor digest, equal to the envelope's `anchor.digest` |
| `derivation` | the identifier, equal to the envelope's `derivation` |
| `evidence_stream` | the stream the deal's records are held in |
| `records` | one entry per record of the deal at the anchor, in log order |
| `subject` | the request's `subject`, by value |

Each `records` entry carries `digest` (the record's identifier), `leaf_index` (its position in
the stream), and those members of `reads` that the record's header carries. It carries no other
member: no payload, no payload commitment, no statement, no counterparty or principal reference,
no links.

The artifact is caller-invariant for (subject, anchor, derivation) [ER §5; IP §6.2]. Every member
is a function of those three and the stream; nothing in it depends on the request's nonce, route
or carriage.

### 4.4 What the holder checks before release

Before a History is released, the holder's host:

1. confirms that every selected deal holds only records of the kinds in §3;
2. byte-scans every reply it will release for any text outside the declared field set [PA-5]:
   counterparty names, contact details, addresses, items, amounts, message text, and the deal
   references of deals not selected. A match means the History is not released.

The scan is the holder's control. A recipient's verifier checks the field set (§6.2
`artifact_form`), not the absence of text it has never seen.

### 4.5 Linkage

- Deal references are carried in the clear in `selection` and in every request. They MUST NOT be
  derived from counterparty, item, amount or message text [PA-6]. A random identifier chosen when
  the deal is opened meets this.
- A deal's references and its record digests are the same in every History that includes it. Two
  recipients who compare their Histories can tell that they received the same deal. This revision
  has no per-share handle that would prevent that (PA-7). A verifier states the limit (§6.3).

## 5. Units

A History is counted in **selected deals**. Records are counted separately, as records. No figure
adds deals to records or steps, and no figure is computed across deals, holders or counterparties
[PA-8].

For each selected deal, a verifier derives exactly one of:

| Deal state | Rule |
|---|---|
| with a recorded failed step | at least one record is `step_failed` |
| with recorded completed steps only | at least one record is `step_completed`, and none is `step_failed` |
| with no recorded step | neither (a deal of no records is not served, §6.2 `artifact_form`) |

What a History at the Basic level establishes and what it does not:

| Established, under §6 | Not established |
|---|---|
| which deals the holder selected for this recipient | that the selection is all of the holder's deals (`completeness` `not_asserted`) |
| when each record was committed to the holder's stream, and the event time the holder's agent claimed, as two separate times | that anything happened at the claimed event time |
| whether each recorded step completed or failed, as the holder's agent recorded it | any outcome: sale, payment, delivery, receipt or return |
| that one holder key answered for every deal | who holds the key |

A verifier shows "not established" for each item in the right-hand column. It never shows a
missing outcome as a failure.

## 6. Acceptance

A History is accepted when IP's verifier accepts every envelope in it (§6.1), and every History
property passes (§6.2).

### 6.1 Interop properties

Each exchange is verified exactly as IP §7.3 describes, with the requester's own retained request
octets. An envelope answering at the Basic level is accepted when:

- `profile_version`, `envelope_signature`, `responder_trust`, `issued_at_form`,
  `request_binding`, `subject_binding`, `artifact_digest` and `anchor_match` are `PASS`;
- `anchor_inclusion` is `NOT_CHECKED`. IP registers no verification-material kind for a
  derivation's artifact, so a conforming verifier cannot run the check (IP §6.2, P-13). A History
  Basic answer carries no `verification` member. A later IP revision that registers such a kind
  turns this into `PASS` without changing this profile;
- `verification_binding` is not required, because `verification` is absent [IP §7.2].

The IP §8 mapping applies unchanged, and IP §6.7.3 item 4 after it: a requirement whose condition
needs the History to be complete is never `SATISFIED` from a Basic level History, which declares
`holder_selected` (§2). With `anchor_inclusion` `NOT_CHECKED`, every requirement a
Basic level answer is the only evidence for maps to row 4: status `UNKNOWN`, sufficiency
`UNKNOWN`, verdict `not_evaluable` [IP §8.1; RES]. The Basic level never yields `met` or `not_met`.
That is correct for this level: it makes no outcome claim for a requirement to meet.

### 6.2 History properties

Each is reported in the IP §7.1 vocabulary [PA-10]:

| Property | Check |
|---|---|
| `definition_form` | the definition carries exactly the members of §4.1, with the values §4.1 fixes; `selection` is non-empty, sorted and duplicate-free |
| `definition_binding` | every envelope's `derivation` equals SHA-256 of UTF-8 of JCS of the definition the recipient holds |
| `selection_coverage` | every envelope's `subject` is `{"correlation": r}` with `r` in `selection`, and every member of `selection` is answered by exactly one envelope |
| `single_signer` | every envelope names the same `responder` |
| `single_anchor` | every envelope carries the same `anchor`, whether or not the envelopes name the same stream. Whether that anchor is a checkpoint or a witnessed checkpoint tick is not checked (§2, PA-14) |
| `artifact_form` | every artifact is the §4.3 object: exactly its five members, `anchor`, `derivation` and `subject` equal to the envelope's, `records` non-empty, each entry carrying `digest` and `leaf_index` and no member outside `reads`; checked per envelope, `evidence_stream` a non-empty text string. Two envelopes may name different streams. Whether the named stream holds the records is not checked (§2, PA-14) |
| `record_kinds` | every record's `record_type` is in §3's list |

The History properties are checked only over envelopes accepted under §6.1. A History property
that is not `PASS` means the History is not accepted, whatever the envelopes' own statuses are.
A History property never changes an envelope property or an IP §8 status.

### 6.3 What a verifier shows

A verifier showing an accepted History at the Basic level shows, in this order:

1. that outcomes are not established (§5), and that the coverage kind is `holder_selected`, with
   completeness not asserted [IP §6.7.3], before any count;
2. the number of selected deals, and the count of each deal state of §5, each in its own unit;
3. per deal, its records' committed and claimed times as two separate values, and their kinds;
4. which checks ran and which did not, including `anchor_inclusion` `NOT_CHECKED`;
5. the limits of §4.5 and §9.

### 6.4 Acceptance vectors (informative)

The acceptance run for this revision built a History at the Basic level of three selected deals
from a holder stream of four deals with an IP responder, and verified it with IP's reference
verifier. All seven History properties were `PASS`; every envelope met §6.1; the IP §8 mapping of a recipient
requirement was `UNKNOWN`/`not_evaluable`. Each of these mutants failed the property named:

| Mutant | Fails |
|---|---|
| one step's kind changed in an artifact in transit | IP `artifact_digest` |
| a deal added to the definition the recipient holds | `definition_binding` |
| an envelope, signed by the holder key, for a deal not selected | `selection_coverage` |
| a selected deal not answered | `selection_coverage` |
| one deal answered under a second key the relying party also trusts | `single_signer` |
| one deal answered at another anchor | `single_anchor` (and IP `anchor_match`) |
| a record kind outside §3, re-signed by the holder key | `record_kinds` |
| a record carrying a member outside `reads`, re-signed by the holder key | `artifact_form` |
| a definition whose `reads` adds `statement` and `counterparty_ref` | `definition_form` |

A request under the definition from any requester other than its `recipient` was refused
`not_authorized` [ER §4.2]. Publishing these as conformance vectors beside IP §11.5 is PA-11. They
are published in `vectors/personal-history-basic-v0/`.

## 7. Lifecycle links

The Basic level declares no `links` in `reads`, so it carries no lifecycle statement and shows only
what was recorded at the anchor. A later amendment, correction, dispute or resolution of a deal is
an IP lifecycle statement [IP §11.2], obtained by its own request, under its own authorization:

- subject `{"exchange": <digest of the record the statement cites>}` [ER §3.1], which names every
  record that cites it;
- with no derivation, or a derivation of its own. It is never added to a Basic level answer.

IP's issuer rules apply unchanged [IP §11.2.4]: a holder may amend or supersede only its own
records; another party may dispute or contradict, never replace; a resolution is the resolving
process's statement. A verifier showing both keeps the historical recorded state and the latest
supported state apart [IP §11.2.6].

## 8. Carriage

### 8.1 Asked by the recipient

The recipient receives the definition document from the holder, by any channel, and asks for each
selected deal under it. The requests and replies are carried by any IP carriage (the native
stream, HTTP, A2A or MCP), with IP's rules unchanged [IP §11.4]. In this mode `request_binding`
binds each answer to a request the recipient itself made.

A responder answers a Basic level request only for the requester its definition names, after
authenticating it [IP §6.5 item 4]. Any other requester is refused `not_authorized`, or
`policy_declined` where the more specific token would disclose what the policy protects
[IP §6.3]. Possessing a definition, a deal reference or a History grants nothing.

A discovery manifest never lists a Basic level definition, its identifier or its deal
references [IP §11.4.3].

### 8.2 Handed over as one file

A holder MAY instead hand the recipient a History as one JSON object [PA-12]:

| Member | Value |
|---|---|
| `history` | `"personal_history_basic/1"` |
| `definition` | the definition document, as a JSON value |
| `exchanges` | one `{"request": C, "reply": C}` per selected deal, where `C` is `{"media_type", "octets_text"}` for JSON or `{"media_type", "octets_hex"}` for CBOR: the octets exactly as carried |

The holder's host forms the requests. Then `request_binding` shows only that each answer matches
the request octets in the file, not that the recipient asked. A verifier states which mode it
checked. Everything else in §6 is the same.

## 9. Security and privacy considerations

- **Minimum disclosure.** `reads` and §3 bound what a History reveals. The holder's byte scan
  (§4.4) and the verifier's `artifact_form` check are the two halves of that bound.
- **Recipient binding is not secrecy.** The definition names its recipient, and the responder
  answers only that requester. A recipient can still forward what it received.
- **Linkage.** Deal references and record digests are stable across Histories (§4.5).
- **What one key proves.** Every envelope verifies under the holder key. That does not prove the
  key's holder made the deals, because a record's identifier does not cover the signature it was
  sealed with, and the Basic level does not reveal those signatures.
- **Selection is not completeness.** A holder can leave out any deal. `completeness`
  `not_asserted` says so, and a verifier shows it. Every envelope verifying under the holder key
  does not change that: a valid signature never implies completeness [IP §6.7]. A requirement that
  relies on completeness is never `SATISFIED` from a Basic level History [IP §6.7.3 item 4].
- **Claimed times.** `event_time_claim` is the holder's agent's claim. `committed_at` is the time
  the holder's own stream assigned. Neither is a witnessed time; both are shown, separately.
- **No ordering.** This profile defines no figure that orders or grades deals, holders or
  counterparties, and a verifier that follows it shows none.

## 10. Open points

| # | Point |
|---|---|
| PA-1 | One holder key per History. Composing Histories across a key rotation needs a signed link between the two keys, which no pinned document defines yet. |
| PA-2 | The closed list of record kinds (§3). Its two kinds may later move into an EL revision's `record_type` guidance. |
| PA-3 | The definition document's member names (§4.1), which IP leaves open as P-14. If IP fixes common names, `/2` adopts them. |
| PA-4 | The artifact form of a derivation answer (§4.3). IP fixes no artifact content; this profile fixes it for its derivation so that two responders give the same bytes. |
| PA-5 | The holder's pre-release byte scan (§4.4) as a requirement of the host, not of the responder. |
| PA-6 | Deal references not derived from counterparty, item, amount or message text. |
| PA-7 | Per-share handles that would stop two recipients joining a deal through its reference. Records' digests would still link it. |
| PA-8 | Units (§5). |
| PA-9 | Outcome claims with source labels (the holder's agent's own outcome record, a third party's signed message, an adjudicator's statement, the other party's own record), each shown side by side and never combined. Defined as the Outcome level, `personal_history_outcome/1`, in `spec/personal-agent-history-outcome-v0.md`. |
| PA-10 | The History properties (§6.2) as properties in IP's vocabulary that are not IP §7.2 envelope properties and never enter the IP §8 mapping. |
| PA-11 | Publishing the §6.4 run as conformance vectors beside IP §11.5. |
| PA-12 | The one-file History container (§8.2). |
| PA-13 | Record-level inclusion for a derivation's artifact: needs an IP verification-material kind (IP P-13); until then `anchor_inclusion` is `NOT_CHECKED`. |
| PA-14 | A History over several streams at one witnessed checkpoint tick (§2). Showing that the tick is witnessed and commits to each stream an artifact names needs verification material from the tick to the stream's checkpoint, which IP does not register (IP P-13); until then a verifier checks only that every envelope names the same anchor. |
| PA-15 | The Basic level's coverage kind (§2, §4.1). `completeness` `not_asserted` is read as IP §6.7's `holder_selected`, so `/1` keeps its bytes. A level that declares `stream_interval` or `source_authoritative` carries `coverage_declaration` in its definition instead. The IP vectors use an example definition for both, which is not registered (IP §6.7.6). The Outcome level (`spec/personal-agent-history-outcome-v0.md` §3) is that level. |
