# Registries of record — Agent Action Capsule vocabularies

**Status.** This document is the **interim registry of record** for the
extensible vocabularies of the Agent Action Capsule profile, until RFC
publication establishes the corresponding IANA registries. The registries and
their normative definitions are in the Internet-Draft
(`draft-mih-scitt-agent-action-capsule`, this repository's `spec/`), §12 (IANA
Considerations). Registration policy: **Specification Required** per
[RFC 8126 §4.6]. Change controller: **Action State Group, Inc.** (interim) →
**IETF** on publication.

**The never-reject invariant.** Verifiers MUST treat unregistered values as
informational and MUST NOT reject a record solely because it carries an
unregistered value. The digest commits whatever bytes are present; an unknown
value breaks only semantic interpretation, never digest verification.

**Descriptive, not generative.** The registry text is DESCRIPTIVE of the
vocabulary defined normatively in the Internet-Draft; it never generates new
semantics. A registration records a value and its specification — it does not
amend the format.

This record applies only to Capsules conforming to the base profile's format-4
requirements. A registry entry cannot make a pre-format-4 Capsule or any other
unsupported canonicalization declaration conforming or verifiable.

[RFC 8126 §4.6]: https://www.rfc-editor.org/rfc/rfc8126#section-4.6

## Designated-expert guidance (all registries)

A designated expert evaluating a registration applies three tests:

1. **Clear semantics** — two independent implementations would apply the value
   identically.
2. **No overlap** with existing values.
3. **Publicly available spec** documenting the value.

The Specification Required policy answers a specific threat: a vocabulary value
whose meaning is defined only inside a closed product would make two verifiers
disagree on what the value means. The publicly-available-spec requirement is the
mitigation — a value enters the shared vocabulary only once its semantics are
pinned in a specification any implementer can read (Internet-Draft §12).

**Worked example — rejected registration.** `ready` (proposed as a disposition
value) — REJECTED: `ready` is a derived state computed from the chain (an open
item whose constraints are all satisfied), not a verdict the gate issued.
Derived states are never registry values; registering one would let a capsule
assert a state that only the store can compute.

---

## 1. `verdict_class`

Defined in §5.4.1 of the Internet-Draft (the `verdict_class` vocabulary).
Initial contents:

| Value | Semantics |
|---|---|
| `executed` | The action ran (effect_mode confirmed \| dispatched_unconfirmed). |
| `blocked` | A blocking constraint stopped it pre-dispatch. |
| `hitl_dispatched` | Routed to an operator; awaiting resolution. |
| `denied` | Operator/policy refused pre-dispatch. |
| `timeout` | Timed out (pre-dispatch: not_applicable; post: dispatched_unconfirmed). |
| `errored` | Ran and threw; final state unknown (dispatched_unconfirmed). |
| `engine_failure` | The engine could not evaluate (pre-dispatch). |
| `deferred` | A human elected to postpone the decision; open item. |
| `needs_decision` | Evaluation complete, decision required, not yet routed to a decider; open item. |
| `expired` | TTL policy on the deferral elapsed; terminal unless superseded by escalation. |
| `escalated` | Expiry or policy routed the item to a higher authority; open item at the new authority. |
| `resolved` | A terminal decision capsule closed the chain without executing (pairing rule, Internet-Draft §5.4.2). |
| `epoch_boundary` | An administrative capsule (`action_type: "fyi"`) marking a configuration-epoch transition. REQUIRES `effect_mode: "not_applicable"` — no effect is dispatched by an administrative epoch record. Defined in §5.1 (Configuration epochs) of the Internet-Draft. |

**`deferred` token ownership.** The `deferred` token's semantics are OWNED by
the `verdict_class` registry; the `disposition.decision` entry of the same
spelling (§2) is a cross-reference to it.

## 2. `disposition.decision`

Defined in §5.4 of the Internet-Draft (Disposition).
Initial contents: `accept`, `reject`, `needs_input`, `deferred`.

**`deferred` token ownership.** The `deferred` token's semantics are OWNED by
the `verdict_class` registry (§1); this `disposition.decision` entry is a
cross-reference to it.

## 3. `effect.type`

Defined in §5.2 of the Internet-Draft (Effect Record and the confirmed-effect
binding). Initial contents:

| Value | Semantics |
|---|---|
| `write_order` | Seeded example value of the profile (Internet-Draft §5.2). |
| `send_payment` | Seeded example value of the profile (Internet-Draft §5.2). |
| `inference_completion` | An inference request to a model-serving runtime whose committed effect is producing a completion. `request_digest` is the JSON digest of the request body as received at the serving boundary; `response_digest` is the JSON digest of the completion body as returned. |

## 4. `irreversibility_class`

Defined in §5.2 of the Internet-Draft (Effect Record). An **ordered**
vocabulary by ascending consequence; a registration MUST state its position in
the consequence order relative to the existing values. Initial contents, in
order:

1. `two_way`
2. `one_way_recoverable`
3. `one_way_consequential`
4. `one_way_terminal`

## 5. `effect_attestation`

Defined in §5.2 of the Internet-Draft (Effect Record; the validity matrix).

**Grade-floor rule (registry preamble).** Consumers MUST treat an unregistered
or unrecognized `effect_attestation` value as **no stronger than
`runtime_claimed`**. The never-reject invariant holds — unknown values are
informational, never a verification failure — but unknown NEVER grades up.

**Planned carve (registry preamble).** `effect.status = "planned"` asserts no
execution — `effect_attestation` MUST be absent (nothing to grade; a phantom
grade would poison grade-based queries); it becomes REQUIRED the moment
dispatch occurs (Internet-Draft §5.2).

Initial contents:

| Value | Semantics |
|---|---|
| `gate_executed` | The commit transited the gate; the engine observed the effect boundary directly. |
| `runtime_claimed` | The gate issued a verdict only; the executing runtime asserted completion; the capsule records that claim, not an observation. |
| `host_served_observed` | The serving host's runtime reported the completion (its request and response digests) through the host's lifecycle channel; the producer observed that report, not the effect boundary itself. **Grade: equal to `runtime_claimed`** — it records a runtime's report of completion, never a gate observation, so it never grades above `runtime_claimed`. |

**Grade order.** `gate_executed` is the stronger grade; `runtime_claimed` and
`host_served_observed` are equal in grade to each other and below
`gate_executed`. Registering `host_served_observed` changes no grading: the
grade-floor rule above already treated it, while unregistered, as no stronger
than `runtime_claimed`.

**Designated-expert guidance (this registry).** Plausible future registrations
exist and are deliberately NOT seeded here — e.g. independent sensor
confirmation of a claimed effect, or hardware/TEE-anchored execution. A
registration MUST state where its grade sits relative to the seeded values.

## 6. `chain.relation`

Defined in §5.5.4 of the Internet-Draft (Chained Capsules; the chain block).
Initial contents:

| Value | Semantics |
|---|---|
| `follows` | Non-terminal: a bare next-link — this capsule appends to the producer's stream after the parent and asserts no outcome, observation, or transition over it; the parent's open state is unaffected. The default relation for an ordinary sequential record, including a record whose substance lies in its own fields or its `references[]` citations rather than in any claim about the parent (e.g. a counterparty-half custody record citing a foreign half via `citation_purpose: counterparty_half`, §11). **Verifier consequence:** verifiers and downstream evidence evaluators MUST NOT read a `follows` link as confirming, superseding, or otherwise grading the parent — it is ordering only. |
| `confirms` | Non-terminal: this capsule observes or records the outcome of the parent — the parent's open state remains. The most common chain link: *attempted → confirmed*. |
| `supersedes` | Terminal transition over the parent — resolution, expiry, escalation close/replace the parent's open state. |
| `epoch_opens` | Non-terminal: this capsule opens a new operational configuration epoch. The chain parent MUST be the last capsule produced under the prior epoch. The opening capsule carries the new `epoch_id`. Defined in §5.1 (Configuration epochs, Epoch-boundary Capsules) of the Internet-Draft. |
| `duplicates` | Non-terminal: this capsule is a backfilled import of the same logical event already recorded by the parent, a contemporaneous capsule in this producer's own stream. Defined in the Internet-Draft's Provenance mode section (`-05` and later revisions). A `duplicates`-linked pair is counted once by verifiers and downstream evidence evaluators; the contemporaneous parent's assurance and disposition govern. |

**Designated-expert guidance (this registry).** Seeded with the bare ordering
link (`follows`), the core non-terminal and terminal relations, plus
`epoch_opens` for configuration-epoch boundaries and `duplicates`
for backfilled-record deduplication. Additional
non-terminal relations — deposit-toward-open and effort-toward-open relations,
or `amends` / `contradicts` — are expected future registrations, each admitted
once its semantics and any verifier consequence are pinned in a publicly
available specification. Such relations are anticipated in a future revision of
the Internet-Draft and are registered into this same registry rather than
establishing a new one.

**Deployed legacy alias — `sequence`.** The reference implementation's adapter
tier (tool-wrapping integrations) has emitted `sequence` as its default
next-link relation with the same bare-ordering intent as `follows`. The
Internet-Draft distinguishes no relation vocabulary by producer tier, so
`sequence` is NOT registered as a separate value: `follows` is the registered
form, and `sequence` is a deployed legacy alias slated for migration to
`follows`. A verifier encountering `sequence` handles it under the never-reject
invariant like any unregistered value — an informational finding, never a
rejection — and producers SHOULD emit the registered `follows`.

## 7. Reserved payload members — selective disclosure

Reserved by the companion Internet-Draft
`draft-mih-scitt-agent-action-capsule-sel-disc` (Selective Disclosure
Profile), §9 (IANA Considerations). These members carry the salted-hash
selective-disclosure structure and MUST NOT be used for any other purpose. They use
the underscore-prefixed naming convention (following SD-JWT (RFC 9901)) to avoid
collision with current or future Capsule payload members.

| Member | Type | Location | Defined in |
|---|---|---|---|
| `_sd_alg` | string | Top-level Capsule object | Selective-Disclosure profile, "Algorithm Identifier" section (`"sha-256"` only) |
| `_sd` | array of string | Any SD-eligible JSON object | Selective-Disclosure profile, "Salted-Hash Commitment Construction" section (commitment digests) |

A plain (non-SD) Capsule carries neither member. The `_sd`/`_sd_alg` structure is
part of the content-addressed form, so it is covered by `capsule_id` and is
tamper-evident; a verifier unaware of the SD profile processes an SD-Capsule as a
plain Capsule and sees the concealed REQUIRED fields as missing. See the companion
draft for producer requirements, the eligible-field set, and the two-phase
verifier checks.

## 8. `domain`

Defined in §5.1 of Internet-Draft `-02` (`domain` / `provenance` addendum). The
capsule's epistemic role — what kind of act this capsule records. **Optional**;
absent implies the receiver SHOULD treat the capsule as `"action"`.

| Value | Semantics |
|---|---|
| `action` | A tool call, side-effecting step, or any act that could in principle be confirmed against an external system. The most common value; applies to all capsules where the agent *did something*. |
| `memory` | A write-to or read-from a persistent memory store (retrieval, consolidation, eviction). |
| `reasoning` | A STANDALONE reasoning / chain-of-thought step that is itself the recorded act — not an action-with-reasoning (those stay `"action"`). A reasoning capsule typically carries no `effect`. |

**Extension convention.** Values with an `x-` prefix are reserved for private
experiments and MUST NOT be submitted for registration. A public extension MUST
have a publicly available specification (Specification Required, §12).

## 9. `provenance`

Defined in §5.1 of Internet-Draft `-02` (`domain` / `provenance` addendum). A
dedup rank signal: when the same logical event produces capsules from multiple
tiers, the higher-ranked provenance is authoritative. **Optional**; absent
implies receivers SHOULD treat the capsule as `"runtime"`. Rank order is
strictly gate > runtime > collector; equal rank resolves by earliest timestamp.

| Value | Rank | Semantics |
|---|---|---|
| `gate` | 3 | Emitted at the gate / policy-enforcement boundary. The most authoritative form: the capsule was produced at the point where the decision was made and committed. |
| `runtime` | 2 | Emitted by the executing runtime (agent framework, tool adapter). Authoritative for the execution record but cannot see the gate's internal decision details. |
| `collector` | 1 | Emitted by a general observability or telemetry system that observed the action passively. Lowest authority; used when neither the gate nor the runtime directly produce capsules. |

**Dedup rule (verifier / ledger-reader, NOT wire).** On dedup, the capsule with
the highest-ranked `provenance` wins; equal rank resolves by earliest timestamp.
The dedup rule is a consumer-side read algorithm, not a wire constraint — a
collector-provenance capsule is still valid; it loses only when a higher-ranked
capsule for the same event is also present.

## 10. Reserved wrapper members and disclosable fields — disclosure envelope

Reserved by the companion Internet-Draft
`draft-mih-scitt-agent-action-capsule-disclosure-envelope` (Disclosure
Envelope Profile), §8 (IANA Considerations). `capsule` and `disclosures`
are wrapper-level member names — never Capsule payload members — used only
by a Disclosure Envelope, the out-of-band structure a producer builds
around an unmodified, already-sealed Capsule to reveal the raw content
behind a digest-only field without altering `capsule_id`.

| Member | Type | Location | Defined in |
|---|---|---|---|
| `capsule` | object | Top-level Disclosure Envelope object | Disclosure Envelope profile, "Envelope Object" section (the unmodified Capsule payload) |
| `disclosures` | object | Top-level Disclosure Envelope object | Disclosure Envelope profile, "Envelope Object" section (OPTIONAL; absent members are WITHHELD) |

The disclosure-eligible fields this initial revision defines. This table is a
**Specification Required** registry:

| `disclosures` member | Committed-digest field (in `capsule.model_attestation.compute_attestation`) |
|---|---|
| `agent_input` | `agent_input_digest` |
| `agent_output` | `agent_output_digest` |

A `disclosures` member outside this table is non-conforming; a verifier
treats it as an unrecognized member rather than attempting to verify it.
An extension MUST add a digest-only Capsule field, register the member-to-
committed-digest-field pair, add format-4 vectors and increment their vector
version, and require producers to retain the original value for revelation.
This registry is currently limited to fields directly under
`capsule.model_attestation.compute_attestation`; widening it requires generic
path resolution in every implementation. The disclosure unit is the whole
registered member. CPB's salted-commitment mechanism, not this envelope,
governs selective disclosure of a sub-field. `capsule_id` is computed over
`capsule` alone and is unaffected by the presence or absence of any
`disclosures` member. See the companion draft for the full verifier checks
(digest recomputation and comparison).

## 11. `citation_purpose`

Defined in the Internet-Draft's Cross-record references section (`-04` and
later revisions). Governs the `citation_purpose` field of a `references[]`
entry — a Capsule's citation of a record outside its own `chain` scope (a
different producer or stream). Distinct from, and never a repurposing of,
CPB's own `purpose` field on a typed digest reference
(scitt-payload-binding), which selects among an artifact type's registered
digest contexts.

| Value | Semantics |
|---|---|
| `acted_on` | The citing Capsule's action targeted, consumed, or was performed against the cited record's declared content. Not a custody claim. |
| `responds_to` | The citing Capsule addresses or answers the cited record without a same-stream chain relationship to it. |
| `corroborates_source_time` | The citing Capsule's `references[]` entry cites, by digest, a signed or independently witnessed timestamp supporting a `provenance_mode` block's `source_asserted_at` claim. Defined in the Internet-Draft's Provenance mode section (`-05` and later revisions). The only citation this profile permits to raise `provenance_mode.time_rung` from `self_attested` to `witnessed`. |
| `counterparty_half` | The cited record is the counterparty's half of a two-party exchange, received and held by the citing node, which records `received_from`/`via`/`received_at`/`signature_ok` plus the received half's digests in this Capsule's `compute_attestation.received_half` and cites the counterparty's already-sealed Capsule by digest. The citing node does NOT re-assert the cited half as its own observation — it records custody of an external half, never an action or outcome of its own. |
| `counterparty_inclusion` | The citing Capsule cites, by digest, a counterparty's inclusion proof and the checkpoint covering it — and that checkpoint's receipt when it is witnessed — for a counterparty half this node already holds under an earlier `counterparty_half` citation, one `references[]` entry per cited artifact; the cited artifacts are stored as held artifacts, never entered into this node's chain. The citing Capsule chains to its own head via `follows` and never mutates the earlier `counterparty_half` citation: inclusion evidence is added by a new record, never by amending the custody record. |

**Boundary rule.** A citation to the producer's own same-stream `chain`
parent is never expressed via `references`/`citation_purpose`; a
`references` entry MUST NOT duplicate `chain.parent_capsule_id`. A
`counterparty_half` citation is compatible with this rule precisely because
it cites a FOREIGN half while the citing Capsule chains to its own LOCAL
head in `chain`: the two targets are different records, so nothing is
duplicated. The `chain.relation` to that local head remains the ordinary
same-stream link — `follows` when the record asserts nothing over that head
(§6, Internet-Draft `#hitl`); holding a foreign half is
carried entirely by the `references[]` entry and this `citation_purpose`,
never by minting a new `chain.relation` value (see the designated-expert
note below and §6).

**Designated-expert guidance (this registry).** `counterparty_half` is
registered here, on the citation axis, and deliberately NOT as a
`chain.relation` value (§6). The two axes answer different questions:
`chain.relation` describes the link to the citing Capsule's own same-stream
parent (§6), while a `citation_purpose` describes why the Capsule cites a
record outside that chain. Holding a counterparty's foreign half is a
citation, not a parent-link, so registering it as a `chain.relation` value
(for example a proposed `cites`) would conflate the two axes — the very
conflation the Internet-Draft's Cross-record references section forbids when
it states that a cross-stream citation "is a `references` entry with the
appropriate `citation_purpose`, not a new `chain.relation` value." The
record still carries an ordinary same-stream `chain.relation` to its own
head — `follows` when it makes no other claim over that head; the relation
asserts no outcome over the parent (§6), and the
custody-of-a-foreign-half meaning lives solely in this `citation_purpose`.
`counterparty_inclusion` follows the same discipline: later evidence about a
held half (its inclusion in the counterparty's log) is a further citation by
a later record, never an amendment of the record that first took custody.

## 12. `provenance_mode`

Defined in the Internet-Draft's Provenance mode section (`-05` and later
revisions). A MODE on the ordinary Capsule — never a distinct record type —
disambiguating a contemporaneous action record from a backfilled import of a
historical one. Distinct from, and never a repurposing of, the unrelated
top-level `provenance` member (§9 above, the `-02` dedup-rank signal): the
two names are deliberately different so that adding one never collides with
the other. **Optional**; absent implies `mode: "contemporaneous"`.

| `provenance_mode.mode` value | Semantics |
|---|---|
| `contemporaneous` | The default. The Capsule was produced close to when the action occurred; no import metadata is carried. |
| `backfilled` | The Capsule records an action that occurred before this Capsule was produced — a migration, reconciliation, or bulk historical import. REQUIRES `source_ref`, `source_asserted_at`, `import_batch`, and `imported_at` on the same block. |

`provenance_mode.mode` is a closed two-value enum, not itself
Specification-Required-governed (mirroring `assurance.attestation_mode`'s
treatment, Internet-Draft §5.3): an unrecognized `mode` value is a
structural failure, not an informational finding, because downstream
evidence-sufficiency logic depends on being able to tell the two modes
apart.

`provenance_mode.time_rung` (OPTIONAL; MUST be absent unless `mode` is
`"backfilled"`) is `self_attested` or `witnessed`, ordered
`self_attested` < `witnessed` for overclaim detection — the same
never-grades-up discipline as `attestation_mode` / `ledger_mode` /
`cross_party_rung`. Absent implies `self_attested`. A producer MUST NOT
claim `witnessed` without a `references[]` entry carrying
`citation_purpose: "corroborates_source_time"` (§11 above).

## 13. Evidence Bundle kind

Defined in `draft-mih-zhang-agent-action-capsule-evidence-bundle`,
"Evidence Bundle Object". This is a **Specification Required** registry.
It identifies a neutral presentation and verification container, not a Capsule
payload type.

| Value | Semantics |
|---|---|
| `evidence-bundle/v2` | Version 2 AAC Evidence Bundle, with `bundle_version: "2"`. |

## 14. Evidence Bundle extension kind

Defined in `draft-mih-zhang-agent-action-capsule-evidence-bundle`,
"Typed Extensions". This is a **Specification Required** registry. The
`extensions` object's member name is the registered kind. Its registered
specification defines that extension's block shape and semantic checks; the
neutral bundle core does not interpret it. A private `x-`-prefixed kind is not
registered.

No initial extension kind is defined. A company-specific row model such as
`report/v1` is an extension only when its independently available
specification is registered; this registry does not define that row model.

## 15. Evidence Bundle countersignature type

Defined in `draft-mih-zhang-agent-action-capsule-evidence-bundle`,
"Countersignatures". This is a **Specification Required** registry. It names
the encoding and verification rules for a signature by a party other than the
bundle producer over the bundle digest.

| Value | Semantics |
|---|---|
| `cose-sign1` | A tagged COSE_Sign1 whose attached payload is the raw 32-byte bundle digest, as defined by the Evidence Bundle draft. |

## No registry

The following vocabularies are deliberately **not** registries of this document:

- **COSE algorithms** — by reference to the IANA
  [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
  registry (Internet-Draft §12, "No new registry").
- **Constraint `id` / `check_type`, `compliance.framework_tags`,
  `assurance.sources[].kind`** — governed by the namespacing convention
  (Internet-Draft §9): bare names are reserved for the seeded values; new values
  use a URI or reverse-DNS prefix.
