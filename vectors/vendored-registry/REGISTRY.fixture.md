# Registries of record (conformance fixture)

Sections 6, 10, 17 and 18 of spec/REGISTRY.md, frozen for
vectors/vendored-registry/. Not a registry of record.

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

## 10. Reserved wrapper members and disclosable fields — disclosure envelope

Reserved by the companion Internet-Draft
`draft-mih-agent-disclosure-envelope` (Disclosure
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

### Provisional: `agent_input` presentation types

**Held for ratification; not yet registered.** The Disclosure Envelope draft
defines no presentation types. A presentation type names a JSON shape for a
value revealed as the `agent_input` member, and adds checks a verifier runs on
that value after DE-3 has matched it against `agent_input_digest`. It never
changes DE-1 through DE-3, the digest, or `capsule_id`. A value of no
registered type is checked by DE-3 alone. Conformance vectors:
`vectors/minimum-necessary/`.

| Discriminator | Value | Checks after a DE-3 match |
|---|---|---|
| `agent_input_version: "1"` | `{"agent_input_version": "1", "presentations": [<SD-JWT presentation>, ...]}`: the SD-JWT presentations (RFC 9901) the agent received, each an issuer-signed JWT followed by the Disclosures transmitted, exactly as transmitted. `agent_input_digest` is the JSON-DIGEST of this wrapper. | A checker verifying a revealed `agent_input` of this type MUST verify each SD-JWT inside it: (1) the issuer-signed JWT's signature against the JWK carried for its `iss` (in an Evidence Bundle, the `sd-jwt-issuers/v1` extension); (2) the digest of each Disclosure, under the JWT's `_sd_alg`, against its `_sd` array; and (3) the set of disclosed claim names against the `revealed` list for that presentation's `vct` in the policy decision bound to the Capsule (in an Evidence Bundle, the `disclosure-policy-decisions/v1` extension). Without a policy decision, check (3) is reported as not evaluated, never as passed. A failed check is a finding on that disclosure; a value that failed DE-3 is not checked and is never presented as confirmed. |

## 17. Evidence Layer epistemic type

Defined in `draft-mih-agent-evidence-layer`, "Epistemic Type" and IANA
Considerations ("Evidence Layer Epistemic Types"). This is a
**Specification Required** registry. A token is lowercase ASCII,
underscore-separated. It states how a record's content came to be known, is
assigned once at commit, and is never upgraded. It is a different axis from
`domain` (§8), which states what kind of act a Capsule records.

| Token | Semantics |
|---|---|
| `observed_event` | Directly observed by the recording system or actor. |
| `system_of_record_fact` | Asserted by an external system of record. |
| `producer_claim` | Asserted by the record's own producer, unverified by the store. |
| `human_report` | Asserted by a human, not machine-observed. |
| `semantic_judgment` | A judgment or classification reached by interpretation, not direct observation. |
| `derived_metric` | A value computed or aggregated from other records. |
| `adjudication` | A ruling on a matter that was disputed or required judgment. |
| `obligation_reference` | A reference to an obligation the record does not itself discharge. |

## 18. Evidence Layer link type

Defined in `draft-mih-agent-evidence-layer`, "Typed Links" and IANA
Considerations ("Evidence Layer Link Types"). This is a **Specification
Required** registry. A link is a typed, directed reference from one
evidence-store record to another, identified by the target's digest, and
never mutates its target. This registry is distinct from `chain.relation`
(§6) and `citation_purpose` (§11), which govern fields inside a Capsule; the
token `supersedes` is registered in both this registry and §6, and neither
registration defines the other.

| Token | Semantics |
|---|---|
| `cites` | The carrying record depends on the target's committed content. |
| `adjudicates` | The carrying record renders a judgment about the target's claim. Its `epistemic_type` is `adjudication`. |
| `supersedes` | The carrying record replaces the target's content for current use, without mutating it. |
| `acknowledges` | The carrying record states its author has seen and holds the target: receipt, not agreement. |
| `rebuts` | The carrying record disputes the target's claim. |
| `closes` | The carrying record binds a range or set of records as reconciled. |
