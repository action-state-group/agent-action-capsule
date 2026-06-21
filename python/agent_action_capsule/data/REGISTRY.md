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
binding). Initial contents (the profile's seeded examples): `write_order`,
`send_payment`.

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

**Designated-expert guidance (this registry).** Plausible future registrations
exist and are deliberately NOT seeded here — e.g. independent sensor
confirmation of a claimed effect, or hardware/TEE-anchored execution. A
registration MUST state where its grade sits relative to the seeded values.

## 6. `chain.relation`

Defined in §5.4.4 of the Internet-Draft (Chained Capsules; the chain block).
Initial contents:

| Value | Semantics |
|---|---|
| `confirms` | Non-terminal: this capsule observes or records the outcome of the parent — the parent's open state remains. The most common chain link: *attempted → confirmed*. |
| `supersedes` | Terminal transition over the parent — resolution, expiry, escalation close/replace the parent's open state. |

**Designated-expert guidance (this registry).** Seeded with the single terminal
relation. Additional non-terminal relations — deposit-toward-open and
effort-toward-open relations, or `amends` / `contradicts` — are expected future
registrations, each admitted once its semantics and any verifier consequence
are pinned in a publicly available specification. Such relations are anticipated
in a future revision of the Internet-Draft and are registered into this same
registry rather than establishing a new one.

## No registry

The following vocabularies are deliberately **not** registries of this document:

- **COSE algorithms** — by reference to the IANA
  [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
  registry (Internet-Draft §12, "No new registry").
- **Constraint `id` / `check_type`, `compliance.framework_tags`,
  `assurance.sources[].kind`** — governed by the namespacing convention
  (Internet-Draft §9): bare names are reserved for the seeded values; new values
  use a URI or reverse-DNS prefix.
