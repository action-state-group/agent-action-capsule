# Telemetry-Binding Profile

**Status:** Informational profile — not part of core `draft-mih-scitt-agent-action-capsule`.
**Origin:** AARM R8 (telemetry export, a SHOULD).
**Applicable to:** any implementation that projects capsule-mediated decisions
into OTLP, OCSF, or an equivalent observability/SIEM pipeline. This document
is implementable from its own text: the attribute table below plus the
mapping table's target-format semantics are the complete profile — no
external reference implementation is required to conform to it.

---

## Why this is a profile, not core

The capsule is the normative artifact. Telemetry is a projection of it —
naming OTLP or OCSF inside the core spec would inherit their release cycles
and instability, and would imply the projection is authoritative when the
capsule is. Core stays transport- and platform-neutral; a profile can move
at the speed of the thing it binds to, and this one does: OTel's `gen_ai`
semantic conventions are experimental (the entire convention set was
deprecated out of the main `open-telemetry/semantic-conventions` repo on
2026-06-12 into a dedicated one with no tagged release yet), and no ratified
OCSF event class exists for AI-agent activity as of this writing. A profile
absorbs that churn; core does not.

## The rule this profile exists to state

**A telemetry event MUST carry a reference to a capsule, never a copy of
one.** Concretely:

- **MUST.** The event carries the referenced capsule's `capsule_id` (the
  receipt digest) as a first-class field.
- **MUST NOT.** The event carries the capsule payload — `constraints`,
  `disposition`, `asg_signature`/`signature`, `asg_payload`/payload
  extensions, or any other field whose presence would let a consumer treat
  the event as a substitute for fetching and verifying the capsule itself.
- **Fact, not a requirement.** The event carries no signature of its own,
  is operator-controlled, and is therefore trivially forgeable in transit
  or at rest. It is not evidence. This is a statement about what the event
  *is*, not an obligation imposed on whoever consumes it — a MUST cannot
  bind a SIEM operator or auditor who is not implementing this profile and
  has no reason to have read it.
- **MUST NOT.** An implementation MUST NOT present, document, or export
  telemetry events as evidence of what was decided. A SIEM or observability
  pipeline that ingests these events is a **discovery index into the
  capsule ledger**, never a competing record of what happened. If a
  telemetry event and the capsule it references ever disagree, the capsule
  is authoritative, full stop; the disagreement itself is a delivery or
  tampering signal about the telemetry pipeline, not evidence of what the
  guard decided.

Two mutable copies of the same fact are a divergence bug waiting to happen.
An implementation that follows this profile cannot manufacture that
divergence, because the only fact duplicated is an opaque pointer.

## Minimum attribute set

| Attribute | Required? | Meaning |
|---|---|---|
| `action.verb` | MUST | the mediated action's verb |
| `decision` | MUST | `ALLOW \| DENY \| MODIFY \| STEP_UP \| DEFER` |
| `receipt.digest` | MUST | the referenced capsule's `capsule_id`, verbatim, in the JSON-DIGEST representation `draft-mih-scitt-agent-action-capsule` §5.1 defines for that field: lowercase-hex SHA-256, 64 characters. This is the same digest representation `draft-mih-sokolov-scitt-payload-binding`'s typed digest reference mechanism uses for digest-bearing fields — this profile does not invent a second encoding. |
| `action.target` | MAY | dedupe/recipient discriminator, when the action has one |
| `manifest.digest` | MAY | the policy manifest that governed the decision, when one applies |
| `plan.digest` | MAY | the compiled plan that governed the decision, when one applies |
| `outcome.id` | MAY | the declared outcome this action serves, when the implementation tracks one |
| `plan.step_index` | MAY | position within a compiled plan, when applicable |
| `containment.result` | MAY | `pass \| fail` today, when a plan-containment check ran; the vocabulary is **extensible, not closed** — see note below |
| `identity.human` / `.service` / `.agent` / `.session` | MAY | caller-supplied identity facets, whichever the deployment's auth context actually has |

`MAY` fields are **omitted, not null**, when the implementation has no value
for them — an implementation MUST NOT emit a null/empty placeholder to
"complete" the shape. `decision` uses this profile's own five-value
vocabulary, named after AARM R4's decision set but not asserted to be
identical to it. AARM R4 itself defines `STEP_UP` as "require human approval
before execution" and `DEFER` as "delay execution pending additional
context" — it does not specify who or what elects the delay. **This is
this profile's own reading, not AARM's definition:** an example mapping
from a three-outcome `allow`/`deny`/`escalate` engine maps `escalate` →
`STEP_UP` when escalation means "routed to a human, awaiting resolution"
(consistent with AARM R4's `STEP_UP`), and reserves `DEFER` for a
*human*-elected postponement the engine did not itself decide — narrower
than AARM R4's `DEFER`, which covers any context-driven delay regardless of
who or what triggers it. An implementation claiming both AARM R4
conformance and this profile MUST NOT assume the two `DEFER` readings are
interchangeable without checking which one its own engine actually
produces.

**`containment.result`'s two-value vocabulary is a starting point, not a
closed enum.** A plan-containment check can satisfy its own success
condition by making an agent violate the check's assumptions rather than
by genuinely following the plan (the non-well-separation failure mode:
Klein & Pnueli, HVC 2010) — a case a strict `pass`/`fail` field cannot
distinguish from a real pass. This profile does not resolve that design
question; it leaves the field open for additional values (e.g. a
vacuous-pass discriminator) as containment implementations mature, and
implementations MUST treat unrecognized `containment.result` values as
"informational, not a rejection" rather than erroring.

## Mapping table

| This profile | OTLP / `gen_ai` | OCSF | Plain JSON lines |
|---|---|---|---|
| Status | Primary target | Secondary, best-effort — no ratified class exists | Fallback — always available, no schema dependency |
| `action.verb` | `gen_ai.tool.name` | carried in the unmapped/extension bag | as-is |
| `decision` | no native field (see gap below) | `disposition_id`/`disposition` on the closest existing class (see below) | as-is |
| `receipt.digest`, `manifest.digest`, `plan.digest`, `containment.result` | no native field — carried under this profile's own namespace alongside the `gen_ai.*` attributes | carried in the unmapped/extension bag | as-is |
| identity facets | `gen_ai.agent.id` (from `identity.agent`), `gen_ai.conversation.id` (from `identity.session`) where present | carried in the unmapped/extension bag | as-is |

**`gen_ai` gap.** `gen_ai` conventions cover LLM/tool-call telemetry — model,
tokens, tool name, agent/conversation identity — and have nothing for
tamper-evidence, signing, or non-repudiation. There is no `gen_ai` field a
receipt digest, manifest digest, or containment result maps onto;
implementations MUST carry those under this profile's own attribute
namespace rather than inventing a `gen_ai.*`-shaped name for them.

**OCSF gap.** No ratified OCSF class exists for AI-agent activity, tool
calls, or AI-governance findings as of this writing (at least one production
SIEM vendor has worked around the same gap with a private schema extension
rather than a standard class). The closest existing class with a
disposition-shaped outcome field is **Detection Finding** (`class_uid`
2004, category "Findings"), whose `disposition_id` enum includes `Allowed`
(1) and `Blocked` (2) — a reasonable fit for `ALLOW`/`DENY` — but has no
value for "routed to a human, awaiting resolution" (`STEP_UP`), a
human-elected postponement (`DEFER`), or an in-flight action altered before
dispatch (`MODIFY`); those three fall back to `Other` (99). Detection
Finding's own semantics assume a detection *about* something that already
happened, not a real-time gate applied *before* dispatch — implementations
MUST document this mismatch alongside any OCSF mapping they ship, not
present it as a native fit. A follow-up proposal for a dedicated OCSF
activity class for mediated agent actions is tracked upstream
(`ocsf/ocsf-schema`); this profile does not block on it.

## Conformance

An implementation conforms to this profile when:

1. Every emitted event carries `receipt.digest` pointing at a real,
   independently-verifiable capsule (Reference, never a copy, above). When
   producing the event requires a capsule that was never sealed — e.g. the
   producer's own fail-closed path minted no capsule at all — the
   implementation MUST emit no event for that decision rather than
   fabricate a digest. A gap in the telemetry stream is therefore a signal
   that no capsule was sealed for that decision, not evidence that the
   exporter is broken; implementations SHOULD document this so a consumer
   reads a gap correctly.
2. No emitted event, in any target format, carries a capsule's signature,
   constraints, disposition, or payload-extension fields verbatim.
3. Exporter failure — network, serialization, or configuration — never
   blocks or alters the decision it would have reported. A telemetry outage
   is an observability gap, never an availability incident, and never
   changes an enforcement outcome.
4. Any OCSF or other best-effort mapping documents its own mismatches
   rather than silently mapping to the nearest lookalike value.

This profile is implementable directly from this document: the minimum
attribute set and mapping table above are the complete surface a conforming
implementation needs, independent of any particular producer's internals.
