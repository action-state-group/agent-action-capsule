# Telemetry-Binding Profile

**Status:** Informational profile — not part of core `draft-mih-scitt-agent-action-capsule`.
**Origin:** AARM R8 (telemetry export, a SHOULD). Reference implementation:
`capsule-ledger`'s `capsule_ledger.otel_export` package.
**Applicable to:** any implementation that projects capsule-mediated decisions
into OTLP, OCSF, or an equivalent observability/SIEM pipeline.

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
- **MUST.** The event is not relied upon as evidence. It is best-effort,
  operator-controlled, and — because it carries no signature of its own —
  trivially forgeable in transit or at rest. A SIEM or observability
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
| `receipt.digest` | MUST | the referenced capsule's `capsule_id` |
| `action.target` | MAY | dedupe/recipient discriminator, when the action has one |
| `manifest.digest` | MAY | the policy manifest that governed the decision, when one applies |
| `plan.digest` | MAY | the compiled plan that governed the decision, when one applies |
| `outcome.id` | MAY | the declared outcome this action serves, when the implementation tracks one |
| `plan.step_index` | MAY | position within a compiled plan, when applicable |
| `containment.result` | MAY | `pass \| fail`, when a plan-containment check ran |
| `identity.human` / `.service` / `.agent` / `.session` | MAY | caller-supplied identity facets, whichever the deployment's auth context actually has |

`MAY` fields are **omitted, not null**, when the implementation has no value
for them — an implementation MUST NOT emit a null/empty placeholder to
"complete" the shape. `decision` uses this profile's own five-value
vocabulary regardless of what vocabulary the producing engine uses
internally (e.g. a three-outcome `allow`/`deny`/`escalate` engine maps
`escalate` → `STEP_UP` when escalation means "routed to a human, awaiting
resolution," reserving `DEFER` for a human-elected postponement the engine
did not itself decide).

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
activity class for mediated agent actions is tracked separately (see
`capsule-ledger`'s outbox, task `ldg-otel-exporter-aarm-r8`); this profile
does not block on it.

## Conformance

An implementation conforms to this profile when:

1. Every emitted event carries `receipt.digest` pointing at a real,
   independently-verifiable capsule, and MUST NOT emit an event with no
   digest to reference (Reference, never a copy, above).
2. No emitted event, in any target format, carries a capsule's signature,
   constraints, disposition, or payload-extension fields verbatim.
3. Exporter failure — network, serialization, or configuration — never
   blocks or alters the decision it would have reported. A telemetry outage
   is an observability gap, never an availability incident, and never
   changes an enforcement outcome.
4. Any OCSF or other best-effort mapping documents its own mismatches
   rather than silently mapping to the nearest lookalike value.

Reference implementation and test suite: `capsule-ledger`'s
`capsule_ledger.otel_export` (`event.py`, `mapping_genai.py`,
`mapping_ocsf.py`, `mapping_jsonl.py`, `exporter.py`) and
`tests/test_otel_export.py`.
