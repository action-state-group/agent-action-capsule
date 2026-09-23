# Fleet Collection Conventions — v0

**Status.** Design specification, pre-Internet-Draft — the same drafting tier as
`evidence-plan-ir-v0.md` in this directory. This document turns the four fleet-collection design
areas of the per-area build plan's Part F into normative conventions so that a collector build
(OTel processor, Go collector-distribution component, or any other collection point) has a spec to
build against instead of a design note. It defines conventions for how a fleet of agent
deployments — spanning many clusters, one or many tenants — tags, classifies, records the
lifecycle of, and identifies the emitters of the telemetry a Capsule producer or collector turns
into Capsules.

**Citation note.** This document's source is the per-area build plan's Part F, as distilled into
the `[a17-fleet-collection-conventions-v0]` work item's own four-part "Do" list — the plan
document itself (an upload external to this workspace) is not present here to cite by literal
section/paragraph number. Each section below cites the corresponding **Part F item (N)** using
that list's own numbering; a future revision SHOULD replace these with literal paragraph anchors
once the source document is checked into a location this profile can cite directly.

**Companion draft.** `draft-palanisamy-scitt-aac-otel-00` (OpenTelemetry Correlation Extension for
Agent Action Capsules) defines the `org.agentactioncapsule.otel` payload block this document's
conventions attach to and constrain. This document does not restate that draft's field tables; it
cites them by section and adds the conventions the draft explicitly leaves open (outcome-context
tagging, lifecycle records, emitter-identity ladder) or explicitly excludes from its own block
(see §1.3).

## Dependency boundary

**Owns:** the outcome-context baggage-key names and their minting/propagation/coverage rules
(§1); the observation-vs-effect classification convention as a fleet-wide collection rule, not an
adapter-local one (§2); the three lifecycle record shapes and the collector-emitted gap record
(§3); the emitter-identity field set and the identity-assurance ladder for delegated,
collector-attested signing (§4).

**Depends on:** the base profile's Capsule payload shape, `provenance` and `provenance_mode`
registries, and assurance ladder (`agent-action-capsule/spec/draft-mih-scitt-agent-action-capsule-05.md`,
REGISTRY.md); `draft-palanisamy-scitt-aac-otel-00`'s `org.agentactioncapsule.otel` block, resource-attribute
table, and Privacy Considerations; `capsule-emit/docs/whats-consequential.md`'s Signal 1
classification rule, which this document adopts by reference rather than re-deriving; W3C Trace
Context and W3C Baggage as OTel defines them.

**Explicitly out of scope (never defined here):**

- Collector code. This is a specs-only item (Area 17, 0–30 days) — no collector, processor, or
  exporter implementation ships against this document until partner access is dated.
- Any named customer, tenant, or deployment. Every worked example in this document uses a
  fictional stand-in, "a 500-cluster enterprise" — never a real operator's name.
- Any Authority, Relay, or scoring concept. Materiality is carried here only as a coarse,
  non-scoring hint (§1.2); this document defines no evaluation, grading, or pricing behavior.
- Changes to the Producer Envelope wire shape or to `org.agentactioncapsule.otel`'s own field
  table. Both are closed by their governing documents; this document adds sibling conventions,
  never edits to those shapes.

---

## 1. Outcome-context baggage keys — Part F item (1)

An **outcome context** is the small set of facts that name *which job* an action belongs to,
carried as OpenTelemetry Baggage (the W3C/OpenTelemetry Baggage specification) so that every span
an agent, sub-agent, or tool call produces over the life of one job can be joined back to it —
without requiring every hop in the call graph to be Capsule-aware.

### 1.1 The four keys

| Baggage key | Value shape | Req | Meaning |
|---|---|---|---|
| `org.agentactioncapsule.job_id` | opaque string, unique within the minting scope | REQUIRED | Identifies the job — the unit of work a human or upstream system requested — that this span's action belongs to. |
| `org.agentactioncapsule.contract_ref` | `<contract_id>@<version>` | REQUIRED when the job is evaluated against an Evidence Contract | The single Evidence Contract this job is evaluated against, in the same compact form `evidence-plan-ir-v0.md` §2 already defines for `contract_ref`. This document does not introduce a second `contract_ref` grammar. |
| `org.agentactioncapsule.principal` | opaque string, stable non-PII identifier | OPTIONAL | The accountable principal the job runs on behalf of — a tenant, business unit, or service-account identifier, never an end-user or session identifier. Scoped the same way `operator` (the base profile, `draft-mih-scitt-agent-action-capsule-05.md` §"Identity and parties") scopes a Capsule's accountable tenant; this key exists so that a fleet whose jobs cross producer boundaries can carry the same accountability fact into telemetry that never becomes a Capsule. |
| `org.agentactioncapsule.materiality_hint` | one of `low`, `standard`, `high` (closed enum) | OPTIONAL | A coarse, producer-set stakes tier for the job, fixed once at mint. It is a **hint**, consulted only to prioritize collection effort or sampling review under resource pressure (§2.3) — never a score, never a compliance verdict, and never derived from evaluating what the action actually did. A verifier or downstream consumer MUST NOT treat this field as an assurance or disposition claim. |

All four keys are namespaced under `org.agentactioncapsule.*`, the same reverse-DNS prefix the
base profile reserves for itself (`draft-mih-scitt-agent-action-capsule-05.md` §"Namespacing
convention") — applied here to a Baggage key rather than a Capsule payload member, because a
shared trace's Baggage is a namespace every other participant in that trace can also write to, and
collision avoidance matters exactly the same way it does inside a Capsule payload.

### 1.2 Minting: entry point only

Outcome-context keys **MUST** be minted exactly once per job, at the job's entry point — the
orchestrator, trigger, or gateway process that first receives the external request that becomes
the job. An agent or sub-agent **MUST NOT** set or overwrite any `org.agentactioncapsule.*` Baggage
key. This is a fail-closed rule, not a convenience one: an agent has no legitimate reason to name
the job it is operating within — it did not create the job — so an agent-originated
`org.agentactioncapsule.job_id` value is definitionally a forgery of the accountability context,
whether or not the agent's intent was adversarial. A collector that observes one of these keys
being set or changed at a span whose owning component is not a recognized entry point SHOULD flag
the record rather than silently accept the new value.

### 1.3 Propagation and where the tag lands

Once minted, the four keys propagate as ordinary OpenTelemetry Baggage through the trace: from the
orchestrator, through every sub-agent span, through every tool-call span, to the span at the
**effect boundary** (§2). A collector or exporter at the effect boundary that also builds the
`org.agentactioncapsule.otel` block reads the caller-configured allow-list of these keys and tags
the outcome context — but **not inside that block**. `draft-palanisamy-scitt-aac-otel-00`'s
Privacy Considerations section is unconditional: no field of `org.agentactioncapsule.otel` may
carry an OpenTelemetry Baggage entry, in clear or digested. Outcome-context tagging is
Baggage-derived by definition, so it is carried in a **sibling** key, `ext.otel.outcome_context`,
following this codebase's existing `ext.*` convention for `compute_attestation` extension keys
(`ext.mcp`, `ext.agentgateway.*`). Each value is a SHA-256 digest of the Baggage value exactly as
received, computed the same way `org.agentactioncapsule.otel`'s own `tracestate_digest` is
computed — never carried clear, because a Baggage entry is caller-supplied string data with no
allow-list of its own, unlike the semconv attributes that block admits.

This is not a new mechanism this document invents: it is the naming of the four keys that the
`capsule-emit` OTel processor's `outcome_context_baggage_keys` allow-list and
`ext.otel.outcome_context` sibling block already implement, wired to an empty allow-list pending
exactly this document (see §5, cross-check with batch3).

### 1.4 No-propagation fallback and coverage labeling

Baggage does not always survive the whole call graph — a hop through a component that does not
forward the W3C Baggage header (a legacy queue, an external API boundary that strips headers, a
batch job with no live trace context) breaks propagation. When a span at the effect boundary
carries no `org.agentactioncapsule.job_id` in Baggage, a collector **MUST NOT** silently omit
outcome-context correlation and **MUST NOT** guess a job identity. Instead it falls back to
**domain-key correlation**: joining the record to a job by the combination of a domain-specific
resource identity (for example, the tenant and workflow name carried in `resource` attributes,
`draft-palanisamy-scitt-aac-otel-00` §"Resource attributes") and a bounded time window around the
record's timestamp. This is a heuristic, not an identity, and every downstream consumer
must be able to tell the two apart.

`ext.otel.outcome_context` therefore carries one additional field:

| Field | Type | Req | Meaning |
|---|---|---|---|
| `coverage` | `key-correlated` \| `context-correlated` (closed enum) | REQUIRED whenever `ext.otel.outcome_context` is present | `key-correlated`: at least `job_id` was present in Baggage and validated. `context-correlated`: no outcome-context Baggage was present; correlation, if any, was achieved only through the domain-key-plus-time-window fallback, external to this block. |

A collector **MUST** label every outcome-context-tagged record with the coverage it actually
achieved. `context-correlated` **MUST NOT** be presented, displayed, or counted as equivalent to
`key-correlated` by any downstream tool — the whole reason this document introduces the label is
that silently treating a heuristic join as a real one is exactly the failure mode Part F asks this
document to close off.

## 2. Observation vs. effect classification — Part F item (2)

### 2.1 The rule, adopted by reference

Fleet collection uses one classification rule everywhere a span or event must be sorted into
"worth turning into a Capsule" or "ordinary observability data": `capsule-emit`'s Signal 1, as
`docs/whats-consequential.md` already states it for that library's own adapters. This document
does not re-derive that rule; it adopts it as the fleet-wide collection convention, because a
fleet with several collection points (an OTel processor, a gateway adapter, a framework-native
adapter) that each classified independently would be a drift risk this document exists to remove.

**Effect** means a state change in a system that outlives the agent — the same test
`whats-consequential.md` gives via Command–Query Separation and HTTP's safe-method distinction.
**Observation** means everything else: a read, a query, telemetry about the agent's own internal
reasoning.

### 2.2 Signal priority, restated for a collector

A collector classifying one span, in priority order:

1. **`destructiveHint: true`** is checked first and is unconditionally effect — MCP's own framing
   treats it as a stronger claim than `readOnlyHint`.
2. Otherwise **`readOnlyHint`**, when present, decides directly: `true` classifies observation;
   anything else (including an explicit `false`) classifies effect. Between them, the two MCP
   annotations are the **primary** signal this document gives priority over every other one, at any
   collection point that has them available (§2.2.1).
3. Absent both MCP hints, the HTTP method (`GET`/`HEAD`/`OPTIONS` observation; everything else
   effect), then the OTel database/messaging/RPC operation attributes
   (`db.operation.name`, `messaging.operation.type`, `rpc.method`), read for an unambiguous
   write/read verb.
4. **Fail-safe default: effect.** When no signal resolves the question, the span classifies as
   effect, never observation. Under-classifying a genuinely consequential action is the failure
   this whole record layer exists to prevent; over-classifying a harmless one costs a Capsule that
   need not have been sealed, which is the safe direction to err in.

MCP annotations are hints, not enforcement (per the Model Context Protocol's own framing) — a
misreporting tool server can only ever cause an observation to be over-classified as effect via
the fail-safe default, never the reverse, because a trusted hint may only downgrade classification
effort when it is affirmatively present, and its absence or falsity never grants an exemption.

#### 2.2.1 MCP hints are only as available as the collection point that sees them

"Primary signal" means priority order, not universal availability. A gateway, decorator, or
framework-listener collection point that observes the MCP protocol message directly (as
`capsule-emit`'s non-OTel adapters already do via `ConnectorEvent.mcp_read_only_hint` /
`mcp_destructive_hint`) evaluates tiers 1–2 first, exactly as ordered above. A collector that only
sees an **OpenTelemetry span** — no OTel GenAI semantic convention currently defines a span
attribute carrying `readOnlyHint` or `destructiveHint` (checked against the attribute table
`draft-palanisamy-scitt-aac-otel-00` §"GenAI semantic conventions" admits, and against this
document's own §4.1 resource table; neither carries one) — has no mechanical way to reach tiers
1–2 and correctly falls through to tier 3. This is not a fallback this document invents to route
around a gap: it is the same priority list evaluated honestly by a collection point with fewer
signals available, and it is why an OTel-span-only collector's classification is only ever as
strong as tier 3–4, never a defect in that collector. A future OTel GenAI semantic-convention
revision that adds an MCP-hint span attribute would let an OTel-span collector reach tier 1–2
directly; until one exists, this document does not invent a non-standard attribute name to fill
the gap (the same allow-list-only, do-not-invent discipline §1.3 already applies to baggage keys).

### 2.3 Never sample at the effect boundary

A collector's sampling policy (head-based, tail-based, cost-driven, or otherwise) **MUST NOT**
drop a span already classified effect. Sampling MAY reduce the volume of spans classified
observation. When classification cannot run before a sampling decision is made (for example, a
head sampler that fires before the span attributes needed for classification exist), the fail-safe
default of §2.2(4) applies transitively: the sampler **MUST** treat the not-yet-classified span as
effect for sampling purposes and retain it, deferring the actual classification to export time.
`capsule-emit`'s reference `CapsuleOTelSpanExporter` already satisfies this by construction — it
runs classification once per ended span, unconditionally, with no sampling step of its own — and
is cited here as the existing conforming behavior, not as something this document changes.

A `materiality_hint` (§1.1) MAY be used to prioritize which effect-classified spans get deeper
collection (fuller `semconv` capture, priority processing under backlog) but **MUST NOT** be used
to decide whether an effect-classified span is collected at all. Materiality prioritizes effort;
it never gates coverage.

## 3. Lifecycle records — Part F item (3)

Fleet collection needs to know not just what an agent *did*, but when an agent instance or a job
*existed* — because the absence of that knowledge, left unrecorded, becomes indistinguishable from
"nothing happened here." This section defines three record shapes, each an ordinary Capsule with
`action_type: "fyi"` (an administrative record, not a decided action — the same posture
`draft-mih-scitt-agent-action-capsule-05.md` §"Epoch-boundary Capsules" already uses) and a new
`domain` registry value, `lifecycle`, alongside the existing `action` / `memory` / `reasoning`
values (REGISTRY.md §8). A future revision of the base profile SHOULD register `lifecycle`
formally; this document specifies its semantics pending that registration.

### 3.1 Agent-instance open and close

An **agent-instance open** record is emitted once, when an agent instance starts serving traffic.
It carries the emitter-identity fields of §4 (agent template, cluster/VPC/namespace, instance id)
and an `opened_at` timestamp.

An **agent-instance close** record is emitted once, when the instance stops. It carries
`chain.relation: "confirms"` to the open record (non-terminal — the same relation an ordinary
attempted-then-confirmed pair uses, REGISTRY.md §6) and a `job_summary_digest`: a SHA-256 digest,
over plain JCS, of a producer-local summary object (at minimum, the count of jobs the instance
handled and its `closed_at` timestamp; a producer MAY include more, at its own discretion, subject
to the same content-admission discipline as any other Capsule field). The summary itself is never
carried in clear in the close record — only its digest — the same commit-by-digest posture the
base profile already applies to sensitive content generally.

### 3.2 Job open and close

Separately from the agent-instance lifecycle, the **orchestrator** — the same entry point that
mints outcome-context Baggage (§1.2) — emits a **job open** record at the moment it mints
`org.agentactioncapsule.job_id`, carrying that `job_id` and, when applicable, `contract_ref`. A
**job close** record follows when the job concludes, `chain.relation: "confirms"` to the job-open
record, carrying a digest of the job's final disposition summary (the same digest-only posture as
§3.1). A job's open/close pair is orthogonal to any single agent instance's open/close pair — one
job may span several agent instances (handoffs, retries across restarts), and one instance
typically serves many jobs.

### 3.3 The collector-emitted gap record: "terminated without close"

Silence must never be read as a clean exit. When a collector has observed an agent-instance-open
or job-open record and no matching close record arrives — detected by a heartbeat timeout, a
session TTL expiry, or an observed process/span termination with no corresponding close event —
the **collector**, never the agent and never the orchestrator, emits an explicit
**terminated-without-close gap record**.

| Field | Type | Req | Meaning |
|---|---|---|---|
| `chain.parent_capsule_id` | Capsule ID | REQUIRED | The open record this gap closes out, structurally (this is a `chain` link, so it participates in `capsule_id` the same as any other chained Capsule). |
| `detected_at` | RFC 3339 timestamp | REQUIRED | When the collector determined the gap, not when the underlying termination is believed to have occurred. |
| `basis` | `heartbeat_timeout` \| `session_ttl_expired` \| `process_exit_without_close` (open, namespace unseeded values per §"Namespacing convention") | REQUIRED | What observation led the collector to conclude termination-without-close. |

A gap record's `provenance` (REGISTRY.md §9) **MUST** be `collector` — the record states what a
passive observer inferred from an absence, not what the agent or orchestrator itself reported, and
`collector` is already this profile's lowest-authority provenance tier for exactly that reason. A
gap record makes an honest claim about uncertainty; it is not, and must never be presented as, a
substitute close record with real content.

### 3.4 Backfilled lifecycle and gap records

A collector does not always detect a gap promptly — a heartbeat-monitoring service that itself was
down, or a bulk reconciliation pass over old telemetry, can produce an agent-instance close, job
close, or `terminated-without-close` gap record well after the window it describes. Such a record
is an ordinary case of the base profile's `provenance_mode: "backfilled"`
(`draft-mih-scitt-agent-action-capsule-05.md` §"Provenance mode and backfilled records") — it is not a
distinct record type or a fourth lifecycle shape. A backfilled lifecycle or gap record carries
`provenance_mode.source_ref` citing whatever telemetry or log artifact the collector reconstructed
it from, `source_asserted_at` for when the gap is believed to have occurred, and `imported_at` for
when the collector actually produced the record — with the same `time_rung` cap: absent a
witnessed reference under `corroborates_source_time`, the reconstructed timing is no stronger than
`self_attested`, exactly as it would be for any other backfilled Capsule. This document adds no
new provenance-mode field; it states that lifecycle and gap records use the existing one when
produced late, the same way any other Capsule does.

## 4. Emitter identity — Part F item (4)

### 4.1 What identifies an emitter

An emitter's identity, for fleet-collection purposes, is the combination of:

- **Agent template identity** — name, version, model, and policy-manifest version. This is not a
  new field: it is what the Capsule's existing `developer` field already carries
  (`draft-mih-scitt-agent-action-capsule-05.md` §"Identity and parties"), together with the model and
  policy facts a `model_attestation` block records when present. This document does not duplicate
  either; a fleet emitter reports them exactly as the base profile already specifies.
- **Cluster / VPC / namespace** — the deployment-topology facts that place a template instance
  within the fleet. These map directly onto `org.agentactioncapsule.otel`'s already-admitted
  `resource` attributes: `service.name`, `service.version`, `service.namespace`,
  `deployment.environment.name` (all clear-safe, per that draft's "Resource attributes" table).
  This document adds no new resource attribute; it states that fleet collection populates the
  ones the OTel correlation extension already allow-lists, and that `service.instance.id`,
  `host.id`, `container.id`, and similar per-process identifiers remain digest-only at most, per
  that same table — they are stable identifiers with small effective entropy across a fleet, and
  hashing them is not anonymization.

### 4.2 Instance id: recorded, never load-bearing

The `instance_id` carried on a lifecycle record (§3.1) exists for operational
correlation and debugging — locating which running process a record came from — and for nothing
else. No verifier, policy engine, or assurance computation may condition an accept/deny decision,
an assurance-mode derivation, or an identity check on `instance_id` equality. Identity, for every
purpose this profile's verification model cares about, is `operator` plus agent-template identity
(`developer`, `model_attestation`); `instance_id` never substitutes for either.

### 4.3 Short-lived workload-identity keys

Producers SHOULD sign Capsules and lifecycle records with a short-lived key issued by the
platform's workload-identity system (for example, a SPIFFE/SPIRE X.509-SVID or JWT-SVID, or an
equivalent cloud workload-identity-federation credential), rotated well inside its own validity
window, rather than a long-lived static key provisioned once per deployment. This changes only
which key material backs the Producer Envelope's existing signature; it does not touch the wire
profile itself, consistent with the base profile's own note that DID, SPIFFE, or another
authorization policy composes underneath it without changing that shape
(`draft-mih-scitt-agent-action-capsule-05.md` §"Issuer Binding").

### 4.4 Collector-attested delegated signing — a lower rung, not a new axis

Some fleet components — a legacy runtime, a third-party agent with no workload-identity
integration — cannot hold a signing key of their own. In that case a nearby collector MAY sign a
Capsule or lifecycle record on the emitter's behalf, asserting only what the collector itself
observed rather than what the emitter cryptographically attested. This document does **not**
introduce a new assurance axis for this case: it is exactly what the base profile's `provenance`
registry (REGISTRY.md §9) already ranks lowest of its three authority tiers —
`gate` (3) > `runtime` (2) > `collector` (1) — "emitted by a general observability or telemetry
system that observed the action passively." Collector-attested delegated signing **is** the
`collector` provenance tier applied to the signing-identity question as well as the
emission-authority question the registry already names it for.

A collector-attested record's `developer` field names the agent template **as best known to the
collector**, and its `provenance` **MUST** be `collector`, disclosing that the identity claim is
second-hand rather than self-attested. A collector-attested record MUST NOT claim an
`attestation_mode` or emitter-identity fact stronger than what the collector's own key and
observation actually support — the same never-grades-up discipline the assurance ladder already
applies everywhere else (`draft-mih-scitt-agent-action-capsule-05.md` §"Assurance").

## 5. Cross-check against the batch-3 OTel processor

`[batch3-otel-processor-v0-digests-only]` (repo `capsule-emit`, held on branch
`batch3-otel-processor-v0-digests-only`, commits `188da2c`/`15ee675`/`26eff8a`) built the
mechanism this document specifies *before* this document existed, and correctly refused to invent
key names it had not been given — it shipped `outcome_context_baggage_keys=frozenset()` (empty)
and filed a `Needs decision` in `action-state-ops/neutral/outbox.md` asking where the real key
names would come from.

**This document resolves that block.** The four keys in §1.1
(`org.agentactioncapsule.job_id`/`contract_ref`/`principal`/`materiality_hint`) are the answer;
turning the mechanism on is the one-line `outcome_context_baggage_keys={...}` configuration change
that item's own docstring already anticipated. No code change to `capsule_emit.otel.block` or
`.processor` is required for the four keys themselves.

**Two items of drift found, both flagged here rather than silently fixed** (this item is
specs-only; fixing either is follow-up work for whoever next touches that branch):

1. **`ext.otel.outcome_context` needs the `coverage` field (§1.4).** The held branch's
   `build_outcome_context_block` tags whatever Baggage entries the allow-list matches, but has no
   concept of `key-correlated` vs. `context-correlated` — because that distinction did not exist
   before this document. A follow-up should add `coverage` to the block, defaulting to
   `key-correlated` when `job_id` is present and `context-correlated` otherwise (per §1.4; the
   fallback's domain-key/time-window join itself is not implemented on that branch at all, and is
   out of scope for a v0 OTel-SDK-level exporter that has no independent job-correlation store to
   consult).
2. **The processor does not set `provenance`.** Nothing in `capsule_emit.otel.processor` or the
   shared `_emit_capsule` path it calls populates the base profile's `provenance` registry field
   (REGISTRY.md §9) at all. Per §4.4 above, every Capsule this processor seals is collector-emitted
   passive observation and should carry `provenance: "collector"`. This is a pre-existing gap in
   `capsule-emit` generally (grepping the whole `emit_capsule` call path finds no `provenance=`
   parameter anywhere, not only in the OTel processor), so fixing it fleet-collection-wide is
   larger than this one processor and is noted here for the neutral lane, not fixed in this item.

**A third observation, not a defect:** the processor's Signal 1 implementation
(`capsule_emit/otel/signal.py`, `classify_span_signal_1`) evaluates only `http.request.method` and
the db/messaging/rpc commit-step attributes — it never reads an MCP `readOnlyHint`/`destructiveHint`
value, because no such span attribute exists to read (§2.2.1). This is the correct behavior for an
OTel-span-only collection point given today's OTel GenAI semantic conventions, not a gap this item
introduces or that a follow-up needs to close — it is called out here only so a future reviewer
does not mistake tier-3-only classification in this processor for an oversight against §2.2's
tier-1/2 MCP priority. §2.3's never-sample posture, by contrast, is already fully satisfied: this
processor's `CapsuleOTelSpanExporter` runs classification unconditionally on every ended span with
no sampling step of its own, and its digest-only-by-default posture for trace/span identifiers
matches `draft-palanisamy-scitt-aac-otel-00`'s Privacy Considerations without needing any change
from this document.

## 6. Worked example

A 500-cluster enterprise runs an orchestrator that receives a claims-processing job. The
orchestrator mints outcome context at the entry point: `job_id=job-9f2e...`,
`contract_ref=ec:claims-review:2026-09@2`, `principal=claims-bu-04`, `materiality_hint=standard`.
It emits a job-open record, then a chain of sub-agent and tool-call spans propagate the four
Baggage keys unchanged across a handoff to a second cluster's agent instance. At the effect
boundary — a tool call that writes a determination to a case-management system — the collector
classifies the span `effect` (an MCP `destructiveHint: true` tool annotation resolves it at
priority 1), builds `org.agentactioncapsule.otel` per the correlation draft, and tags
`ext.otel.outcome_context` with the four digested keys and `coverage: key-correlated`. Thirty
minutes later the second cluster's agent instance crashes without emitting a close record; the
collector's heartbeat monitor detects the gap and emits a `terminated_without_close` record with
`basis: heartbeat_timeout`, chained to that instance's open record, `provenance: collector`. No
record in this example claims more than what was actually observed, and no gap is silent.

---

## Reviewers (for Steven)

Per Area 17's done-when ("conventions draft shared with Amplifier and one OTel-literate
reviewer"), this document is not shared outside until Steven reviews it. Candidates found in the
workspace (no identity invented; both are for Steven to confirm or replace):

- **Amplifier contact:** no named individual is recorded anywhere this search reached
  (`action-state-strategy/docs/strategy/product-strategy/amplifier-*`) — the partner name is
  established, the contact person is not. Steven to name one.
- **OTel-literate reviewer:** G. Palanisamy, co-author of `draft-palanisamy-scitt-aac-otel-00`,
  the companion draft this document builds directly on and cites throughout. The most immediately
  relevant OTel-literate reviewer already in this document's own author line, pending Steven's
  confirmation that a co-author is an appropriate first reviewer versus someone independent of
  that draft.
