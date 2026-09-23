# Capture Policy — v0

**Status.** Design specification, pre-Internet-Draft. This document defines two things that sit
between a Capsule's identity and where its bytes end up: (1) the **effect-boundary capsule id** —
the idempotency key an at-least-once delivery path uses to commit an effect Capsule exactly once
— and (2) the **capture policy** — the per-evidence-class rule for how much of a Capsule's payload
a fleet retains, and where, derived mechanically from an Evidence Contract rather than
hand-written per deployment. It does not define the fleet log topology that entries are appended
to (see the companion `cll-rollup-topology-v0.md`, `checkpointed-local-log/spec/`) or the payload
storage layout that a `payload-in-*` capture level materializes into (see the companion
`payload-store-v0.md`, this directory).

## Dependency boundary

**Owns:** the effect-boundary capsule id construction (§1), the three-value capture-level
vocabulary and its per-evidence-class assignment (§2), the default reversal-window retention rule
for effect payloads (§3), the derivation rule binding capture level to an Evidence Contract's own
requirements rather than to hand-written per-deployment policy (§4), the GitOps-overlay expression
of a derived policy (§5), and the delivery-semantics split between effect capsules (at-least-once,
idempotent commit) and observations (best-effort, drop-accounted) (§6).

**Depends on:**

- `draft-mih-sokolov-scitt-payload-binding` (CPB) §"The Derived Identifier" for the digest
  construction the effect-boundary id reuses unmodified (§1) — this document defines no new
  digest algorithm or canonicalization rule.
- `draft-mih-scitt-agent-action-capsule` §"Effect Record" for `effect.status`,
  `irreversibility_class`, and `effect_attestation` — referenced, not redefined; capture policy
  reads these fields, it does not extend their vocabularies.
- An Evidence Contract (referenced by id, per the convention already established in
  `evidence-plan-ir-v0.md` §"Dependency boundary") for the `evidence_requirements` and
  obligation-profile `retention_check` fields §4 derives capture level from. This document does
  not redefine the Evidence Contract's object model; where its internals are needed, the private
  internal specification governs and this document cites it by reference only.

**Explicitly out of scope:**

- Legal hold, litigation retention, or any customer/operator-specific retention override.
  Capture policy states the DEFAULT a deployment derives mechanically; an operator's own
  retention obligations are the operator's, not this document's, and are layered on top, never
  encoded here.
- The physical storage layout, tiering, or retrieval-logging mechanism a `payload-in-*` capture
  level implies — the companion `payload-store-v0.md` owns that.
- The fleet log topology an effect-boundary id's containing Capsule is ultimately appended to —
  the companion `cll-rollup-topology-v0.md` owns that; this document is agnostic to whether the
  Capsule lands in a single CLL or a rolled-up tree.

## 1. The effect-boundary capsule id {#effect-boundary-id}

An at-least-once delivery path — a retrying client, a queue with redelivery, a network partition
that forces a resend — can present the same logical effect request to a collector more than once.
Without an idempotency key, each redelivery risks a duplicate commit: a second CLL entry for one
real-world effect, a second downstream dispatch, or both.

The **effect-boundary capsule id** is that idempotency key:

```
effect_boundary_id = CANONICAL-DIGEST(A, effect_subject minus exclusion_set)
```

— exactly CPB's Derived Identifier construction (`draft-mih-sokolov-scitt-payload-binding`
§"The Derived Identifier"), applied to the **effect subject**: the fields that identify *what
effect this is*, independent of how many times it has been presented for commit. `A` is the
canonicalization algorithm and `exclusion_set` the self-referential/chain-linkage field set, both
declared by the Capsule's payload class exactly as CPB already requires for any derived
identifier — this document adds no new canonicalization or exclusion-set rule.

**Effect subject, not capsule_id.** `effect_boundary_id` is deliberately not the Capsule's own
`capsule_id` (`draft-mih-scitt-agent-action-capsule` §"Identity"): `capsule_id` commits the whole
Capsule, including fields that vary between two deliveries of the same logical request (a fresh
`issued_at`, a fresh envelope). The effect subject's exclusion set is chosen so that two
deliveries of the same logical effect — same actor, same target, same requested action, same
correlation key — produce the identical `effect_boundary_id` regardless of delivery attempt
number, timestamp, or envelope. This is the entire idempotency property: the id is a function of
*what is being requested*, not of *this particular delivery of the request*.

**Idempotent commit.** A collector receiving an effect Capsule computes `effect_boundary_id` and
checks it against what it has already committed for this log identity. A first arrival commits
normally (a CLL entry per the base draft's Log Discipline). A redelivery bearing the same
`effect_boundary_id` is recognized as the same logical effect and MUST NOT produce a second CLL
entry or a second downstream dispatch; a collector MAY choose to reject the redelivery, or to
acknowledge it against the already-committed entry, but MUST NOT commit it a second time. This is
an application-layer commit discipline layered on top of the base draft's append-only log — it
does not change what a CLL entry is (still opaque, still a digest per the base draft's Entry
definition), only how a collector decides whether a given effect subject has already produced
one.

## 2. Capture level per evidence class {#capture-level}

Every evidence class a capture policy governs is assigned exactly one of three capture levels:

| Level | What is retained |
|---|---|
| `digest-only` | The CLL entry's digest, and nothing else — the underlying payload is never stored by this deployment's own capture layer. Retrievable, if at all, only from the producer's system of record. |
| `payload-in-cluster` | The full payload is retained in the cluster-tier payload store (companion `payload-store-v0.md` §"Two tiers") — co-located with, and retained on the same schedule as, the L0 collector that appended the committing entry. |
| `payload-in-domain` | The full payload is retained in the domain-tier payload store — promoted one tier up from cluster, for evidence classes a deployment's obligations require to survive past a single cluster's own retention horizon. |

The three levels are ordered by retained surface, not by log topology depth: `payload-in-domain`
does not imply the payload is ever an entry at L1 or L2 (roll-up entries are checkpoint digests,
per `cll-rollup-topology-v0.md` §1 — payloads are never roll-up entries at any level). It names
which payload store tier holds the bytes, independent of which log level the committing
Capsule's checkpoint reaches.

## 3. Effect payloads: kept by default for the reversal window {#reversal-window}

An effect Capsule's `irreversibility_class` (`draft-mih-scitt-agent-action-capsule` §"Effect
Record": `two_way`, `one_way_recoverable`, `one_way_consequential`, `one_way_terminal`) already
states how far a committed effect can be walked back. Capture policy's default rule ties directly
to it: **an effect Capsule's payload defaults to `payload-in-cluster` (or higher, per §4) for the
duration of its class's reversal window**, regardless of what the evidence-class default would
otherwise be, because a dispute or correction over an effect that has not yet closed its reversal
window is exactly the case where digest-only (no retrievable payload) leaves a fleet unable to
answer the dispute at all. A `two_way` effect's reversal window MAY be zero (nothing to hold open
— the effect is trivially reversible without needing the original payload retained); the
remaining three classes each carry a non-zero default window, the length of which is a per-class,
registry-governed value this document does not fix (the same registry-governed pattern
`draft-mih-scitt-agent-action-capsule` §"IANA Considerations" already uses for
`irreversibility_class` itself).

At the reversal window's expiry, the payload is eligible for retention compaction
(`payload-store-v0.md` §"Retention compaction") — the CLL entry and every checkpoint that commits
it are unaffected; only the payload store's retrievable copy is removed.

## 4. Derived from the Evidence Contract, not hand-written {#derivation}

A capture policy is **derived**, mechanically, from the Evidence Contract governing the evidence
being captured — never authored by hand per deployment. The derivation rule:

1. For a requirement carrying `evidence_requirements` (every profile — the Evidence Contract's
   own field, referenced not redefined per this document's Dependency boundary), the capture
   level for evidence satisfying that requirement is `payload-in-cluster` if the requirement's
   assurance tier requires a recomputable/verifiable artifact (per the Evidence Contract's own
   sufficiency model), else `digest-only`.
2. For an obligation-profile requirement carrying `retention_check` (`draft-mih-scitt-
   agent-action-capsule`'s evidence layer defers to the Evidence Contract for this field, per
   this document's Dependency boundary), the presence of a `retention_check` promotes the
   evidence class to at least `payload-in-domain` — an obligation that names its own required
   retention evidence is, by construction, asking for more than cluster-local survival.
3. §3's reversal-window rule composes with, and can only raise, whichever level rules 1–2 assign:
   an effect Capsule inside its class's open reversal window is never captured at a level lower
   than `payload-in-cluster`, even where rule 1 alone would have assigned `digest-only`.

**Never hand-written.** A deployment does not author "evidence class X → level Y" mappings
directly; it authors (or inherits) an Evidence Contract, and the mapping above computes capture
level from it. This mirrors `evidence-plan-ir-v0.md`'s own dependency discipline: the private
planning/authoring logic that produces a contract is out of scope everywhere in this repository;
what ships here is only the deterministic projection from a contract's own requirements to a
wire-visible outcome — here, a capture level, rather than a plan node.

## 5. Expressed as a GitOps overlay {#overlay}

The derived capture policy for a given Evidence Contract ships as a GitOps overlay: a declarative
document, keyed by `contract_ref` (the same compact versioned reference —
`<contract_id>@<version>` — `evidence-plan-ir-v0.md` §2 already defines for plan headers),
mapping each of that contract's evidence classes to the capture level §4 derived for it. The
overlay is:

- **Generated, not edited.** A conforming implementation regenerates the overlay whenever the
  cited contract's `evidence_requirements`/obligation `retention_check` fields change, and the
  regenerated overlay replaces the prior one in version control — the overlay is checked-in
  output of §4's derivation, never a second, independently-maintained source of truth that can
  drift from the contract it claims to reflect.
- **Reviewable like any other GitOps change.** Because the overlay is declarative and
  version-controlled, a capture-level change for a given contract is visible as an ordinary diff
  — a promotion from `digest-only` to `payload-in-cluster` (or the reverse) is a reviewable,
  auditable event, not a runtime toggle.
- **Silent about retention length.** Per this document's Dependency boundary, the overlay states
  capture LEVEL only; how long the payload store actually holds a `payload-in-cluster`/
  `payload-in-domain` payload before compaction is `payload-store-v0.md`'s retention-compaction
  concern (and §3's reversal-window rule, for effect payloads specifically) — the overlay does
  not duplicate that schedule.

## 6. Delivery semantics: effects vs. observations {#delivery}

Two distinct delivery disciplines, because they have different failure costs:

**Effect capsules — at-least-once delivery, idempotent commit.** §1's `effect_boundary_id`
exists specifically so a collector can absorb redelivery of the same effect without
double-committing or double-dispatching. A dropped effect delivery is retried until it commits;
losing one silently is not an acceptable failure mode, because an effect Capsule records a
real-world consequence that already happened.

**Observations — best-effort, with drop accounting.** An observation (a non-effect Capsule
recording something noticed rather than something done) MAY be dropped under backpressure,
collector unavailability, or any other best-effort delivery failure — retrying every observation
to guaranteed delivery is not required. What IS required: a collector that drops observations
MUST maintain a **drop count** for the window in which drops occurred, and MUST make that count
available alongside any coverage claim it reports. A deployment reporting "N observations
captured this period" without also reporting how many were dropped is making a claim its own
delivery discipline does not support; the drop count is what keeps "coverage" an honest word
rather than a claim about only the subset that happened to arrive. This mirrors the three-state
honesty pattern already used throughout this repository's dependencies (never collapse "unknown"
or "some dropped" into a false "complete") — applied here to delivery coverage specifically.

## 7. Worked example

An Evidence Contract `ec:fleet-oo-outcome:2026-09-22@1` has two requirements: an outcome-profile
requirement with `evidence_requirements` requiring a recomputable artifact (rule 1: assurance
tier requires verifiable evidence), and an obligation-profile requirement with a `retention_check`
naming a required retention evidence class (rule 2).

Applying §4's derivation:

- The outcome requirement's evidence class → `payload-in-cluster` (rule 1: recomputable artifact
  required).
- The obligation requirement's evidence class → `payload-in-domain` (rule 2: `retention_check`
  present, promotes past cluster-local).

If evidence for the outcome requirement happens to be an effect Capsule with
`irreversibility_class: one_way_consequential` inside its open reversal window, §3 does not lower
its already-assigned `payload-in-cluster` level (rule 1 already met the floor §3 would have
imposed) — §3 only ever raises a level, never lowers one rules 1–2 already set higher.

The resulting overlay for `ec:fleet-oo-outcome:2026-09-22@1`:

```yaml
contract_ref: "ec:fleet-oo-outcome:2026-09-22@1"
capture_levels:
  - evidence_class: outcome-requirement-artifact
    level: payload-in-cluster
  - evidence_class: obligation-retention-evidence
    level: payload-in-domain
```

— generated from the contract, not authored, per §5.

## Vocabulary discipline

This document MUST NOT use, in any form: `Authority`, `Relay`, `score`/`scoring`, `reputation`,
or any legal-hold/litigation-retention policy content — those are operator decisions layered on
top of, never encoded in, the default this document derives. This document specifies capture
level and delivery discipline only; the storage layout a `payload-in-*` level materializes into
is `payload-store-v0.md`; the log topology a committing Capsule's entry lands in is
`cll-rollup-topology-v0.md`.
