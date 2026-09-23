# Payload Store — v0

**Status.** Design specification, pre-Internet-Draft. This document defines the storage layout a
`payload-in-cluster` or `payload-in-domain` capture level (companion `capture-policy-v0.md` §2)
materializes into: how a payload is addressed, where it lives, how it is retrieved, and how it is
compacted at retention expiry. It does not define capture level itself (which evidence classes
get retained at all — `capture-policy-v0.md`'s concern) or the log topology a payload's
committing entry is appended to (`cll-rollup-topology-v0.md`'s concern).

## Dependency boundary

**Owns:** content addressing by the same digest a CLL entry commits (§1), the two-tier store
model and its correspondence to `capture-policy-v0.md`'s capture levels (§2), the
capsule-to-payload retrieval path (§3), the mandatory retrieval-access log (§4), and the
retention-compaction rule that removes payload bytes without touching the committing log (§5).

**Depends on:**

- `checkpointed-local-log`'s CLL base draft for what a committed entry's digest is and means — a
  payload store never invents its own addressing scheme; it reuses the digest the log already
  committed (§1).
- `capture-policy-v0.md` for the capture-level vocabulary (`digest-only` /
  `payload-in-cluster` / `payload-in-domain`) that determines whether, and at which tier, a given
  payload is stored here at all.
- `draft-mih-sokolov-scitt-payload-binding` for the digest/canonicalization convention a stored
  payload's content address follows — this document defines no competing digest algorithm.

**Explicitly out of scope:**

- Which evidence classes get a payload stored at all, or at which tier — `capture-policy-v0.md`
  owns that decision; this document only defines what happens once a level has already been
  assigned.
- Retention *length* (how long a stored payload survives before compaction eligibility) — a
  per-evidence-class, registry-governed value owned by `capture-policy-v0.md` §3's reversal-window
  rule and by the Evidence Contract obligations §4 there derives from. This document owns only
  the mechanics of compaction once expiry is reached (§5), not the schedule.
- Physical storage backend choice (object store, filesystem, database) — an implementation
  concern this document imposes no requirement on beyond content-addressability (§1).

## 1. Content-addressed by the same digest the log commits {#addressing}

A payload store's key for a stored payload is **exactly the digest the committing CLL entry
carries** — not a derived, re-hashed, or otherwise distinct store-internal identifier. If a CLL
entry is `entry_digest(payload)` per the base draft's Entry definition ("typically the digest of
a signed record"), the payload store's lookup key for that payload is that same `entry_digest`
value, in the same representation CPB's Derived Identifier §"Representation" requires payload
classes to declare (bare hex, prefixed text, or raw octets — never treated as interchangeable).

This is a deliberate, single design choice with two consequences: (a) no second identifier
namespace exists to drift from the log's own digests — resolving a payload is always "look up
this exact value," never "map this log-side id to some store-side id first"; and (b) a payload
store implementation can be verified trivially against any CLL implementation without either
knowing about the other's internals — the shared contract is the digest, nothing more.

## 2. Two tiers {#tiers}

| Tier | Co-located with | Materializes |
|---|---|---|
| Cluster | The L0 collector (`cll-rollup-topology-v0.md` §2) | `payload-in-cluster` |
| Domain | The L1 domain aggregator, where one exists | `payload-in-domain` |

A deployment that collapses L1 (`cll-rollup-topology-v0.md` §4) has no domain tier;
`payload-in-domain` payloads in such a deployment are promoted directly to whatever tier the
collapsed topology's aggregation point provides.

A payload assigned `payload-in-domain` by capture policy is NOT additionally required to exist in
the cluster tier — promotion to domain tier is not additive storage, it is a *replacement* of the
retention horizon a cluster-tier-only payload would have had. A deployment MAY choose to also
retain a cluster-tier copy for locality (faster local reads), but this document requires only
that a `payload-in-domain` payload be retrievable at or above the domain tier; a deployment
retaining a redundant cluster-tier copy applies its own consistency discipline for keeping the
two in sync, which this document does not specify.

There is no root-tier (L2) payload store. Per `capture-policy-v0.md` §2 and
`cll-rollup-topology-v0.md` §1, roll-up entries above L0 are checkpoint digests, never payloads —
there is structurally nothing for an L2-tier payload store to hold.

## 3. Retrieval path: capsule → digest → store or system of record {#retrieval}

Given a Capsule (or any record whose committing CLL entry a caller holds), resolution proceeds:

1. **Capsule → digest.** The caller already has, or recomputes, the record's derived identifier
   / entry digest per §1 — this step performs no new computation this document defines; it is
   ordinary CLL/CPB digest recomputation, unchanged.
2. **Digest → store.** The caller queries the payload store tier(s) implied by the evidence
   class's capture level (`capture-policy-v0.md` §2) for that exact digest.
3. **Store hit → payload.** The store returns the payload bytes it holds under that digest. The
   caller MUST re-verify the returned bytes' digest matches the queried key before treating the
   payload as authentic — a store is an untrusted cache from the caller's point of view, not an
   attestation; only the CLL checkpoint chain attests inclusion, never the store.
4. **Store miss → system of record.** If the store holds no payload for that digest — because
   capture level was `digest-only`, or because retention compaction (§5) has already run — the
   caller falls back to the producer's own system of record, if one is named and reachable.
   Whether a system-of-record fallback exists at all is deployment-specific; this document
   imposes no requirement that one does. A miss at both the store and any named system of record
   is reported as a distinct, honest refusal (e.g. "not retained") — never conflated with "this
   digest was never committed," which is a claim only the CLL checkpoint chain, not the payload
   store, is positioned to make. This mirrors the CLL base draft's own §"Segmentation and
   archival" rule for an unmounted segment: a retrieval failure names *why* retrieval failed,
   distinctly from a claim about whether the entry ever existed.

## 4. Every retrieval logged {#retrieval-log}

A payload store MUST log every retrieval it serves, recording at minimum:

| Field | Meaning |
|---|---|
| `who` | The identity of the requesting party (a producer, verifier, or operator identity — not merely a network address). |
| `digest` | The exact digest requested (§1's addressing key). |
| `contract` | The Evidence Contract reference (`contract_ref`, `evidence-plan-ir-v0.md` §2's convention) the retrieval was made in service of, where the caller supplies one. |
| `projection` | What the caller did with the retrieved payload once obtained — e.g. which requirement or plan node consumed it — to the extent the caller declares this; a store MUST NOT infer or guess it. |

This retrieval log is itself evidence: a party auditing who has read a sensitive payload, and
under what evidence-gathering justification, reads this log rather than trusting the requester's
own unlogged say-so. The retrieval log is a distinct object from the CLL log the payload's own
entry lives in — retrieval logging governs read access to already-committed content; it commits
nothing new about the payload itself and does not require its own CLL entry, though a deployment
MAY choose to commit retrieval-log summaries into its own audit trail by whatever mechanism it
already uses for operational logging.

## 5. Retention compaction: payload → digest, log untouched {#compaction}

At a stored payload's retention expiry (`capture-policy-v0.md` §3's reversal-window rule, or
whatever longer schedule an obligation's `retention_check` imposes), the payload store MAY
compact: remove the stored payload bytes, retaining only the digest as a tombstone recording that
a payload once existed under that key and has since expired.

**The committing CLL log is never touched by compaction.** The CLL entry, every checkpoint that
commits it, and every consistency/inclusion proof over it are unaffected — compaction is purely a
payload-store-side deletion of retrievable bytes; it is not, and MUST NOT be represented as, an
edit, removal, or rewrite of any log. This is the same distinction the CLL base draft's own Log
Discipline already draws for erasure ("Erasure of the *content* an entry commits to is a separate
act on separate storage and does not touch the log; the entry (a digest) remains"); retention
compaction is exactly that separate act, named and scheduled here rather than left implicit.

**Post-compaction retrieval.** §3 step 4's "not retained" refusal is the expected, honest outcome
for a retrieval against a compacted digest — the caller's digest recomputation in step 1 and the
log's own checkpoint chain still prove the record existed and was committed at a given position;
only its full bytes are no longer retrievable from this store. A verifier that needs both
existence-proof and content for a compacted record has no source for the latter this document
defines; that is the intended, honest limit retention compaction imposes, not a defect to be
worked around.

## Vocabulary discipline

This document MUST NOT use, in any form: `Authority`, `Relay`, `score`/`scoring`, `reputation`,
or any legal-hold/litigation-retention policy content — retention length and its policy
justification are `capture-policy-v0.md`'s concern and the operator's own obligations, never this
document's. This document specifies addressing, tiering, retrieval, and compaction mechanics
only.
