# Ledger-Grade Capsules

A capsule is *ledger-grade* when it satisfies four properties simultaneously.
Together they make a history of agent actions portable, independently verifiable,
and tamper-evident without requiring the original producer to be online.

## The Four Properties

### 1. Stable principal identity

The `operator` and `developer` fields in the capsule payload are stable,
human-readable strings scoped to the issuing party — they do not change when
signing keys are rotated. A verifier can identify who produced a capsule and
under whose authority without resolving key material.

### 2. Epoch partitioning

An `epoch_id` field partitions the capsule stream at configuration
boundaries — key rotations, operator changes, or policy resets. Capsules that
share an `epoch_id` were produced under the same configuration; a change in
`epoch_id` signals a new context.

> **Dependency note.** `epoch_id` as a first-class field in `emit()` is
> scheduled for the identity-epochs work and has not yet been merged into this
> library. Until that work lands, `epoch_id` can be carried inside
> `compute_attestation` as a best-effort label. The `history` API reads both
> locations and treats them equivalently.

### 3. Chain linkage

Each capsule's `chain` block records the `parent_capsule_id` of its predecessor
and a `relation` tag (`"follows"`, `"sequence"`, `"epoch_opens"`, etc.). This
creates a verifiable sequence: any capsule whose parent is absent from the
observed window is a detectable gap. A capsule with `chain.relation ==
"epoch_opens"` is a legal chain-starter and does not constitute a gap.

Omission is detectable within a window: `verify_chain_completeness()` in
`agent_action_capsule.history` reports missing parents as named gaps and flags
the capsule IDs where the break occurs.

### 4. Anchored by default — a rung, not a gate

Completeness (property 3, chain-gap-freeness) is never conditioned on
anchoring. A capsule is complete when its chain has no gaps, full stop — that
holds at every rung, including a capsule with no anchoring evidence at all.
"Anchored by default" instead means the `history` API always **reports where
a capsule or bundle stands** on an anchoring-evidence rung, so a consumer can
see and act on the assurance level without the library silently assuming more
than the evidence supports.

The rung is one of, least- to most-assured:

| Rung | Evidence |
|---|---|
| `standalone` | No countersignature, no inclusion proof |
| `countersigned` | A matching countersignature is present, but no transparency-service (TS) receipt |
| `local-anchored` | A TS inclusion proof is present but its visibility is unspecified or scoped `local` |
| `counterparty-visible` | A TS inclusion proof scoped `counterparty` — independently checkable by a named counterparty, not the general public |
| `publicly-anchored` | A TS inclusion proof scoped `public` — independently checkable by anyone |

Completeness is a receipt from *a* transparency service, which may be the
local one — the library never treats "not yet publicly anchored" as
incomplete. A capsule with zero anchoring evidence is `standalone` and can
still be chain-complete.

**Never-grades-up discipline.** The rung reported for a *bundle* (a list of
capsules) is the **minimum** rung any one capsule in it has earned — one
capsule's strong evidence never inflates a sibling's absence of evidence, or
the bundle as a whole. Within a single capsule, only evidence keyed to that
capsule's own `capsule_id` is credited; an inclusion proof or countersignature
for a different capsule is ignored. An inclusion proof with no (or an
unrecognised) `visibility` field is credited only `local-anchored`, the floor
anchored tier — evidence of *some* registration is not evidence of *public*
registration.

The `export_verifiable_bundle()` function accepts inclusion proofs and
countersignatures alongside the capsule payload so that the exported bundle is
both self-contained for offline re-verification and carries the rung it
earned.

## Summary table

| Property | Capsule field(s) | Why it matters |
|---|---|---|
| Stable principal identity | `operator`, `developer` | Survives key rotation |
| Epoch partitioning | `epoch_id` (pending), `compute_attestation.epoch_id` | Scopes history to a configuration |
| Chain linkage | `chain.parent_capsule_id`, `chain.relation` | Gaps are detectable |
| Anchored by default | `ChainReport.rung` (`standalone` … `publicly-anchored`) | Reports assurance level; never gates completeness |

## API surface (`agent_action_capsule.history`)

```python
list_capsules(operator, window_start, window_end, epoch_id=None, ledger_path=...) -> list[dict]
verify_chain_completeness(capsules, epoch_id=None, inclusion_proofs=None, countersignatures=None) -> ChainReport
export_verifiable_bundle(capsules, inclusion_proofs=None, countersignatures=None) -> dict
```

`ChainReport` fields: `complete` (bool), `gaps` (capsule IDs with missing
parents), `epoch_opens` (legal chain-starters), `warnings`, `rung` (one of
`RUNGS`: `standalone`, `countersigned`, `local-anchored`,
`counterparty-visible`, `publicly-anchored`).

`inclusion_proofs` / `countersignatures` are lists of dicts keyed by
`capsule_id`: `{"capsule_id": ..., "visibility": "local"|"counterparty"|"public", ...}`
for inclusion proofs, `{"capsule_id": ..., ...}` for countersignatures.

A bundle exported by `export_verifiable_bundle()` can be re-verified by
passing `bundle["capsules"]` (with the same `inclusion_proofs` /
`countersignatures`) back through `verify_chain_completeness()` and should
produce an identical `ChainReport`, including `rung`. The bundle also carries
`bundle["rung"]` at the top level alongside `bundle["chain_report"]`.

Rung-transition vectors — one case per rung plus the never-grades-up guard
cases — live in `python/tests/vectors/rung/` and run via
`python/tests/test_history.py::test_rung_vectors`.
