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

### 4. Anchored by default

A capsule is not considered complete by the `history` API until it has been
registered with a SCITT Transparency Service and an inclusion proof (Receipt) is
available. Registration produces a Signed Statement whose receipt can be
re-verified independently of the original producer. The `export_verifiable_bundle()`
function accepts inclusion proofs alongside the capsule payload so that the
exported bundle is self-contained for offline re-verification.

## Summary table

| Property | Capsule field(s) | Why it matters |
|---|---|---|
| Stable principal identity | `operator`, `developer` | Survives key rotation |
| Epoch partitioning | `epoch_id` (pending), `compute_attestation.epoch_id` | Scopes history to a configuration |
| Chain linkage | `chain.parent_capsule_id`, `chain.relation` | Gaps are detectable |
| Anchored by default | inclusion proof / Receipt | Independently re-verifiable |

## API surface (`agent_action_capsule.history`)

```python
list_capsules(operator, window_start, window_end, epoch_id=None, ledger_path=...) -> list[dict]
verify_chain_completeness(capsules, epoch_id=None) -> ChainReport
export_verifiable_bundle(capsules, inclusion_proofs=None) -> dict
```

`ChainReport` fields: `complete` (bool), `gaps` (capsule IDs with missing parents),
`epoch_opens` (legal chain-starters), `warnings`.

A bundle exported by `export_verifiable_bundle()` can be re-verified by passing
`bundle["capsules"]` back through `verify_chain_completeness()` and should
produce an identical `ChainReport`.
