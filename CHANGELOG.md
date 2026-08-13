# Changelog

## Unreleased

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-03.md` §5.3 Assurance — added the
  cross-party assurance rung, a FOURTH, orthogonal `assurance` claim
  (`cross_party_rung`: `unilateral_fallback` < `acknowledged_receipt` <
  `full_bilateral`) plus its supporting `cross_party` evidence block
  (`initiator_ref`, `counterparty_ref`, `correlator`, `substantive`). Kept
  orthogonal to `attestation_mode` rather than folded into it (log custody and
  counterparty exchange evidence are independent facts a producer can hold in
  any combination); the draft states this reasoning inline. Same
  never-grades-up overclaim discipline as `attestation_mode` / `ledger_mode`.
- `spec/draft-mih-scitt-agent-action-capsule-03.md` §5.4 Disposition —
  extended the CLOSED `disposition.approver` enum from `{human, policy}` to
  `{human, policy, counterparty}`. Stays closed (not registry-governed); the
  pre-existing honesty invariant (`human_disposed: true` REQUIRES
  `approver: "human"`) is unaffected.

### Compat
- **Migration path (never-grades-up):** an old verifier that does not
  recognize `cross_party_rung` or the `cross_party` block simply does not see
  them — it verifies the record on the three axes it already knows and never
  errors on the unrecognized field/block, matching how it already tolerates
  any other unrecognized value. A verifier that DOES recognize the field but
  is handed a `cross_party_rung` value outside what it can independently
  derive ranks the claim below what it knows: a `full_bilateral` or
  `acknowledged_receipt` claim it cannot corroborate is treated no stronger
  than `unilateral_fallback` (the same floor an unrecognized `attestation_mode`
  value is already held to, §5.3) — nothing breaks, and no record is silently
  over-trusted.
- An old verifier encountering `disposition.approver: "counterparty"` before
  this revision would reject the Capsule outright (closed two-member enum);
  this revision is additive, not a relaxation — the enum grows from two
  members to three, still closed, so no third-party value is newly admitted.

### Docs
- `docs/telemetry-binding-profile.md`: new informational profile (AARM R8,
  `capsule-ledger`'s `ldg-otel-exporter-aarm-r8`) specifying the
  reference-never-copy rule for telemetry export, the minimum attribute set,
  and the mapping to OTLP/`gen_ai` (primary) and OCSF (secondary,
  best-effort — documents the mismatch rather than presenting a native fit).
  Not core spec: telemetry is a projection of the capsule, and this profile
  moves at OTel/OCSF's release speed so core doesn't have to.

### Added
- `python/agent_action_capsule/contracts.py`: `CrossParty` producer-side
  carrier (§5.3 Cross-party assurance evidence), `CROSS_PARTY_RUNGS`,
  `CROSS_PARTY_RUNG_RANK`; `AssuranceBlock.cross_party_rung` (OPTIONAL);
  `VALID_APPROVERS` extended to include `"counterparty"`.
- `python/agent_action_capsule/verify.py`: check 7 (`assurance_overclaim`)
  extended to `cross_party_rung` — a claimed rung above what the verifier
  independently rederives from the `cross_party` block is flagged and the
  reported `derived.cross_party_rung` is downgraded to the value the evidence
  supports.
- `python/agent_action_capsule/parse.py`: `Capsule.cross_party` /
  `parse_capsule` round-trip the new block and `assurance.cross_party_rung`.
- `test-vectors/`: four new conformance vectors — one per cross-party rung
  (`pos-cross-party-full-bilateral`, `pos-cross-party-acknowledged-receipt`,
  `pos-cross-party-unilateral-fallback`), and the named overclaim case
  (`neg-cross-party-overclaim`: `full_bilateral` claimed with only the
  initiator's half present) plus `pos-disposition-approver-counterparty`
  confirming the honesty invariant holds against the new approver value.

### Fixed
- Packaging: `python/pyproject.toml` now declares `license-files = ["LICENSE"]` (PEP 639) so the
  BSD-3-Clause `LICENSE` text ships inside both the wheel (`*.dist-info/licenses/LICENSE`) and the
  sdist, not just the `License-Expression` METADATA field. `python/LICENSE` is a symlink to the
  repo-root `LICENSE` (single source of truth; root `LICENSE` text unchanged). Bumped the
  `setuptools` build requirement to `>=77.0.3` (the floor with stable PEP 639 `license-files`
  support) and dropped the now-superseded `License :: OSI Approved :: BSD License` classifier.
- API: the top-level convenience function `anchor()` shadowed the `agent_action_capsule.anchor`
  submodule on attribute access (`import agent_action_capsule.anchor as x` bound the function, not
  the module, under Python's attribute-wins semantics). Renamed the canonical export to
  `anchor_capsule()`; `anchor()` remains available as a deprecated alias (emits
  `DeprecationWarning`, delegates to `anchor_capsule()`) for this release and will be removed in a
  future one, at which point the submodule shadow is fully resolved.

## 0.1.0 — 2026-07-06

### Added
- `history` module: `list_capsules`, `verify_chain_completeness`, `export_verifiable_bundle`, `ChainReport` — ledger-grade capsule history API
- `selective_disclosure` module: salted per-field SHA-256 commitments, `commit_fields`, `disclose_subset`, `verify_disclosure`
- `bilateral` module: four-move bilateral attestation handshake (`BilateralHandshake`), `seal_request/action/bilateral`, `BilateralState`
- `verify_pair` module: bilateral capsule pair verification

### Changed
- Registry: seeded `"confirms"` in `chain.relation` allowed values

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-02.*` — compiled -02 spec artifact
