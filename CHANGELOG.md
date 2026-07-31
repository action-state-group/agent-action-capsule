# Changelog

## Unreleased

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
