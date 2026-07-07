# Changelog

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
