# Changelog: agent-action-capsule (Rust)

## Unreleased

- Strict Evidence Bundle verification (feature `strict`):
  `bundle::verify_bundle_strict` and the `witness` module, as the Python
  reference's `verify_bundle(..., strict=True)` (#280).
  `envelope::verify_record_signature` and `canonical::normalize` are new.
- The two-party settlement verifier (feature `settlement`):
  `settlement::verify_settlements` (#280).

## 0.1.0

- First release. Canonicalization and `capsule_id`, Class 1 verification
  (checks 1-9, `verify_store` with concurrent-supersedes and duplicates),
  the profile registries, Producer Envelope verification, and the Evidence
  Bundle v2 verifier behind the `bundle` feature.
- Replaces the unpublished `aac-bundle` crate (`rust/bundle`). Against it:
  checks 8 and 9 and `provenance_mode` typing are new, so findings now match
  Go and Python in full; negative zero canonicalizes as `0`; float and
  unsafe-integer paths walk keys in byte order without recursion;
  `effect_attestation: null` counts as absent, as in Python and Go; capsules
  and bundle fragments decode through a strict RFC 8259 decoder that keeps an
  object holding `serde_json`'s private number token an object; and
  `checkpointed-local-log` comes from crates.io (0.3).
