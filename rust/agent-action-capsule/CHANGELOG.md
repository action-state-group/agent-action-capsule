# Changelog: agent-action-capsule (Rust)

## Unreleased

## 0.1.0

- First release. Canonicalization and `capsule_id`, Class 1 verification
  (checks 1-9, `verify_store` with concurrent-supersedes and duplicates),
  the profile registries, Producer Envelope verification, and the Evidence
  Bundle v2 verifier behind the `bundle` feature.
- Replaces the unpublished `aac-bundle` crate (`rust/bundle`). Against it:
  checks 8 and 9 and `provenance_mode` typing are new, so findings now match
  Go and Python in full; negative zero canonicalizes as `0`; float and
  unsafe-integer paths walk keys in byte order without recursion; and
  `checkpointed-local-log` comes from crates.io (0.3).
