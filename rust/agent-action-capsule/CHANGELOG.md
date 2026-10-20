# Changelog: agent-action-capsule (Rust)

## Unreleased

- Evidence Bundle -02, as the Python reference reads it. Certificate modes:
  `completeness.selection` names the certificate's mode; a producer-selected
  Bundle is no longer a failure in plain mode, and any other value withholds
  interval coverage and per-record membership with
  `bundle::CERTIFICATE_MODE_UNSUPPORTED`. Non-record leaves: a range covers
  padding leaves carried in `completeness_certificate.non_record_leaves`.
  Category coverage: `bundle::check_category_coverage`,
  `bundle::verify_bundle_with` and `CategoryInputs`; the five properties are
  `VerificationResult::category_coverage`, and in strict mode
  (`StrictOptions::category`) a `FAIL` of the form, signature or consistency
  is INVALID. Producer: the optional `ProofSource::leaf_content` (default
  `None`) with `BuildOptions::carry_non_record_leaves`. New public struct
  fields (`VerificationResult::category_coverage`, `StrictOptions::category`,
  `BuildOptions::carry_non_record_leaves`): a struct literal needs them, or
  `..Default::default()` where the type has one.
  `bundle::SELECTION_PRODUCER_SELECTED` is now defined with feature `bundle`.

## 0.4.0

- Evidence Bundle producer (feature `strict`): `bundle::build_evidence_bundle`
  over a `ProofSource`, `proof_source_from_cll` for a CLL backend and a
  `RecordSource`, and `build_unproven_bundle`. Each Bundle is checked with
  `verify_bundle_strict` and refused when INVALID. Requires
  `checkpointed-local-log` 0.3.1.

## 0.3.0

- `settlement`: a `fee_asset_differs` finding names the leg or legs whose
  fee is in another asset (the payer leg for `routing_fee`, the payee leg
  for `receive_fee`, payer first), not always the payee leg
  (capsule-cli#233, #281).

## 0.2.1

- `settlement`: the `wrapped_resigned` check reads an SD-JWT as the
  issuer-signed JWS before the first `~`, so a re-signed SD-JWT with a
  disclosure (`JWT~disclosure~`) is reported (#280).

## 0.2.0

- Strict Evidence Bundle verification (feature `strict`):
  `bundle::verify_bundle_strict` and the `witness` module, as the Python
  reference's `verify_bundle(..., strict=True)` (#280).
  `envelope::verify_record_signature` and `canonical::normalize` are new.
- The two-party settlement verifier (feature `settlement`):
  `settlement::verify_settlements` (#280).
- `verify_bundle`, `verify_bundle_strict`, `verify_record_signature` and
  `verify_settlements` refuse a caller-built `Value` nested deeper than 128
  levels before any recursive work.

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
