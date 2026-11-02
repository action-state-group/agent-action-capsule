# Changelog: agent-action-capsule (Rust)

## Unreleased

## 0.9.0 — 2026-11-02

Tag `crates/agent-action-capsule-v0.9.0`.

- New `inference-history` feature and `inference_history` module (action-state-group/agent-action-capsule#558): derives and checks the Standard level of `inference-service-history/0` (`spec/inference-service-history-profile-v0.md`) under any Standard definition: `Definition::from_document` (ISH §8.3 `definition_form`), `period_counts`, `artifact` and `check_artifact` (`definition_binding`, `period_alignment`, `period_anchor`, `period_floor`, the coverage declaration, `history_card_digest`). Passes the Standard cases of `vectors/inference-service-history-v0` and `-interop-v1`. No wire or normative change; additive.

## 0.8.0 — 2026-10-31

Tag `crates/agent-action-capsule-v0.8.0`.

- Breaking for consumers of the `bundle` and `strict` features: `checkpointed-local-log` moves from 0.3.1 to 0.4.0, so the CLL types in the public API are 0.4.0's (the `cll::log::EntrySource` and `CheckpointStateStore` backend that `bundle::producer::proof_source_from_cll` takes, and `cll::checkpoint::DecodedCheckpointCose`), and a CLL 0.3.1 backend no longer compiles against it. CLL 0.4.0 also refuses Ed25519 signatures by small-order keys, which 0.3.1 accepted (checkpointed-local-log#108); `verify_bundle`, the strict path and the producer verify checkpoints through it, so a checkpoint forged that way no longer verifies. No wire or normative change (evidencebook#254 §7.4, AAC#536).

## 0.7.0 — 2026-10-31

Tag `crates/agent-action-capsule-v0.7.0`.

- Rollout gate: no producer may emit `non_record_leaves` until all four verifiers (Go, Python,
  TypeScript, Rust), `capsulectl`, the hosted verify page and Evidencebook have released the check.
  A verifier from this release reads them; a producer's flag for emitting them stays off until each
  of those has released it.
- One stated decoding rule for COSE Receipts (AAC#520): the strict receipt check decodes under the
  receipt encoding rule of `spec/interop-profile-v1.md` §6.2.2 with the crate's own strict reader,
  and verifies the inclusion proof and signature itself. Neither `coset` nor `scitt-cose-receipt` is
  on the path any more: `scitt-cose-receipt` is no longer a dependency, and `coset` only a
  dev-dependency. Changed outcomes: indefinite
  lengths, repeated keys, non-shortest arguments, floats, tags and bignums are refused, as in the other
  languages; a `kid` that is not a byte string, or a content type that is not `type/subtype`, is
  ignored like any unread label instead of refused; a receipt over 10,485,760 octets is refused. The
  reader's repeated-key check is no longer quadratic, which also bounds the anchor check on a large map.
  Passes the 25 new strict vectors and the two renamed float vectors.
- The embedded copy of `REGISTRY.md` cites the base draft's -05 section numbers (AAC#501, closes
  #497).
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
  `None`) with `BuildOptions::carry_non_record_leaves`. Breaking: new public struct
  fields (`VerificationResult::category_coverage`, `StrictOptions::category`,
  `BuildOptions::carry_non_record_leaves`): a struct literal needs them, or
  `..Default::default()` where the type has one.
  `bundle::SELECTION_PRODUCER_SELECTED` is now defined with feature `bundle`.
  The `category_coverage` signature verifies under strict Ed25519, the same
  check as the witness receipts (now shared with feature `bundle`).
- The strict receipt check refuses a COSE Receipt whose payload is CBOR undefined (`0xf7`)
  (AAC#519): `coset` reads it as an absent payload, so it was taken as detached. Only null
  (`0xf6`) is detached, as scitt-cose's Python verifier has it. Passes the new strict vector
  `neg-witness-cll-undefined-payload`.

## 0.6.0 — 2026-10-31

Tag `crates/agent-action-capsule-v0.6.0`.

- Witness Receipts over an anchor (feature `strict`, AAC#508):
  `witness::check_anchor_witnessed` runs `anchor_witnessed` of
  `spec/interop-profile-v1.md` §6.2.2 over `cll-witness-receipt` Receipts
  (RFC 9942, RFC9162_SHA256, leaf entry the anchor digest) under a witness
  policy, and passes `vectors/anchor-witness-v1/`.
- Breaking: `canonical::jcs` (and `json_digest`, `compute_capsule_id`) refuses a value nested more
  than 128 levels deep with the new `CanonicalError::TooDeep` instead of recursing, and
  `verify::verify` reports only `verifier_internal_error` for such a Capsule, as Go, Python and
  TypeScript now do. The decoder's limit is unchanged (128); the four implementations now share it
  and `tests/json_nesting.rs` runs the shared `vectors/json-nesting/` (AAC#498).
- Registry predicate table (AAC#496, closes #407): `REGISTRY.md` §19 lists nine predicates
  (`performed`, `acknowledged`, `settled`, `refunded`, `disputed`, `adjudicated(outcome, judge, pack)`,
  `controls-domain`, `key-continuous-since`, `answered-within-deadline`), each with its version,
  allowed sources, unit and work class, and a verifier reports a predicate the table does not list
  as `NOT_CHECKED`. The section is a table, not a registry. The Go, Python and Rust embedded copies
  of `REGISTRY.md` are updated byte for byte.
- Security, settlement: the `wrapped_resigned` check verifies a wrapped JWS
  under the leg key with dalek's `verify_strict`, not `verify`, so a
  small-order key (such as the identity key's forgery, R the identity and
  S = 0) or a small-order R no longer counts as a signature by that key, as
  in Go, Python and TypeScript. dalek's `verify` already refused a
  non-canonical R (#448).

## 0.5.0 — 2026-10-30

Tag `crates/agent-action-capsule-v0.5.0`.

- Security, strict witness receipts (feature `strict`): an EdDSA witness
  receipt now verifies only under strict Ed25519. scitt-cose-receipt 0.1.1
  verifies with dalek's `verify`, which accepts a small-order key, so a
  receipt under a directory row pinning such a key could be forged by
  anyone. The key A and the signature's R must now be canonical and not of
  small order, and S less than L, before that check; the strict vector
  `neg-witness-cll-small-order-key` pins it (#439).
- **Breaking**, strict witness receipts: `WitnessReceiptResult` gains `key_id`,
  `registration_time` and `registration_time_reason`, and `ReceiptCheck`
  gains `registration_time` and `registration_time_reason`, so a struct
  literal must add them. A passing receipt names the directory key id it
  verified under and the protected CWT `iat` its witness signed, or a
  `REASON_` constant saying why it has none, as the strict vectors pin (#392).
- Strict Bundle verification (feature `strict`): `verify_bundle_strict`'s
  `checkpoint` claim also holds the completeness certificate's `log_id`, when
  stated (a `null` counts as stated), to the signed log identifier, and
  reports `checkpoint_field_mismatch:log_id` once when it differs, whatever
  the checkpoint's own copy says. A producer-selected Bundle whose certificate
  names another log was INCOMPLETE and is now INVALID (#380, the strict
  vectors `neg-producer-selected-certificate-log-id`,
  `neg-producer-selected-both-log-ids` and
  `neg-producer-selected-certificate-log-id-null`).
- Witness receipts: a `checkpoint.witnesses` entry is malformed unless every
  member is present, `ts_url`, `entry_hash` and `receipt_b64` are non-empty
  strings, and `receipt_b64` is canonical standard base64. An entry with every
  member and a string `ts_url` that fails one of the new checks (an empty
  `ts_url`, an empty or non-string `entry_hash`, or an empty, non-string or
  non-canonical `receipt_b64`) was read as a receipt. It was withheld when no
  usable key checked it (no directory row, a row without a usable key, or a
  stub), and an empty or non-string `entry_hash` beside a rekor or scrapi
  receipt that verified passed, since only the cll binding reads it. In each
  case the Bundle stayed VALID. It now fails as
  `witness_receipt_malformed:<index>`, with or without a row (#386, the strict
  vectors `neg-witness-malformed-member-no-row`,
  `neg-witness-malformed-members` and `neg-witness-malformed-shapes`).

## 0.4.1

- `verify::verify` does bounded work on hostile numbers. The float and
  unsafe-integer walk writes a path only for a number that fails, where it
  used to build one for every member it visited. It reports at most 64
  `float_in_digest_field` and 64 `unsafe_integer_in_digest_field` findings,
  and each quotes at most 256 characters of its path, then `...`. Verdicts do
  not change, but on a record with more than 64 of either, Rust now lists
  fewer findings than the Go and Python verifiers, which list every one. A
  1 MB record holding 250,000 floats under a 500 KB key used to keep about
  125 GB of path text (250,000 paths of 500 KB each), and now verifies in a
  few times the memory of one parsed copy. `canonical::float_paths` and
  `unsafe_int_paths` still return every path, in full.

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
