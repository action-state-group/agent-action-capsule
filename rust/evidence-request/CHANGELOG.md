# Changelog

## Unreleased

- **`unavailable_window`**: ER -02 §4.7 unavailable-window statements. `recognize` reads a
  statement for a responder key and the receipts held for it: a `ReasonClass` from the closed list,
  `start` <= `end`, the responder key's signature checked in the vectors' signature profile
  (`verify_strict` Ed25519 over the RFC 8785 form of the present members among `end`,
  `reason_class` and `start`; -02 §4.7 item 3 leaves the format to the deployment), and at least
  one accepted `RegistrationReceipt`. It gives the registration time, the earliest accepted
  receipt's (the first given on a tie), or why the statement is `Ignored` (`malformed`,
  `not_signed_by_responder`, `not_registered`). `display` shows a recorded absence beside the
  statements held: covered by closed-interval overlap with the waiting window, shown as `SHOWN_AS`
  with a `Label` per covering statement (class, stated period, registration time,
  `stated_afterwards`). Any other state is shown as itself. `tests/vectors.rs` reads
  `unavailable-window.json` (35 cases).
- **`controller-binding` feature: Controller Binding v0** (`controller_binding`;
  `spec/controller-binding-v0.md`), the Rust sibling of Go's `controllerbinding`. `verify` reports
  a binding record's §6.1 properties (form, signatures, window, revocation, and the credential
  through a `CredentialVerifier` the caller passes) and what it proves (§7 item 2);
  `Report::applies_to` says whether it applies to a pair (§6.2), and `pair_independence` gives the
  `issuer_independence` (§7 item 4, IP §6.7.4). An `ed25519` key verifies with `verify_strict`; a
  `bip340` (Nostr) key verifies the BIP-340 signature over its NIP-01 signing event (§4.1), with
  k256 0.13 (new optional dependency). A revocation list a using profile declared complete
  (§5.1): `Options::revocation_list` carries the declaration's JSON object as received, the
  list's octets and the evaluation time E, and `Report::revocation_list` reports the declaration
  as delivered, whether it `counts`, and a diagnostic `reason` when it does not. A malformed
  declaration does not count, and the list's entries are still received statements, so an
  applying one is still `FAIL`. With no time T, no declaration counts; `max_age` is compared in
  whole seconds. Under a declaration that counts, `controller_binding_revocation` is `PASS`.
  `parse_declaration` checks a declaration's form. Every case of
  `vectors/controller-binding-v0/` (42) gives its whole expected block.

## 0.3.0

- **`evidence-interop/1`** (`spec/interop-profile-v1.md`, ER -02): `envelope::PROFILE_V1` and
  `envelope::PROFILES`. `Envelope::verify_for_profile` accepts an envelope that names the identifier
  the request asked for (`verify_for` is it with /0), and `cll_material::check_anchor_inclusion`
  reads an envelope under either identifier; `envelope::sign_with_profile` signs under one (`sign` keeps
  `evidence-interop/0`). `envelope::refusal_reasons` gives each identifier's §9.1 tokens: /0's
  eight, /1's ten, so `capacity_exceeded` is registered under /1 only. `acceptance` checks records
  and receipts under either identifier the caller's `profiles_implemented` lists
  (`acceptance::PROFILE_IDS`). The v1 corpora run beside the v0 ones. **Breaking** for an
  exhaustive `match` on `SignError` (new `Profile`).
- `registry::Reason` gains the two -02 refusal reasons, `CapacityExceeded` (`capacity_exceeded`)
  and `RequestUnauthenticated` (`request_unauthenticated`); `Reason::ALL` has ten.
  `retention::classify_refusal` reads both as `NoBreach` inside and after `until`
  (`capacity_exceeded` is never a breach). `tests/vectors.rs` reads `refusal-02.json`. A refusal
  with either token is now `reason_registered`. **Breaking** for an exhaustive `match` on `Reason`.
- `acceptance`: §11.1.5 rule 2 is `FAIL` only for an `issued_at` later than a time held for the
  action; an equal time no longer is (the profile's change; corpus cases
  `acceptance-equal-time-H` and `acceptance-after-action-by-a-second-I`).
- **`acceptance` feature: the interop profile's acceptance records** (`acceptance`;
  `spec/interop-profile-v0.md` §11.1), a port of the profile's Python verifier.
  `acceptance::evaluate` reports each candidate's and each receipt's §11.1.7 properties and the
  §11.1.8 finding, for a transaction or a session, with the execution-record reader supplied by
  the caller (`read_fixture_execution_record` reads the §11.5 fixture format). `sign`,
  `record_digest` and `parse` build and read records and receipts. `parse` is a strict decoder of
  its own (not serde_json's, whose `arbitrary_precision` feature reads the member
  `$serde_json::private::Number` as a number): it refuses duplicate member names, numbers other
  than digits from 0 to 2^53 − 1, unpaired surrogates and nesting deeper than 128, so both
  parties compute the same record digest. `TrustPolicy::from_pin` reads a vectors-form
  `trust_policy` pin. Statuses and findings are the result; `method` and `detail` texts are
  informative.
  Every `acceptance-*` case in `vectors/interop-profile-v0/` gives its expected report, and
  session-scoped cases frozen from the Python verifier give its report. No new dependency.
- `status::Status`: the §7.1 statuses, now shared by `cll_material` (still re-exported there as
  `cll_material::Status`) and `acceptance`, with `Status::as_str`.
- `time::parse_rfc3339` reads any RFC 3339 time (offsets, lower-case `t`/`z`, a leap second), to
  the microsecond, as the profile's verifier does; ASCII digits only, year 0001 or later.
- `refusal::sign_with_detail` signs a refusal with the optional `detail` (profile P-6), carried
  outside the signed members as in the Go signer; `Refusal` gains `detail: Option<String>`, which
  `to_json` and `to_cbor` emit when present. `sign` is unchanged, and the signature is the same with
  or without a detail.

## 0.2.0

- **The artifact response is the interop profile's envelope** (`envelope`;
  `spec/interop-profile-v0.md` §6.2, `evidence-interop/0`), as in the Go and
  Python implementations. `envelope::sign` builds and signs it, refusing an
  envelope the profile does not allow. `Envelope::encode` writes the reply in
  either binding: RFC 8785 JSON with byte strings as unpadded base64url, or
  core deterministic CBOR. `envelope::parse_reply` reads a reply as carried.
  `Envelope::verify_for` accepts one as a responder's answer to a request.
  Tests re-sign the profile corpus's envelopes byte for byte, and the
  cross-language interlock builds identical envelopes in Python, Go and Rust.
- **`cll` feature: checking Checkpointed Local Log material**
  (`cll_material::check_anchor_inclusion`, profile §6.2.1 steps 1 to 14),
  against `checkpointed-local-log` 0.3.1. Every envelope reply in
  `vectors/interop-profile-v0/` gets the `anchor_inclusion` status the corpus
  states.
  `cll_material::encode_inclusion_proof` and `encode_consistency_proof` write
  the two proof kinds from paths a log computed, as the Go package's encoders
  do.
- `envelope::parse_reply` refuses a byte string inside a signed member or a
  refusal (never reading it as its base64url text), and a present empty
  `verification`, which would sign differently from its absence.
- **Breaking: the `answer` feature and module are removed.** Building an
  artifact from a log is the responder's business: the Checkpointed Local Log
  builder moves to the `evidencebook` crate (agent-action-capsule#270).
  `answer::verify` checked the crate's own pre-profile envelope, which no
  other implementation signs; use `Envelope::verify_for` and
  `check_anchor_inclusion`. No feature is on by default.
- `request::subject_from_value` and `request::derivation_from_text` read a
  subject and a derivation as an envelope repeats them.

## 0.1.0

- **Renamed and moved.** The crate is now `evidence-request` (lib
  `evidence_request`), developed in
  [agent-action-capsule](https://github.com/action-state-group/agent-action-capsule)
  next to draft-mih-agent-evidence-request-00 and its vectors. It was
  `capsule-emit-evidence-request` (lib `capsule_emit_evidence_request`) in
  capsule-emit through 0.0.4; those releases stay published. The API is the
  same as 0.0.4: replace `capsule_emit_evidence_request` with
  `evidence_request` in `use` paths.
- **Features.** `answer` (default) enables the `answer` and `receipt` modules
  and the checkpointed-local-log dependency; `receipt` enables `receipt`
  alone. With `default-features = false` the crate is the protocol core
  (registry, request parsing and digest, resolution, refusals, outcomes,
  invariance, retention) and does not depend on checkpointed-local-log, so a
  crate on a different checkpointed-local-log line can use it.

## 0.0.4

- **`request::parse_cbor` accepts only core deterministic CBOR** (RFC 8949
  §4.2.1, as §10 requires of the stream binding's frames), checked on the
  bytes as received and at every depth, including inside members the crate
  ignores. A request is `request_malformed` when it has a duplicate map key,
  map keys out of the bytewise order of their encodings (JCS order is not
  that order: a shorter key comes first), a non-text map key, an argument not
  in its shortest form, an indefinite length, a tag, a floating-point value,
  a byte string, a simple value other than `false`/`true`/`null`, or an
  integer outside 0 to 2^53 - 1 (`evidence-interop/0` §5.2). A request then
  has one CBOR encoding, so one digest wherever it is carried as CBOR. Breaking for a
  caller that sent non-deterministic CBOR: it was accepted before.
  `parse_json` is unchanged.

## 0.0.3

- Receipt verification tries every structurally valid inclusion proof, independent
  of unprotected proof order. Impossible tree/index/path shapes and trailing CBOR
  return `ReceiptError::Malformed` from both `check_form` and verification with
  a key, and `VerifyError::ReceiptMalformed` at the answer boundary.

- **`answer::verify` checks the witness receipts an answer carries** (§4.1,
  §8.1). Every receipt on the anchor and on a `checkpoints` or
  `history_card/1` list must be bound to the checkpoint it is carried on (its
  entry hash is `SHA-256(checkpoint digest)`) and must be a COSE receipt with
  an RFC 9162 inclusion proof; otherwise `VerifyError::ReceiptMalformed` or
  `VerifyError::ReceiptBinding`. `verify` takes the requester's witness trust
  policy, `witness_key(ts_url) -> Option<VerifyingKey>`: under a key, the
  receipt's proof and signature must cover that checkpoint's entry. Each
  receipt is reported in `VerifiedAnswer::receipts` as `Verified`, `NoKey`
  (bound and well formed, not authenticated) or `Stub`; only `Verified`
  counts as independent witnessing, and how many are required stays the
  requester's policy. Breaking: `verify` has a new last argument.
- **A fixed exchange-half pin has a stable anchor** (§5 fixed-pin
  invariance). An `exchange` subject pinned by the requester's own half is
  answered under the earliest checkpoint covering every checkpointed record
  that cites the half, no longer the latest, so growth that adds no citing
  record leaves the artifact unchanged. A new citing record, once a
  checkpoint covers it, advances the anchor, and the artifact lists the
  records it covers. `verify` enforces it: the anchor's own signed
  `prev_size` must not already cover the last served record
  (`VerifyError::CoverageUnmet`).
- **The refusal's CBOR binding is deterministic** (RFC 8949 §4.2.1, as §10
  requires): map keys in the bytewise order of their encodings (`sig`,
  `key_id`, `reason`, `issued_at`, `request_digest`), pinned by an exact
  wire-byte test.
- New dependencies: `coset` 0.4 and `base64` 0.22 (both already in the tree
  through `checkpointed-local-log`). `receipt` is the Ed25519 subset of the
  RFC 9162 receipt verifier in action-state-group/scitt-cose.

## 0.0.2

- `answer`: build the artifact response over a checkpointed local log
  (`checkpointed-local-log`) and verify it offline. The artifact is
  deterministic RFC 8785 JSON of (subject, anchor, derivation); the
  verification material carries the anchor checkpoint and inclusion, range
  or consistency proofs; the envelope binds the request digest, the anchor
  and the artifact digest under the responder's key.
- `answer::MAX_RECORDS` caps an answer's records or checkpoints; `verify`
  refuses a larger answer before parsing it, and `build` takes a limit
  (`BuildError::OverLimit`, answered as `policy_declined`).
- Checkpoint lists (`checkpoints`, `history_card/1`) must start at the
  stream's first checkpoint.
- New dependency: `checkpointed-local-log` 0.2.0.

## 0.0.1

- `request`, `digest`, `resolve`, `refusal` (`sign`, `verify_for`,
  `check`), `outcome`, `invariance`, `retention` for
  draft-mih-agent-evidence-request-00, tested against the draft's
  conformance vectors.
