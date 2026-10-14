# Minimum Evidence Interoperability Profile v0 conformance vectors

These vectors exercise `spec/interop-profile-v0.md` (identifier `evidence-interop/0`), a
pre-Internet-Draft profile. Its §11.5 describes this corpus. Every case cites the sections its
expected values come from.

## Derivation

`python/scripts/generate_interop_profile_v0_vectors.py` writes every file except this README. It
uses the standard library and `cryptography` (Ed25519) only and runs no repository
implementation. Every expected status is written by hand from the profile text.

`python/tests/test_interop_profile_v0_vectors.py` checks the corpus from the case inputs alone. It
recomputes every digest, signature and encoding with its own code: this library's RFC 8785 `jcs`,
a strict deterministic-CBOR decoder, and MMR functions written from the pinned MMR -02 algorithms.
It derives every status with its own evaluator and compares it with the stated one. The test also
regenerates the directory twice and requires both runs to be byte-identical to the committed
files. Finally, it runs ten defective evaluators, and each must disagree with at least one case.

The test's MMR functions and the generator's are both written from the same pinned draft. Both
are anchored by the §10.1 bytes, which the profile states and the test finds in the profile.
The evaluator and the generator share one author's reading of the profile. The readings that
the text leaves open are listed below.

## What each case pins

| Pin | Where |
|---|---|
| Trust roots | `pins.trust_policy`: accepted responder keys, log keys per log identity (`iss`, `sub`, `kid`), keys accepted for carried foreign objects, the key-to-party map, key successions, and whether a time for the action from a party other than the acceptor is required |
| Verification policy | `pins.verification_policy`: offline, the profile identifiers and verification-material kinds implemented |
| Contract version | `pins.contract_ref` and `pins.contract_digest`; the document is `contract.document`. It was validated against the Evidence Contract v0 schema `evidence-contract-v0.json` that the profile pins as EC, SHA-256 `contract.schema.sha256`. That schema is not in this repository, so the test checks the contract's digest and shape and that the recorded SHA-256 is the profile's EC pin |
| Evaluation time | `pins.evaluation_time` |
| Inputs | `inputs`. Every request, reply and signed record is given as the octets carried: JSON octets as their text (`octets_text` or a JSON string), CBOR octets as hex. Carriage wrappers (the A2A `Message` and `Task`, the MCP call and result, and the manifests) and plain references (transaction, process, keys) are given as JSON values |

**All keys are test keys.** Each private key is the Ed25519 seed SHA-256 of the label in
`test_keys`. The responder key and the log key are those of §10 and §10.1. Never use any of them
for anything else.

## Fixture formats

The profile leaves two record formats to this corpus (§11.1.9, §11.2.7). Neither is registered,
and both exist only for these vectors:

- **Execution record:** `action_at`, `issuer`, `links` (EL link shape, type `cites`),
  `transaction`, `sig`.
- **Producer record:** `claim`, `issued_at`, `producer`, `sig`. Its issuer is `producer` (§11.2.3).

In both formats, `sig` is Ed25519 over UTF-8 of JCS of the other members. The digest is SHA-256
over UTF-8 of JCS of the whole object, `sig` included.

## Cases

| Family | Cases | Profile |
|---|---|---|
| Exchange | `valid-exchange` (the §10.1 bytes, PASS through the CLL material); `invariance-two-nonces-two-transports`; `tampered-artifact`; `wrong-request-digest`; `envelope-bad-signature`; `envelope-untrusted-responder`; `envelope-subject-mismatch`; `envelope-anchor-not-the-pin`; `verification-material-tampered`; `inclusion-proof-forged-and-signed`; `forged-refusal-untrusted-key`; `forged-refusal-bad-signature`; `declined`; `missing-evidence-no-such-subject` (GAP); `missing-evidence-recorded-absence`, `-signed`, `-key-id-unsigned`, `-key-id-without-sig` and `-sig-without-key-id` (§6.4's signing input); `unsupported-version-mismatch`, `-absent`, `-unimplemented`, `-refused` | §3.3, §6, §7, §8, §9, §10.1 |
| Foreign object | `foreign-native-check-fails` (row 5 for the requirement that IS the check, row 6 for one it SUPPORTS); `foreign-native-check-passes`; `foreign-native-check-fails-envelope-fails` | §5.1, §7.2, §8.1 |
| Acceptance | `acceptance-absent`; §11.1.9 variants A to G, and G under a policy requiring a time from another party | §11.1 |
| Lifecycle | §11.2.7 variants A to I, and D in the other order of receipt | §11.2 |
| Carriage | `carriage-invariance` and the seven negative halves of §11.4.8 | §11.4 |

## Reading the expected values

- `properties` are §7.1 statuses. `requirements` maps each requirement to its §8.1 row, with that
  row's status, sufficiency and verdict.
- Row 7 (`envelope-7`) is `UNKNOWN`, `UNKNOWN`, `not_evaluable`. The contract evaluates the
  Artifact's content, the profile fixes no content rule, and no case names a content evaluator, so
  the verifier cannot apply the requirement and reports it `UNKNOWN` (§11.3.7). No field is `null`.
- No case yields `met` or `not_met` unless sufficiency is `SATISFIED`. The test asserts this, and
  shows that the assertion catches a corpus mutated to break it.
- `claim` gives `evidence[]` and `proofs[]` as §8.3 fills them.
- Acceptance cases give each candidate's §11.1.7 properties, each receipt's properties, and the
  §11.1.8 finding. Lifecycle cases give each statement's §11.2.5 properties and finding, and what
  the verifier shows (§11.2.6).

Each case maps only the contract requirements it concerns. The exchange cases map `r-record`,
and the foreign-object cases map `r-carried-signature` and `r-authorized`.

Readings that the profile leaves open are fixed here. The first four are open points:

- **P-54:** `forged-refusal-bad-signature` and `envelope-bad-signature` report
  `responder_trust` on the key the message names, even though its signature fails.
- **P-55:** `caller_invariance` `FAIL` puts every envelope in the compared set on §8.1 row 1.
- **P-56:** `unsupported-version-mismatch` uses a verifier that implements both versions, so
  only the mismatch rule of §3.3 step 5 applies.
- **P-57:** rows 5 and 6 apply when every *required* envelope property passed.
  `responder_key_current` is `NOT_CHECKED` offline.
- The receipts "relied on" (§11.1.8) are the counted receipts whose ordering point gives
  `acceptance_ordering` `PASS`. In variant C and under the G policy no receipt is relied on.
- `unsupported-version-unimplemented` still cites the envelope's `artifact_digest` in its claim
  (§8.3), read by the v0 member name.
