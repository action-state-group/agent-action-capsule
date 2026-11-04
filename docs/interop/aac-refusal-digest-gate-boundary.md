# AAC ↔ Refusal Digest — Gate-Boundary Vector

**Status:** Compatibility experiment. No commitment to adoption, integration or
specification change on either side.
**Directory:** [`aac-refusal-digest-gate-boundary/`](aac-refusal-digest-gate-boundary/)
(its own `SHA256SUMS`; every file regenerates byte for byte from `generate.py`).

## Pins

| | pinned at |
|---|---|
| AAC profile | `draft-mih-scitt-agent-action-capsule-06`; Capsules carry `spec_version` `draft-mih-scitt-agent-action-capsule-05`, format 4, JCS |
| AAC reference verifier | `python/` at `518303c` (the commit the check-5 result was observed at) and at `33aa732`; identical results |
| Refusal digest | `css-refusal-digest` v0.2, `jsabes24/css-succession-receipts` `spec/refusal-transparency.md` at `edc254b`; `draft-sabey-refusal-transparency-03` |
| Refusal-digest verifier | the public browser verifier, `https://continuitylaboratories.com/verifier/sr-verify.wasm`, SHA-256 `5c3acb19…90db` (full pin in `vector.json`), run under Node by `check_digest.mjs`. Its source is not public; the format, specification and corpus are, so any implementation of refusal-transparency §4 can be substituted |

## Purpose

A Capsule for a never-dispatch verdict (`blocked`, `denied`, …) derives
`effect_mode: not_applicable`, and the effect-attestation matrix then requires
`effect_attestation` to be absent. So an executed Capsule can say who observed the
effect, and a blocked one cannot say who observed the gate: a resealed blocked Capsule
carrying `gate_executed` fails check 5. `evidence_digest` can bind the gate's record,
but checking it is Class 2 and needs the manifest.

This vector puts the two records of one blocked attempt side by side and pins, by named
check, what each verifier rejects and what neither can see:

- the **Capsule** says what the gate decided: `verdict_class: blocked`, one blocking
  Constraint Record whose `evidence_digest` binds the gate's evidence;
- the **refusal digest** makes the gate's refusal checkable: the verbatim refusal ground
  and the signed, hash-chained ledger of the attempt, in which the refused transition is
  absent.

Neither record trusts the other, and neither tries to be the other. The vector is the
evidence a gate-scoped attestation grade would need; it proposes none.

## The attempt

Probe `clock-overreach` of the digest: a caller holding only the operator role attempts
to approve a succession. The gate refuses it at the router before the approval is
recorded. Its ledger (20 events, all signed) must not contain `SuccessionApproved`,
`SuccessionRejected`, `SuccessionCompleted` or `AuthorityGranted`.

The Capsule's `action_id` is `clock-overreach@<run.seed>`. Its Constraint Record
(`org.example.operator_role_gate`, `result: fail`, `blocking: true`) carries
`evidence_digest = json_digest(evidence)`. Here `capsule/evidence.json` names the digest
by its `digest_hash`, the probe, the run seed, the verbatim refusal ground and the
forbidden event types, and `capsule/manifest.json` is the manifest's evidence schema for
that constraint.

## Derivation inputs

- `inputs/issued-digest.json`: the digest exactly as its issuer emitted it
  (`digest_hash` `e6bf7355…15ad`).
- `run.seed` = `sha256("aac-refusal-digest-gate-boundary")`; the staged identities in
  each probe ledger derive from it (refusal-transparency §2.2).
- Test signing key: the Ed25519 seed is `sha256("aac-refusal-digest-gate-boundary/test-signing-key")`,
  `key_id` `gate-boundary-test`, public key `inputs/test-key.pub`. It is a test
  constant that secures nothing, published so the re-signed (lying-issuer) cases can be
  reproduced.
- `capsule_id` and `evidence_digest`: AAC `compute_capsule_id` / `json_digest` (JCS).
  The digest's own canonical form and event hashes are not JCS. They follow
  refusal-transparency §3 and the ledger-export event-hash rule. `generate.py`
  implements both and asserts, before writing anything, that it reproduces every hash in
  the issued digest.

## Run it

From the repository root:

```bash
# Capsule side (Class 1, manifest-dependent, cross-format):
(cd python && python -m pytest -q tests/test_interop_refusal_digest_gate_boundary.py)

# Byte-for-byte regeneration (with python/ installed: pip install -e "python[dev]"):
(cd python && python ../docs/interop/aac-refusal-digest-gate-boundary/generate.py --check)

# Refusal-digest side (Node >= 20; the script checks the WASM's SHA-256 against the pin first):
cd docs/interop/aac-refusal-digest-gate-boundary
mkdir -p verifier
curl -o verifier/sr-verify.wasm https://continuitylaboratories.com/verifier/sr-verify.wasm
curl -o verifier/wasm_exec.js https://continuitylaboratories.com/verifier/wasm_exec.js
node check_digest.mjs verifier
```

`verifier/` is a download location; it is not part of the vector.

## Capsule cases

Class 1 is the §6 check set. Manifest-dependent results (the evidence schema and
`evidence_digest` recomputation) are reported in their own column and never change a
Class 1 result.

| case | Class 1 | rejected at | manifest-dependent | cross-format |
|---|---|---|---|---|
| `c-blocked-control` | pass | — | pass | pass |
| `c-gate-executed-resealed` | **fail** | **check 5** | pass | pass |
| `c-gate-executed-no-status-resealed` | fail | check 4 | pass | pass |
| `c-gate-executed-not-resealed` | fail | checks 2, 5 | pass | pass |
| `c-dispatched-under-blocked-resealed` | fail | check 4 | pass | pass |
| `c-capsule-id-mutated` | fail | check 2 | pass | pass |
| `c-evidence-digest-mutated-resealed` | pass | — | **fail: evidence_digest** | n/a |
| `c-evidence-binds-other-digest-resealed` | pass | — | pass | **fail: digest_binding** |
| `c-action-id-other-probe-resealed` | pass | — | pass | **fail: attempt_join** |

- **The check-5 case** differs from the control only by
  `effect: {status: planned, effect_attestation: gate_executed}` and a recomputed
  `capsule_id`; the test asserts both facts and that check 5 alone rejects it.
- **The check that catches `gate_executed` depends on `effect.status`.** With no status,
  the effect derives `dispatched_unconfirmed`, for which the matrix *requires* an
  attestation. Check 5 is then satisfied and check 4 alone rejects it.
- **The last three rows pass Class 1.** Whether the Capsule's evidence still matches its
  `evidence_digest`, and whether it names the digest that was supplied, is invisible
  without the evidence. `attempt_join`'s `action_id` half is visible at Class 1, but it
  is a string match, not a cryptographic binding.

Cross-format checks:
- `attempt_join`: `action_id` equals `evidence.probe_id@evidence.run_seed`, that probe is
  a refused probe of the supplied digest, and its `run.seed` matches.
- `digest_binding`: `evidence.refusal_digest.digest_hash` equals the supplied digest's
  verified `proof.digest_hash`, and the ground and forbidden event types equal the
  probe's verbatim.

## Refusal-digest cases

`rejected at` names the refusal-transparency §4 step. `-resigned` means the altered
digest was re-signed with the issuer's key, which models a lying issuer.

| case | result | rejected at |
|---|---|---|
| `d-golden` | pass | — |
| `d-ground-reworded` | fail | proof |
| `d-forbidden-event-injected-resigned` | fail | forbidden_event |
| `d-event-payload-altered-resigned` | fail | event_hash |
| `d-event-signature-bitflip-resigned` | fail | event_signature |
| `d-summary-miscount-resigned` | fail | summary |
| `d-seed-flipped-resigned` | fail | seed_derivation |
| `d-spec-version-unknown-resigned` | fail | structure |
| `d-lying-issuer-untrusted` | fail | proof |
| `d-boundary-ground-rewritten-by-issuer` | **pass** | — (boundary) |
| `d-boundary-tail-truncated-by-issuer` | **pass** | — (boundary) |

The forged `SuccessionApproved` in `d-forbidden-event-injected-resigned` is well formed:
it is the probe's own succession and legitimacy ids, chained to the last event, hashed
and signed. The only thing wrong with it is that the refused transition is now on the
record. A second, independent implementation of the digest verifier agrees on every row.

## Collection scope and completeness

**Absence from the supplied ledger does not, by itself, establish that the transition
never occurred.** What the digest establishes is narrower:

- **Scope is the probe's isolated instance.** Each probe runs on a freshly constructed
  system instance, and `events[]` is stated to be that instance's complete ledger. That
  statement is the issuer's (`run.attestation: "self"`). It says nothing about any other
  system, including the one a production Capsule came from.
- **Integrity, not completeness.** Per-event hashes and signatures, and the digest
  signature, make the supplied events tamper-evident against everyone except the
  signer. They do not make the list complete. `d-boundary-tail-truncated-by-issuer`
  drops the last event, is re-signed, and verifies.
- **Freshness from the seed.** At v0.2 the staged identities derive from `run.seed`, so
  a ledger replayed from another run fails `seed_derivation` even fully re-signed. This
  shows the ledger was produced for this seed. It does not show nothing was left out.
- **The ground is the issuer's statement.** `d-boundary-ground-rewritten-by-issuer`
  verifies: nothing in a digest can contradict its own signer about why it refused.

What would establish completeness is outside both artifacts: an externally anchored
commitment to the instance's ledger head (refusal-transparency §5; the external-anchoring
specification in the same repository), or an independent party running or
countersigning the probe (a future version). Until then the absence claim is "absent
from the ledger the issuer attests is complete, and tamper-evident thereafter".

## What is not claimed

- That a refusal digest satisfies AAC's attestation requirements, or that a Capsule
  satisfies the digest's, or that either should reference the other.
- That a gate-scoped grade should take any particular form. This vector is evidence for
  that discussion, not a proposal.
- That the Capsule cases cover the COSE Signed Statement envelope. They are payload-level,
  as `vectors/capsule/` is.
