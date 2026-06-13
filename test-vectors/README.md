# Conformance vectors

Frozen, byte-pinned conformance vectors for the Agent Action Capsule profile,
following the [`scitt-cose`](https://github.com/action-state-group/scitt-cose)
pattern: a versioned set of valid and invalid cases, each a directory of
committed bytes plus an `expected.json` stating the verifier's required verdict.

> **Status: scaffold.** The vector set is generated alongside the reference
> library (`../python/`). This README fixes the layout and the rules so the
> bytes, once frozen, never drift.

## Rules

- **Frozen bytes.** Every file here is content, not convenience. `SHA256SUMS`
  pins the set; `.gitattributes` disables EOL normalization so checkout cannot
  silently corrupt it.
- **Valid and invalid.** Each `fail-*` case is a Capsule that a conforming
  Class 1 verifier MUST reject, with `expected.json` naming the failing check.
  Negative cases are first-class — a profile that only ships valid vectors
  cannot prove its verifier rejects anything.
- **Keys are TEST-ONLY.** Any `*.test-private` / `*.pub` material here is for
  reproducing signatures over the frozen payloads; it secures nothing.
- **External agreement.** A vector's `expected.json` is the contract a verifier
  built from the I-D text alone must satisfy — independent of any one
  implementation.

## Planned layout

```
test-vectors/
  README.md
  SHA256SUMS                     # pins every byte below
  manifest.json                  # index: case -> kind, expected ok, failing check
  v1/
    valid-executed/             expected.json + statement.cose + payload.bin (+ keys)
    valid-blocked-with-findings/ ...
    fail-capsule-id-mismatch/   expected: ok=false, check "capsule_id_mismatch"
    fail-confirmed-without-response/ expected: ok=false, confirmed-effect binding
    fail-verdict-effect-conflict/    expected: ok=false, orthogonality
    fail-dishonest-human-disposed/   (hand-crafted; the SHOULD defensive check)
```

Each case directory mirrors the scitt-cose vector shape so a single harness can
run both substrate and profile vectors.
