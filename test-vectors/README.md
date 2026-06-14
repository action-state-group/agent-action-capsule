# Conformance vectors

Frozen Class-1 conformance vectors for the Agent Action Capsule profile
(`../spec/`). Each case is an input plus the expected Class-1 verifier result,
version-pinned and hand-checkable.

## These are DERIVED and FROZEN (not hand-authored)

Every `expected.json` is **derived** by running the spec-faithful reference
verifier over a hand-built `input.json`, then **frozen** — the same discipline
as golden digests. This is a **freeze surface**: a change to the result of any
case is either a spec/format revision (regenerate the vectors and review the
diff) or a regression (fix the code). They regenerate via:

```bash
cd python && PYTHONPATH=. python3 scripts/generate_vectors.py
```

The expected values are **spec-anchored**, so a third party can confirm them
from the draft text without running this package:

- `ok` — does the capsule pass Class-1 verification (§6)?
- `findings[].check` — the §6 Class-1 check number (1–8) a finding belongs to
  (or `null` for the non-gating defensive disposition-honesty assert, which §6
  carves out of the gating enumeration); `severity` is `error` (gates `ok`),
  `warning` (non-gating defensive), or `info`.
- `derived` — `effect_mode` / `attestation_mode` / `ledger_mode`, rederived per
  §5.2/§5.3. (This payload layer never derives `anchored`; substrate/Receipt
  verification is by reference, §6.)
- `capsule_id_recomputed` — the JSON-DIGEST of the canonical capsule form
  (§5.1). A third party regenerating it can compare byte-for-byte.

The `code` and `detail` strings are this implementation's labels (for
debugging); a conforming verifier may use its own. Conformance is agreement on
`ok`, the §6 check numbers + severities, the derived modes, and `capsule_id`.

## Layout

```
test-vectors/
  README.md
  vectors.json              — manifest: every case with kind + one-line description
  SHA256SUMS                — pins every input.json / expected.json byte
  <case>/input.json         — a Capsule, or {"ledger": [...]} for store-level cases
  <case>/expected.json      — { ok, derived, capsule_id_recomputed, findings[] }
                              (store cases: { results: [ ... per capsule ] })
```

## Cases

Positive (conformant, `ok=true`): a clean executed capsule; one per
single-capsule `verdict_class` category (blocked, denied, hitl_dispatched,
deferred, errored, timeout pre- and post-dispatch); the full
`effect_attestation` matrix (confirmed→REQUIRED for both grades,
dispatched_unconfirmed→REQUIRED, not_applicable→absent, the planned carve,
failed→REQUIRED, reverted→REQUIRED); unknown registry values (informational,
never rejected); and the store-level supersedes chain and concurrent-supersedes
cases.

Negative (`ok=false`): confirmed without `response_digest`; a float in a
digest-bearing field; an integer beyond the JS-safe range in a digest-bearing
field (see the -01 flag below); `effect_attestation` present where it MUST be
absent and absent where REQUIRED; a never-dispatch `verdict_class` with a
non-`not_applicable` effect_mode; a `capsule_id` that does not recompute; a chain
referencing a missing parent; and an `approver` outside the closed enum.

## Spec-independence note + -01 flags

Every vector's expected output is confirmable from the -00 text **except one**,
flagged here so the deviation is explicit rather than silently baked into a
golden file:

- **`neg-unsafe-integer-in-digest-field`** encodes an implementation guard that
  is **ahead of the -00 spec text**. §5.1 forbids JSON floats and mandates exact
  decimal **strings** for monetary/quantity values, but the -00 draft does *not*
  yet state a bound on plain JSON **integers**. An integer beyond
  `2^53 - 1` (`Number.MAX_SAFE_INTEGER`) cannot round-trip through an
  ECMAScript-Number-based reader, so two conforming verifiers could derive
  different digests from the same bytes — a real cross-implementation hazard.
  This reference rejects such an integer (`unsafe_integer_in_digest_field`,
  check 1); the expected `ok=false` therefore reflects the impl guard, not a
  rule a third party can read out of -00 today.
  **-01 FLAG:** the draft should state that integers outside the
  IEEE-754-double safe range MUST be represented as exact decimal strings (the
  same remedy §5.1 already gives monetary/quantity values). Until then, this is
  the one vector an independent -00-only implementation may legitimately not
  reproduce.

Honesty (per §6): a parsed capsule with `human_disposed=true` and a non-human
approver is reported as a **non-gating** defensive `warning`; `ok` still reflects
the gating checks — disposition honesty is structurally guaranteed at
construction and is not one of the §6 gating checks.

## Running

The reference suite runs every vector through `verify()` / `verify_store()` and
asserts each `expected.json` — see `python/tests/test_vectors.py`. To check an
independent implementation, run it over each `input.json` and compare `ok`, the
finding check-numbers/severities, the derived modes, and `capsule_id`.
