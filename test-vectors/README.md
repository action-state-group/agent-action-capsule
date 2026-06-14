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
digest-bearing field; `effect_attestation` present where it MUST be absent and
absent where REQUIRED; a never-dispatch `verdict_class` with a non-`not_applicable`
effect_mode; a `capsule_id` that does not recompute; a chain referencing a
missing parent; and an `approver` outside the closed enum.

Honesty (per §6): a parsed capsule with `human_disposed=true` and a non-human
approver is reported as a **non-gating** defensive `warning`; `ok` still reflects
the gating checks — disposition honesty is structurally guaranteed at
construction and is not one of the §6 gating checks.

## Running

The reference suite runs every vector through `verify()` / `verify_store()` and
asserts each `expected.json` — see `python/tests/test_vectors.py`. To check an
independent implementation, run it over each `input.json` and compare `ok`, the
finding check-numbers/severities, the derived modes, and `capsule_id`.
