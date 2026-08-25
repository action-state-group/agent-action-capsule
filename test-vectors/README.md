# Conformance vectors

Frozen Class-1 conformance vectors for the Agent Action Capsule profile
(`../spec/`). Each case is an input plus the expected Class-1 verifier result,
version-pinned and hand-checkable. The corpus covers both the current format-4
identity profile and the absent-field format-2 vintage verification path.

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
- `capsule_id_recomputed` — the derived Capsule ID (§5.1). Format 4 removes
  only `capsule_id` and uses plain JCS; vintage format 2 removes `capsule_id`
  and `chain` and applies absent-field normalization before JCS.

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

Identity cases include a current format-4 Capsule with a committed chain,
post-seal chain tampering, a missing declaration, explicit withdrawn `jcs-n`,
an unknown declaration, a non-string declaration, and a format-2 Capsule that
incorrectly declares an algorithm.

Other negative (`ok=false`) cases include confirmed without `response_digest`; a float in a
digest-bearing field; an integer beyond the JS-safe range in a digest-bearing
field (see the historical note below); `effect_attestation` present where it MUST be
absent and absent where REQUIRED; a never-dispatch `verdict_class` with a
non-`not_applicable` effect_mode; a `capsule_id` that does not recompute; a chain
referencing a missing parent; and an `approver` outside the closed enum.

## Spec-independence note

Every vector's expected output is confirmable from the current draft except
the historical note below:

- **`neg-unsafe-integer-in-digest-field`** encodes an implementation guard that
  is **ahead of the -00 spec text**. §5.1 forbids JSON floats and mandates exact
  decimal **strings** for monetary/quantity values, but the -00 draft does *not*
  yet state a bound on plain JSON **integers**. An integer beyond
  `2^53 - 1` (`Number.MAX_SAFE_INTEGER`) cannot round-trip through an
  ECMAScript-Number-based reader, so two conforming verifiers could derive
  different digests from the same bytes — a real cross-implementation hazard.
  The current draft now requires integers outside the IEEE-754 safe range to be
  represented as decimal strings. The vector is retained to prove the guard and
  remains ahead only of the historical -00 text.

Honesty (per §6): a parsed capsule with `human_disposed=true` and a non-human
approver is reported as a **non-gating** defensive `warning`; `ok` still reflects
the gating checks — disposition honesty is structurally guaranteed at
construction and is not one of the §6 gating checks.

## Running

The reference suite runs every vector through `verify()` / `verify_store()` and
asserts each `expected.json` — see `python/tests/test_vectors.py`. To check an
independent implementation, run it over each `input.json` and compare `ok`, the
finding check-numbers/severities, the derived modes, and `capsule_id`.

**The `transparent` extra is required for a clean run.** `pip install -e ".[dev]"`
alone omits `scitt-cose` (`cryptography`/`cbor2`), so `tests/test_scitt_offline.py`
fails to collect — a missing optional dependency reads as a failing suite rather
than what it is. `pip install -e ".[dev,transparent]"` installs it. Reproduced in
a fresh venv against this commit: **without** the extra, `615 passed, 8 skipped,
4 errors` (all four errors are `ModuleNotFoundError: No module named
'cryptography'` in `test_scitt_offline.py`); **with** it, `620 passed, 7 skipped`.
Either count is a clean run — read the count against which extras you installed,
not as a regression.
