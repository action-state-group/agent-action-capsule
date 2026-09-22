# Freeze log — composition vectors

`SHA256SUMS` fixes every file (see `RUNKIT.md`). This log records every
re-freeze: which vector changed, the superseded and current digests, and why.
A re-freeze never silently replaces a value — the prior value stays here.

## 2026-09-22 — `pos-composition-grid-curtailment` re-frozen under plain JCS

**Reported by:** oneshot2001 (issue #93), reproduced independently, stdlib
only, no library import. Confirmed root cause his.

**What broke:** `agent_action_capsule.canonical.json_digest` changed digest
functions between library releases:

| Version | Location | Function |
|---|---|---|
| `0.1.0` | `canonical.py:151` | `sha256(jcs(normalize(v)))` |
| `0.3.0` | `canonical.py:166` | `sha256(jcs(v))` — normalization moved to `vintage_json_digest` (verification-only, format-2 `capsule_id` recomputation) |

`pos-composition-grid-curtailment/input.json`'s
`what.model_attestation.compute_attestation.human_authorization_ref.digest`
was frozen under the `0.1.0` (normalized) form. Under the `0.3.0`+ library
that `pip install agent-action-capsule>=0.1.0` resolves today, the
`ref_binds` stage of `verify_composition.py` recomputes
`SHA-256(JCS(who))` with no normalization, disagrees with the frozen value,
and the documented positive case returns `verified: false`,
`failed_stage: ref_binds`, exit 2.

**Decision:** re-freeze under plain JCS (the `0.3.0`+, format-4 direction).
Do NOT pin `==0.1.0` — that would freeze the kit to a canonicalization this
profile has moved off.

**What changed:**

| Field | Superseded (0.1.0, normalized JCS) | Current (0.3.0+, plain JCS) |
|---|---|---|
| `what.model_attestation.compute_attestation.human_authorization_ref.digest` | `a1bee3358bebec5bee352db25fa286a927c2c34992696d6aac06a0e80cad16ee` | `228bacf852f63bdf20dd7d07ecc45d2e0c17b2f3f9ebce20279e210be6345bbb` |
| `what.capsule_id` | `6e61fa84886b5b8be2ef4e5e6daeb1946a218270a5c487839b93e35293f2fe7f` | `47c938cc979ceb5d1251b540c24cb4cc444f99c651ae4b7b9fc54c618235bb78` |

`capsule_id` changed as a consequence of the `human_authorization_ref.digest`
edit: this vector declares `canonicalization_id: "jcs"`, so `capsule_id` is
plain `SHA-256(JCS(capsule minus capsule_id/chain))` over a capsule whose
content just changed. Nothing else in `input.json` changed;
`subject_digest`, `action.json`, and every `who/` file are untouched and
their `SHA256SUMS` entries are unchanged. (Superseded `capsule_id` shown is
the value carried on `main` before this fix, under `spec_version`
`draft-mih-scitt-agent-action-capsule-04`; the `human_authorization_ref.digest`
there was still the pre-fix normalized-JCS value, so the whole-capsule digest
recomputed once the ref digest was corrected.)

**Superseded `SHA256SUMS` entry:**
```
63c13f6f9419d06d23e0b854c249c392e40abe9addbf06dfa3a8820e288f4480  pos-composition-grid-curtailment/input.json
```
**Current `SHA256SUMS` entry:**
```
6b77175fe287bc99a552f3dc61e9da76b2b13115b1726a7bd2eea18f614b03e9  pos-composition-grid-curtailment/input.json
```

**Verified:** full kit re-run against the current `SHA256SUMS` — the
documented positive case now passes and all three documented negative cases
still match `RUNKIT.md` verbatim (each rejecting at its own documented
stage, none touched by this change).

**Also fixed this pass:** `RUNKIT.md`'s `pip install agent-action-capsule>=0.1.0`
was an unbounded floor on the library whose digest function just changed
under it — the actual defect underlying oneshot2001's report, independent
of the digest re-freeze above. Constrained to `>=0.3.0`, the floor at which
`json_digest` became plain JCS.
