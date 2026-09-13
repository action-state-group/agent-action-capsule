# `ran_under` citation vectors — a Capsule citing a runtime attestation record

Six cases making checkable a claim that PR #95 currently states only in prose:
a grade carried by a record cited with `citation_purpose: "ran_under"` is
narrower than it looks, in two independent directions, and a Capsule citing
that record must lift neither.

## The claim

1. A grade on the cited record does not extend to claims stated *inside* that
   record (§6.1 non-propagation — TRACE's rule, restated in #95).
2. A grade on the cited record does not extend to whether the verifier trusts
   *who signed* it (signer trust is external context; the corresponding
   boundary on the TRACE side is `agentrust-io/trace-spec#341`).

**A passing grade is not a passing citation.** Two of the six cases carry a
*good* grade and still refuse to lift — that contrast with the one case that
carries a good grade and *does* lift is the point of the set.

## The property under test, stated explicitly

**This harness never re-implements runtime-attestation verification.** It
takes the cited format's verifier result as an input — `cited_verifier_result`
in each `input.json` — the way a real consumer would after running the cited
format's own tooling. `verify_ran_under.py` never parses attestation bytes,
evaluates a measurement, or derives a grade. The one thing it does with the
cited record's raw bytes (`cited_record`) is recompute a content digest
(`SHA-256(JCS(...))`) to check it against the Capsule's declared reference —
that is generic content-addressing, the same operation `verify_composition.py`
performs over the WHO artifact, not attestation verification. Search the
source: it contains no quote-parsing, no measurement evaluation, no grading
logic of its own.

## Cases

| Case | Cited record | Expected | Failed stage |
|---|---|---|---|
| `pos-ran-under-attested` | good grade, signer in roots, measurement matches | **accept** — grade reported for what it covers | — |
| `neg-ran-under-signer-untrusted` | **good grade**, signer **not** in the verifier's roots | reject the lift, not the record — reported as `untrusted_signer`, never `invalid` | `signer_trusted` |
| `neg-ran-under-measurement-mismatch` | grade present, measurement disagrees with the citing claim | reject at the binding stage | `claim_value_binds` |
| `neg-ran-under-grade-absent` | no grade | no lift — reported as `not_established`, never as failed | `grade_established` |
| `neg-ran-under-inner-claim` | **good grade**, but the claim the Capsule relies on is self-reported *inside* the cited record | **no lift** — the §6.1 case, the most important vector in the set | `claim_is_attested` |
| `neg-ran-under-digest-mismatch` | cited bytes do not match the cited digest | reject at content binding | `digest_binds` |

Each negative fails at exactly one documented stage; no negative fails for two
reasons (see `SHA256SUMS`-pinned `expected.json` per case, and the mutant-kill
evidence below).

The staged verifier (`verify_ran_under.py`) checks, in order: `citation_present`
→ `digest_binds` → `capsule_class1` → `grade_established` → `claim_is_attested`
→ `claim_value_binds` → `signer_trusted`. A bundle that clears every stage is
`accepted` (lift). Anything short of that reports one of four distinct
non-`accepted` verdicts — `invalid`, `not_established`, `unattested_claim`,
`untrusted_signer` — so a caller never has to infer *why* a citation didn't
lift from a bare boolean.

## Run

```
cd vectors/interop/ran_under
python3 verify_ran_under.py pos-ran-under-attested/input.json
# {"verified": true, "lift": true, "verdict": "accepted", ...}   exit 0
python3 verify_ran_under.py neg-ran-under-inner-claim/input.json
# {"verified": false, "lift": false, "verdict": "unattested_claim",
#  "failed_stage": "claim_is_attested", ...}   exit 2
```

`agent-action-capsule>=0.1.0` on the path (or run from the repo tree; the
script falls back to `../../python` when the package isn't installed).

## Bundle shape

Each `input.json` is:

```json
{
  "capsule": { ...an AAC Capsule carrying a `references` entry with
               citation_purpose: "ran_under"... },
  "cited_record": { ...the cited artifact's raw content, over which the
                     digest binding is checked... },
  "relied_claim": {"field": "<name>", "expected_value": "<value>"},
  "cited_verifier_result": {
    "grade": "<str>" | null,
    "signer_trusted": true | false,
    "attested_fields": { ...fields the cited format's OWN verifier actually
                          attests, by name... },
    "self_reported_fields": { ...fields present in the record's content but
                               NOT covered by its attestation grade... }
  }
}
```

`relied_claim` names the specific fact this Capsule's `ran_under` citation
depends on. `claim_is_attested` asks whether that fact is one the cited
format's verifier actually attests (`attested_fields`) as opposed to merely
self-reported content inside the same record (`self_reported_fields`) — this
is the mechanical form of the §6.1 non-propagation rule. `claim_value_binds`
then checks the attested value against what the Capsule claims. The two
checks are independent: a claim can be attested-but-wrong (measurement
mismatch) or wrong-kind-of-claim entirely (inner-claim case), and each is its
own documented stage.

## Registry status

`citation_purpose: "ran_under"` is seeded by PR #95, which is open and not yet
merged — `spec/REGISTRY.md` on `main` does not list it yet. Class-1
verification treats an unseeded `citation_purpose` value as informational,
never gating (§12), so `capsule_class1` still passes on every case here; this
set does not depend on #95 landing first. Per the sequencing note on the
originating task: if this set lands first, #95's body can cite it once merged;
if #95 lands first, nothing here changes.

## Pinning

**Do not block on `trace-spec#341`.** It is open and unmerged; its branch head
is not a durable pin. `neg-ran-under-signer-untrusted` is constructed entirely
on our side — a `cited_verifier_result` reporting `signer_trusted: false` —
and needs no upstream fixture. When `trace-spec#341` merges, this README will
gain a line naming it as the corresponding upstream fixture; it is referenced,
never vendored.

## Frozen

`SHA256SUMS` fixes every file in this directory. CI (`python/tests/
test_ran_under_vectors.py`, run by `.github/workflows/python.yml`) runs every
case through `verify_ran_under.py` and asserts both the CLI exit code and the
`verdict`/`failed_stage` against each case's `expected.json`, so a change that
silently breaks a stage fails the build rather than only a manual read.

## Mutant-kill evidence (R4)

Each stage's condition was mechanically removed (the `if not r[...]:
return ...` replaced with a no-op) and the corresponding negative re-run:

| Stage removed | Case | Result with stage removed |
|---|---|---|
| `digest_binds` | `neg-ran-under-digest-mismatch` | flips to `accepted` (lift=true) |
| `grade_established` | `neg-ran-under-grade-absent` | flips to `accepted` (lift=true) |
| `claim_value_binds` | `neg-ran-under-measurement-mismatch` | flips to `accepted` (lift=true) |
| `signer_trusted` | `neg-ran-under-signer-untrusted` | flips to `accepted` (lift=true) |
| `claim_is_attested` | `neg-ran-under-inner-claim` | still rejected, but at `claim_value_binds` instead — the relied field (`workload_identity`) genuinely isn't a key in `attested_fields`, so removing the *gate* doesn't manufacture a false accept; the structural absence of the field is a second, independent barrier. This is the one stage whose mutant does not fully flip to accept, and that is the credible reason why. |

Four of five mutants fully flip their case to a false accept, proving the
removed check is what was rejecting it. The fifth (`claim_is_attested`) is
caught a second time by the data shape itself — worth stating plainly rather
than only claiming a clean flip that didn't happen.
