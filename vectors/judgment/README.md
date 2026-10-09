# Judgment extension vectors (provisional)

**Status: PROVISIONAL.** The judgment extension is held for ratification and is
not registered. **The `rubric_digest` and `judge_parameters_digest` rules below
are proposed and unratified.** They may change before ratification; if they do,
these vectors are regenerated under a new member name rather than rewritten in
place once released.

Schema: `schemas/judgment/judgment-extension-v1.json`.

## What the extension adds

A Capsule that records a judgment (by a model judge or a human expert) carries
one namespaced member at `/model_attestation/compute_attestation/x-judgment-v1`:

| Member | Meaning |
|---|---|
| `rubric_digest` | JSON-DIGEST of the published rubric document |
| `rubric_version` | the producer's label for the rubric, verbatim; a label, never identity |
| `judge_parameters_digest` | JSON-DIGEST of how the judge was asked, excluding the judge's identity |

Base fields keep their meaning: `developer` is the judge (model and version, or
a non-identifying rater role label); `agent_output_digest` binds the judge's
answer `{verdict, rationale}`; `references[]` carries exactly one `judged_from`
entry naming the evidence by digest. The binding makes a judgment re-runnable,
not reproducible: a verifier never re-runs a model. It recomputes digests from
published preimages.

## Digest rules (proposed, unratified)

JSON-DIGEST is the base profile's rule: lowercase-hex SHA-256 of
`UTF8(JCS(value))` (RFC 8785), with no member filtering at any depth.

- `rubric_digest` = JSON-DIGEST(rubric). The rubric is the whole published
  document. When the judge reads reference text, the rubric carries
  `policy_digest` = SHA-256 of that text's raw bytes.
- `judge_parameters_digest` = JSON-DIGEST of
  `{instruction_template_digest, prompt_digest, axes_digest, sampling_params,
  min_confidence_micros?, judge_batch?}` for a model judge, or of
  `{protocol, packet_digest}` for a human expert. `instruction_template_digest`
  and `packet_digest` are JSON-DIGESTs; `prompt_digest` and `axes_digest` are
  SHA-256 of raw file bytes.
- `agent_output_digest` = JSON-DIGEST(`{verdict, rationale}`).

## Cases (`vectors.json`)

| id | expected |
|---|---|
| `pos-ai-judge` | pass: every digest recomputes; one `judged_from` (the evidence Capsule) and one `calibrated_against` (the expert judgment) |
| `pos-human-expert` | pass: same `rubric_digest` and same `judged_from` as `pos-ai-judge`; parameters are the rating protocol and the packet shown |
| `neg-judge-parameters-digest-mismatch` | fail: schema-valid and Class 1 valid, but `judge_parameters_digest` does not recompute from the published parameters |
| `neg-missing-rubric-version` | fail: the schema rejects the member (required `rubric_version` absent) |

Each case carries `preimages.values` (the JSON values) and `preimages.canonical`
(their literal JCS strings). `raw_files` holds the text whose raw-byte digests
are inner members. `evidence` is the Capsule both judgments are made from.
`judged_from` and `calibrated_against` are not yet registered citation purposes;
a base verifier reports them as informational, never as a failure.

## Regenerating and checking

```bash
python3 python/scripts/generate_judgment_extension_vectors.py
python -m pytest python/tests/test_judgment_extension_vectors.py
python3 schemas/check_judgment_extension_examples.py
```

The run is deterministic and uses no keys. The test recomputes every digest
from the files alone, cross-checks JCS against an independent RFC 8785
implementation, and runs base Class 1 verification on every Capsule.
