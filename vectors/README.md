# Authoritative conformance vectors

This directory is the language-agnostic, releasable conformance surface for
the Agent Action Capsule repository. Python, Go, and TypeScript consume these
same-commit files in CI.

- `capsule/`: format-4 JCS, Capsule ID, Class-1, store, `references[]`, and
  deliberate unsupported-format rejection cases. Most cases carry
  `spec_version` `-04` and stay frozen: they show format-4 Capsules carrying
  `-04` still verify.
  The `pos-v05-*` cases carry `-05` and exercise the `-05` registrations;
  `python/scripts/generate_v05_vectors.py` regenerates them.
- `producer-envelope/`: binary COSE Producer Envelope cases.
- `disclosure-envelope/`: Disclosure Envelope DE-1 through DE-3 cases.
- `cross-language/`: format-4 inputs used by the all-producer/all-consumer
  interlock: the released `-04` `seal-input.json` and its `-05` twin
  `seal-input-v05.json`.
- `interop/`: established composition and run-under interoperability suites.
- `evidence-request/`: draft-mih-agent-evidence-request-00 cases (request map,
  subject forms, request digest, signed refusal, outcomes, caller invariance,
  retention), derived from the draft text;
  `python/scripts/generate_evidence_request_vectors.py` regenerates them.
- `settlement/`: draft-mih-agent-settlement-records-00 cases (two-party
  payer/payee leg records, the payment reference join, wrapped objects by
  digest, exact amounts, delivered-content digests, derived states), derived
  from the draft text; `python/scripts/generate_settlement_vectors.py`
  regenerates them.
- `minimum-necessary/`: provisional registry entries held for ratification
  (`spec/REGISTRY.md` §10, §14, §16): SD-JWT (RFC 9901) presentations as a
  revealed `agent_input`, the `disclosure-policy-decisions/v1` and
  `sd-jwt-issuers/v1` Bundle extensions, and the `minimum_necessary_report/1`
  result shape, over one worked example;
  `python/scripts/generate_min_necessary_vectors.py` regenerates them.
- `judgment/`: PROVISIONAL judgment extension cases (the `x-judgment-v1`
  Capsule member: `rubric_digest`, `rubric_version`, `judge_parameters_digest`,
  schema `schemas/judgment/judgment-extension-v1.json`). The digest rules are
  proposed and unratified;
  `python/scripts/generate_judgment_extension_vectors.py` regenerates them.

Reference-derived corpora and checksum manifests can be regenerated with:

```bash
python3 python/scripts/generate_all_vectors.py
```

Do not overwrite `spec-derived` cases with generator output. Their recorded
preimages and expected results are the implementation-independent authority.

The `vectors/vX.Y.Z` release workflow archives this directory directly. The
release asset is a deterministic snapshot at the selected commit; consumers
must pin the printed SHA-256 digest.

## Provenance

Each case may carry a `provenance` field in both its `vectors.json` entry and
its `expected.json`. `reference-derived` identifies an expected result frozen
from the reference verifier. `spec-derived` identifies a value derived from the
draft and RFC 8785 without running any repository implementation. A
`spec-derived` expected result records each literal RFC 8785 canonical string
used for a SHA-256 golden value in `canonical_preimages`.
