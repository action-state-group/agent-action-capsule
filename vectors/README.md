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
- `evidence-layer/padding/`: draft-mih-agent-evidence-layer-00 padding
  records ("What a Checkpoint Reveals"): valid records with their
  `capsule_id`, and negatives for a missing or misencoded `store_nonce`, extra
  members, links, payload commitments, `subject_ref`, `principal_ref`, a wrong
  `epistemic_type` and a wrong `capsule_id`;
  `python/scripts/generate_evidence_layer_padding_vectors.py` regenerates them.
- `cll-material/`: profile `evidence-interop/0` §6.2.1 CLL proof encodings: a
  responder's inputs and the exact `cll-inclusion-proof` and
  `cll-consistency-proof` octets, including the §10.1 worked example's;
  `python/scripts/generate_cll_material_vectors.py` regenerates them.
- `minimum-necessary/`: provisional registry entries held for ratification
  (`spec/REGISTRY.md` §10, §14, §16): SD-JWT (RFC 9901) presentations as a
  revealed `agent_input`, the `disclosure-policy-decisions/v1` and
  `sd-jwt-issuers/v1` Bundle extensions, and the `minimum_necessary_report/1`
  result shape, over one worked example;
  `python/scripts/generate_min_necessary_vectors.py` regenerates them.
- `bundle/strict/`: strict Evidence Bundle verification
  (`verify_bundle(..., strict=True)`): producer signatures, including vintage
  `jcs-n` records, the checkpoint read from its signed COSE form,
  producer-selected Bundles, the `disclosures` claim and witness receipts of the
  `cll`, `rekor` and `scrapi` bindings under a supplied witness directory;
  `python/scripts/generate_bundle_strict_vectors.py` regenerates them.
- `judgment/`: PROVISIONAL judgment extension cases (the `x-judgment-v1`
  Capsule member: `rubric_digest`, `rubric_version`, `judge_parameters_digest`,
  schema `schemas/judgment/judgment-extension-v1.json`). The digest rules are
  proposed and unratified;
  `python/scripts/generate_judgment_extension_vectors.py` regenerates them.
- `interop-profile-v0/`: conformance cases for `spec/interop-profile-v0.md`
  (`evidence-interop/0`): the exchange, a carried foreign object, the acceptance
  record, lifecycle links and carriage over A2A and MCP, each pinning its trust
  policy, verification policy, contract version and evaluation time;
  `python/scripts/generate_interop_profile_v0_vectors.py` regenerates them.

- `presentation-resolution/`: shared presentation resolution vectors for
  `spec/presentation-contract-v0.md` (ABI refusal, the descriptor, the match,
  the tiers and the static ambiguity test), normative for the TypeScript
  registry and the Go package `go/presentation`; the TypeScript registry
  generates them (see its README).

Reference-derived corpora and checksum manifests can be regenerated with:

```bash
python3 python/scripts/generate_all_vectors.py
```

The top-level `SHA256SUMS` lists every file under this directory except the
checksum files themselves. A corpus with its own `SHA256SUMS` lists its files
there as well; `judge/`, `profiles/` and `cross-language/` rely on the
top-level list alone.
The release workflow checks the top-level list before it archives the
directory, so a file it does not list would ship unverified.

A full run must leave this directory unchanged;
`.github/workflows/vectors.yml` enforces it, so a generator that drops or
rewrites a case fails CI. Generators run in manifest order: a base generator
writes its corpus manifest and later ones, including the append-only
`generate_parity_hardening_vectors.py` and
`generate_envelope_encoding_vectors.py`, append their cases.

The `-04` capsule cases are a deliberate compatibility set, kept `-04`
because a verifier must accept `-04` and `spec_version` is in the Capsule ID
preimage; new cases default to `-05`. The four legacy-format negatives
(`neg-format-version-unknown`, `neg-v2-canonicalization-absent`,
`neg-v2-canonicalization-null`, `neg-v3-format-version-unsupported`) are
frozen fixtures: the reference refuses to seal formats 1, 2 and 3, so the
generators list them without rewriting them.

`spec-derived` cases stay the implementation-independent authority: their
recorded preimages and expected results come from the draft and RFC 8785. The
generators reproduce them only to show the reference agrees. If a generator's
output differs from one, fix the generator or the reference, never the case.

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
