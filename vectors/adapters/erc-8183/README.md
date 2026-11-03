# ERC-8183 adapter profile vectors

Vectors for `spec/adapters/erc-8183-v0.md`, which binds an ERC-8183 (Agentic Commerce) job's
`reason` to the Capsule ID of a sealed JF `evaluation-report/v1`.

- `vectors.json`: the cases (profile §10). Each is one job: its recorded lookups (`getJob` and
  the job's events, in the shapes a chain node returns), the evaluator's report capsule with its
  Producer Envelope (`envelope_hex`, COSE_Sign1 octets) and payload, the provider's deliverable
  capsule, the contract version document when the verifier holds it (`null` when it does not),
  the expected status of each of the seven checks of §7, and the predicates of §9 that hold.
- `manifest.json`: the set, its status and the SHA-256 of each generated file.
- `SHA256SUMS`: every file here.

Nothing was read from a chain. The contract, client, provider and evaluator addresses are example
values on Base Sepolia (`eip155:84532`). Every key is a test key derived from a public label
(`test_keys` in `vectors.json`). Judge pin digests, the rubric digest and the deliverable payloads
are placeholders.

Regenerate with `python python/scripts/generate_adapter_erc8183_vectors.py`; check with
`pytest python/tests/test_adapter_erc8183_vectors.py`. The workflow
`.github/workflows/adapter-erc8183.yml` fails when a regeneration differs from these files.
