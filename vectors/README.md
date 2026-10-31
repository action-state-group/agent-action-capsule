# Authoritative conformance vectors

The index of every vector set, with case counts, is [`../VECTORS.md`](../VECTORS.md).

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
  `seal-input-v05.json`, `bundle-producer-log.json`, one checkpointed log
  of signed records every implementation builds the same Evidence Bundles
  from, and `bundle-producer-padded-log.json`, the same for a log whose range
  covers padding leaves (Bundle -02 `non_record_leaves`);
  `python/scripts/generate_bundle_producer_fixture.py` regenerates both.
  `verify-number-findings.json` pins the number findings every verifier
  reports for one record (at most 64 per code, paths cut to 256 characters);
  `python/scripts/generate_verify_number_findings_fixture.py` regenerates it.
  `cll-ed25519-vectors.json` is a verbatim copy of checkpointed-local-log's
  `checkpoint-conformance-vectors/ed25519-vectors.json`, the strict Ed25519
  cases the witness receipt tests of every
  implementation run.
- `interop/`: established composition and run-under interoperability suites.
- `evidence-request/`: draft-mih-agent-evidence-request-00, -01 and -02 cases
  (request map, subject forms, which record members carry a correlation
  identifier or cite an exchange half, request digest, signed refusal,
  outcomes, caller invariance, retention, the `categories` field, A2A and MCP
  carriage, unavailable-window statements), derived from the draft text;
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
- `anchor-witness-v1/`: profile `evidence-interop/1` §6.2.2 witness Receipts
  over an anchor and the `anchor_witnessed` report, positive and MUST-reject;
  `python/scripts/generate_anchor_witness_v1_vectors.py` regenerates them.
- `json-nesting/`: the nesting limit every implementation shares: JSON text
  nested 128 levels deep is read and canonicalized, 129 levels is refused as
  malformed, and a value past the limit has no RFC 8785 form; `spec/interop-profile-v1.md` §5.2
  states the limit (#498);
  `python/scripts/generate_json_nesting_vectors.py` regenerates them.
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
- `bundle/fragment/`: the Evidence Bundle permalink codec ("Fragment Codec" of
  `draft-mih-zhang-agent-disclosure-bundle`): payloads and the tokens an
  independent encoder wrote for them, run by the TypeScript and Go codecs
  (see its README). Hand-maintained; `SHA256SUMS` pins it.
- `bundle/non-record-leaves/`, `bundle/certificate-mode/` and
  `bundle/category-coverage/`: Evidence Bundle -02 under strict verification:
  a range that carries padding leaves in full in
  `completeness_certificate.non_record_leaves`, the producer-selected
  certificate in the shape producers emit, `completeness.selection` values
  naming a mode the verifier does not implement
  (`certificate_mode_unsupported`, never a failure), and the
  `category_coverage` member's five properties;
  `python/scripts/generate_bundle_02_vectors.py` regenerates them.
- `bundle/composed-controller-binding/`: the `controller_binding` join basis
  of Evidence Bundle -02's `composed/v1`: a linked join (redundant, never
  corroborating), unjoined joins (revoked, one key signing for both, other
  keys, outside the window), a declared state a revocation contradicts, and
  joins that cannot be derived (no binding record delivered, a method or key
  type not implemented), and joins with an empty-history member (linked:
  `one_sided`; revoked: `unjoined`; no checkpoint: not derivable);
  `python/scripts/generate_bundle_composed_cb_vectors.py` regenerates them.
- `judgment/`: PROVISIONAL judgment extension cases (the `x-judgment-v1`
  Capsule member: `rubric_digest`, `rubric_version`, `judge_parameters_digest`,
  schema `schemas/judgment/judgment-extension-v1.json`). The digest rules are
  proposed and unratified;
  `python/scripts/generate_judgment_extension_vectors.py` regenerates them.
- `interop-profile-v0/`: conformance cases for `spec/interop-profile-v0.md`
  (`evidence-interop/0`): the exchange, a carried foreign object, the acceptance
  record, lifecycle links and carriage over A2A and MCP, each pinning its trust
  policy, verification policy, contract version and evaluation time;
  `python/scripts/generate_interop_profile_v0_vectors.py` regenerates them. Frozen with
  `evidence-interop/0`.
- `interop-profile-v1/` and `interop-profile-v1-requirement-facts/`: the same cases for
  `spec/interop-profile-v1.md` (`evidence-interop/1`, ER -02), plus the two -02 refusal reasons
  and `capacity_exceeded` answering a request for `evidence-interop/0`;
  `python/scripts/generate_interop_profile_v0_vectors.py --profile 1` regenerates them.
- `personal-history-basic-v0/`: the acceptance run of
  `spec/personal-agent-history-profile-v0.md` §6.4 (Basic level): one History answered by an
  IP responder at a pinned commit (`responder-run.json`, reproduced by `producer/main.go`), the
  nine mutants of the §6.4 table and a refusal to another requester;
  `python/scripts/generate_personal_history_basic_v0_vectors.py` regenerates them from the run.
- `coverage-declaration-v0/`: the coverage declaration of `spec/interop-profile-v0.md` §6.7: one
  positive per coverage kind, the cherry-picked and record-missing negatives, an aggregate
  declaring more than its evidence, two source negatives, and two pairs of agreeing halves for
  issuer independence. Built from the personal-history run;
  `python/scripts/generate_coverage_declaration_v0_vectors.py` regenerates them.
- `controller-binding-v0/`: the controller binding record of `spec/controller-binding-v0.md` and
  its use in issuer independence (`spec/interop-profile-v0.md` §6.7.4): one valid binding per claim
  type, and expired, revoked, one-key-signed, same-key, other-keys, no-half-key-bound, forged-credential,
  unknown-method, unbound-delegator and revocation cases, each over a pair of agreeing halves;
  `python/scripts/generate_controller_binding_v0_vectors.py` regenerates them.
- `deal-reconcile-v0/`: the Evidence Contract `ec:deal-reconcile@1` of
  `spec/deal-reconcile-contract-v0.md`: a deal whose two halves' amount and currency commitments
  open and match, and one whose amount opening fails, with the six tallies and the Evidence Result
  of each; `python/scripts/generate_deal_reconcile_v0_vectors.py` regenerates them.
- `personal-history-outcome-v0/`: the Outcome level of the personal-agent History profile
  (`spec/personal-agent-history-outcome-v0.md`): one positive per outcome source (the holder's
  record, the other party's half, an x402 native object, a judge's verdict under consent), a
  `not_evaluable` delivery beside an established payment, the deal commitment unopened and
  wrongly opened, and one mutant per property the level adds. Derived from the personal-history run
  and the x402 adapter corpus;
  `python/scripts/generate_personal_history_outcome_v0_vectors.py` regenerates them.
- `standard-history-v0/`: the derivation `standard_history/1` of `spec/standard-history-v0.md`:
  positive cards for a person and a node, checked with and without the policy, the anchor and the
  deal entries, the month-end window clamp and an empty window, and one negative per property of
  its §6 (a percentage, a count without its denominator, a counted shop purchase, a window not in
  the policy, among others); `python/scripts/generate_standard_history_v0_vectors.py` regenerates
  them.
- `inference-service-history-v0/`: the Inference-Service History Profile
  `spec/inference-service-history-profile-v0.md`: a served-only Standard History, the period
  negatives, two anchors over the same closed periods, peer confirmation and labels at the
  Detailed level, and the interval and recipient refusals. Constructed;
  `python/scripts/generate_inference_service_history_v0_vectors.py` regenerates them. Frozen
  with `evidence-interop/0`.
- `inference-service-history-v0-interop-v1/`: the same cases under `evidence-interop/1`, plus
  `refused-capacity-exceeded` (a History the node declines for its own load, `UNKNOWN`);
  `python/scripts/generate_inference_service_history_v0_vectors.py --profile 1` regenerates them.
- `history-frame-v0/`: the History frame `spec/history-frame-v0.md`: each instance's counting
  table and wording pack with the digests the frame lists, and negatives for a mismatched pack
  digest, a translated pack, a changed table, a pack carrying a checked string and a pack naming
  another instance. Constructed; `python/scripts/generate_history_frame_v0_vectors.py`
  regenerates them.
- `adapters/x402/`: the x402 adapter declaration `spec/adapters/x402-v0.md`: a positive and a
  native-check-fails case for an `exact`/`eip3009` payment, with the wrapped objects' octets, the
  relying party's policy and recorded lookup, and the expected `native_check` reports. Constructed,
  not recorded, and signed with a published development key;
  `python/scripts/generate_adapter_x402_vectors.py` regenerates them.

- `viewer-core-text/`: the core's fixed text of
  `spec/verification-display-v0.md` sections 6.1 and 6.2 (the banner's line
  for each verification state, the refusal, and the check lists' lines),
  which a viewer's words must equal; the TypeScript viewer generates them
  (see its README).
- `adapters/ucp/`: the UCP adapter cases of `spec/adapters/ucp-v0.md` §3, a
  checkout carrying `ap2.merchant_authorization`: a positive and a
  native-check-fails case, signed with the RFC 7515 Appendix A.3 example key;
  `python/scripts/generate_ucp_adapter_vectors.py` regenerates them.

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
