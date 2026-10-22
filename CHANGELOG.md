# Changelog

## Unreleased

- Evidence Result v0: `out_of_scope` is a fourth verdict, and a requirement's applicability is
  sealed data (#349, #350), revised in place: `result_version` stays `evidence-result-v0`, and every
  new member is optional, so a Result that validated before validates unchanged. `out_of_scope`
  pairs only with `SATISFIED`, only on a requirement claim that carries `out_of_scope_allowed`
  (copied from the Evidence Contract), and sits in its own `buckets.out_of_scope`, present exactly
  when a claim is switched on; it is never in `met`. `applies_from` (copied from the contract's
  `clause.effective_from`) makes a claim later when it is after the UTC date of `generated_at`: a
  later claim keeps its verdict as readiness, sits in no bucket, and is counted in
  `coverage.not_yet_in_force`. The schema, the checker's new cross-element rules and the
  TypeScript reader enforce these, with a strict RFC 3339 date grammar. The core Result page draws
  the fourth bucket, a "not yet in force" list and the as-of date, labelled as copied from the
  contract; the two deprecated cards count `out_of_scope` on their own and leave later claims out.
  The Plan IR's decision verdict and the interop profile's pair invariant gain the fourth value,
  the Go and Python evaluators copy both facts (P-61) and refuse a contract whose `effective_from`
  is not a calendar date (P-62), and a new vector set, `vectors/interop-profile-v0-requirement-facts/`,
  pins the copy. `contract-report/v1` gains the fourth count, a "Not yet in force" section, the as-of
  date and wording keys. The interop profile re-pins the Evidence Contract v0 schema to
  capsule-engine `773ae9e` (SHA-256 `6b969610…b770`), which carries the verdict and the switch;
  the frozen personal-history Basic level keeps its released pin.
  (#368)
- Evidence Result v0 coverage counts evaluations, one per claim, as every implementation counted:
  the spec text now says so, the core page reads "N evaluations of M requirements … N with an
  unknown result", and no count rolls a requirement up to one verdict. (#362, #363)
- Judge records carry `out_of_scope` (#371). `x-judgment-v1` gains a second answer definition,
  `JudgeAnswerWithOutOfScope`; `JudgeAnswer` and its digest are unchanged, so every pin and record
  stays valid. A judge declaration names one definition by `schema_hash`, and the join gains check
  7: a disclosed answer matches its committed digest and fits the definition named. A withheld
  answer joins only as "produced by the declared judge; answer not disclosed, so not checked".
  `evaluation-report/v1` cases may be `out_of_scope`; a reader that counts case verdicts counts it
  on its own, never as `met` or `not_evaluable` and never as the not-applicable exclusion. A judge
  answers `out_of_scope` only for a switched-on requirement, and a producer never maps it to
  another verdict: the personal-history outcome profile gains `judge_verdict_allowed`, so such a
  case no longer falls through to `not_evaluable`.

- TypeScript viewer: the verification page's countersignature line now adds "Checking a
  countersignature is not one of the bundle's own checks, so its result never changes the
  bundle's verdict." A failed
  countersignature can sit under a verified banner, because a countersignature is outside the
  bundle digest (presentation contract section 6.2), and the line now says why the two do not
  disagree. `vectors/viewer-core-text/` carries the new line. (Sherlock2's review of #364)
- TypeScript viewer: a producer-selected Bundle (`completeness.selection: "producer-selected"`,
  which `buildEvidenceBundle(..., { intervalFrom: null })` produces) renders as `incomplete`, the
  strict verdict, instead of being refused as failed. The plain checks read a selection as an
  interval and failed per-record membership; the context now reads interval coverage
  (`selection_not_checkable`) and per-record membership as the strict checks do, so the render
  gate, the coverage statement and the check lists agree with the strict verdict. A selection
  the strict checks call INVALID is still refused. The browser build cannot authenticate the
  checkpoint, so the strict checks withhold a selection's proofs there, and the page still
  refuses it rather than show records a full verifier may call INVALID. (#361)
- TypeScript: `buildVerifiedBundleContext` no longer throws `RangeError` on input nested beyond
  the stack. Its copy and freeze of the input are iterative, so the verifier's own refusal
  (`bundle_malformed`, INVALID in strict mode) is what the context carries, and
  `renderEvidenceGraph` draws the refusal instead of rejecting. (#360)
- TypeScript viewer: plain words for the banner and the verification page (#346), and five
  verification states always distinct, with `checking` shown (#309). **Breaking for anything that
  matches the banner's words or `data-verify`.** `data-verify` now names the state the reader is
  told: `checking`, `verified`, `incomplete`, `failed` or `unable`. `verified` appears only with
  `data-verdict="valid"`; an incomplete page, and a page whose checks failed but whose records
  still render, no longer carry `verified`. Whether the records are refused is still the refusal
  line (`data-refusal="unverified-bundle"`). Each state has one fixed line
  (`VERIFICATION_BANNER_LINES`): "Checking…", "✓ Unchanged since it was sealed", "None of the
  bundle's checks failed, but some were not run" (with a pointer to the not-checked list when the
  page draws one), "✗ A check failed: do not rely on this page", "✗ This bundle did not verify: do
  not rely on it" and "Couldn't check this page here: check it with a full verifier". The findings
  #196 added to the banner move to a details line under it (`data-banner-detail`). `checking` is
  drawn as soon as `renderEvidenceGraph` starts on a bundle, and a render that rejects while its
  own `checking` is shown puts back what the root held. A module that, while it renders, changes
  the banner's words or attributes (other than the class `setChromeClass` sets), hides or moves
  it, removes it or its details line, or draws a second banner, is discarded for the
  `presentation-failed` refusal. The state follows the strict verdict, so a countersignature or a
  top-level witness receipt is listed on the verification page but never changes it. On the
  verification page, each check-list line keeps its words in `[data-check-line]` and gains its
  technical name (`VERIFICATION_CHECK_TECHNICAL_NAMES`) in `[data-check-name]`. The digests, the
  completeness statement and the ten checks move under a closed "Technical details" disclosure
  (`[data-technical-details]`); the ten checks' heading is "Each check, by its technical name", and
  "suppressed fields" with nothing suppressed reads "none", not `[]`. Extension rows say "Shown by
  the page's module", "Read by this page itself" or "not interpreted by this page's checks",
  always with whether the file's fingerprint covers the block; the interpreter's id moves to
  `data-interpreter`. `spec/presentation-contract-v0.md` gains section 6.2 (the banner's states),
  and the new `vectors/viewer-core-text/` pins every fixed line. `UNVERIFIED_BUNDLE_REFUSAL` and
  `renderChecking` are exported. Wording reviewed by Sherlock2.
- TypeScript viewer: the banner states the strict verdict (`verifyBundle`'s `strict`), the
  outcome a full verifier reports, and no longer says "Bundle verification passed" for a bundle
  that verifier calls INCOMPLETE. It sets `data-verdict` (`valid`, `incomplete`, `invalid`) and
  `data-checkpoint` (`verified`, `unverified`, `invalid`, `absent`); `data-verify` is still the
  render gate. "Passed" is kept for `valid`. `incomplete` names what the page did not check, and
  coverage or membership resting on a checkpoint the page did not authenticate is labelled
  `checkpoint_unverified`, relative to a producer-asserted checkpoint (Evidence Bundle,
  completeness). Records bound to no log position now read "Bundle verification failed: N of M
  records are uncheckpointed …" (INVALID, as every verifier says) where the banner said "passed";
  their rows still render. With no Ed25519 there is no strict verdict, and that alone is
  never a failure: a bundle that passes the page's own checks, with every record bound to a log
  position, reads `incomplete`. The verification page's
  check lists now list the producer signatures and the checkpoint signature as checked or failed
  when the page checked them. `VerifiedBundleContext` gains `strict`; `CheckListInputs` gains
  `strict`, and the lists also read the strict proof claims and the witness receipts in
  `checkpoint.witnesses`. `CHECKPOINT_NOT_CHECKED_NOTE`'s text changed: it no longer says the page
  shows the bundle as passing. A styled banner gets `oi-banner-incomplete` (a new
  `OUTCOME_REPORT_CSS` rule, so a page that hashes that stylesheet for its CSP gets a new hash), and
  an unsigned bundle no longer gets `oi-banner-ok`. Building a context now also runs the strict
  checks: one Ed25519 verification per record, the checkpoint and the witness receipts. Tests
  carried over from #197 (Steven Mih). (#196)
- Evidence Result v0: `Claim.evidence` now has `minItems: 1`, matching §1's Traceability rule that
  `evidence[]` is REQUIRED on every claim. A Result with a claim that cites nothing no longer
  validates. §2 says a claim about a `recorded_absence` cites the absence record by digest, and
  `vectors/evidence-result/` gains `pos-example-org-recorded-absence-result.json` and
  `neg-claim-evidence-empty.json`. The TypeScript viewer is unchanged: it still shows such a claim
  as `unsupported`. The deal-reconcile contract (§7.3) makes no Result for a period with no half.
  (#353)
- Registry: `contract-report/v1` registered in `REGISTRY.md` §14 (with the Go, Python and Rust
  mirrors), defined in the new `spec/contract-report-v1.md` with the schema
  `schemas/contract-report-v1.json`. One neutral Evidence Bundle extension kind for a report over
  any Evidence Contract's Result: the block is a closed empty object (a producer's opt-in), the
  view reads only the sealed Result (aggregate first, then one row per `contract_ref` and
  `requirement_ref` with its claims counted by verdict), and every word comes from the rendering
  module's wording pack, never from the bundle. A block that is not an empty object is declined.
  The kind defines its wording keys; `example-wording-pack-contract-report.json` is an example
  pack, and `schemas/check_contract_report_examples.py` (run by `schemas.yml`) checks the block
  fixtures, their mutants and the keys. TypeScript exports `CONTRACT_REPORT_KIND` and
  `readContractReport`.
- Presentation contract, TypeScript and Go: a `contract-report/v1` reader in §4.2 and in both
  descriptors, and a seventh built-in manifest, `aac.builtin.result-contract-report/v0`, which
  draws the generic Result page for a Result root that opts in; the core runtime ships no
  contract-report module, and a runtime that has one registers it in its place. The built-in
  Result page and the two earlier display cards forbid `contract-report/v1`, so the new kind wins
  over an earlier block. The resolution table grows to 3,072 cases; `vectors/presentation-resolution/`
  gains descriptor overlays for the new block (engaged and three declined forms) and registration
  cases for a contract-report module beside and in place of the built-in.
- Deprecated: `outcome-report/v1` and `eu-ai-act-compliance/v1`, aliases of `contract-report/v1`
  (presentation contract §4.2 deprecation table). Deprecated in ts 0.6.0 and go v0.12.0, removed
  in ts 0.7.0 and go v0.13.0 (the second not before a Result revision carries applicability,
  #350); until then their readers and cards are unchanged, and their built-in manifests differ
  only in forbidding `contract-report/v1`.
- Outcome report model, TypeScript: a case that names its agent model (`case.agent_model`) now
  matches the conversation id `benchmark:domain:<model>:task-N:trial-T`; the id without the model
  still matches, and the transcript is still tied to the judged case by digest. New `reportState`
  says what the bundle shows of each cited report: disclosed, withheld, mismatch (the original does
  not match its commitment), unreadable (not an object), invalid (a book record whose report
  capsule is missing or does not check out: never counted as withheld) or not carried; each
  criterion carries it. Only when every report of a conversation is withheld is its case read from
  the claims (`caseFrom: "claims"`), and only when the record is a case record for that
  conversation (a checked carried capsule whose own `action_id` declares the case, new
  `CitedRecord.carriedActionId`), each claim cites exactly one, every claim the same one, and no
  other conversation's claims cite it; otherwise there is no case. A case read from the claims
  never makes the transcript `verified`: the new transcript state `cited` says the claims cite this
  case and, the reports being withheld, which conversation the judge read is not shown. Disclosed
  reports that name no case, or mismatched, unreadable or invalid ones, leave the case unresolved
  and the transcript unverified. Only a withheld report's judged day falls back to its capsule's
  own stated timestamp. `runInfo.reportsWithheld` counts only withheld reports;
  `reportsMismatched`, `reportsUnreadable` and `reportsInvalid` are counted apart, all of
  `reportsCited`. Each criterion carries the judge pin digest its disclosed report states.
  `parseJudgeProbabilities` reads whole numeric tokens (signed exponents included) and drops the
  whole probabilities set when any value is outside [0, 1] or is not a whole number, never a
  partial set; a confidence outside [0, 1] is dropped. New exports `reportState`,
  `reportSealedDay`, `claimsCitedCase` and `withheldReports`. `resolveCarriedInput` tells a
  supplied payload that fails from one the bundle leaves out: payload bytes that do not hash to
  their commitment, or a JSON original whose JSON-DIGEST is not the capsule's committed digest,
  resolve `disclosure_mismatch` (reportState `mismatch`), never `withheld`, so they unlock no
  claims fallback; only a payload left out is withheld.

## 0.11.0 — 2026-10-20

- TypeScript: outcome-report and bundle-page fixes. A resolved conversation's summary and
  drill-down count the criteria the pack judged instead of always saying "nine", and the report
  fits a phone (#323); with one criterion the Why line reads "1 criterion met" (#325). A bundle
  page that fails another check no longer says it shows the bundle as passing without the
  checkpoint (#326).
- Interlock: the Evidence Bundle producer is checked across implementations.
  `scripts/cross-language-interlock.sh` gains a producer step: Python, Go, TypeScript and Rust each
  build, with their own `proof_source_from_cll` and `build_evidence_bundle`, a whole-log Bundle, a
  suffix Bundle and a producer-selected Bundle from one checkpointed log of signed records
  (`vectors/cross-language/bundle-producer-log.json`, regenerated by
  `python/scripts/generate_bundle_producer_fixture.py`), plus a one-byte change of the whole-log
  Bundle. Every implementation's strict verifier reads all sixteen: whole-log and suffix VALID,
  producer-selected INCOMPLETE, the changed Bundle INVALID. The three built Bundles must be the
  same JCS bytes in all four languages. Each interlock adapter gains `bundle-produce <kind>` and
  `bundle-verify`; the Rust `cross_language` example now requires feature `strict`, and the
  conformance job installs the Python `bundle` extra.
- Evidence Bundle producer in each implementation's `bundle` module, beside the verifier: Python
  `build_evidence_bundle` / `build_unproven_bundle` / `proof_source_from_cll`, Go
  `BuildEvidenceBundle` / `BuildUnprovenBundle` / `ProofSourceFromCLL`, TypeScript
  `buildEvidenceBundle` / `buildUnprovenBundle` / `proofSourceFromCll`, Rust
  `build_evidence_bundle` / `build_unproven_bundle` / `proof_source_from_cll` (feature `strict`).
  The producer assembles an `evidence-bundle/v2` from a `ProofSource` (the log's signed COSE
  checkpoint, its leaves, records by Capsule ID, inclusion and range proofs) using the verifier's
  citation-closure rule, holds no key, and refuses any result strict verification calls INVALID.
  The interval is required: a range proof from a chosen seq to the checkpoint tip, or explicitly
  none (producer-selected records). `proof_source_from_cll` adapts a CLL backend and a record
  store; `build_unproven_bundle` builds the form with no log proof. Dependency floors: the Python
  `bundle` extra requires `checkpointed-local-log>=0.6.0` and the Rust `cll` dependency `0.3.1`,
  the first releases with the CLL backend interface (`load_cll`).
- Go: an evidence-interop/0 verifier and the Personal-Agent History Profile v0 Basic level
  evaluator, ported from the Python reference. `evidencerequest.Verifier.Verify` checks a set of
  exchanges as `InteropVerifier.verify` does: the §7.2 envelope and refusal properties, absence
  records, CLL `anchor_inclusion` (§6.2.1 steps 1 to 14), the JWS `native_check`,
  `caller_invariance` across every envelope held, and the §8 mapping with contract `uncertainty`.
  The new package `personalhistory` builds the Basic level definition and its derivation id,
  reads and writes the §8.2 one-file History, and evaluates §6.1, the seven §6.2 History
  properties and the §5 deal states. The tests run every exchange case of
  `vectors/interop-profile-v0` and every case of `vectors/personal-history-basic-v0` against each
  case's whole expected block. No vector or spec text changes. The History evaluator, in Go and
  in the Python test, reads an Artifact only when its octets are exactly the JCS of one object
  (PH §4.3), and each records entry's values only in their forms (a 64-hex `digest`, an unsigned
  `leaf_index`, a text string for each read member), so a re-signed Artifact with trailing data,
  a duplicate member or an object in a permitted member fails `artifact_form`, as does an Artifact
  `anchor` that is not a digest; every vector's expected result is unchanged. Received CBOR is
  read with a port of the reference's strict decoder (`interop_profile._cbor`): the first of a
  repeated key is kept, and undefined, other simple values and indefinite lengths are no data
  item. A JSON reply with an unpaired surrogate escape is not well formed.

- Vectors `capsule/canonical-integer-negative-zero` and
  `capsule/canonical-integer-negative-zero-as-zero` (spec-derived): `-0` as a direct member,
  nested in an object and inside an array, beside `0`, must serialize as `0` (RFC 8785), and
  the same input written with `0` must give the same `capsule_id`. Python, Go, TypeScript and
  Rust now also check each case's JCS bytes against its literal `canonical_preimages.capsule_id`,
  and a `same_capsule_id_as` twin against the case it names.
  `python/scripts/generate_negative_zero_vectors.py` regenerates them. First reviewed in #190,
  which merged into the already-merged #188 branch and so never reached main. Existing vector
  files are unchanged; `capsule/vectors.json` and the two `SHA256SUMS` files gained entries.
- Evidence Result v0 §4.1: `type: reconcile` is normative (`join_key`, `peer`, `period`, the six
  tallies, `state_of_record`). `type: close` stays PROPOSED. No schema structure, vector or
  rendering rule changes; the `ClaimType` description now states each type's status.
- UCP adapter declaration and vectors: `spec/adapters/ucp-v0.md` declares the five FR-19 items
  for UCP v2026-08-25 (`cd78fb38e819de77d9b527d110476eccb876f1bd`). The checkout carrying
  `ap2.merchant_authorization` (AP2 Mandates Extension) is the one merchant-signed object and gets
  a native check. The order object and a checkout without AP2 are possession-only. New vectors in
  `vectors/adapters/ucp/`: `positive` and `native-check-fails`, signed with the RFC 7515 Appendix
  A.3 example key and validated with `ucp-schema` 1.4.1 against UCP's published schema;
  `python/scripts/generate_ucp_adapter_vectors.py` regenerates them. The `ucp.checkout` wrapped
  object type is proposed, not registered.
- ACP adapter declaration v0 (`spec/adapters/acp-v0.md`), informational. ACP 2026-04-17 signs no
  object that an outside verifier can check. The checkout session, the order and the delegated
  payment token are unsigned, and the order webhook's HMAC is under a secret the two parties share.
  So the native check is `NOT_PRESENT` or `NOT_CHECKED`, mapped as interop profile §8.1 rows 3-4,
  and the declaration names what ACP would need to add. No vectors, by design.
- Personal-Agent History Profile v0 (`spec/personal-agent-history-profile-v0.md`): one History
  may span several evidence streams under one holder key, for example one stream per deal, all
  answered at one coverage anchor. Over two or more streams that anchor is a witnessed checkpoint
  tick that commits to each stream's checkpoint (§2, new open point PA-14). In §6.2,
  `single_anchor` now reads as one checkpoint or one witnessed tick, and `artifact_form` checks
  `evidence_stream` per envelope instead of requiring one stream across the History. A History
  over one stream at one checkpoint is accepted as before. Two derived cases are added to
  `vectors/personal-history-basic-v0/`: `multi-stream-one-tick` (accepted) and
  `mutant-multi-stream-mixed-anchor` (fails `single_anchor`). The existing twelve cases are
  unchanged. Changed released files: `vectors/personal-history-basic-v0/vectors.json`,
  `manifest.json`, `README.md` and `SHA256SUMS`, and `vectors/SHA256SUMS`.
- Coverage declaration (`spec/interop-profile-v0.md` §6.7, new open points P-58 to P-60). A set of
  answers under one derivation, such as a History, declares exactly one coverage kind:
  `holder_selected`, `stream_interval` (every record of the live set the holder opens at one
  anchor, under a rule, in an interval) or `source_authoritative` (the units a named external
  source lists, checked by its own method). A valid signature never implies completeness.
  - New coverage properties (§6.7.2). A completeness-dependent requirement is never `SATISFIED`
    unless every applicable property is `PASS` (§6.7.3).
  - `coverage_declaration_commitment` is `NOT_CHECKED` in v0, so no completeness-dependent
    requirement reaches `SATISFIED` from a `stream_interval` set yet.
  - `issuer_independence` (§6.7.4): one key gives `FAIL`, "redundant, not corroborating". Two keys
    with no evidence about their controllers give `NOT_CHECKED`, "not corroborating". No `PASS` in
    this revision.
- Personal-Agent History Profile v0: the Basic level's `completeness` `not_asserted` is the coverage
  kind `holder_selected` (§2, §4.1, §6.3, §9, new PA-15). The `personal_history_basic/1` bytes and
  its vectors are unchanged.
- Evidence Result v0: OPTIONAL `aggregate.coverage_declaration` `{"kind"}`, PROPOSED (§7.2).
  - The kind is never stronger than the evidence the claims rest on.
  - **A strict validator using the previous `schemas/evidence-result-v0.json` rejects an aggregate
    that carries the member**, because `Aggregate` is closed. Producers that omit it are unaffected,
    and every existing fixture is byte-identical.
  - New fixtures: `pos-example-org-coverage-declaration-result.json` and
    `neg-coverage-declaration-unknown-kind.json`.
- New corpus `vectors/coverage-declaration-v0/` (thirteen cases, built from the personal-history run):
  - one positive per kind;
  - `cherry-picked`, `stream-interval-record-missing`, `-anchor-mismatch` and `-unknown-rule`;
  - `aggregate-stronger-than-evidence`;
  - three source negatives;
  - `same-controller-halves-same-key` and `same-controller-halves-unbound-keys`.

  `python/scripts/generate_coverage_declaration_v0_vectors.py` regenerates it, and
  `python/tests/test_coverage_declaration_v0_vectors.py` checks it. Its example
  definition `coverage_declaration_example/0` and its population object are fixed for the vectors
  only and are not registered (IP §6.7.6).
- Changed released files: `spec/interop-profile-v0.md`,
  `spec/personal-agent-history-profile-v0.md`, `spec/evidence-result-v0.md`,
  `schemas/evidence-result-v0.json`, `schemas/_result_types.py`,
  `schemas/generate_result_examples.py`, `schemas/check_evidence_result_examples.py`,
  `vectors/evidence-result/README.md` and `SHA256SUMS`, `vectors/README.md`,
  `vectors/manifest.json`, `vectors/SHA256SUMS` and `python/scripts/generate_all_vectors.py`.
- Controller Binding v0 (`spec/controller-binding-v0.md`, new open points CB-1 to CB-6). It defines
  a binding record between two keys, for example a node key and a personal agent's holder key.
  - **Claim types.** There are three, each with its verification method: `same_controller_asserted`
    and `delegated_by` (`dual_signature/0`), and `same_organization_credentialed`
    (`dual_signature_credential/0`, with a credential named by digest).
  - **Signatures.** Both keys sign the same bytes: JCS of the record without `sigs`. A record that
    one key signed alone is not a binding. The binding digest is SHA-256 of those bytes, so a
    revocation names every copy of the record, whatever signatures it carries.
  - **Validity.** The record has a validity window. Either key can revoke it with a signed
    statement. No revocation source is registered, so revocation is `FAIL` or `NOT_CHECKED`.
  - **What a binding proves.** A verifier reports control of each key when it signed the record,
    and never an identity. A failed credential is reported, but it does not stop a binding from
    applying: both keys' signatures already state the claim.
- `spec/interop-profile-v0.md` §6.7.4 changes. A controller binding that applies to a pair now gives
  `issuer_independence` `FAIL`, "redundant, not corroborating". Before, that pair was `NOT_CHECKED`.
  - It never gives `PASS`: a binding shows common control, the opposite of independence. A binding
    that does not apply leaves the pair where it would be with no binding.
  - **This reverses P-60's earlier text**, which named a signed binding between two keys as the
    expected route to `PASS`. P-60 now says a binding gives `FAIL`, and that `PASS` needs evidence
    of distinct controllers, which is still open.
  - The binding is pinned as CB, and the catalogue has a new row for the controller binding
    properties.
- `spec/REGISTRY.md`: new provisional value `controller_binding` under "Provisional: composed/v1
  join basis values". It is held for ratification and not registered.
  - The Evidence Bundle `-01` `join-basis` list is closed and is not edited.
  - A producer MUST NOT carry the value in a `composed/v1` block until a posted Bundle revision lists
    it.
  - The Python, Go and Rust `data/REGISTRY.md` mirrors are updated to match.
- New corpus `vectors/controller-binding-v0/` (fourteen cases over pairs of agreeing halves):
  - one valid binding per claim type;
  - `credential-method-unimplemented`, `credential-forged`, `revoked-after-the-pair` and
    `revocation-by-other-key`, which still apply;
  - `expired`, `revoked`, `one-key-signed`, `same-key-halves`, `other-keys`, `unknown-method` and
    `delegator-not-bound`.

  `python/scripts/generate_controller_binding_v0_vectors.py` regenerates it, and
  `python/tests/test_controller_binding_v0_vectors.py` checks it. Existing vector bytes are
  unchanged.
- Changed released files: `spec/interop-profile-v0.md`, `spec/REGISTRY.md`,
  `python/agent_action_capsule/data/REGISTRY.md`, `go/registries/data/REGISTRY.md`,
  `rust/agent-action-capsule/data/REGISTRY.md`, `vectors/README.md`, `vectors/manifest.json`,
  `vectors/SHA256SUMS` and `python/scripts/generate_all_vectors.py`.
- Personal-Agent History Profile v0, Outcome level (`spec/personal-agent-history-outcome-v0.md`,
  new open points PO-1 to PO-8), informational. It is the level PA-9 named, with its own definition
  `personal_history_outcome/1`.
  - Each outcome claim names one source of four: the holder's own record, the other party's half,
    a native object read through an adapter declaration, or a judge's verdict given after the
    holder's consent. A verifier checks each claim against its source and shows the claims side by
    side, never combined.
  - Five shared predicates (`completed`, `delivered`, `paid`, `disputed`, `cancelled`) are one
    table, `outcome_predicates/1`, with digest
    `b5c7fe64bd1b4978aeef89cbc3bd9ecc23c2a57a48202a3d8d29e713ef4abfdc`. Every definition carries
    it. The table says which sources and adapter predicates count for each predicate. Evidence
    answers only its own question: payment evidence never establishes delivery.
  - `disputed` rests only on an IP §11.2 `disputes` statement, never on an outcome claim. Its EL
    link-type registration is still proposed for the Evidence Layer -01 (PO-4).
  - A deal's terms are committed as `sha256-jcs-nonce256`. The opening travels in the History or a
    bundle, never in an envelope.
  - The definition carries `coverage_declaration`, so the three coverage kinds of IP §6.7 become
    available to a History. `stream_interval` takes only the rule `all_records`.
  - A seller's and a buyer's History are two selection and requirement sets over this one level.
    Neither defines a figure across deals.
- Personal-Agent History Profile v0: the Status paragraph, §2, PA-9 and PA-15 now point to the
  Outcome level. No Basic level rule changes.
- New corpus `vectors/personal-history-outcome-v0/` (twenty-four cases, derived from the
  personal-history run and re-signed by the holder key):
  - one positive per source, and a `not_evaluable` delivery beside a `met` payment requirement;
  - the deal commitment unopened and wrongly opened;
  - a mutant for every level property that can be `FAIL`, except `native_check`.

  Its native object is the x402 adapter corpus's `positive` case, with the lookup stating `final`,
  so it holds under the released x402 adapter text and its pending revision.
  `python/scripts/generate_personal_history_outcome_v0_vectors.py` regenerates it, and
  `python/tests/test_personal_history_outcome_v0_vectors.py` checks it. Existing vector bytes are
  unchanged, the Basic level corpus included.
- Changed released files: `spec/personal-agent-history-profile-v0.md`, `vectors/README.md`,
  `vectors/manifest.json`, `vectors/SHA256SUMS` and `python/scripts/generate_all_vectors.py`.

## 0.10.0 — 2026-10-17

- **Breaking**, Python: `agent_action_capsule.emit` (the module and the root `emit` export) and
  `agent_action_capsule.integrations` (`crewai`, `langchain`) are removed, with the `langchain`
  and `crewai` extras. They were deprecated in 0.9.0 (#287). Use capsule-emit 0.11.0 or later:
  `capsule_emit.builder.build_capsule` is the former `emit()`, unchanged, and `capsule_emit.adapters.crewai`
  and `capsule_emit.adapters.langchain` replace the integrations (#281). `Capsule.seal()`,
  `build_disclosure_envelope` and the version constants in `agent_action_capsule.versions` stay.
- **Breaking**, Go: the `go/emitter` package is removed. It moved unchanged to capsule-viewer
  (`github.com/action-state-group/capsule-viewer/go/emitter`, from `go/v0.1.0`), which renders
  the page and keeps the Go/TypeScript byte-parity goldens (#281). Its presentation-fragment
  decoder and wording-pack check went with it, so Go has no twin of `presentation-fragment.ts`
  any more. `go/presentation` and the Evidence Bundle fragment codec (`bundle.EncodeFragment`,
  `bundle.DecodeFragment`, now checked against the shared fragment vectors in `go/bundle`) stay.
- **Breaking**, TypeScript: `emitter.ts` and `presentation-builder.ts` are removed, along with
  their root-entry exports (`emitEvidenceGraphHtml`, `emitStaticEvidenceGraphHtml`,
  `escapeJsonForHtmlScript`, `cspHashSourceFromHex`, `buildPresentation`, `availablePackagings`,
  `offlineHtmlFromFragment`, `buildFragmentViewerHtml`, `checkWordingPack`, the
  `PresentationBuildError` family and their constants and types) and `dist/emitter-shell.html`.
  They moved to `@action-state-group/capsule-viewer` 0.1.0, which imports AAC by package name
  (#281). The presentation contract,
  `presentation-fragment.ts`, `presentation-mount.ts`, the registry and the browser IIFE stay.
- Settlement, all four languages: a `fee_asset_differs` finding names the leg or legs whose fee is
  in another asset than its amount: the payer-observed leg for `routing_fee`, the payee-observed
  leg for `receive_fee`, payer first. It always named the payee leg, so a consumer had to repeat
  the pair selection to find the leg at fault. The code and the `unjoined` state are unchanged; a
  consumer reading `records` sees the payer leg where only the routing fee differs. New vectors
  `neg-ln-receive-fee-asset-differs`, `neg-ln-routing-fee-asset-differs` and
  `neg-ln-both-fee-assets-differ` in `vectors/settlement/`. This retires capsule-cli's own
  mapping (the known limitation in capsule-cli#233; #281).

- x402 adapter declaration v0 (`spec/adapters/x402-v0.md`), informational. It declares the five
  foreign-object items for an x402 v2 `exact`/`eip3009` payment. The `PaymentPayload` is
  payer-signed, and its native check is EIP-712 recovery with the domain taken from the relying
  party's policy. The `SettlementResponse` is unsigned: possession and transport-level provenance
  only, with settlement checked by a recorded transaction lookup. The payee receipt is declared for
  payload version 1 and both open version 2 proposals. New vectors in `vectors/adapters/x402/`:
  `positive` and `native-check-fails`, constructed (not recorded) and signed with a published
  development key; `python/scripts/generate_adapter_x402_vectors.py` regenerates them.
- Evidence Result v0 `coverage_report` (`spec/evidence-result-v0.md` §7.1, PROPOSED). An optional
  top-level member that reports, per requirement, which evidence exists, what is missing and which
  source would close each gap. A Result without it is unchanged and still valid, and coverage is never
  a verdict. New vectors in `vectors/evidence-result/`: `pos-example-org-coverage-result` and seven
  `neg-coverage-*` negatives. The TypeScript mirror (`validateEvidenceResult`) admits the member and
  does not check it.

- personal-history-basic-v0 vectors: `vectors/personal-history-basic-v0/` publishes the Basic level
  acceptance run of `spec/personal-agent-history-profile-v0.md` §6.4 (PA-11) as 12 cases: one
  History of three selected deals, the nine mutants of the §6.4 table, a second reading of the
  other-anchor mutant, and a refusal to a requester other than the recipient. The positive run is
  an IP responder's own octets (evidencebook `Book.Respond` at
  `43f3cb1b955d647bc92cb4da0d823973d1981cad`, reproduced by the corpus's `producer/main.go`);
  `python/scripts/generate_personal_history_basic_v0_vectors.py` builds the cases from it. The
  interop profile reference verifier gives every case's stated envelope statuses, and every
  accepted envelope maps to row 4, `UNKNOWN`/`not_evaluable`.
- Evidence Result v0 extension slot (`spec/evidence-result-v0.md` §8a). The document and each claim
  admit members named `x-...` (`patternProperties` `^x-` in `schemas/evidence-result-v0.json`).
  Verifiers ignore them, and an `x-` member never changes a claim's meaning or verdict. Every other
  member stays closed. The change is additive: every existing vector gets the same result. The
  TypeScript mirror (`validateEvidenceResult`) admits `x-` members at the top level. New vectors in
  `vectors/evidence-result/`: `pos-example-org-extended-result`, `neg-unprefixed-document-member`,
  `neg-unprefixed-claim-member`, plus a judging producer's output before
  (`neg-judge-producer-unprefixed-result`) and after (`pos-judge-producer-x-judge-result`) its
  members are renamed into the slot.

## 0.9.1 — 2026-10-16

- Settlement, all four languages: the `wrapped_resigned` check reads an SD-JWT as the
  issuer-signed JWS before the first `~`. It stripped only trailing `~`, so an SD-JWT with a
  disclosure (`JWT~disclosure~`) re-signed with the wrapping leg's key was not reported. New
  vectors `neg-wrapped-sd-jwt-resigned-with-disclosure` and
  `neg-wrapped-sd-jwt-resigned-no-disclosure` pin both forms (#280).

- TypeScript: `verifyBundle(bundle, { strict: true, requireSignature, witnessDirectory })` is
  the Python strict mode, and its result's `strict` member carries `verdict`, `claims`, per-record
  and per-receipt results (#280). It passes every case in `vectors/bundle/strict/`. It checks
  `cll` and `scrapi` receipts with a COSE Receipt verifier (tag-18 COSE_Sign1 with a detached
  payload, `vds` 1, EdDSA under an Ed25519 key or ES256 under a P-256 key, RFC 9162 inclusion)
  and `rekor` entries with WebCrypto, so the browser entries keep working. A Rekor key must be
  ECDSA P-256, and `integratedTime` and `logIndex` must be JSON integers. Every base64 field a
  receipt check reads is canonical padded base64, and a receipt check that cannot run is
  `withheld`, never `fail`; a key of the wrong type, including one WebCrypto cannot import, is
  `fail`. A directory `public_keys` entry counts only when it holds an Ed25519 key or an ECDSA
  P-256 key with its point on the curve, checked without WebCrypto. Without the Node-only CLL checkpoint verifier the `checkpoint` claim is `withheld`
  (`checkpoint_verifier_unavailable`); without Ed25519 strict mode throws
  `Ed25519UnavailableError` rather than return a verdict. The plain verifier is
  unchanged. `verifyRecordSignature` grades one record's producer signature (`jcs`, or `jcs-n`
  declared or implied). The new `@action-state-group/agent-action-capsule/witness` entry (also
  on the root entry) exports the receipt checks for reuse: `verifyCoseReceipt` (receipt, leaf
  bytes, public key), `verifyReceipt`, `verifyRekorReceipt`, `verifyScrapiReceipt`, and the
  directory and key helpers `witnessRowFor` and `witnessRowKeys`.

- Go: `bundle.VerifyStrict(value, StrictOptions{RequireSignature, WitnessDirectory})` is the
  strict `verify_bundle`, with `KindOK`, ordered `Claims`, `Records`, `Witnesses`,
  `WitnessReceipts`, `SignedCheckpoint`, `SignerMatchesCheckpoint` and `Verdict`; it passes every
  case in `vectors/bundle/strict/` (#280). `envelope.VerifyRecordSignature` grades one record's
  signature. The new package `witness` holds the witness directory (`ParseDirectory`, `RowFor`,
  `Row.Keys`), `BindingOf`, `EndpointOf`, `ParseSignedCheckpoint`, `CheckpointDigest`, a COSE
  Receipt check over any leaf (`VerifyCOSEReceipt`), the Rekor check (`VerifyRekorEntry`), the
  per-receipt `VerifyReceipt` and `VerifyReceipts`. The new package `settlement` holds `Verify`,
  which passes every case in `vectors/settlement/`. `VerifyBundle` is unchanged, and
  `veraison/go-cose` becomes a direct dependency.

- Rust: `agent-action-capsule` ports both (#280). With the new `strict` feature,
  `bundle::verify_bundle_strict(&bundle, &StrictOptions { require_signature, witness_directory })`
  returns a `StrictVerificationResult` with `verdict()`, the claims in report order, per-record
  and per-receipt results, and the plain `VerificationResult` unchanged as `base`; the `witness`
  module holds the `cll`, `rekor` and `scrapi` receipt checks, using `scitt-cose-receipt` for RFC
  9162 receipts and `p256` for Rekor's Signed Entry Timestamp. `envelope::verify_record_signature`
  grades one record's signature and `canonical::normalize` is the vintage `jcs-n` normalization.
  The new `settlement` feature adds `settlement::verify_settlements`, which compares amounts exactly
  as decimal digit strings. Every case in `vectors/bundle/strict/` and `vectors/settlement/`
  passes. `verify_bundle`, `verify_bundle_strict`, `verify_record_signature` and
  `verify_settlements` refuse a caller-built `Value` nested deeper than 128 levels (the decoder's
  limit) before any recursive work, so deep input cannot overflow the stack: the Bundle is
  `bundle_malformed` on every claim, the record `invalid`, the leg `capsule_invalid`.
- interop-profile-v0 vectors and reference verifier: a row 7 requirement with no content
  evaluator is reported `UNKNOWN`, sufficiency `UNKNOWN`, verdict `not_evaluable`, as §11.3.7
  requires, instead of three `null`s. The verifier does the same when no `content_evaluator` is
  supplied or it gives no result. The profile text is unchanged.
- interop-profile-v0 vectors: the corpus grows from 49 to 53 cases (§6.4). They are a
  requester-signed absence record, one signed over the refusal's signing input instead of the
  absence record's, and one each with `key_id` or `sig` alone. The MCP results and manifest
  result carry `resultType` `complete`, and the MCP calls carry `_meta`, as MCP 2026-07-28
  requires.

## 0.9.0 — 2026-10-16

- Python: `emit()` (`agent_action_capsule.emit.emit`, exported from the root as
  `agent_action_capsule.emit`) and the emit-tier adapters in `agent_action_capsule.integrations`
  (`LangChainCapsuleEmitter`, `CrewAICapsuleEmitter`, `emit_tool`, with the `langchain` and `crewai`
  extras) are deprecated (#281). Producing Capsules belongs to capsule-emit: use `capsule_emit.seal`
  in place of `emit()`, and capsule-emit's adapters
  (`capsule_emit.adapters.langchain.LangChainCapsuleEmitter`,
  `capsule_emit.adapters.crewai.CrewAICapsuleEmitter`, whose `wrap()` replaces `emit_tool`) in place
  of the integrations. Both keep working in this release: calling `emit()` raises a
  `DeprecationWarning` naming `capsule_emit.seal`, and importing the integrations or constructing an
  emitter raises one naming capsule-emit's adapters. They, and the `langchain` and `crewai` extras,
  are removed in the next minor release. The version constants (`DEFAULT_SPEC_VERSION`,
  `DEFAULT_FORMAT_VERSION`, `ACCEPTED_SPEC_VERSIONS`, `SPEC_VERSION`, `FORMAT_VERSION`) now live in
  `agent_action_capsule.versions`; the root exports and `agent_action_capsule.emit`'s re-exports
  keep working with no warning. `Capsule.seal()` stays this package's public sealing boundary, and
  `build_disclosure_envelope` stays, both unchanged. AAC's tests are now verifier-only: they seal
  test data with `Capsule.seal()`, and the emitter-behaviour tests move to capsule-emit.
- Python: `verify_bundle(bundle, strict=True, require_signature=..., witness_directory=...)`
  adds the checks capsule-emit ran on top of `verify_bundle`, so verification of Evidence Bundles
  lives in one place (#280). Strict mode checks each record's producer signature (vintage `jcs-n`
  records included), reads the checkpoint only from its signed COSE form, and refuses a plain
  VALID without one. It also reads producer-selected Bundles, reports the `disclosures` overlay as
  one claim, and checks witness receipts (`cll`, `rekor`, `scrapi`) in `checkpoint.witnesses`
  under a supplied witness directory, trusting none by default. The result carries `verdict`,
  `claims`, per-record results and per-receipt results. The plain verifier is unchanged.
  `producer_envelope.verify_record_signature` grades one record's signature, and
  `agent_action_capsule.witness` holds the receipt checks. `completeness.selection` and
  `checkpoint.witnesses` are not defined by the Bundle draft, so strict mode reads them as
  verifier extensions. New vectors: `vectors/bundle/strict/`.
- Python: `agent_action_capsule.settlement.verify_settlements` derives settlement states from
  both parties' leg records (`draft-mih-agent-settlement-records-00`), as capsule-emit did, and
  passes every case in `vectors/settlement/` (#280). Building and sealing legs stays with
  producers.
- CI: the Python job installs the released `checkpointed-local-log` (0.6) instead of a pinned
  commit, since strict mode needs its COSE checkpoint verifier.
- Python: `evidence_request.encode_cll_inclusion_proof(leaf, path)` and
  `encode_cll_consistency_proof(old_size, new_size, old_peaks, paths, new_peaks)` write the
  `cll-inclusion-proof` and `cll-consistency-proof` octets (`spec/interop-profile-v0.md` §6.2.1)
  for proofs a log has computed, as Go's `EncodeCLLInclusionProof` / `EncodeCLLConsistencyProof`
  and Rust's `encode_inclusion_proof` / `encode_consistency_proof` do. A Python responder serving a
  Checkpointed Local Log can now send the material `check_cll_material` reads. The consistency
  encoder computes the right peaks itself and refuses paths that do not reach the new peaks, as
  Rust's does. New corpus `vectors/cll-material/` (184 cases, including the §10.1 worked example's
  two proofs) gives each encoder's inputs and the exact octets; Python, Go and Rust check their
  encoders against it.

## 0.8.1 — 2026-10-15

- Python: `agent_action_capsule.evidence_request.sign_envelope` builds and signs the artifact
  response in the interop profile's form (`spec/interop-profile-v0.md` §6.2, `PROFILE =
  "evidence-interop/0"`): `Envelope.signing_body()` is JCS over the signed members, and
  `Envelope.encode("json" | "cbor")` writes the reply, byte strings as unpadded base64url in JSON
  and as CBOR byte strings in core deterministic CBOR (a new encoder beside the profile's CBOR
  decoder). -00 fixes no envelope members (§4.1), so until now a Python responder had no artifact
  response to send. Tests compare it byte for byte with the generator of
  `vectors/interop-profile-v0/`, and `scripts/evidence-request-interlock.sh` gains a step where
  Python and Go build identical envelopes in both bindings and Go verifies Python's (#271). Rust
  joined that step when `evidence-request` 0.2.0 adopted the profile's envelope (#273, #270).
  `sign_envelope` refuses, before signing, any envelope the profile does not allow: a subject or
  derivation no request could carry, an empty artifact, or an `issued_at` or time `freshness`
  outside the §5.2 form.
- Python: a requester can now read and verify the interop profile's artifact envelope (#272).
  `evidence_request.parse_reply(octets, binding)` reads a reply, an `Envelope` or a `Refusal`,
  in either binding, as the inverse of `Envelope.encode`. `Envelope.verify()` checks the strict
  Ed25519 signature by `responder`, the artifact digest and each verification item's digest;
  `Envelope.verify_for(request_bytes, responder)` also binds the profile, the pinned responder key
  and the request as sent. `check_cll_material(envelope, trust)` reports `anchor_inclusion` for
  the Checkpointed Local Log material (§6.2.1, steps 1 to 14), and `verify_cll_inclusion` and
  `verify_cll_consistency` check one proof against given peaks, as Go's `VerifyCLLInclusion` and
  `VerifyCLLConsistency` do. They reuse the profile verifier's MMR-02 code, so they need no
  `checkpointed-local-log`. Every envelope reply in `vectors/interop-profile-v0/` gets the
  statuses the corpus states. Like Go and Rust, `parse_reply` refuses a present but empty
  `verification`. The shared MMR path check now refuses a path that climbs past height 52, so a
  long proof no longer raises `OverflowError` here or in the profile reference verifier. In
  `scripts/evidence-request-interlock.sh`, Python, Go and Rust each verify all three languages'
  envelopes, and a new step checks the worked example's CLL material: Python, Go and Rust each
  sign it in an envelope, byte-identical, and each accepts every producer's, rejects a signed
  envelope whose inclusion or consistency proof is altered in a path node for that proof, and
  rejects material altered after signing for its digest. Rust uses `evidence-request`'s
  `check_anchor_inclusion` (feature `cll`); Go's adapter is given the checkpoint's peaks (#278).
- Evidence Layer (`draft-mih-agent-evidence-layer-00`): a padding record carries its random value
  in the member `store_nonce`, 32 bytes as 64 lowercase hex, as evidencebook and capsule-cli
  already write it. `vectors/evidence-layer/padding/` adds conformance cases for the record, and
  their generator runs in the full regeneration check. No library code changes (#277).
- Go: `evidencerequest.ParseReply` refuses an envelope whose `verification` is present and empty.
  The signer would have covered the empty array, but `SigningBody` omits it, so such an envelope
  verified under a signature over different members (#273).
- Python: the interop profile's time check no longer accepts seconds above 60
  (`2026-10-15T00:00:99Z`); it used to clamp them to 59.

## 0.8.0 — 2026-10-15

- Evidence Request (`draft-mih-agent-evidence-request-00`): every implementation now lives in
  this repository next to the draft and its vectors, and passes `vectors/evidence-request/`
  (124 cases) (#262).
  - Python: `agent_action_capsule.evidence_request` implements -00: the six subject forms,
    `coverage` with exactly one of `expected_pin` or `min_freshness` (a malformed member is
    `request_malformed` before the both-or-neither check, A4), exact resolution only, the eight
    registered refusal reasons, the request digest over the bytes as received in the JSON and
    core-deterministic CBOR bindings, and signed refusals. The responder `answer()` runs over
    a caller's `EvidenceStore`. This replaces the pre-00 responder moved from capsule-emit in
    #244 (its `chain_segment` subject and `subject.kind` shape are gone); that module was never
    released. The module and its tests are Apache-2.0 (SPDX header on each file); the package
    declares `BSD-3-Clause AND Apache-2.0` and ships both licence files (#244, #266).
  - Rust: the crate `evidence-request` 0.1.0 (lib `evidence_request`), moved here with its
    history from capsule-emit, where it was `capsule-emit-evidence-request` through 0.0.4. The
    default `answer` feature adds the artifact answer path and witness receipts over
    checkpointed-local-log; without it the crate is the protocol core with no
    checkpointed-local-log dependency (#264, #265).
  - Go: the package `go/evidencerequest`, the protocol logic extracted from evidencebook
    (request parsing and validation, encodings and digests, resolution rules, reply parsing,
    refusal signing and verification) (#267).
  - `scripts/evidence-request-interlock.sh`, run in CI: Python, Go and Rust classify every
    request vector identically, sign byte-identical refusals and verify each other's (#268).
  - `LICENSING.md` section 3 lists the Apache-2.0 paths.
- Registry conformance, a producer-side check: `agent_action_capsule.registry_conformance`
  (also `python -m agent_action_capsule.registry_conformance FILE...`, exit 1 on a
  non-conformant value) and Go `registries.LoadAxes` / `CheckCapsule`. It classifies every
  registry-governed Capsule field as `registered`, `legacy_alias` (§6), `cross_axis` (registered
  on a different registry), `private` (`x-` domain) or `unregistered`, with the sets parsed from
  `spec/REGISTRY.md`. It is not verification: `verify()` still never rejects an unregistered
  value. No registered set changes. Vectors: `vectors/registry-conformance/` (26 sealed
  Capsules).
- Spec: `spec/personal-agent-history-profile-v0.md`, the Personal-Agent History Profile v0, an
  Informational host profile written against `spec/interop-profile-v0.md` and changing neither it
  nor any draft. It defines the Basic level: a holder's selection of their own deals for one
  recipient, as an IP §6.5 recipient-specific derivation (`personal_history_basic/1`, identified
  by its definition digest). It fixes:
  - the definition document's members, including the signed selection, the recipient and the
    declared field set;
  - two record kinds (`step_completed`, `step_failed`) and nothing else per record beyond its
    times;
  - the artifact form of each deal's answer;
  - one holder key and one anchor per History;
  - seven History properties in IP's status vocabulary, and the acceptance rule
    (`anchor_inclusion` is `NOT_CHECKED` for a derivation in IP v0, so the §8 mapping gives
    `not_evaluable`);
  - deals and records as separate units, with outcomes stated as not established;
  - lifecycle statements by their own `exchange` request, and a one-file History container.
- Vectors: `vectors/interop-profile-v0/` holds 49 conformance cases for
  `spec/interop-profile-v0.md`, generated deterministically by
  `python/scripts/generate_interop_profile_v0_vectors.py`. The cases cover:
  - the §10.1 exchange and caller invariance;
  - tampered, misbound, forged, declined, missing and unsupported-version responses, and each
    required envelope property failing on its own;
  - a carried foreign object failing its native check;
  - the backdated acceptance (§11.1.9 A to G);
  - the non-issuer supersession (§11.2.7 A to I);
  - carriage over the native stream, A2A and MCP (§11.4.8).

  Each case pins its trust policy (test keys only), verification policy, contract version and
  evaluation time. `python/tests/test_interop_profile_v0_vectors.py` derives every status from
  the inputs with code separate from the generator. It also asserts that no case yields `met` or
  `not_met` unless sufficiency is `SATISFIED`. §11.5 now points to the corpus, and open points
  P-54 to P-57 are added.
- Python: `agent_action_capsule.interop_profile` is a reference verifier for
  `spec/interop-profile-v0.md`. Its input is the requester's retained request octets, the
  replies, a trust policy, a verification policy, an evaluation time and the contract version.
  It reports:
  - every §7.2 property of each reply as `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` or
    `INCONCLUSIVE`, with the method used, including the §6.2.1 Checkpointed Local Log
    `anchor_inclusion` procedure;
  - `caller_invariance` across every envelope held, and `native_check` of a carried JWS;
  - the §8.1 row for each requirement evaluated, with the claim's `evidence[]` and `proofs[]`.
    It also gives the row's status, sufficiency and verdict, except under row 7. There the
    contract judges the Artifact's content, which the profile does not define, so the result
    comes from an evaluator the caller supplies, or is left empty as the vectors leave it;
  - the acceptance properties and finding (§11.1). Acceptance records are read as JSON. Cited
    authority is labelled `agent_origin_assertion` and is not otherwise checked;
  - the lifecycle properties and findings, with what a verifier shows (§11.2). Links in an
    Evidence Layer record header are not evaluated;
  - reply classification over A2A and MCP, and the manifest properties (§11.4).

  It does not raise on malformed or hostile input; it reports it. It works offline and reads no
  clock. Online checks are `NOT_CHECKED` unless the caller supplies
  a resolver. Trust is checked as of each object's own time or as of the evaluation time, never
  "now". It needs `cryptography` for Ed25519, and nothing from outside this repository.
  `python/tests/test_interop_profile_verifier.py` runs it on all 49 cases and matches every
  expected value. It also checks the §10, §10.1 and §11.4 worked examples and each step of
  §6.2.1.
- Cross-language parity hardening. Each change aligns the four verifiers on the stricter
  behaviour one of them already had, and new shared vectors pin it:
  - TypeScript: a JSON member named `__proto__` is kept as an ordinary member, so it stays
    inside `capsule_id` (it previously set the object's prototype and dropped out of the
    canonical form, letting its content change undetected). Disclosure names `constructor` and
    `__proto__` are ineligible fields rather than prototype lookups.
  - Evidence Bundle graph closure visits each record once and stops when no new record is
    reached, in Go, Python, Rust and TypeScript, so its work is bounded by the records supplied
    rather than by the declared `closure_depth`; a dangling target is reported once.
  - TypeScript `decodeFragment` keeps a non-integer number's spelling, so `"closure_depth": 2.0`
    fails as in Go, Python and Rust; it still keeps the last of a repeated name, like them.
  - Producer Envelope protected headers: Python and TypeScript require integer labels, each
    once, and an integer `alg`; TypeScript checks `alg`, content type and `kid` before the label
    count, as Go and Python do. The TypeScript verifier no longer depends on `cborg`.
  - Check 9 (`provenance_mode`) in TypeScript; `provenance_mode` and
    `self_reported_reasoning` must be objects and `domain`/`provenance` strings in Go, Rust and
    TypeScript, as in Python.
  - TypeScript Disclosure Envelopes without a `capsule` member fail instead of verifying the
    envelope itself; Python requires a lowercase-hex committed digest (DE-2).
  - Go `DecodeCapsuleJSON` and `bundle.DecodeFragment` reject invalid UTF-8 and unpaired
    surrogate escapes, and `DecodeCapsuleJSON` rejects trailing data. Python Bundle integers are
    bounded to ±(2^53 − 1). Go, Python and TypeScript refuse base64url with non-zero trailing
    bits, as Rust does. Go reports withheld disclosures in a fixed order.
  - Vectors (`python/scripts/generate_parity_hardening_vectors.py`): five `capsule/` cases, six
    `producer-envelope/` cases, two `disclosure-envelope/` cases and two `bundle/` closure-depth
    cases. Released cases are unchanged.
- TypeScript evidence graph: `provenanceMode` is read from the `provenance_mode` block's `mode`,
  not from a string-valued member.
- Rust: new crate `agent-action-capsule` (`rust/agent-action-capsule/`), the
  Rust reference verifier: canonicalization and `capsule_id`, Class 1
  verification with checks 1-9 and the store checks, the profile registries,
  Producer Envelopes, and Evidence Bundle v2 behind the `bundle` feature. It
  runs the capsule, provenance-mode, producer-envelope and bundle corpora, and
  the interlock now seals and verifies in Rust as well. It replaces the
  unpublished `aac-bundle` crate (`rust/bundle/`). Released from
  `crates/agent-action-capsule-v*` tags through Release · Prepare.
- Interlock: the injected canonicalization divergence is now checked per
  consumer. Each of Python, Go, TypeScript and Rust must reject it as a
  `capsule_id_mismatch`; previously the script stopped at Python's rejection.

## 0.7.1 — 2026-10-14

- Release: Python and TypeScript releases are now a merged version bump. Run
  **Release · Prepare** with the package and `patch`, `minor` or `major`; merging the
  pull request it links tags `python/v*` or `ts/v*` and publishes. TypeScript now
  publishes from a `ts/v*` tag through the `npm` environment instead of a manual run on
  `main`. See `RELEASING.md`.
- Release: Python releases are now tagged `python/v<version>`, matching the
  `go/v*`, `ts/v*` and `vectors/v*` tags of the other artifacts. The PyPI version
  is unchanged (`0.8.0`, not `python/0.8.0`). Releases up to 0.7.0 keep their bare
  `v<version>` tags.
- composed/v1 (`draft-mih-zhang-agent-disclosure-bundle-01`): an artifact member may carry
  `response`, the responder's signed response as received with the artifact bytes removed. A
  verifier requires its `request_digest` to equal the member's and its `artifact_digest` the
  member's digest (either mismatch fails the block). Its signature is checked under the
  deployment profile, as a refusal's is, and otherwise reported `signature_unverified`. It is
  outside the composed digest. Go: `Options.ResponseSignature` and
  `ComposedMemberResult.ResponseSignature`. TypeScript mirrors the check without a signature
  profile. Vectors: `artifact-response-bound` and `artifact-response-other-request`, and every
  composed/v1 case now states the block's expected `status`.
- Spec: `spec/interop-profile-v0.md`, the Minimum Evidence Interoperability Profile v0
  (`evidence-interop/0`). It is an Informational, pre-Internet-Draft profile that pins
  `draft-mih-agent-evidence-request-00` and its conformance vectors, the Disclosure Envelope
  digest rule, the settlement-records as-transmitted rule, and Evidence Result v0. It changes no
  draft. It fixes:
  - profile versions and unsupported-version behaviour;
  - one name table shared by the CBOR and JSON encodings;
  - canonical bytes, including the as-transmitted rule for foreign objects;
  - the signed response envelope that binds a request digest to the caller-invariant Artifact
    digest, responder and issuance time;
  - the refusal and absence-record shapes;
  - recipient-specific disclosures as definition-digest derivations with salted-digest
    commitments;
  - a five-value per-property verification status (`PASS`, `FAIL`, `NOT_PRESENT`,
    `NOT_CHECKED`, `INCONCLUSIVE`);
  - the mapping from outcome to status to Evidence Result;
  - the refusal registry as the only error codes, kept apart from transport errors.

  It includes a worked example with reproducible digests and Ed25519 signatures. The acceptance
  record, lifecycle links, Evidence Contract prose, carriage and vectors are placeholder
  headings for later revisions.
- Spec: `spec/interop-profile-v0.md` registers its first verification-material kinds:
  `cll-checkpoint`, `cll-inclusion-proof` and `cll-consistency-proof`, for a Checkpointed Local
  Log. They are pinned to the posted `draft-mih-scitt-checkpointed-local-log-01` and
  `draft-bryce-cose-receipts-mmr-profile-02`, each by the SHA-256 of its archive `.txt`. The new
  §6.2.1 gives their bytes and the step-by-step `anchor_inclusion` check. A `record` envelope can
  now reach `PASS` on every required property: §10.1 does so with real bytes, a computed
  seven-entry log, a signed checkpoint, and inclusion and consistency proofs. Open point P-13 is
  narrowed, and P-31 is added.

- Spec: `spec/interop-profile-v0.md` §11.1 now defines the acceptance record: one signed record
  type (`proposed`, then `accepted`, `declined` or `countered`) naming the contract version
  digest, a transaction reference and both parties, with an optional session scope. It also
  defines the proposer's signed acceptance receipt, and two normative forms of ordering evidence:
  a counterparty-signed receipt, and a transparency-service or witness receipt. Causal binding
  is informative. A verifier reports "accepted before action" only with one of those forms, and
  otherwise reports that the acceptance exists and execution cites it. An acknowledgment is a
  receipt, never an acceptance, and acceptance is never authority. The section adds the
  verification properties, five acceptance findings, and the backdated-acceptance case
  described as a future vector. It pins `draft-mih-agent-bilateral-attestation-02` and
  `draft-mih-agent-evidence-layer-00`.

- Spec: `spec/interop-profile-v0.md` §11.2 now defines lifecycle links. A correction or
  challenge is a new signed lifecycle statement naming the earlier record by digest, with one
  link of five tokens. `supersedes` and `rebuts` are the Evidence Layer's registered tokens, and
  contradiction is carried as `rebuts`. `amends`, `disputes` and `resolves` are the profile's own,
  proposed for registration in `draft-mih-agent-evidence-layer` -01, and are not edited into
  -00. Only the issuer of a record, the key that signed it, or a successor key that the trust
  policy names, may amend or supersede it. A non-issuer `supersedes` is reported
  `lifecycle_issuer` `FAIL` with the finding `lifecycle_not_issuer`, and changes nothing. Anyone
  may dispute or rebut, and neither changes the record. A `disputes` statement names a resolving
  process, and only that process's `resolves` statement, carrying the same process and an
  outcome, closes it. A `supersedes` link in an Evidence Layer record header follows the same
  issuer rule. A verifier always shows the historical claim beside the latest supported state,
  shows forks without choosing a branch, and shows every dispute and rebuttal. The section adds the verification properties, four
  lifecycle findings, and the non-issuer supersession described as a future vector.

- Spec: `spec/interop-profile-v0.md` §11.4 now carries the exchange over A2A and MCP as two
  more adapters of the same request, beside the native `evidence-request/1` stream. Every
  carriage moves the request and reply octets unchanged, so the same request octets give the
  same request digest and the same canonical Artifact on all three. A2A: an Agent Card extension
  whose URI is the draft's Datatracker URL, one `raw` part for the request, and one reply
  Artifact in a completed task. MCP: the tools `evidence_manifest` and `evidence_request`, with
  the octets in base64url and the reply in `structuredContent`. A2A task states, MCP errors and
  `TASK_STATE_REJECTED` are never refusals. The section fixes one manifest, served unchanged on
  every carriage and to every caller, and states what discovery must not reveal: no counts,
  sizes, evidence digests, activity times, parties or conduct summaries. It names a request on
  the `exchange` subject an "exchange inquiry", adds the discovery properties `manifest_form`
  and `manifest_consistency`, and describes the cross-carriage invariance case as a future
  vector. It pins A2A v1.0.1 and MCP 2026-07-28.

- Spec: `spec/interop-profile-v0.md` §11.3 now describes the Evidence Contract v0 schema, pinned
  by commit and file SHA-256. It covers every member and allowed value, with its type and
  presence: the root (`id`, `version`, `requirements` and four optional objects), the seven
  requirement profiles and the nine shapes they take, evidence requirements (accepted epistemic
  types, sources, independence, minimum assurance, freshness, coverage), and the native, abstract
  and stub members. It describes the schema and does not extend it. It also says how a contract
  feeds the profile: the acceptance record's `contract_digest` covers the whole contract object,
  `contract_ref` is built and compared and never split, each requirement gives one claim, and a
  requirement the verifier cannot apply is `UNKNOWN`. Requirement ids must be unique within a
  contract version. Open points P-46 to P-53 list what the schema does not say, among them
  whether evidence is needed before the action, which the schema has no member for.

- TypeScript: verification works without WebCrypto. `crypto.subtle` exists only in a secure
  context, so a report in a non-secure or opaque origin (some apps' attachment viewers, an http:
  or data: page) could not hash, and every digest, membership and range check failed on a valid
  bundle. `sha256Hex` now uses a plain
  SHA-256 (`src/sha256.ts`, FIPS 180-4 examples and node:crypto cross-checks in
  `test/sha256.test.ts`) when SubtleCrypto is absent, and `@action-state-group/cll` 0.2.1 does the
  same for MMR proofs: the built browser runtime, run with no `crypto` global, passes the same ten
  checks on a fixture as with WebCrypto (`test/no-webcrypto-iife.test.ts`). New:
  `digestCapability()` ("webcrypto" | "fallback" | "none"), `probeEd25519()` and
  `ed25519Available()`.
- TypeScript: a runtime with no SHA-256 at all (only reachable with the fallback switched off by
  `setSha256FallbackForTesting(false)`) is never reported as a failed verification:
  `verifyBundle` and `buildVerifiedBundleContext` throw `Sha256UnavailableError`, and
  `renderEvidenceGraph` draws the "unable to verify in this viewer" state
  (`renderUnableToVerify`, `data-verify="unable"`) with `options.verifyCommand` when given.
- TypeScript: without Ed25519 (no SubtleCrypto, or one that rejects Ed25519 as not supported), a
  countersign/v1 entry is stamped `{ kind: "unverified", reason: "no-ed25519" }`, "not checked in
  this viewer", instead of "invalid". The `unverified` stamp gains `reason` (`"type"` for a type
  this viewer does not implement, as before).
- TypeScript: without Ed25519 a record's Producer Envelope is not checked: its signer is a stated
  key_id with `keyNotChecked: true`, the ignored-link reasons say this viewer cannot check it, and
  a close claim's state is shown as asserted (`derivation: "producer-asserted"`) instead of being
  recomputed from links it cannot check. Before, the claim was failed for a state mismatch.
- Go: `go/presentation`, the presentation resolver of `spec/presentation-contract-v0.md` in Go
  (manifest parsing and the registry's structural rules, the section 4.2 descriptor over a bundle
  the Go verifier checked, the section 3.2 ABI refusal and its exact wording, the section 4.3
  match and tiers, the section 4.5 static ambiguity test, and the six built-in page manifests and
  the composition section manifest embedded byte for byte), so a Go command-line tool can list
  and resolve presentations without its own copy. New shared vectors,
  `vectors/presentation-resolution/` (the 1,536-case table, 53 registration and refusal cases,
  377 descriptor cases over real bundles), are generated by the TypeScript registry and run by
  both the TypeScript and the Go test suites.
- TypeScript: `VerifiedBundleContext` (`buildVerifiedBundleContext`) verifies a bundle once and is
  what every builder reads. `buildReportRows`, `buildResultRoot`, `isResultRoot`,
  `buildEvidenceGraph` and `renderEvidenceGraph` take a context (new overload; the `(bundle)`
  form still works and builds one); the 24 per-builder disclosure re-resolution sites are gone and
  a payload reaches a builder only when `verifyBundle` classified it `disclosure_match`.
  `renderEvidenceGraph` reads the countersigner list from the context when no third argument is
  passed. Rendered output is byte-identical for every fixture. Called directly, a builder no
  longer reads a record whose capsule_id does not recompute (it previously could).
- TypeScript: a `VerifiedBundleContext` is effectively immutable. It is built over the library's
  own copy of the bundle and its whole object graph (verification result, `resolvedDisclosures`,
  records and `recordIndex`, countersignatures and the countersigner list, extensions,
  completeness) is frozen; the two maps are read-only views. Code that tries to change any of it
  throws, and every later reader sees what the verifier produced. The caller's bundle and
  countersigner list are copied, not frozen. Payload objects a builder returns from the context
  are the frozen ones.
- `spec/presentation-contract-v0.md` + `schemas/presentation-manifest-v0.json`: the presentation
  contract (module interface, `aac.presentation-manifest/v0` manifests, resolution where an
  ambiguous match is a hard error, two trust classes, the chrome and text-binding rules,
  `sha256-jcs-nonce256`, `wording_sha256`, invariants, depth levels L0/L1/L2 mapped to the shell
  slots). The six built-in manifests express today's dispatch; `schemas/check_presentation_manifest_examples.py`
  proves no pair is ambiguous and that they resolve as today over 1,536 cases. Documents and
  schema only; no runtime change.
- Presentation contract amendments: a presentation ABI versioned on its own. Every manifest
  declares `presentation_api` (`aac.presentation-api/v0`) and `runtime_min`; `id` is the module
  id. A runtime refuses a module whose `presentation_api` it does not implement, or whose
  `runtime_min` it does not meet, and says so on the page in fixed words, never by a silent
  fallback. The verified bundle context MUST be effectively immutable. Invariant I4 now holds
  for every packaging target supported for a bundle, and an unsupported target MUST be reported.
  A module MUST NOT take wording or depth from a bundle-carried presentation setting. New
  negatives: a manifest with no `presentation_api`, a module with an unsupported one (refused at
  resolution), and a declarative module naming a hint as its wording source.

- TypeScript: `ExtensionResult.status` is `interpreted` (with an `interpreter` id) or
  `uninterpreted`; only a block a viewer module actually reads is `interpreted`
  (`presentation/v1`, `producer-key/v1`, `outcome-report/v1`, `eu-ai-act-compliance/v1`,
  `evidencebook/payloads`, `capsulectl/agent-input-originals/v1`; `composed/v1` and unknown kinds
  stay uninterpreted). `integrityCovered` is now false when the bundle digest is uncomputable. The
  verification page renders one row per extension (id, integrity, semantics); an uninterpreted
  block reads "Integrity verified; meaning not interpreted by this viewer". No verdict changes.
- TypeScript: the presentation registry (`spec/presentation-contract-v0.md`).
  `renderEvidenceGraph` picks its page shape with `resolve(context, audience, format)` instead of
  an if-chain; the five page shapes and the no-aggregate note are six built-in modules whose
  manifests (`BUILTIN_MANIFESTS`) state the old precedence with `forbids`. `PresentationRegistry`,
  `createPresentationRegistry`, `registerPresentation`, `resolvePresentation` and
  `describeContext` are new. Registration refuses two same-tier manifests one descriptor could
  match; a tie is an error, never first-wins. Rendered output is byte-identical for every fixture.
- TypeScript and Go: one presentation builder (`spec/presentation-builder-v0.md`).
  `buildPresentation(context, {presentation, audience, format})` scopes the bundle for the
  audience, resolves the module through the registry, and packages the result as an offline
  `.html` file with its per-page CSP, a fragment permalink (`aac.presentation-fragment/v0`, the
  Evidence Bundle permalink codec, refused over 1,046,528 characters, never truncated) or a
  mount for a host element. `offlineHtmlFromFragment` (Go: `OfflineHTMLFromFragment`) rebuilds
  the exact offline file from a fragment; `BuildOfflineHTML` is the Go twin of the offline
  packaging. With the default settings the builder writes exactly the page the emitter writes.
  `renderEvidenceGraph` takes optional `depth` and `wording` options.
- TypeScript: the builder reports packaging availability and gains a static target.
  `availablePackagings(context, settings)` returns, for `html`, `fragment`, `embedded` and
  `static`, available or unavailable with a reason (`fragment-too-large` with the length and the
  limit, `runtime-missing`, `no-document`, `static-carries-script`), and returns no packaging.
  Fragments are packaged within a default budget of 65,536 characters
  (`FRAGMENT_TOKEN_DEFAULT_BUDGET`; `maxFragmentLength` lowers it or raises it up to the
  1,046,528 ceiling), so a monthly report of a few hundred kilobytes is reported unavailable as a
  link; a direct build still throws `FragmentTooLargeError`. `format: "static"` renders the page
  at build time into HTML with no script (`script-src 'none'`), no bundle and no runtime, stating
  "Not self-verifying; verify the bundle separately." and the verification result computed at
  build time. The default offline output is unchanged byte for byte.
- TypeScript: the presentation registry applies the presentation ABI. A `PresentationRegistry`
  takes the runtime's declaration (`REFERENCE_PRESENTATION_RUNTIME`: `aac.presentation-api/v0`,
  runtime 0.1.0); every manifest, the six built-ins included, carries `presentation_api` and
  `runtime_min`. A manifest missing either is malformed and throws at registration. A module whose
  `presentation_api` the runtime does not implement, or whose `runtime_min` it does not meet, is
  registered as refused (`register` returns the outcome; `refused()` lists them): never selected,
  none of its methods called, still counted for ambiguity, and every resolution it matches
  carries it in `refused`. `renderEvidenceGraph` names refused modules in
  `data-presentation-refused` on the page root; `presentationRefusalRow` and
  `presentationRefusalLine` give the contract's exact words for the verification page. Rendered
  output is byte-identical for every fixture.
- TypeScript: `composed/v1` is verified and shown. `verifyBundle` verifies the block as the Go
  reference does (`verifyComposed`, `composedDigest`, `composedDigestPreimage`; member bundles
  recursively) and reports it on the extension result as `composed`; the results equal
  `capsulectl verify --bundle` for every published vector and five derived cases. A new built-in
  composition section (`aac.builtin.composed/v0`, requires `composed/v1`) renders, on a bundle that
  verified, the composed digest, members, observers, composition closure, each join's declared and
  derived state, and per agreeing pair "redundant, not corroborating" or corroborating on declared
  custody. It is resolved in a section registry (`BUILTIN_SECTIONS`, `createSectionRegistry`) and
  drawn after the page module, because as a page module it is ambiguous with the five specific
  built-ins and with any composition-aware page module. Its extension row then reads "interpreted by
  aac.builtin.composed/v0". No viewer verdict changes; pages without `composed/v1` are unchanged.
- TypeScript: the verification page draws presentation refusals (contract section 3.2). Each
  extension a refused module requires gets the `presentationRefusalRow` wording in its semantics
  cell, with `data-semantics="refused"`, `data-refused-module` and `data-refusal`; a refusal
  outranks "interpreted by". A refused module that requires no extension gets the
  `presentationRefusalLine` after the extension rows (`data-presentation-refused`,
  `data-refusal`). The section registry applies the same ABI: the composition section manifest
  declares `aac.presentation-api/v0` and runtime 0.1.0, `createSectionRegistry` takes an optional
  runtime, and a refused section is named on the page root and in its `composed/v1` row, never
  skipped silently. `extensionRows` and `buildVerificationPageModel` take the refusals; the model
  gains `presentationRefusals`. Pages with no refusal are unchanged.
- TypeScript: the builder refuses a module the page's runtime would refuse (presentation contract
  section 3.2). A module-slot script may be passed with its `manifest`
  (`PresentationModuleScript`); when the page's runtime would refuse that module, or when
  `presentation` names a module the registry holds as refused, `buildPresentation` writes no page
  and throws `PresentationModuleRefusedError`, naming the module's id, `presentation_api` and
  `runtime_min` and the runtime's declaration. The builder's core runtime type is renamed
  `CoreRuntimeScript` (it was `PresentationRuntime`, now the name of the runtime's ABI
  declaration). Default output is unchanged byte for byte.
- Presentation contract revision 1 (`spec/presentation-contract-v0.md`,
  `schemas/presentation-manifest-v0.json`):
  - A declarative field may name `member`: `agent_input` (the default) or `agent_output`, so a
    declarative module can show rows a record keeps in `agent_output`. `source` points into that
    member's verified payload; a member that is not `disclosed` makes `canRender` false. New
    fixtures: `example-declarative-outcome.json` (with its wording pack) and
    `neg-declarative-member.json`; the checker models the source rule, with a mutant.
  - `module.title` is reserved in `aac.wording-pack/v0`: the presentation's own name for list and
    choice UIs, distinct from `page.title` (the page's `<title>`, which the builder reads). Both
    reserved keys are documented in one table; both example packs carry them.
  - `canRender` returns `boolean | Promise<boolean>`, as the reference runtime already types it.
  - **Pending ratification:** a `buildModel` failure on a verified bundle rejects the render and
    draws nothing (the reference runtime's behaviour); only a `render` failure shows the refusal.
    The contract previously required the refusal for both.
  - Appendix C brought up to date: extension interpretation status is now reported (item 6);
    the section registry, the unimplemented services and declarative renderer, and the single
    depth element are recorded. Appendix A and the `TITLE_SLOT` row describe the code as it is.
### Emitter (Go and TypeScript)
- The HTML shell has named slots: `TITLE_SLOT`, `THEME_SLOT`, `BUNDLE_SLOT`, `CORE_RUNTIME_SLOT`,
  `MODULE_SLOT` (zero or more digest-pinned scripts) and `BOOTSTRAP_SLOT`, plus `CSP_SLOT` for the
  policy. Each slot must occur exactly once in the shell. New entry points take the optional
  fills: `EmitEvidenceGraphHTMLWithOptions` (Go) and the third `options` argument of
  `emitEvidenceGraphHtml` (TypeScript). A supplied title is HTML-escaped; with none, the title
  stays "Evidence Graph". A module's bytes must match its lowercase hex SHA-256 pin, and a
  core-runtime pin is checked when given.
- A module carries a list of stylesheet pins (`Module.StyleSHA256` in Go, `styleSha256` in
  TypeScript): the lowercase hex SHA-256 of each stylesheet it inserts at render time, as in the
  presentation contract's `style_sha256`. The emitter lists each, in base64 form, in `style-src`
  after the core runtime's, and refuses a malformed pin. Pages with no module stylesheets are
  unchanged.
- The presentation builder passes each module's stylesheet pins through to the emitter
  (`buildPresentation`, `offlineHtmlFromFragment`; Go `BuildOfflineHTML`,
  `OfflineHTMLFromFragment`). A module given with its manifest (`PresentationModuleScript.manifest`;
  Go: the new optional `Module.Manifest`) must declare the same stylesheets in
  `executable.style_sha256`, compared as a set; on a mismatch no page is written and
  `PresentationStylePinsError` (Go: `*StylePinsError`) names both lists. Default output is
  unchanged byte for byte.
- Every emitted page carries a Content-Security-Policy meta element: `default-src 'none'`,
  `script-src` and `style-src` as SHA-256 hashes of the inline elements actually written (plus the
  two stylesheets the reference runtime inserts at render time, listed in
  `go/emitter/runtime-style-hashes.txt`), `img-src data:`, `connect-src 'none'`,
  `base-uri 'none'`, `form-action 'none'`. A script whose hash is not listed does not run. The core
  runtime's entry is the base64 form of the same digest as its hex `.sha256` pin.
- The shell carries a base stylesheet: theme tokens as CSS variables, a typography baseline,
  page width, overflow containment (wide tables scroll inside their own box below 760px), focus
  and reduced-motion defaults, details/summary disclosure, a verification-banner class and print
  defaults. Every rule has zero specificity, so a presentation's own stylesheet wins. No report
  layout is in the shell. Rendered page content is unchanged.
- Inline content that would change where its element ends (`</script`, `</style`, `<!--`) or
  that the HTML parser rewrites before hashing (CR, NUL) is refused.
- Pages emitted by this version run only the scripts the emitter wrote. A consumer that edits
  the emitted HTML afterwards to add a script or style element must pass it through the new
  slots instead, or the browser will refuse it.

## 0.7.0 — 2026-10-07

**Headline: string-typed fields are type-checked in every verifier.** A list, an object or a
null where the profile requires a string now fails check 1 (`field_not_string`) in Python, Go,
TypeScript and Rust, and a malformed `references[].retention` declaration (§5.5.5) is rejected
(#147, #148, #149, #150). Records that 0.6.0 accepted with an informational finding, or silently,
are now refused. Capsule vector case files shipped in 0.6.0 / `go/v0.6.0` are byte-identical; the
new cases are added beside them. The Evidence Result and judge-record fixture vectors were
regenerated with the `EXAMPLE-ORG` placeholder and their positive files renamed (#158); a consumer
pinning those files by name or hash re-pins.

### Verifier (all four implementations)
- A non-string in a string-typed field fails check 1 (#147). The string-typed block members
  (`disposition.decision`, `verdict_class`; `effect.status`, `type`, `irreversibility_class`,
  `effect_attestation`; `chain.relation`; `assurance.effect_mode`, `attestation_mode`,
  `ledger_mode`, `cross_party_rung`) holding any other JSON type, null included, give
  `field_not_string` (error), in that order. A non-string `disposition.approver` gives
  `field_not_string`. Python's closed-set lookups take strings only, so a list or an object no
  longer raises and yields a single `verifier_internal_error`; a registry field holding a
  non-string is treated as any unseeded value (informational, never a rejection). Fixes #146.
- `provenance_mode.source_asserted_at`, `import_batch`, `imported_at` and
  `references[].retention.declarant`, `retained_until`, `not_retained_after` are type-checked
  the same way (#148).
- A malformed `references[].retention` (§5.5.5) is rejected in check 1 (#149): a retention that
  is not a JSON object (null included) is `field_not_object` and nothing else in it is checked; an
  absent or null `declarant` is `missing_required_field`; an empty retention is
  `retention_empty`.
- Vectors `neg-retention-null` and `neg-retention-declarant-missing-and-empty` pin the finding
  order; the generator now lets a case expect several findings (#150).

### Added
- Evidence Request vectors (`vectors/evidence-request/`) for
  `draft-mih-agent-evidence-request-00`, derived from the -00 text: the request map and its
  refusal reasons, the six subject forms, coverage, exact-match resolution, the request digest
  over the bytes as received (JSON and deterministic CBOR), signed refusals, the three outcomes
  and pending, caller invariance, and retention commitments. Open readings are listed as
  ambiguities in the README (#142). DIFFS items 1 and 2 are marked resolved (#170).
- Evidence Request vectors: three request cases for coverage that carries both members where a
  value does not conform (`neg-coverage-both-pin-malformed`, `neg-coverage-both-freshness-malformed`,
  `neg-coverage-both-both-malformed`), all refused `request_malformed`. Ambiguity note A4 is
  amended with the 2026-10-06 ruling: a responder checks each present member's value first, and
  only then refuses both-or-neither `coverage_unsatisfiable`. The normative sentence goes into
  `-01` §3.2; the posted `-00` files are unchanged. Existing vector bytes are unchanged (#189).
- Evidence Bundle `-01` working revision (`spec/draft-mih-zhang-agent-disclosure-bundle-01`;
  the posted `-00` files are unchanged). It defines the `countersign/v1` entry (signing input
  `UTF8(JCS({over, signer, statement, type}))`, five per-check results, self-countersignature
  rendered as not independent), the `producer-key/v1` extension kind, `composed/v1`, and
  provisional SD-JWT kinds (#167).
- `producer-key/v1` registered in `REGISTRY.md` §14 (with the Python and Go mirrors), and
  `countersign/v1` in §15. The block is `{"public_key": "<64 lowercase hex>"}`, digest-covered;
  a verifier uses it only to classify a countersignature by that key as not independent. A
  malformed block is ignored.
- TypeScript: `declaredProducerKeys(bundle)` and `PRODUCER_KEY_V1`, exported from the
  countersignature stamp; the evidence graph view now reads the declared key through it
  (unchanged behaviour).
- Vectors `vectors/bundle/producer-key/` (generator
  `python/scripts/generate_bundle_producer_key_vectors.py`): a declared self-countersignature
  is not independent; the same Bundle without the declaration, a different signer, and five
  malformed blocks are not. Consumed by Python and TypeScript tests. Existing vector files are
  unchanged; only the top-level `SHA256SUMS` and `manifest.json` gained entries.
- Go: `bundle.VerifyBundle` now interprets the `composed/v1` extension (bundle `-01` §7.2)
  instead of reporting it uninterpreted. `ExtensionResult.Composed` reports the recomputed
  composed digest, each member (outcome, body carried or declared missing, digest reproduced,
  and a carried member Bundle's own verification), composition closure
  (`pass`/`withheld`/`fail`), each join's declared and re-derived state
  (`pre_agreed_identifier`, `shared_artifact_digest`; the reserved bases are `not_derivable`),
  and per-join redundancy. `bundle.ComposedDigest` recomputes the digest from the block alone.
  Refusal signatures use a caller-supplied profile (`Options.RefusalSignature`) and are
  `signature_unverified` without one. Tested byte for byte against `vectors/bundle/composed/`.
  Python and TypeScript still report the block uninterpreted (#168).
- Evidence Result v0: optional claim `type` (`requirement` | `reconcile` | `close`; absent means
  `requirement`), with the `reconcile` and `close` bodies, fixtures and mutant checks. Existing
  fixtures validate unchanged (#140).
- TypeScript emitter: a sealed Result v0 as the bundle root (`buildResultRoot`). Headlines come
  from the root and drill-downs from the records it cites; a claim whose cited ids do not resolve
  renders `unsupported`, and a root that is not a Result v0 is an error (#141).
- TypeScript emitter: two Result v0 presentation profiles, the outcome-report card
  (`extensions["outcome-report/v1"]`, #160) and the EU AI Act obligations card (#164), each
  selected only after the verify-first gate. A claim citing a published capsule now resolves to
  the book record carrying it.
- `spec/draft-mih-agent-settlement-records-00` with `vectors/settlement/` (14 spec-derived cases;
  payer and payee legs, gross, fee and net per side, exact integer amount comparison), for
  review (#159).
- TypeScript package: isolated `./core` entry points and a manual npm trusted-publishing workflow
  (`publish-ts.yml`, `ts/v*` tags). The npm package is versioned on its own train; the PyPI
  release workflow ignores `ts/v*` releases (#184).

### Changed
- A null `references[].retention.declarant` is now reported as `missing_required_field` (check 1),
  as a null `disposition.approver` is: `declarant` is REQUIRED (§5.5.5). #148 had reported it as
  `field_not_string`; #149 changed the code in every verifier (Python, Go, TypeScript, Rust).
- `close/v1`: the peer-Close link moves off `citation_purpose` (`reconciles_with` was never
  registered) into an Evidence Layer `cites` link carried in `x-evidence-links`. A Close with
  `reconcile` carries exactly one `cites` link to the peer's Close for the same period. The old
  positive `pos-example-org-close.json` is frozen and now rejected; the new positive is
  `pos-example-org-close-linked.json` (#176).
- `REGISTRY.md` §6: the `chain.relation` tokens `resolves`, `escalates`, `adjudicates`, `assesses`
  are noted as read-only legacy aliases (never emitted; mapped to `supersedes` / `confirms`). The
  parsed table is unchanged (#178).
- Fixture placeholder org renamed to `EXAMPLE-ORG` across spec, schema descriptions, generators,
  checkers and vectors (#158); the fixture placeholder is called the counterparty placeholder
  (#154).

### Fixed
- Go `canonical.JCS` writes negative zero as `0`, as RFC 8785 and the Python and TypeScript
  serializers do; `-0` previously gave a different digest in Go (#188).
- TypeScript: a verified bundle whose root is not `report/v1`, a Result v0, or an
  `evaluation-summary/v1` renders with a plain-text note instead of throwing (#191).
- `vectors/disclosure-envelope/README.md` checksum refreshed in both `SHA256SUMS` files (#156).

### Spec
- Bilateral `-02`: retention decay of the bilateral property stated as a named mechanism property,
  with the three verifier states kept apart (#119). Bilateral `-03`: RFC 9943 terms, no
  "witnesses" role, "countersign" pinned (#151); the "anchor" verb replaced by SCITT registration
  terms (#174).
- Evidence Bundle `-01`: "anchored" becomes "bound" in Interval coverage (#173).
- Evidence Layer `-00`: freshness pass before first upload (references pinned to posted
  revisions, RFC 9942/9943 terms, Reconcile and Close states) (#175).
- Result v0: names the right enum for `NOT_APPLICABLE` and `UNKNOWN` (wording only, #181); Close
  rules stated without review-round attributions (#161).
- AAC `-05` draft artifacts regenerated for the October build date (#153); guide and Bundle author
  email refreshed (#183); rulings cited by date (#155); value sets and rules described directly
  (#145).

### CI
- Neutrality scanner: reads only regular files and does not follow symlinks; redacts terms on
  untrusted runs (#143); scans every tracked file (`git ls-files -z`) with pinned actions (#144);
  catches adoption claims about reference projects (#169); refuses a double-encoded
  `NEUTRALITY_TERMS` (#186).
- Leak lint reads its term list from the `LEAK_LINT_TERMS` secret and fails closed (#171).

## 0.6.0 — 2026-09-27

**Headline: the -05 wire.** Producers now emit `spec_version`
`draft-mih-scitt-agent-action-capsule-05`; verifiers accept both `-04` and `-05`. The -05
registrations are seeded (below). Released vectors are unchanged: every vector case file
shipped in 0.5.0 / `go/v0.5.x` is byte-identical, and the -05 cases are added beside them
(only the corpus indexes, `SHA256SUMS` manifests and READMEs gained entries).

### Changed
- TypeScript countersignature stamp (`ts/src/countersignature-stamp.ts`) now verifies
  `countersign/v1` entries: `over` must equal the recomputed bundle digest, and the Ed25519
  signature (128 hex, under the 64-hex `signer.key_id`) must cover
  `UTF8(JCS({over, signer, statement, type}))`, with `signer` and `statement` signed as they
  appear on the wire. A result or `signer.id` edited after signing makes the entry `invalid`, and
  its checks are not shown. An absent or empty `type` is verified as `countersign/v1`: the input
  binds `"countersign/v1"`, so a signature over `""` fails. `cose-sign1` and any other type the
  viewer does not implement render as `unverified`. Previously the stamp accepted only
  `cose-sign1` and classed a `countersign/v1` entry as `invalid`.
- Countersigners are named from a list the caller passes in (`CountersignerSource`: `{name,
  key_ids[]}` listings), or one loaded by `pinnedCountersignerSource` against a pinned SHA-256.
  They are never read from the witness directory: a `witnesses.json` document resolves no signer.
  A key listed under two names resolves to neither. The checks and results come from the signed
  statement and are listed per check as the signer's statement, never totalled. The old flat
  directory (`publicKey`/`name`/`logoDataUrl`/`checksRecomputed`) and the stamp logo are removed.
  A present receipt is shown as unverified; the viewer does not verify receipts.
- Stamp states: `hollow`, `unverified`, `invalid`, `not-independent`, `unresolved-signer`,
  `resolved`. **Breaking (TypeScript API):** `classifyCountersignatures(entries, digest,
  producerKeys[], countersigners)`. `renderEvidenceGraph`'s third argument is a
  `CountersignerSource`, and the emitted report shell passes none. `CountersignerDirectoryEntry`
  and `BUNDLE_DIGEST_CONTENT_TYPE` are removed.
- Tests consume capsule-anchor's shared `countersign/v1` golden vector, vendored byte for byte as
  `ts/test/testdata/countersign-v1-anchor-golden.json` with its SHA-256 pinned (`d057691c…155fb`).
  Its negatives fail as the vector says: flipped result, digest-only signature, spoofed
  `signer.id`, and signature without `signer` are invalid, and a receipt for a different
  statement leaves the entry valid with the receipt unverified.

### Fix: bundle completeness without the CLL reference is not an invalid certificate
- `verify_bundle` (Python) reported every well-formed `completeness_certificate` as
  `completeness_certificate_invalid` on interval coverage and per-record membership when
  the CLL reference (`cll`) was not installed. `pip install agent-action-capsule` never
  installs it, so the clean report bundles were rejected there while the TS and in-report
  verifiers passed them. A certificate that is structurally valid but cannot be checked
  now fails closed as `completeness_verifier_unavailable`: it never passes, and it is never
  called invalid. A certificate that is wrong on its face is still
  `completeness_certificate_invalid` with or without CLL. A missing COSE checkpoint
  authenticator now leaves the checkpoint `checkpoint_unverified` (as in TS), not
  `checkpoint_authentication_invalid`.
- New `bundle` extra: `pip install 'agent-action-capsule[bundle]'` adds
  `checkpointed-local-log>=0.4.0`. It is an extra, not a core dependency, because
  `checkpointed-local-log` depends on this package.
- Vectors: `vectors/bundle/report-single-record.json` holds literal single-record report
  bundles (the rendered-report shape): the positive, `neg-checkpoint-root-mismatch` and
  `neg-leaf-index-equals-seq`, with `expected_without_cll` for the Python reference
  without the extra. Python and TS test it. `vectors/bundle/SHA256SUMS` now covers it, and
  its stale `README.md` line is corrected.

### Wire: `spec_version` -05
- **A producer conforming to -05 emits `draft-mih-scitt-agent-action-capsule-05`; a
  verifier accepts `-04` and `-05`** (the revisions that define format 4).
  `spec_version` never selects an algorithm, and an unrecognized value is informational,
  never by itself a rejection. Python `DEFAULT_SPEC_VERSION` (and `SPEC_VERSION`) moves to
  -05; Python, Go and TypeScript export the current and accepted values
  (`ACCEPTED_SPEC_VERSIONS`, `verify.CurrentSpecVersion` / `verify.AcceptedSpecVersions`,
  `CURRENT_SPEC_VERSION` / `ACCEPTED_SPEC_VERSIONS`). No verifier branches on
  `spec_version`, so a format-4 Capsule carrying -04 verifies unchanged; each
  implementation tests a committed -04 vector and its -05 twin, and an unrecognized value.
- Registrations in -05: `chain.relation` `follows` (and `duplicates`, with
  `provenance_mode`); `citation_purpose` `ran_under` (#95), `corroborates_source_time`,
  `counterparty_half` and `counterparty_inclusion`; `effect.type` `inference_completion`;
  `effect_attestation` `host_served_observed`. Python check 8 (and Go, which reads the same
  `REGISTRY.md`) now reports `inference_completion` and `host_served_observed` as seeded
  values rather than unknown ones.
- Vectors: released vectors are unchanged. The capsule corpus keeps its -04 cases and adds
  five `pos-v05-*` cases (`python/scripts/generate_v05_vectors.py`); the provenance-mode
  corpus and the cross-language interlock fixture each gain `-v05` twins beside the
  released -04 files.
  The top-level `vectors/SHA256SUMS` also now lists the correct digests for three
  `interop/composition/` files whose bytes did not change; the 0.5.0 manifest had stale
  entries. Go's registry-vocabulary test fixture (`go/verify/testdata/vocabulary.json`) is
  regenerated for the new registrations; it is test data, not a conformance vector.
- TypeScript `registries.ts` now matches `spec/REGISTRY.md` (it was on the draft-04 seed
  sets) and is checked against it by a test.

### Spec
- `spec/draft-mih-agent-evidence-request-00.md` — new Internet-Draft, "An
  Interaction Model for Requesting Verifiable Evidence" (sole author Steven
  Mih), defining a transport-agnostic request/response interaction for
  verifiable evidence: a request naming a subject and a coverage anchor,
  resolving to exactly one of three outcomes — the evidence artifact, a
  signed refusal carrying a machine-readable reason (registry includes
  `derivation_unsupported`), or a recorded absence — with a distinct
  pending state for a request still inside its waiting window. Defines no
  evidence format, identity scheme, trust policy, or availability
  guarantee; requester identity, purpose, authorization, and disclosure
  policy are explicit non-goals.
- `spec/judge-record-family-v1.md` — added the Judge Record Family: eight companion JSON
  Schemas (`schemas/judge/*.json`) unifying two previously-divergent record families for the
  same two capsules (`evaluation-compiler` fixtures vs. `capsule-judge`'s
  `judge_judgment`/`judge_adjudication`) into one — `contract-compile/v1` (`producer_claim`),
  `evaluation-report/v1` (`semantic_judgment`; per-case `met`/`not_met`/`not_evaluable`),
  `close/v1` (`producer_claim`; period + counts + head + optional reconcile), `sample-manifest/v1`
  (`producer_claim`), `human-rating/v1` (`human_report`; `blind: true` fixed, rater as
  `principal_ref`, never a name), `calibration-summary/v1` (`derived_metric`; k-of-n per clause,
  never a rate), plus the mesh family (`adjudication/v1`, `adjudication-response/v1`) schema-ing
  capsule-emit-mesh's twin `adjudication`/`adjudication_delivery_receipt`/`ack`/`rebuttal` so
  `evaluation-report/v1` is the single-party case of the same adjudication shape rather than a
  parallel one. `epistemic_type` is fixed per schema and vendored from the Evidence Layer's closed
  set (`schemas/vendor/epistemic-types.json`), held in sync by a three-way parity check (schema
  `const`, python-side table, vendored set) with its own mutant check. §9 maps every old capsule-judge/capsule-emit-mesh
  field onto this family so the pin/drift port is mechanical.
- `spec/draft-mih-scitt-agent-action-capsule-05.md` — retention-undertaking declaration and
  cross-algorithm re-anchoring format (#118); corrected the selective-disclosure I-D reference
  and stale pins (#120); cites RFC 9942 in place of the superseded merkle-tree-proofs draft
  (#128). The evidence-bundle and disclosure-envelope drafts pin AAC -05 (#127).
- `spec/evidence-result-v0.md` + `schemas/evidence-result-v0.json` — Evidence Result schema
  v0, with examples and a checker (#114).

### Added
- Go: check 9 (`provenance_mode`) in `go/verify`, with seven more provenance-mode vectors
  (#113; first tagged as `go/v0.5.1`).
- Interop: TRACE digest-agreement fixture and test (#115; `rfc8785==0.1.4` added to the
  `dev` extra for the cross-check only), and `docs/interop/aac-trace-references.md` (#97).
- Emitter (Go `go/emitter`, TypeScript `ts/src/emitter.ts`): renders an Evidence Bundle as a
  self-contained HTML report — evidence-graph drill-down, verification page,
  `presentation/v1` header, countersignature stamp — byte-equal between Go and TypeScript.
- CI: fail-closed internal-leak lint (#121, #129).

### Fixed
- Python tests read capsule vectors as UTF-8 (#109).

## 0.5.0 — 2026-09-22

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-05.md` — added `provenance_mode`,
  a MODE on the ordinary Capsule (never a distinct record type; ruled
  2026-09-22) disambiguating a contemporaneous action record from a
  backfilled import of a historical one: `mode` (`contemporaneous` default |
  `backfilled`), and — REQUIRED when backfilled — `source_ref` (typed digest
  reference), `source_asserted_at`, `import_batch`, `imported_at`. Normative
  time semantics: `timestamp`/`source_asserted_at` are always producer
  self-attestations, never log-witnessed by virtue of being carried in the
  Capsule; a backfilled record's occurrence-time claim (`time_rung`:
  `self_attested` | `witnessed`) is capped at self-attested unless a
  `references[]` entry cites a signed/witnessed source timestamp under the
  new `corroborates_source_time` citation_purpose — and even then never
  upgrades `attestation_mode`/`ledger_mode`, which stay independently
  derived. Class 1 verification gains check 9: the required-field structural
  check, the `time_rung` overclaim (gating — unlike the informational
  overclaim treatment check 7 gives `attestation_mode`/`ledger_mode`/
  `cross_party_rung`), and the `imported_at == source_asserted_at`
  laundering-shape failure (a backfilled record must not be made to look
  contemporaneous by construction). Deliberately named `provenance_mode`,
  not `provenance` — REGISTRY.md §9's pre-existing `provenance` field (the
  `-02` gate/runtime/collector dedup-rank signal) is an unrelated
  vocabulary; the two names never collide. New `chain.relation: "duplicates"`
  (REGISTRY.md §6) lets a backfilled Capsule cite the contemporaneous
  Capsule of the same logical event in this producer's own stream; a
  `duplicates`-linked pair is counted once, the contemporaneous record
  governing — never fold history retroactively (an imported record is
  appended at import position, never spliced into the chain at the position
  its `source_asserted_at` implies).
  Authored by Steven Mih (draft author of record,
  `draft-mih-scitt-agent-action-capsule`).

### Added
- **`provenance_mode` (§5.3(bis) Provenance mode, draft -05).**
  `python/agent_action_capsule/contracts.py`: `ProvenanceMode` producer-side
  carrier (`mode`, `source_ref`, `source_asserted_at`, `import_batch`,
  `imported_at`, `time_rung`), enforcing the four-companion-fields-REQUIRED-
  when-backfilled invariant and the orphaned-fields-forbidden-when-
  contemporaneous invariant at construction; `PROVENANCE_MODES`,
  `TIME_RUNGS`, `TIME_RUNG_RANK`. `python/agent_action_capsule/parse.py`:
  `Capsule.provenance_mode` / `parse_capsule` round-trip the new block.
  `python/agent_action_capsule/emit.py`: `emit(provenance_mode=...)`.
  `python/agent_action_capsule/verify.py`: new check 9 — the
  required-field structural check, `provenance_mode_source_ref_malformed`,
  the `time_rung` overclaim (`provenance_time_rung_overclaim`, rederived
  from a well-formed `references[]` entry citing
  `citation_purpose: "corroborates_source_time"`, never from the claim),
  and `provenance_time_laundering_shape` (`imported_at == source_asserted_at`
  on a backfilled record) — all gating, unlike check 7's informational
  overclaim treatment of `attestation_mode`/`ledger_mode`/`cross_party_rung`.
  `derived.provenance_mode`/`derived.provenance_time_rung` are always
  reported in `VerificationResult.assurance` when the block is present.
  `verify_store()`: `chain.relation: "duplicates"` store-level handling —
  `duplicate_collapsed` (info) records the collapse, and
  `duplicate_parent_not_contemporaneous` (info) flags a `duplicates` parent
  that is itself backfilled. `spec/REGISTRY.md`: `duplicates` added to the
  `chain.relation` registry (§6), `corroborates_source_time` added to the
  `citation_purpose` registry (§11), new §12 `provenance_mode` documenting
  the closed two-value `mode` enum and `time_rung`'s scope
  (`python/agent_action_capsule/data/REGISTRY.md` resynced to match — it had
  also drifted on an unrelated section number, §5.4.4 vs §5.5.4, fixed as a
  side effect of the resync).
  `provenance-mode-vectors/`: a new frozen-vector corpus (one positive, three
  negative, one store-level) in the same discipline as
  `disclosure-envelope-vectors/` — kept OUT of `test-vectors/` because that
  corpus is cross-language-shared with the Go reference implementation,
  which has never implemented the `-02` `domain`/`provenance` addendum
  either; `provenance_mode` joins that same Python-only surface rather than
  breaking Go conformance on a feature it does not implement.
  `evaluation-compiler`'s `demo/backfill/backfill.py` (a downstream backfill
  tool that seals historical tau2-bench transcripts — exactly the
  `mode: "backfilled"` case) now threads `mode`/`source_asserted_at`/
  `import_batch`/`imported_at` into its existing opaque, already-digest-
  committed `payload.provenance` dict, using field names that match this
  profile's `provenance_mode` block 1:1 — not yet a first-class, wire-level
  Capsule field, since `capsule-emit-go`'s `emit.Input` has no
  `ProvenanceMode` member and `capsulectl`'s request decoder rejects unknown
  fields outright; promoting these to a real `capsule.ProvenanceMode` block
  (with a genuine `source_ref` digest) is a follow-up once that Go-side
  support lands.

## 0.4.0 — 2026-09-17

### Reference (breaking)
- **Format-4-only canonical reference.** The Python and Go reference verifiers and
  `capsule_id` computation now accept `format_version: "4"` only; any other value is
  rejected with `unsupported_format_version`, and the legacy absent-field ("vintage")
  construction has been removed rather than left unreachable. Records in the retired
  format-2 (vintage absent-field) construction remain verifiable with the frozen reference release
  **`legacy-verify/v0.1.0`** (commit `43b349dd6e8ee5f30dac3add9261b8f84e13ba7e`, the
  pre-format-4-only `main` tip), which the `pinned-legacy-format-2-verification`
  conformance job checks out to re-verify the cited July interop record. That tag is
  the single pinned legacy artifact; do not re-tag.

## 0.3.0 — 2026-09-08 (Python library)

### Python
- **draft-04 `references[]` — parity with the Go reference implementation.** The
  builder, `Capsule` model, parser, and serialization now carry `references[]`,
  preserving the tri-state **absent ≠ empty ≠ populated**. Reference validation
  mirrors `go/verify/references.go` 1:1 (entry structure; AAC/SHA-256 digest
  format; no duplicate chain-parent target; optional citation-purpose /
  log-coordinate checks). Foreign reference types / digest contexts remain open;
  unknown citation purposes are informational; coordinate checks do not verify
  inclusion proofs. Adds the `citation_purpose` registry (7th §12 registry) and
  validates against the 25 shared Go test vectors + producer-path unit tests.
  This is the version emit/CLL should pin as their AAC floor for `references[]`.

### Added
- **Python `references[]` parity with Go (draft-04 §5.5.5, {{xref}}).**
  `python/agent_action_capsule/contracts.py`: `ReferenceEntry` and
  `LogCoordinates` producer-side carriers. `python/agent_action_capsule/parse.py`:
  `Capsule.references` — a genuine tri-state (`None` omits the key; `()` emits
  `"references": []`; a populated tuple emits the entries), since absent and
  empty are the same claim but distinct bytes and therefore distinct
  `capsule_id` digests; the "MUST NOT duplicate `chain.parent_capsule_id`"
  boundary rule is enforced at `Capsule.__post_init__`.
  `python/agent_action_capsule/verify.py`: `references[]` findings (entry
  structure, the AAC/SHA-256 self-identity digest-format gate, the duplicate-
  chain-parent check, `citation_purpose` and `log_coordinates` checks) spliced
  into checks 1/6/8, mirroring `go/verify/references.go` finding-for-finding —
  foreign reference types/digest contexts stay open, unknown `citation_purpose`
  values are informational (never rejected), and `log_coordinates.inclusion_proof`
  is recorded as structural only, never independently verified.
  `python/agent_action_capsule/registries.py`: `citation_purpose` added as the
  seventh registry (§12), with the same missing-section fallback as the Go
  loader for an older `REGISTRY.md` snapshot. `python/agent_action_capsule/emit.py`:
  `emit(references=...)`. Validated against the 25 shared vectors in
  `go/verify/testdata/references.json` (`python/tests/test_references.py`),
  replaying the same store and check-order assertions as
  `go/verify/references_test.go`.

## 0.2.0 — 2026-08-28

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-03.md` §5.3 Assurance — added the
  cross-party assurance rung, a FOURTH, orthogonal `assurance` claim
  (`cross_party_rung`: `unilateral_fallback` < `acknowledged_receipt` <
  `full_bilateral`) plus its supporting `cross_party` evidence block
  (`initiator_ref`, `counterparty_ref`, `correlator`, `substantive`). Kept
  orthogonal to `attestation_mode` rather than folded into it (log custody and
  counterparty exchange evidence are independent facts a producer can hold in
  any combination); the draft states this reasoning inline. Same
  never-grades-up overclaim discipline as `attestation_mode` / `ledger_mode`.
- `spec/draft-mih-scitt-agent-action-capsule-03.md` §5.4 Disposition —
  extended the CLOSED `disposition.approver` enum from `{human, policy}` to
  `{human, policy, counterparty}`. Stays closed (not registry-governed); the
  pre-existing honesty invariant (`human_disposed: true` REQUIRES
  `approver: "human"`) is unaffected.

### Compat
- **Migration path (never-grades-up):** an old verifier that does not
  recognize `cross_party_rung` or the `cross_party` block simply does not see
  them — it verifies the record on the three axes it already knows and never
  errors on the unrecognized field/block, matching how it already tolerates
  any other unrecognized value. A verifier that DOES recognize the field but
  is handed a `cross_party_rung` value outside what it can independently
  derive ranks the claim below what it knows: a `full_bilateral` or
  `acknowledged_receipt` claim it cannot corroborate is treated no stronger
  than `unilateral_fallback` (the same floor an unrecognized `attestation_mode`
  value is already held to, §5.3) — nothing breaks, and no record is silently
  over-trusted.
- An old verifier encountering `disposition.approver: "counterparty"` before
  this revision would reject the Capsule outright (closed two-member enum);
  this revision is additive, not a relaxation — the enum grows from two
  members to three, still closed, so no third-party value is newly admitted.

### Docs
- `docs/telemetry-binding-profile.md`: new informational profile (AARM R8,
  `capsule-ledger`'s `ldg-otel-exporter-aarm-r8`) specifying the
  reference-never-copy rule for telemetry export, the minimum attribute set,
  and the mapping to OTLP/`gen_ai` (primary) and OCSF (secondary,
  best-effort — documents the mismatch rather than presenting a native fit).
  Not core spec: telemetry is a projection of the capsule, and this profile
  moves at OTel/OCSF's release speed so core doesn't have to.

### Added
- `python/agent_action_capsule/contracts.py`: `CrossParty` producer-side
  carrier (§5.3 Cross-party assurance evidence), `CROSS_PARTY_RUNGS`,
  `CROSS_PARTY_RUNG_RANK`; `AssuranceBlock.cross_party_rung` (OPTIONAL);
  `VALID_APPROVERS` extended to include `"counterparty"`.
- `python/agent_action_capsule/verify.py`: check 7 (`assurance_overclaim`)
  extended to `cross_party_rung` — a claimed rung above what the verifier
  independently rederives from the `cross_party` block is flagged and the
  reported `derived.cross_party_rung` is downgraded to the value the evidence
  supports.
- `python/agent_action_capsule/parse.py`: `Capsule.cross_party` /
  `parse_capsule` round-trip the new block and `assurance.cross_party_rung`.
- `vectors/capsule/`: four new conformance vectors — one per cross-party rung
  (`pos-cross-party-full-bilateral`, `pos-cross-party-acknowledged-receipt`,
  `pos-cross-party-unilateral-fallback`), and the named overclaim case
  (`neg-cross-party-overclaim`: `full_bilateral` claimed with only the
  initiator's half present) plus `pos-disposition-approver-counterparty`
  confirming the honesty invariant holds against the new approver value.

### Fixed
- Packaging: `python/pyproject.toml` now declares `license-files = ["LICENSE"]` (PEP 639) so the
  BSD-3-Clause `LICENSE` text ships inside both the wheel (`*.dist-info/licenses/LICENSE`) and the
  sdist, not just the `License-Expression` METADATA field. `python/LICENSE` is a symlink to the
  repo-root `LICENSE` (single source of truth; root `LICENSE` text unchanged). Bumped the
  `setuptools` build requirement to `>=77.0.3` (the floor with stable PEP 639 `license-files`
  support) and dropped the now-superseded `License :: OSI Approved :: BSD License` classifier.
- API: the top-level convenience function `anchor()` shadowed the `agent_action_capsule.anchor`
  submodule on attribute access (`import agent_action_capsule.anchor as x` bound the function, not
  the module, under Python's attribute-wins semantics). Renamed the canonical export to
  `anchor_capsule()`; `anchor()` remains available as a deprecated alias (emits
  `DeprecationWarning`, delegates to `anchor_capsule()`) for this release and will be removed in a
  future one, at which point the submodule shadow is fully resolved.

## 0.1.0 — 2026-07-06

### Added
- `history` module: `list_capsules`, `verify_chain_completeness`, `export_verifiable_bundle`, `ChainReport` — ledger-grade capsule history API
- `selective_disclosure` module: salted per-field SHA-256 commitments, `commit_fields`, `disclose_subset`, `verify_disclosure`
- `bilateral` module: four-move bilateral attestation handshake (`BilateralHandshake`), `seal_request/action/bilateral`, `BilateralState`
- `verify_pair` module: bilateral capsule pair verification

### Changed
- Registry: seeded `"confirms"` in `chain.relation` allowed values

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-02.*` — compiled -02 spec artifact
