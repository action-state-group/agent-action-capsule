# Minimum-necessary SD-JWT input vectors

**Provisional.** These vectors exercise four registry entries in
`spec/REGISTRY.md` that are proposed and held for ratification:

| Entry | REGISTRY.md section |
|---|---|
| `agent_input` presentation type `agent_input_version: "1"` (a list of SD-JWT presentations) | §10, Disclosure Envelope |
| Evidence Bundle extension kind `disclosure-policy-decisions/v1` | §14 |
| Evidence Bundle extension kind `sd-jwt-issuers/v1` | §14 |
| Evidence Request derivation `minimum_necessary_report/1` | §16 |

They use one worked example: three records for one office visit (a
professional claim, an encounter note and an eligibility record), sealed once
as SD-JWTs (RFC 9901), and two agents with different field policies. Policy
`P-1` (claims processing) reveals the member and billing fields and withholds
the clinical note. Policy `A-1` (audit) reveals the clinical note and the
billing fields and withholds the member's identity. Neither allow-list contains
the other. All values are illustrative and the organization is `EXAMPLE-ORG`.

## Derivation

`python/scripts/generate_min_necessary_vectors.py` writes every file except
this README. It uses only the standard library and `cryptography`: SD-JWT
issuance, the Producer Envelope, the two-leaf MMR and the COSE checkpoint are
built in the script and no repository implementation is run. Every salt, decoy
digest and Ed25519 seed is SHA-256 over a fixed label, so the output is a pure
function of the script. `python/tests/test_min_necessary_vectors.py`
regenerates the directory byte for byte, verifies every SD-JWT, checks every
Capsule with the base profile's Class 1 verifier, and checks every Bundle with
the Evidence Bundle verifier (including the MMR proofs and the COSE checkpoint
when the log reference is installed).

## Fixed choices

- SD-JWT: `alg` `EdDSA` (Ed25519, deterministic), `typ` `dc+sd-jwt`,
  `_sd_alg` `sha-256`, 128-bit salts, two decoy digests per record, `_sd`
  sorted. A Disclosure is base64url of the RFC 8785 serialization of
  `[salt, name, value]`. No Key Binding JWT.
- Clear fields are correlation handles only: `claim_id`, `note_id` and `vct`.
  `member_id` is low-entropy and identifying, so it is sealed.
- `icd10` and nested objects such as `charge` are sealed as one field each;
  per-element array disclosure is not exercised.
- A presentation is the issuer-signed JWT followed by the Disclosures the
  policy allows, each terminated by `~`. A policy that reveals nothing from a
  record still transmits that record's JWT (`<jwt>~`).
- The `agent_input` value is
  `{"agent_input_version": "1", "presentations": [claim, note, eligibility]}`,
  and `agent_input_digest` is its JSON-DIGEST.
- The constraint record is not registered. Its `id`, `check_type` and `method`
  carry the producer's reverse-DNS prefix (`org.example.`), because bare names
  are reserved for values the base profile seeds. A checker finds the record by
  `evidence_digest`, not by name.
- The log has two records (`seq` 1 and 2) in one MMR of size 3, and one
  checkpoint signed by the log key (`checkpoint.cose`). No SCITT Receipt is
  included in any vector.

## Cases

| Case | Input | Expected |
|---|---|---|
| `sdjwt-issue-claim`, `sdjwt-issue-note`, `sdjwt-issue-eligibility` | Record, salts, decoys, issuer key | The issuer-signed JWT, its `_sd` array, each Disclosure and its digest |
| `presentation-P1`, `presentation-A1` | Issuer-signed JWTs, policy decision | The presentations, the `agent_input` wrapper, its JSON-DIGEST, the SD-JWT check |
| `policy-decision-P1`, `policy-decision-A1` | The decision document | Its JSON-DIGEST, equal to the Capsule's constraint `evidence_digest` |
| `capsule-pricing`, `capsule-audit` | Capsule payload, input, output | `capsule_id`, canonical preimage, Producer Envelope (COSE_Sign1), Class 1 `ok` |
| `capsule-policy-fail` | A presentation with one Disclosure beyond the `P-1` allow-list | Constraint `result: fail`, `verdict_class: blocked`, no `agent_output_digest` |
| `log-two-records` | The two Capsule IDs | `seq` 1 and 2, MMR nodes, root, inclusion and range proofs, `checkpoint.cose` |
| `bundle-internal-audit` | Both Capsules, both decisions, `agent_input` and `agent_output` revealed | Every check passes; each Disclosure set equals its `revealed` list |
| `bundle-external-auditor` | The same, both members withheld | Closure, coverage, membership and the policy-decision digests pass; no record field value appears anywhere in the Bundle |
| `bundle-mismatch` | `agent_input` revealed with one Disclosure value altered | `disclosure_mismatch` on that Capsule only; its SD-JWT check is not evaluated |
| `bundle-not-registered` | The checkpoint carries no signature and is not registered with a Transparency Service | Interval coverage and membership qualified `checkpoint_unverified` |

The external-auditor Bundle withholds `agent_output` as well as `agent_input`:
the audit finding names the procedure code, which is a record value.

## Expected-result fields for Bundles

- `graph_closure`, `interval_coverage`, `per_record_membership`, `disclosures`:
  the Evidence Bundle checks (`spec/draft-mih-zhang-agent-disclosure-bundle-00.md`).
- `extensions`: the kinds present. A verifier that does not implement them
  reports them as uninterpreted and digest-covered.
- `policy_decisions`: per Capsule, the JSON-DIGEST of its
  `disclosure-policy-decisions/v1` entry, whether a constraint record in that
  Capsule carries it as `evidence_digest`, and that record's `result`.
- `sd_jwt_presentations`: per Capsule, the presentation-type check on a
  revealed `agent_input` that matched its digest: the issuer signature against
  the `sd-jwt-issuers/v1` JWK, each Disclosure's digest against `_sd`, and the
  disclosed names against the decision's `revealed` list for that `vct`.
  `not_evaluated` when `agent_input` is withheld or did not match its digest.

## Never-enters tier

No Capsule carries the member's identity, in clear or hashed. The test scans
every Capsule in this directory for `member_identifiers` (from `manifest.json`)
in clear and in each digest form a producer could plausibly write (SHA-256 of
the raw value or its JSON form, hex or base64url, and the SD-JWT Disclosure
and its digest for each identifying field) and fails on any match.

## Files

- `<case>/input.json`, `<case>/expected.json`: one directory per case.
- `manifest.json`: keys (seed, public key, JWK), fixed choices, the member
  identifiers, the case list, and the SHA-256 of every generated file.
- `SHA256SUMS`: SHA-256 of every file in this directory tree except itself.
