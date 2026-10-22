# Minimum Evidence Interoperability Profile v0: requirement facts

These vectors exercise the facts `spec/interop-profile-v0.md` §8.3 copies from a requirement into
its claim. They are a second set beside `vectors/interop-profile-v0/`, with their own contract,
pins and exchanges, so that set's contract and its `contract_digest` references stay unchanged.

## Derivation

`python/scripts/generate_interop_profile_v0_vectors.py --set requirement-facts` writes every file
except this README, with the same builders, test keys and log as the main set. Every expected value
is written by hand from the profile text. `python/tests/test_interop_profile_v0_vectors.py`
regenerates the directory and requires it to be byte-identical to the committed files. The Go
verifier (`go/evidencerequest/interop_verify_vectors_test.go`) and the Python reference verifier
(`python/tests/test_interop_profile_verifier.py`) each reproduce every expected block.

## Contract

`contract.document` has three native requirements, so it validates against the Evidence Contract
v0 schema the profile pins as EC (SHA-256 `contract.schema.sha256`):

| Requirement | Shape | `clause.effective_from` |
|---|---|---|
| `r-obligation-dated` | native obligation | 2027-08-02, after the evaluation time |
| `r-outcome-dated` | native outcome | 2026-01-01, before the evaluation time |
| `r-outcome` | native outcome | none |

Each case's `inputs.requirements` names the requirements it evaluates.

## Cases

| Case | What it shows |
|---|---|
| `facts-row-7` | A verified envelope, §8.1 row 7 with no content evaluator: each requirement is UNKNOWN, and each dated block carries `applies_from`, copied from its clause whether or not the date has passed |
| `facts-refusal` | A `no_such_subject` refusal: NOT_FOUND, GAP, with the same copied facts |

A block carries `applies_from` exactly when its requirement's clause states `effective_from`.
No block here carries `out_of_scope_allowed`: the EC schema the profile pins has no such member
yet. A switched-on native requirement, and an open stub carrying the same name (which grants
nothing), are added when the EC pin moves (capsule-engine#196).

**All keys are test keys.** Never use any of them for anything else.
