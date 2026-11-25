# Evidence Contract: one obligation shape

`spec/interop-profile-v2.md` §11.3.2 and P-71: under `evidence-interop/2` the
obligation profile of an Evidence Contract has one shape, the native,
pack-declared one, and EC pins `schemas/evidence-contract-v0.json`, which
drops the abstract obligation shape. `evidence-interop/0` and `/1` pin the
capsule-engine copy, under which both shapes are valid.

`cases.json` names the schema it is checked against by SHA-256 (`schema`).
Each case holds a whole contract (`document`) and whether it is valid against
that schema (`accept`).

| Case | Valid |
|---|---|
| `pos-obligation-native` | yes: a native obligation requirement, with `evidence_rule`, both verdicts and `clause` |
| `neg-obligation-abstract` | no: the same obligation cited only by `clause_ref`, the dropped abstract shape |
| `pos-outcome-abstract` | yes: an abstract outcome requirement; the outcome profile keeps both shapes |

`schemas/check_evidence_contract_examples.py` runs the cases. This set is
hand-written; it has no generator.
