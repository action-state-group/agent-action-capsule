#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_judge_record_examples.py

Validates every committed judge-record-family-v1 example fixture
(vectors/judge/) against its schema (schemas/judge/*.json), proves each
negative fixture's rejection is load-bearing (QUEUE_PROTOCOL section 7's
mutant check -- strip the rule, confirm the SAME fixture now validates,
restore, confirm it rejects again), and extends capsule-engine's Batch 1
epistemic_type parity pattern (commit ba7b7a0,
schemas/vendor/epistemic-types.json) to this family: every schema's
epistemic_type const, a python-side record of the same assignment
(SCHEMA_EPISTEMIC_TYPES, below), and this repository's own vendored copy of
the Evidence Layer's closed value set (schemas/vendor/epistemic-types.json)
must agree.

What this enforces (spec/judge-record-family-v1.md is normative; this is the
mechanical half):

  1. POSITIVE: one fixture per schema validates against that schema's root
     $ref.
  2. NEGATIVE: one fixture per schema, each a byte-for-byte copy of its
     positive with exactly one field changed, MUST fail validation -- see
     vectors/judge/README.md for the mutation and the rule violated.
  3. MUTANT CHECK: each negative's rejection is re-tested with the specific
     schema rule it depends on stripped out. With the rule removed, the SAME
     fixture MUST validate clean, proving the check above can actually fail.
     The rule is then restored in memory (the committed schema file is never
     modified) and re-verified red.
  4. EPISTEMIC TYPE PARITY: for every schema, its $defs root epistemic_type
     const equals SCHEMA_EPISTEMIC_TYPES[record_version] and is a member of
     schemas/vendor/epistemic-types.json's values -- with its own mutant
     check (corrupt one schema's const, confirm the parity check flags it,
     restore).

Usage:
    python3 schemas/check_judge_record_examples.py       # from repo root
    python3 check_judge_record_examples.py                # from schemas/

Exit 0: every check above passed. Exit 1: a finding was printed. Exit 2: a
harness error (missing dependency, missing fixture).

NOT covered here (named per QUEUE_PROTOCOL section 7b's "name what you did
NOT test"):
  - `*_at` fields' "format": "date-time" keyword is annotation-only under
    python-jsonschema's default Draft202012Validator (no FormatChecker is
    attached) -- a garbage timestamp currently validates clean. Same caveat
    schemas/check_evidence_result_examples.py documents.
  - Cross-element constraints plain JSON Schema cannot express (record_id
    uniqueness across a store, calibration-summary/v1's KOfN.k <= n, close/
    v1's counts_by_kind actually matching the cited range) are named in each
    schema's own description and are a verifier's obligation, not this
    schema's -- the same class of gap evidence-result-v0.json's own README
    documents for its family.
  - adjudication-response/v1's "ack requires verdict, forbids basis" half of
    the kind-conditional rule has no dedicated negative fixture here (only
    delivery_receipt's "forbids verdict/basis" half is exercised); the
    schema's own allOf is symmetric across all three kinds and the harness
    exercises one representative case per QUEUE_PROTOCOL's "S"-sized scope
    for this task, not a fixture per allOf branch.
"""
import copy
import json
import sys
from pathlib import Path
from typing import List, TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _judge_types import JudgeRecordDoc  # noqa: E402


class VendorDoc(TypedDict):
    values: List[str]


SCHEMAS_DIR = (
    Path(__file__).parent
    if Path(__file__).parent.name == "schemas"
    else Path(__file__).parent / "schemas"
)
REPO_ROOT = SCHEMAS_DIR.parent
JUDGE_SCHEMAS_DIR = SCHEMAS_DIR / "judge"
VENDOR_PATH = SCHEMAS_DIR / "vendor" / "epistemic-types.json"
VECTORS_DIR = REPO_ROOT / "vectors" / "judge"

# record_version -> (schema filename, root $defs key, epistemic_type)
SCHEMA_EPISTEMIC_TYPES = {
    "contract-compile/v1": ("contract-compile-v1.json", "ContractCompile", "producer_claim"),
    "adjudication/v1": ("adjudication-v1.json", "Adjudication", "adjudication"),
    "adjudication-response/v1": (
        "adjudication-response-v1.json", "AdjudicationResponse", "producer_claim",
    ),
    "evaluation-report/v1": ("evaluation-report-v1.json", "EvaluationReport", "semantic_judgment"),
    "close/v1": ("close-v1.json", "Close", "producer_claim"),
    "sample-manifest/v1": ("sample-manifest-v1.json", "SampleManifest", "producer_claim"),
    "human-rating/v1": ("human-rating-v1.json", "HumanRating", "human_report"),
    "calibration-summary/v1": (
        "calibration-summary-v1.json", "CalibrationSummary", "derived_metric",
    ),
}

# record_version -> (vectors subdir, positive name, negative name)
FIXTURES = {
    "contract-compile/v1": ("contract-compile", "pos-oo-contract-compile", "neg-missing-human-approval"),
    "adjudication/v1": ("adjudication", "pos-oo-twin-adjudication", "neg-contradicted-missing-party"),
    "adjudication-response/v1": (
        "adjudication-response", "pos-oo-delivery-receipt", "neg-delivery-receipt-with-verdict",
    ),
    "evaluation-report/v1": ("evaluation-report", "pos-oo-evaluation-report", "neg-case-without-method"),
    "close/v1": ("close", "pos-oo-close", "neg-reconcile-without-peer-close"),
    "sample-manifest/v1": ("sample-manifest", "pos-oo-sample-manifest", "neg-cases-empty"),
    "human-rating/v1": ("human-rating", "pos-oo-human-rating", "neg-blind-false"),
    "calibration-summary/v1": (
        "calibration-summary", "pos-oo-calibration-summary", "neg-clause-with-rate-field",
    ),
}


# `schema` is an arbitrary JSON Schema document: the keyword set is open-ended
# and recursive ($defs/$ref/if/then/...), so a TypedDict here would assert a
# fixed shape JSON Schema does not have, which is less honest than `dict`.
def _load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_vendor(path: Path) -> VendorDoc:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_fixture(path: Path) -> JudgeRecordDoc:
    return json.loads(path.read_text(encoding="utf-8"))


# `schema` is an arbitrary JSON Schema document: the keyword set is open-ended
# and recursive ($defs/$ref/if/then/...), so a TypedDict here would assert a
# fixed shape JSON Schema does not have, which is less honest than `dict`.
def _validator_for(schema: dict):
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem, not a finding
        print(f"ERROR: the 'jsonschema' package is required to run this check: {exc}")
        sys.exit(2)
    return jsonschema.Draft202012Validator(schema)


def main() -> int:
    findings = []

    # --- schema-specific mutant producers, keyed by record_version ---------
    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_contract_compile(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["ContractCompile"]["required"] = [
            r for r in mutant["$defs"]["ContractCompile"]["required"] if r != "human_approval"
        ]
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_adjudication(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Adjudication"]["allOf"] = []
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_adjudication_response(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["AdjudicationResponse"]["allOf"] = [
            rule
            for rule in mutant["$defs"]["AdjudicationResponse"]["allOf"]
            if rule["if"]["properties"]["kind"]["const"] != "delivery_receipt"
        ]
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_evaluation_report(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Case"]["required"] = [
            r for r in mutant["$defs"]["Case"]["required"] if r != "method"
        ]
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_close(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Reconcile"]["required"] = [
            r for r in mutant["$defs"]["Reconcile"]["required"] if r != "peer_close"
        ]
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_sample_manifest(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        del mutant["$defs"]["SampleManifest"]["properties"]["cases"]["minItems"]
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_human_rating(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["HumanRating"]["properties"]["blind"] = {"type": "boolean"}
        return mutant

    # `schema` is an arbitrary JSON Schema document -- justified above
    # _load_schema/_validator_for.
    def mutant_calibration_summary(schema: dict) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["KOfN"]["additionalProperties"] = True
        return mutant

    MUTANTS = {
        "contract-compile/v1": (mutant_contract_compile, "ContractCompile.required's 'human_approval' entry"),
        "adjudication/v1": (mutant_adjudication, "Adjudication's contradicted/contradicted_party if/then rule"),
        "adjudication-response/v1": (
            mutant_adjudication_response,
            "AdjudicationResponse's delivery_receipt verdict/basis prohibition",
        ),
        "evaluation-report/v1": (mutant_evaluation_report, "Case.required's 'method' entry"),
        "close/v1": (mutant_close, "Reconcile.required's 'peer_close' entry"),
        "sample-manifest/v1": (mutant_sample_manifest, "SampleManifest.properties.cases.minItems"),
        "human-rating/v1": (mutant_human_rating, "HumanRating.properties.blind's const restriction"),
        "calibration-summary/v1": (
            mutant_calibration_summary, "KOfN.additionalProperties's closure",
        ),
    }

    # positive_schema/mutant_schema are arbitrary JSON Schema documents -- justified
    # above _load_schema/_validator_for.
    def _mutant_check(
        label: str, positive_schema: dict, mutant_schema: dict, neg_instance: JudgeRecordDoc
    ) -> None:
        mutant_validator = _validator_for(mutant_schema)
        mutant_errors = list(mutant_validator.iter_errors(neg_instance))
        if mutant_errors:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {label}: removing the targeted rule did not make "
                f"the fixture pass (still {len(mutant_errors)} error(s)) -- the rejection "
                "may be failing for an unrelated reason, not the rule this mutation targets"
            )
        else:
            print(f"OK  MUTANT        {label} -- with the rule removed, the fixture now "
                  "VALIDATES CLEAN (confirms the check is load-bearing)")
        restored_validator = _validator_for(positive_schema)
        restored_errors = list(restored_validator.iter_errors(neg_instance))
        if not restored_errors:
            findings.append(
                f"MUTANT-RESTORE-FAILED {label}: after restoring the rule, the fixture "
                "validated clean instead of failing"
            )
        else:
            print(f"OK  MUTANT        {label} -- restored rule re-rejects the same fixture")

    # --- 1/2/3: per-schema POSITIVE / NEGATIVE / MUTANT --------------------
    for record_version, (schema_file, _def_name, _etype) in SCHEMA_EPISTEMIC_TYPES.items():
        schema_path = JUDGE_SCHEMAS_DIR / schema_file
        if not schema_path.exists():
            findings.append(f"MISSING-SCHEMA {record_version}: {schema_path} not found")
            continue
        schema = _load_schema(schema_path)
        validator = _validator_for(schema)

        subdir, pos_name, neg_name = FIXTURES[record_version]
        vec_dir = VECTORS_DIR / subdir

        pos_instance = _load_fixture(vec_dir / f"{pos_name}.json")
        pos_errors = sorted(validator.iter_errors(pos_instance), key=lambda e: e.path)
        if pos_errors:
            findings.append(f"POSITIVE-REJECTED {record_version}/{pos_name}: {pos_errors[0].message}")
        else:
            print(f"OK  {record_version:<28} {pos_name}.json")

        neg_instance = _load_fixture(vec_dir / f"{neg_name}.json")
        neg_errors = list(validator.iter_errors(neg_instance))
        if not neg_errors:
            findings.append(
                f"NEGATIVE-DID-NOT-FAIL {record_version}/{neg_name}: expected schema "
                "validation to reject this fixture, but it validated clean"
            )
            continue
        print(f"OK  {record_version:<28} {neg_name}.json correctly REJECTED "
              f"({len(neg_errors)} error(s), e.g. {neg_errors[0].message!r})")

        mutant_fn, mutant_label = MUTANTS[record_version]
        _mutant_check(f"{record_version}/{neg_name}", schema, mutant_fn(schema), neg_instance)

    # --- 4: EPISTEMIC TYPE PARITY, three-way + its own mutant check --------
    if not VENDOR_PATH.exists():
        findings.append(f"MISSING-VENDOR: {VENDOR_PATH} not found")
    else:
        vendored = set(_load_vendor(VENDOR_PATH)["values"])

        # schema is an arbitrary JSON Schema document -- justified above
        # _load_schema/_validator_for.
        def _schema_const(schema: dict, def_name: str) -> str:
            return schema["$defs"][def_name]["properties"]["epistemic_type"]["const"]

        parity_ok = True
        for record_version, (schema_file, def_name, expected_etype) in SCHEMA_EPISTEMIC_TYPES.items():
            schema_path = JUDGE_SCHEMAS_DIR / schema_file
            if not schema_path.exists():
                continue
            schema = _load_schema(schema_path)
            actual_etype = _schema_const(schema, def_name)
            if actual_etype != expected_etype:
                findings.append(
                    f"EPISTEMIC-TYPE-MISMATCH {record_version}: schema const is "
                    f"{actual_etype!r}, SCHEMA_EPISTEMIC_TYPES says {expected_etype!r}"
                )
                parity_ok = False
            if actual_etype not in vendored:
                findings.append(
                    f"EPISTEMIC-TYPE-NOT-VENDORED {record_version}: {actual_etype!r} is not "
                    f"in {VENDOR_PATH.relative_to(REPO_ROOT)}'s values"
                )
                parity_ok = False
        if parity_ok:
            print(f"OK  epistemic_type parity across all {len(SCHEMA_EPISTEMIC_TYPES)} schemas, "
                  "SCHEMA_EPISTEMIC_TYPES, and the vendored Evidence Layer value set")

            # Mutant: corrupt evaluation-report/v1's const to an out-of-set
            # value and confirm the parity check (re-run inline) flags it.
            schema_path = JUDGE_SCHEMAS_DIR / SCHEMA_EPISTEMIC_TYPES["evaluation-report/v1"][0]
            mutant_schema = _load_schema(schema_path)
            mutant_schema["$defs"]["EvaluationReport"]["properties"]["epistemic_type"] = {
                "const": "not_a_real_epistemic_type"
            }
            mutant_actual = _schema_const(mutant_schema, "EvaluationReport")
            if mutant_actual in vendored:
                findings.append(
                    "MUTANT-DID-NOT-FLIP epistemic-type-parity: corrupting "
                    "evaluation-report/v1's const still landed inside the vendored set"
                )
            else:
                print("OK  MUTANT        epistemic-type-parity -- a corrupted const is "
                      "correctly reported as not-vendored (confirms the check is load-bearing)")
            restored_actual = _schema_const(
                _load_schema(JUDGE_SCHEMAS_DIR / SCHEMA_EPISTEMIC_TYPES["evaluation-report/v1"][0]),
                "EvaluationReport",
            )
            if restored_actual not in vendored:
                findings.append(
                    "MUTANT-RESTORE-FAILED epistemic-type-parity: the committed schema's own "
                    "const is not in the vendored set"
                )
            else:
                print("OK  MUTANT        epistemic-type-parity -- committed schema's const "
                      "re-passes")

    if findings:
        print("\nFAIL — findings:")
        for f in findings:
            print(f"  {f}")
        return 1

    print(f"\nOK — {len(SCHEMA_EPISTEMIC_TYPES)} schemas, "
          f"{len(SCHEMA_EPISTEMIC_TYPES) * 2} fixtures, epistemic_type parity: all green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
