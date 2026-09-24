#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_evidence_result_examples.py

Validates every committed Evidence Result v0 example fixture
(vectors/evidence-result/) against schemas/evidence-result-v0.json, and
proves each negative fixture's rejection is load-bearing rather than a check
that can never fire.

What this enforces (spec/evidence-result-v0.md is normative; this is the
mechanical half):

  1. POSITIVE: pos-oo-claims-result.json (three claims, one per verdict
     bucket) validates against $defs/EvidenceResult.
  2. NEGATIVE: five fixtures, each a byte-for-byte copy of the positive with
     exactly one field changed, MUST fail validation:
       - neg-untiered-claim.json: claim-1 missing `tier`.
       - neg-met-with-sufficiency-gap.json: claim-1 keeps verdict `met` with
         sufficiency changed to `GAP` (spec section 1's binding rule).
       - neg-aggregate-without-coverage.json: `aggregate.coverage` removed.
       - neg-contract-ref-missing.json: claim-1 missing `contract_ref`.
       - neg-disclosure-carrier-under-withheld.json: claim-3's presentation
         changed from `analysis` to `disclosure` while `status` stays
         `WITHHELD` (spec section 2's disclosure-policy gate).
  3. MUTANT CHECK: each negative's rejection is
     re-tested with the specific schema rule it depends on stripped out. With
     the rule removed, the SAME fixture MUST validate -- proving the check
     above can actually fail, not just report green by construction. The
     rule is then restored in memory (the committed schema file is never
     modified) and re-verified red.

Usage:
    python3 schemas/check_evidence_result_examples.py       # from repo root
    python3 check_evidence_result_examples.py                # from schemas/

Exit 0: every check above passed. Exit 1: a finding was printed. Exit 2: a
harness error (missing dependency, missing fixture).

NOT covered here (named per the principle of stating what you did NOT test):
  - `generated_at`'s "format": "date-time" keyword is annotation-only under
    python-jsonschema's default Draft202012Validator (no FormatChecker is
    attached) -- a garbage generated_at value currently validates clean.
    Same caveat evidence-plan-ir-v0.md's checker documents; not a defect
    introduced here.
  - Claim `id` uniqueness within a Result, and `aggregate.buckets` entries
    actually naming a claim `id` that exists with the matching `verdict`,
    are, by spec/evidence-result-v0.md section 4's own text, cross-element
    constraints plain JSON Schema cannot express. Nothing in this repository
    enforces them yet; they are a verifier's obligation, not this schema's.
  - The one-directional disclosure gate (disclosure-carrier status is
    restricted; analysis/story are not) is exercised by exactly one negative
    fixture (kind: disclosure under WITHHELD). The converse -- an
    analysis/story carrier used when disclosure would have been legal -- is
    valid by design (spec section 6) and is not a rejection case.
"""
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _result_types import EvidenceResultDoc  # noqa: E402

SCHEMAS_DIR = (
    Path(__file__).parent
    if Path(__file__).parent.name == "schemas"
    else Path(__file__).parent / "schemas"
)
VECTORS_DIR = SCHEMAS_DIR.parent / "vectors" / "evidence-result"
SCHEMA_PATH = SCHEMAS_DIR / "evidence-result-v0.json"

POSITIVE_RESULT = "pos-oo-claims-result"

# name -> (mutant description, path to the $defs entry whose rule is
# stripped to prove the rejection is load-bearing)
NEGATIVES = [
    "neg-untiered-claim",
    "neg-met-with-sufficiency-gap",
    "neg-aggregate-without-coverage",
    "neg-contract-ref-missing",
    "neg-disclosure-carrier-under-withheld",
]


def _load(name: str) -> EvidenceResultDoc:
    path = VECTORS_DIR / f"{name}.json"
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


# `schema` and the return value are the same open-ended JSON Schema document
# type justified above `_validator_for` -- a mutant is that same document with
# one $defs rule altered, not a shape this module owns.
def _mutant_schema_dropping_claim_required(schema: dict, field: str) -> dict:
    mutant = copy.deepcopy(schema)
    mutant["$defs"]["Claim"]["required"] = [
        r for r in mutant["$defs"]["Claim"]["required"] if r != field
    ]
    return mutant


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found at {SCHEMA_PATH}")
        return 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = _validator_for(schema)

    findings = []

    # --- 1. POSITIVE ---
    instance = _load(POSITIVE_RESULT)
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
    if errors:
        findings.append(f"POSITIVE-REJECTED {POSITIVE_RESULT}: {errors[0].message}")
    else:
        print(f"OK  EvidenceResult {POSITIVE_RESULT}.json")

    # --- 2. NEGATIVE: each of the five MUST fail ---
    negative_errors_by_name = {}
    for name in NEGATIVES:
        neg_instance = _load(name)
        neg_errors = list(validator.iter_errors(neg_instance))
        negative_errors_by_name[name] = neg_errors
        if not neg_errors:
            findings.append(
                f"NEGATIVE-DID-NOT-FAIL {name}: expected schema validation to reject "
                "this fixture, but it validated clean"
            )
        else:
            print(f"OK  EvidenceResult {name}.json correctly REJECTED "
                  f"({len(neg_errors)} error(s), e.g. {neg_errors[0].message!r})")

    # --- 3. MUTANT CHECKS: strip the specific rule, confirm the SAME -------
    #        negative fixture now validates, then confirm restoring makes it
    #        fail again. Proves each check 2 case is load-bearing.

    # `mutant_schema` is again the open-ended JSON Schema document type
    # justified above `_validator_for`.
    def _mutant_check(name: str, mutant_schema: dict, mutation_label: str) -> None:
        neg_instance = _load(name)
        mutant_validator = _validator_for(mutant_schema)
        mutant_errors = list(mutant_validator.iter_errors(neg_instance))
        if mutant_errors:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: removing {mutation_label} did not make "
                f"the fixture pass (still {len(mutant_errors)} error(s)) -- the "
                "rejection may be failing for an unrelated reason, not the rule "
                "this mutation targets"
            )
        else:
            print(f"OK  MUTANT        {name} -- with {mutation_label} removed, "
                  "the fixture now VALIDATES CLEAN (confirms the check is load-bearing)")
        restored_validator = _validator_for(schema)
        restored_errors = list(restored_validator.iter_errors(neg_instance))
        if not restored_errors:
            findings.append(
                f"MUTANT-RESTORE-FAILED {name}: after restoring {mutation_label}, "
                "the fixture validated clean instead of failing"
            )
        else:
            print(f"OK  MUTANT        {name} -- restored rule re-rejects the same fixture")

    if negative_errors_by_name["neg-untiered-claim"]:
        _mutant_check(
            "neg-untiered-claim",
            _mutant_schema_dropping_claim_required(schema, "tier"),
            "Claim.required's 'tier' entry",
        )

    if negative_errors_by_name["neg-met-with-sufficiency-gap"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Claim"]["allOf"] = []
        _mutant_check(
            "neg-met-with-sufficiency-gap",
            mutant,
            "Claim's sufficiency/verdict if/then rule",
        )

    if negative_errors_by_name["neg-aggregate-without-coverage"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Aggregate"]["required"] = [
            r for r in mutant["$defs"]["Aggregate"]["required"] if r != "coverage"
        ]
        _mutant_check(
            "neg-aggregate-without-coverage",
            mutant,
            "Aggregate.required's 'coverage' entry",
        )

    if negative_errors_by_name["neg-contract-ref-missing"]:
        _mutant_check(
            "neg-contract-ref-missing",
            _mutant_schema_dropping_claim_required(schema, "contract_ref"),
            "Claim.required's 'contract_ref' entry",
        )

    if negative_errors_by_name["neg-disclosure-carrier-under-withheld"]:
        mutant = copy.deepcopy(schema)
        # Widen DisclosureCarrier.status back to the full EvidenceStatus set,
        # removing the section 2 gate's restriction to DisclosedStatus.
        mutant["$defs"]["DisclosureCarrier"]["properties"]["status"] = {
            "$ref": "#/$defs/EvidenceStatus"
        }
        _mutant_check(
            "neg-disclosure-carrier-under-withheld",
            mutant,
            "DisclosureCarrier.status's restriction to DisclosedStatus",
        )

    if findings:
        print("\nFAIL — findings:")
        for f in findings:
            print(f"  {f}")
        return 1

    print(f"\nOK — 1 positive result, {len(NEGATIVES)} negative fixture(s), "
          "and all mutant checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
