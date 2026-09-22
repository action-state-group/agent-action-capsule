#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_evidence_plan_ir_examples.py

Validates every committed Evidence Plan IR v0 example fixture
(schemas/examples/evidence-plan-ir-v0/) against schemas/evidence-plan-ir-v0.json,
and proves the negative fixture's rejection is load-bearing rather than a
check that can never fire.

What this enforces (spec/evidence-plan-ir-v0.md is normative; this is the
mechanical half):

  1. POSITIVE: the three synthetic OO plans (outcome, obligation, process
     profiles) and their plan-result / attestation-record companions all
     validate against $defs/EvidencePlan, $defs/PlanResult, and
     $defs/AttestationRecord respectively.
  2. NEGATIVE: invalid-local-only-under-remote-planner.json — a LOCAL_ONLY
     node serialized into a plan whose planner_id does not begin with
     "local:" (spec section 4.1) — MUST fail $defs/EvidencePlan validation.
  3. MUTANT CHECK (QUEUE_PROTOCOL section 7): the negative fixture's
     rejection is re-tested with the schema's locality if/then block
     (EvidencePlan's top-level "if"/"then") stripped out. With the rule
     removed, the SAME fixture MUST validate — proving check 2 above can
     actually fail, not just report green by construction. The rule is
     then restored in memory (the committed schema file is never modified)
     and re-verified red.

Usage:
    python3 schemas/check_evidence_plan_ir_examples.py       # from repo root
    python3 check_evidence_plan_ir_examples.py                # from schemas/

Exit 0: every check above passed. Exit 1: a finding was printed. Exit 2: a
harness error (missing dependency, missing fixture).

NOT covered here (named per QUEUE_PROTOCOL section 7b's "name what you did
NOT test"):
  - `header.created_at`'s "format": "date-time" keyword is annotation-only
    under python-jsonschema's default Draft202012Validator (no FormatChecker
    is attached) -- a garbage created_at value currently validates clean.
    This is standard JSON Schema behavior (format is non-normative unless a
    consumer opts in), not a defect introduced here, but it means this
    script does not prove created_at is actually checked.
  - Node `id` uniqueness and the DAG-order rule (spec sections 1 and 3.1) and
    the node/header `contract_ref` cross-check (spec section 2) are, by the
    spec's own text, cross-element/cross-object constraints plain JSON
    Schema cannot express. Nothing in this repository enforces them yet;
    they are a verifier's obligation, not this schema's.
"""
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ir_types import IRDocument  # noqa: E402

SCHEMAS_DIR = (
    Path(__file__).parent
    if Path(__file__).parent.name == "schemas"
    else Path(__file__).parent / "schemas"
)
EXAMPLES_DIR = SCHEMAS_DIR / "examples" / "evidence-plan-ir-v0"
SCHEMA_PATH = SCHEMAS_DIR / "evidence-plan-ir-v0.json"

POSITIVE_PLANS = ["plan-outcome", "plan-obligation", "plan-process"]
POSITIVE_RESULTS = ["plan-outcome-result", "plan-obligation-result", "plan-process-result"]
POSITIVE_ATTESTATIONS = ["attestation-record-example"]
NEGATIVE_PLAN = "invalid-local-only-under-remote-planner"


def _load(name: str) -> IRDocument:
    path = EXAMPLES_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# `schema` is an arbitrary JSON Schema document: the keyword set is open-ended
# and recursive ($defs/$ref/if/then/...), so a TypedDict here would assert a
# fixed shape JSON Schema does not have, which is less honest than `dict`.
def _validator_for(schema: dict, defn: str):
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem, not a finding
        print(f"ERROR: the 'jsonschema' package is required to run this check: {exc}")
        sys.exit(2)
    sub_schema = dict(schema)
    sub_schema["$ref"] = f"#/$defs/{defn}"
    return jsonschema.Draft202012Validator(sub_schema)


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found at {SCHEMA_PATH}")
        return 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    findings = []

    # --- 1. POSITIVE: plans validate against $defs/EvidencePlan ---
    plan_validator = _validator_for(schema, "EvidencePlan")
    for name in POSITIVE_PLANS:
        instance = _load(name)
        errors = sorted(plan_validator.iter_errors(instance), key=lambda e: e.path)
        if errors:
            findings.append(f"POSITIVE-PLAN-REJECTED {name}: {errors[0].message}")
        else:
            print(f"OK  EvidencePlan   {name}.json")

    # --- 1b. POSITIVE: plan-result / attestation-record companions ---
    result_validator = _validator_for(schema, "PlanResult")
    for name in POSITIVE_RESULTS:
        instance = _load(name)
        errors = sorted(result_validator.iter_errors(instance), key=lambda e: e.path)
        if errors:
            findings.append(f"POSITIVE-RESULT-REJECTED {name}: {errors[0].message}")
        else:
            print(f"OK  PlanResult     {name}.json")

    attestation_validator = _validator_for(schema, "AttestationRecord")
    for name in POSITIVE_ATTESTATIONS:
        instance = _load(name)
        errors = sorted(attestation_validator.iter_errors(instance), key=lambda e: e.path)
        if errors:
            findings.append(f"POSITIVE-ATTESTATION-REJECTED {name}: {errors[0].message}")
        else:
            print(f"OK  AttestationRecord {name}.json")

    # --- 2. NEGATIVE: the LOCAL_ONLY-under-remote-planner plan must fail ---
    negative_instance = _load(NEGATIVE_PLAN)
    negative_errors = list(plan_validator.iter_errors(negative_instance))
    if not negative_errors:
        findings.append(
            f"NEGATIVE-DID-NOT-FAIL {NEGATIVE_PLAN}: expected schema validation to "
            "reject a LOCAL_ONLY node under a remote: planner, but it validated clean"
        )
    else:
        print(f"OK  EvidencePlan   {NEGATIVE_PLAN}.json correctly REJECTED "
              f"({len(negative_errors)} error(s), e.g. {negative_errors[0].message!r})")

    # --- 3. MUTANT CHECK: strip the locality if/then, confirm the SAME ---
    #        negative fixture now validates, then confirm restoring it makes
    #        it fail again. Proves check 2 is load-bearing.
    mutant_schema = copy.deepcopy(schema)
    plan_def = mutant_schema["$defs"]["EvidencePlan"]
    removed_if = plan_def.pop("if", None)
    removed_then = plan_def.pop("then", None)
    if removed_if is None or removed_then is None:
        findings.append(
            "MUTANT-HARNESS-BROKEN: EvidencePlan has no if/then to remove — "
            "the schema shape changed under this check"
        )
    else:
        mutant_validator = _validator_for(mutant_schema, "EvidencePlan")
        mutant_errors = list(mutant_validator.iter_errors(negative_instance))
        if mutant_errors:
            findings.append(
                "MUTANT-DID-NOT-FLIP: removing the locality if/then block did not "
                f"make the negative fixture pass (still {len(mutant_errors)} "
                "error(s)) — check 2 may be failing for an unrelated reason, not "
                "the locality rule"
            )
        else:
            print(
                "OK  MUTANT        with the locality if/then removed, "
                f"{NEGATIVE_PLAN}.json now VALIDATES CLEAN (confirms check 2 is "
                "load-bearing, not vacuous)"
            )
        # restore and re-verify red, proving the mutation was reverted correctly
        restored_schema = copy.deepcopy(schema)
        restored_validator = _validator_for(restored_schema, "EvidencePlan")
        restored_errors = list(restored_validator.iter_errors(negative_instance))
        if not restored_errors:
            findings.append(
                "MUTANT-RESTORE-FAILED: after restoring the locality if/then block "
                "in memory, the negative fixture validated clean instead of failing"
            )
        else:
            print("OK  MUTANT        restored rule re-rejects the same fixture")

    if findings:
        print("\nFAIL — findings:")
        for f in findings:
            print(f"  {f}")
        return 1

    print(f"\nOK — {len(POSITIVE_PLANS)} positive plan(s), "
          f"{len(POSITIVE_RESULTS)} plan-result(s), "
          f"{len(POSITIVE_ATTESTATIONS)} attestation-record(s), "
          "1 negative plan, and the mutant check all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
