#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_contract_report_examples.py

Validates the contract-report/v1 block fixtures
(schemas/examples/contract-report-v1/) against schemas/contract-report-v1.json
and proves each rejection is load-bearing.

What this enforces (spec/contract-report-v1.md section 1 is normative; this
is the mechanical half):

  1. POSITIVE: pos-*.json validates (the closed empty object).
  2. NEGATIVES, each MUST fail: neg-member.json and neg-enabled.json (a
     member of any name: the block carries no words, flags or provenance),
     neg-not-object.json (an array). MUTANT CHECK: with the one rule each
     depends on removed in memory (maxProperties, type), the fixture MUST
     validate, and the restored schema MUST reject it again.
  3. RENDERING CASES: every case in rendering-cases.json names a Result
     fixture that exists.

The kind's wording keys and example wording pack, and their check, are
capsule-viewer's (its spec/contract-report-module-v1.md).
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

SCHEMAS_DIR = Path(__file__).parent
EXAMPLES_DIR = SCHEMAS_DIR / "examples" / "contract-report-v1"
SCHEMA_PATH = SCHEMAS_DIR / "contract-report-v1.json"

NEGATIVES = [
    ("neg-member", "maxProperties", lambda s: s.pop("maxProperties")),
    ("neg-enabled", "maxProperties", lambda s: s.pop("maxProperties")),
    ("neg-not-object", "type", lambda s: s.pop("type")),
]


def _validator(schema: dict):
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem, not a finding
        print(f"ERROR: the 'jsonschema' package is required to run this check: {exc}")
        sys.exit(2)
    return jsonschema.Draft202012Validator(schema)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    schema = _load(SCHEMA_PATH)
    findings: list[str] = []

    # --- 1. POSITIVE ---
    validator = _validator(schema)
    positives = sorted(EXAMPLES_DIR.glob("pos-*.json"))
    if not positives:
        findings.append("HARNESS: no positive fixture")
    for path in positives:
        errors = list(validator.iter_errors(_load(path)))
        if errors:
            findings.append(f"POSITIVE-REJECTED {path.name}: {errors[0].message}")
        else:
            print(f"OK  contract-report/v1 {path.name}")

    # --- 2. NEGATIVES + MUTANTS ---
    listed = {f"{name}.json" for name, _, _ in NEGATIVES}
    on_disk = {p.name for p in EXAMPLES_DIR.glob("neg-*.json")}
    if listed != on_disk:
        findings.append(f"HARNESS: negatives on disk {sorted(on_disk)} != listed {sorted(listed)}")
    for name, rule, strip in NEGATIVES:
        instance = _load(EXAMPLES_DIR / f"{name}.json")
        errors = list(validator.iter_errors(instance))
        if not errors:
            findings.append(f"NEGATIVE-DID-NOT-FAIL {name}: validated clean")
            continue
        print(f"OK  contract-report/v1 {name}.json correctly REJECTED (e.g. {errors[0].message!r})")
        mutant = copy.deepcopy(schema)
        strip(mutant)
        if list(_validator(mutant).iter_errors(instance)):
            findings.append(f"MUTANT-DID-NOT-FLIP {name}: with '{rule}' removed it still fails")
        else:
            print(f"OK  MUTANT        '{rule}' removed: {name}.json VALIDATES CLEAN")
        if not list(validator.iter_errors(instance)):
            findings.append(f"MUTANT-RESTORE-FAILED {name}")

    # --- 3. RENDERING CASES ---
    # The rendering cases a contract-report module runs: every Result exists.
    cases = _load(EXAMPLES_DIR / "rendering-cases.json")["cases"]
    repo = SCHEMAS_DIR.parent
    for case in cases:
        if not (repo / case["result"]).is_file():
            findings.append(f"RENDER-CASE {case['name']}: {case['result']} does not exist")
    print(f"OK  {len(cases)} rendering case(s) name existing Results")
    if findings:
        print("\nFAILED:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("\nOK — contract-report/v1 block fixtures, their mutants and the rendering cases all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
