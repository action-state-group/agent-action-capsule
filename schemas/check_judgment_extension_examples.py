#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_judgment_extension_examples.py

Validates the judgment extension vectors (vectors/judgment/vectors.json,
PROVISIONAL) against schemas/judgment/judgment-extension-v1.json:

  1. Every case's Capsule validates (or is rejected) as its expect.schema_valid
     says.
  2. MUTANT CHECK: the schema-rejected negative (neg-missing-rubric-version)
     validates once `rubric_version` is dropped from the member's `required`
     list in memory, proving the rejection is load-bearing; the committed
     schema file is never modified.
  3. model_hosting accepts exactly the closed set {hosted, self_hosted} (checked on
     in-memory copies of pos-ai-judge; the vectors are not rewritten).
  4. The published preimages validate against their $defs (JudgeParameters,
     ExpertProtocolParameters, RubricDocument, JudgeAnswer).

Digest recomputation is python/tests/test_judgment_extension_vectors.py's job.

Usage (repo root):  python3 schemas/check_judgment_extension_examples.py
Exit 0: all checks passed. Exit 1: a finding was printed. Exit 2: harness error.
"""
import copy
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    print("jsonschema is required: pip install jsonschema", file=sys.stderr)
    sys.exit(2)

SCHEMAS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCHEMAS_DIR.parent
SCHEMA_PATH = SCHEMAS_DIR / "judgment" / "judgment-extension-v1.json"
VECTORS_PATH = REPO_ROOT / "vectors" / "judgment" / "vectors.json"


def validator(schema: dict, def_name: str | None = None) -> Draft202012Validator:
    if def_name is not None:
        schema = {**schema, "$ref": f"#/$defs/{def_name}"}
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def main() -> int:
    if not SCHEMA_PATH.is_file() or not VECTORS_PATH.is_file():
        print(f"missing {SCHEMA_PATH} or {VECTORS_PATH}", file=sys.stderr)
        return 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    cases = {c["id"]: c for c in data["cases"]}
    failures = []

    root = validator(schema)
    for case in data["cases"]:
        got = root.is_valid(case["capsule"])
        if got is not case["expect"]["schema_valid"]:
            failures.append(f"{case['id']}: schema_valid={got}, expected {case['expect']['schema_valid']}")

    mutant = copy.deepcopy(schema)
    mutant["$defs"]["JudgmentMember"]["required"].remove("rubric_version")
    if not validator(mutant).is_valid(cases["neg-missing-rubric-version"]["capsule"]):
        failures.append("mutant: neg-missing-rubric-version still rejected without the rubric_version rule")
    if root.is_valid(cases["neg-missing-rubric-version"]["capsule"]):
        failures.append("restore: neg-missing-rubric-version validates under the committed schema")

    # model_hosting: the closed set a pack's judge declaration uses, accepted on the
    # member; a value outside it is rejected (in-memory copies; vectors unchanged).
    hosting_checks = 0
    for value, want in (("hosted", True), ("self_hosted", True), ("hosted_remote", False), ("", False)):
        capsule = copy.deepcopy(cases["pos-ai-judge"]["capsule"])
        capsule["model_attestation"]["compute_attestation"]["x-judgment-v1"]["model_hosting"] = value
        hosting_checks += 1
        if root.is_valid(capsule) is not want:
            failures.append(f"model_hosting={value!r}: schema_valid={not want}, expected {want}")

    pre = {cid: cases[cid]["preimages"]["values"] for cid in ("pos-ai-judge", "pos-human-expert")}
    checks = [
        ("JudgeParameters", pre["pos-ai-judge"]["judge_parameters"]),
        ("ExpertProtocolParameters", pre["pos-human-expert"]["judge_parameters"]),
    ]
    for values in pre.values():
        checks += [("RubricDocument", values["rubric"]), ("JudgeAnswer", values["agent_output"])]
    for def_name, value in checks:
        if not validator(schema, def_name).is_valid(value):
            failures.append(f"preimage does not validate against $defs/{def_name}")

    for line in failures:
        print(f"FAIL {line}")
    if not failures:
        print(f"ok: {len(data['cases'])} cases, 1 mutant, {hosting_checks} model_hosting checks, {len(checks)} preimages")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
