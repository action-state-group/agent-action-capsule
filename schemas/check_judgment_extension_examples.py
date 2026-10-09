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
  4. model_digest / model_reference: empty, all-zero and uppercase digests, empty or
     blank references, a digest without model_hosting, and a digest beside hosted are
     rejected, each with a mutant proving the rule is load-bearing.
  5. The published preimages validate against their $defs (JudgeParameters,
     ExpertProtocolParameters, RubricDocument, JudgeAnswer).
  6. prompt_file_digest is optional: JudgeParameters without it validates, an empty
     value is rejected, and the retired name prompt_digest is rejected (with a mutant
     proving that rejection rests on additionalProperties: false).

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

    # model_digest / model_reference: absent stays absent. An empty or all-zero digest
    # and an empty reference are rejected; a digest needs model_hosting and never sits
    # beside hosted. In-memory copies of pos-ai-judge only; the vectors are unchanged.
    zero = "0" * 64
    real = "9f2c" * 16

    def with_member(**fields):
        capsule = copy.deepcopy(cases["pos-ai-judge"]["capsule"])
        capsule["model_attestation"]["compute_attestation"]["x-judgment-v1"].update(fields)
        return capsule

    identity_cases = [
        ("self_hosted + model_digest", with_member(model_hosting="self_hosted", model_digest=real), True),
        ("self_hosted + model_reference", with_member(model_hosting="self_hosted", model_reference="example/judge@r1/model.weights"), True),
        ("empty model_digest", with_member(model_hosting="self_hosted", model_digest=""), False),
        ("all-zero model_digest", with_member(model_hosting="self_hosted", model_digest=zero), False),
        ("uppercase model_digest", with_member(model_hosting="self_hosted", model_digest=real.upper()), False),
        ("empty model_reference", with_member(model_hosting="self_hosted", model_reference=""), False),
        ("blank model_reference", with_member(model_hosting="self_hosted", model_reference="  "), False),
        ("model_digest without model_hosting", with_member(model_digest=real), False),
        ("hosted + model_digest", with_member(model_hosting="hosted", model_digest=real), False),
    ]
    for label, capsule, want in identity_cases:
        if root.is_valid(capsule) is not want:
            failures.append(f"{label}: schema_valid={not want}, expected {want}")

    # MUTANTS: each identity rejection is load-bearing. Drop the rule in memory and the
    # rejected value validates; the committed schema file is never modified.
    def mutant_valid(mutate, capsule):
        m = copy.deepcopy(schema)
        mutate(m["$defs"]["JudgmentMember"])
        return validator(m).is_valid(capsule)

    identity_mutants = [
        ("empty model_digest", lambda d: d["properties"]["model_digest"]["allOf"].pop(0),
         identity_cases[2][1]),
        ("all-zero model_digest", lambda d: d["properties"]["model_digest"]["allOf"].pop(1),
         identity_cases[3][1]),
        ("model_digest without model_hosting", lambda d: d.pop("dependentRequired"),
         identity_cases[7][1]),
        ("hosted + model_digest", lambda d: d.pop("then"), identity_cases[8][1]),
    ]
    for label, mutate, capsule in identity_mutants:
        if not mutant_valid(mutate, capsule):
            failures.append(f"mutant: {label} still rejected without its rule")

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

    # prompt_file_digest: optional, absent is absent, and the retired name is not accepted.
    params_validator = validator(schema, "JudgeParameters")
    base_params = pre["pos-ai-judge"]["judge_parameters"]
    without_file = {k: v for k, v in base_params.items() if k != "prompt_file_digest"}
    renamed = {**without_file, "prompt_digest": base_params["prompt_file_digest"]}
    prompt_file_cases = [
        ("JudgeParameters without prompt_file_digest", without_file, True),
        ("empty prompt_file_digest", {**base_params, "prompt_file_digest": ""}, False),
        ("retired name prompt_digest", renamed, False),
    ]
    for label, value, want in prompt_file_cases:
        if params_validator.is_valid(value) is not want:
            failures.append(f"{label}: valid={not want}, expected {want}")
    open_params = copy.deepcopy(schema)
    open_params["$defs"]["JudgeParameters"].pop("additionalProperties")
    if not validator(open_params, "JudgeParameters").is_valid(renamed):
        failures.append("mutant: retired name prompt_digest still rejected without additionalProperties: false")

    for line in failures:
        print(f"FAIL {line}")
    if not failures:
        print(f"ok: {len(data['cases'])} cases, 1 mutant, {hosting_checks} model_hosting checks, "
              f"{len(identity_cases)} identity checks, {len(identity_mutants)} identity mutants, {len(checks)} preimages, "
              f"{len(prompt_file_cases)} prompt_file_digest checks, 1 prompt_file_digest mutant")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
