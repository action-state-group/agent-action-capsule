#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_contract_report_examples.py

Validates the contract-report/v1 block fixtures
(schemas/examples/contract-report-v1/) against schemas/contract-report-v1.json
and the example wording pack against the presentation manifest schema's
$defs/WordingPack, and proves each rejection is load-bearing.

What this enforces (spec/contract-report-v1.md is normative; this is the
mechanical half):

  1. POSITIVE: pos-*.json validates (the closed empty object).
  2. NEGATIVES, each MUST fail: neg-member.json and neg-enabled.json (a
     member of any name: the block carries no words, flags or provenance),
     neg-not-object.json (an array). MUTANT CHECK: with the one rule each
     depends on removed in memory (maxProperties, type), the fixture MUST
     validate, and the restored schema MUST reject it again.
  3. WORDING KEYS (spec section 3): every key the kind defines for a Result
     v0 enum value, assembled from the lowercased value, is a valid
     WordingKey, and the same key built from an uppercase value is not (so
     the lowercasing rule is load-bearing). The example wording pack
     validates as a WordingPack, names the page and the module separately
     (presentation contract section 7.4), and every one of its entries is a
     key the kind defines or a reserved key.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

SCHEMAS_DIR = Path(__file__).parent
EXAMPLES_DIR = SCHEMAS_DIR / "examples" / "contract-report-v1"
SCHEMA_PATH = SCHEMAS_DIR / "contract-report-v1.json"
MANIFEST_SCHEMA_PATH = SCHEMAS_DIR / "presentation-manifest-v0.json"
RESULT_SCHEMA_PATH = SCHEMAS_DIR / "evidence-result-v0.json"
PACK_PATH = SCHEMAS_DIR / "examples" / "presentation-manifest-v0" / "example-wording-pack-contract-report.json"

NEGATIVES = [
    ("neg-member", "maxProperties", lambda s: s.pop("maxProperties")),
    ("neg-enabled", "maxProperties", lambda s: s.pop("maxProperties")),
    ("neg-not-object", "type", lambda s: s.pop("type")),
]
# spec/contract-report-v1.md section 3: key prefix -> Result v0 enum ($defs).
ENUM_KEYS = {
    "verdict": "Verdict",
    "sufficiency": "Sufficiency",
    "tier": "Tier",
    "grade": "Grade",
    "status": "EvidenceStatus",
}
RESERVED = ("page.title", "module.title")
FIXED_KEYS = (
    "report.title",
    "report.summary",
    # Result v0 sections 4.2 and 4.3 (spec section 2's applicability rules).
    "applicability.not_yet_in_force.title",
    "applicability.not_yet_in_force.note",
    "applicability.as_of",
    "contract_fact.note",
)
# The one slot applicability.as_of carries: exactly one, or the word is missing.
AS_OF_SLOT = "{date}"
ROW_SUFFIXES = ("label", "detail", "not_evaluable")


def _validator(schema: dict, defn: str | None = None):
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem, not a finding
        print(f"ERROR: the 'jsonschema' package is required to run this check: {exc}")
        sys.exit(2)
    if defn is not None:
        schema = dict(schema)
        schema["$ref"] = f"#/$defs/{defn}"
    return jsonschema.Draft202012Validator(schema)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


RESULT_DEFS = _load(RESULT_SCHEMA_PATH)["$defs"]
# Each enum key prefix and its lowercased Result v0 values.
ENUM_VALUES = {
    prefix: {v.lower() for v in RESULT_DEFS[defn]["enum"]} for prefix, defn in ENUM_KEYS.items()
}


def defined_key(key: str) -> bool:
    """A key spec/contract-report-v1.md section 3 defines, or a reserved key."""
    if key in RESERVED or key in FIXED_KEYS:
        return True
    head, _, rest = key.partition(".")
    if head in ENUM_VALUES:
        return rest in ENUM_VALUES[head]
    if head == "group":
        return rest.endswith(".title") and "." not in rest[: -len(".title")]
    if head == "row":
        return any(rest.endswith(f".{suffix}") for suffix in ROW_SUFFIXES)
    return False


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

    # --- 3. WORDING KEYS ---
    manifest_schema = _load(MANIFEST_SCHEMA_PATH)
    key_pattern = re.compile(manifest_schema["$defs"]["WordingKey"]["pattern"])
    for prefix, defn in ENUM_KEYS.items():
        for value in RESULT_DEFS[defn]["enum"]:
            key = f"{prefix}.{value.lower()}"
            if not key_pattern.match(key) or not defined_key(key):
                findings.append(f"ENUM-KEY {key}: not a valid, defined WordingKey")
            if value != value.lower() and key_pattern.match(f"{prefix}.{value}"):
                findings.append(f"ENUM-KEY-CASE {prefix}.{value}: the uppercase form must be invalid")
    print("OK  every Result v0 enum value maps to a valid key once lowercased")

    pack = _load(PACK_PATH)
    errors = list(_validator(manifest_schema, "WordingPack").iter_errors(pack))
    if errors:
        findings.append(f"PACK-REJECTED {PACK_PATH.name}: {errors[0].message}")
    else:
        print(f"OK  WordingPack {PACK_PATH.name}")
    entries = pack["entries"]
    reserved = [entries.get(k) for k in RESERVED]
    if None in reserved or reserved[0] == reserved[1]:
        findings.append(f"PACK-RESERVED: page.title and module.title must both be present and differ, got {reserved}")
    for key in entries:
        if not defined_key(key):
            findings.append(f"PACK-KEY {key}: not a key spec/contract-report-v1.md defines")
    if not defined_key("row.intake.confirmed.label") or defined_key("row.intake.confirmed"):
        findings.append("HARNESS: defined_key misreads row keys")
    for undefined in ("verdict.mte", "tier.unknown", "status.gap", "grade.self_attested"):
        if defined_key(undefined):
            findings.append(f"HARNESS: defined_key accepts {undefined}, which no Result v0 enum defines")
    # The rendering cases a contract-report module runs: every Result exists,
    # and every malformed as-of override really is malformed.
    cases = _load(EXAMPLES_DIR / "rendering-cases.json")["cases"]
    repo = SCHEMAS_DIR.parent
    for case in cases:
        if not (repo / case["result"]).is_file():
            findings.append(f"RENDER-CASE {case['name']}: {case['result']} does not exist")
        override = case.get("pack_entries", {}).get("applicability.as_of")
        if override is not None and override.count(AS_OF_SLOT) == 1:
            findings.append(f"RENDER-CASE {case['name']}: its as-of override is well formed")
    print(f"OK  {len(cases)} rendering case(s) name existing Results")
    as_of = entries.get("applicability.as_of")
    if as_of is not None and as_of.count(AS_OF_SLOT) != 1:
        findings.append(f"PACK-AS-OF: applicability.as_of must carry exactly one {AS_OF_SLOT}, got {as_of!r}")
    for malformed in ("In force as of", "In force as of {date} ({date})"):
        if malformed.count(AS_OF_SLOT) == 1:
            findings.append(f"HARNESS: the slot check accepts {malformed!r}")
    if not findings:
        print(f"OK  every entry of {PACK_PATH.name} is a key the kind defines or a reserved key, "
              f"and applicability.as_of carries one {AS_OF_SLOT}")

    if findings:
        print("\nFAILED:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("\nOK — contract-report/v1 block fixtures, their mutants and the kind's wording keys all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
