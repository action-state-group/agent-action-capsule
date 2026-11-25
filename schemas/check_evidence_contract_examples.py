#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_evidence_contract_examples.py

Checks schemas/evidence-contract-v0.json against the digest the interop
profile pins, and validates the contract every vector corpus carries.

What this enforces:

  1. PIN: the file's SHA-256 is SCHEMA_SHA256, the digest
     spec/interop-profile-v2.md pins as EC, and that file names it. This copy
     is the capsule-engine copy (ENGINE_SHA256, pinned as EC by
     spec/interop-profile-v0.md and -v1.md) with its $id changed and the
     abstract obligation shape dropped (v2 §11.3.2, P-71). Any other edit
     changes the digest and fails here.
  2. VECTORS: every vectors/*/vectors.json carrying a `contract.document`
     names evidence-contract-v0.json, its document validates, and its pinned
     `contract.schema.sha256` is the one CORPUS_PINS or OLDER_PINS gives it,
     else ENGINE_SHA256.
  3. OBLIGATION SHAPE: vectors/evidence-contract-obligation/cases.json pins
     SCHEMA_SHA256, and each case's document validates exactly when the case
     says `accept`.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

SCHEMAS_DIR = Path(__file__).parent
REPO = SCHEMAS_DIR.parent
SCHEMA_PATH = SCHEMAS_DIR / "evidence-contract-v0.json"

SCHEMA_ID = "https://agentactioncapsule.org/schemas/evidence-contract-v0.json"
SCHEMA_SHA256 = "bf9a1cdee27c8cf6d35b2371fe3b778cf5e1db671dd9c4bce9f503e8842cb78b"
SPEC_PINNING = REPO / "spec" / "interop-profile-v2.md"
# The capsule-engine copy at 773ae9e96285e4442cab8139923b1479b103e14c, the EC pin
# of evidence-interop/0 and /1. Corpora generated for those revisions pin it.
ENGINE_SHA256 = "6b969610e6f120a9f5b98555aa5045644c62665f14075bb83fb9e78bab21b770"
# Corpora generated for evidence-interop/2 pin this copy.
CORPUS_PINS = {
    "interop-profile-v2": SCHEMA_SHA256,
    "interop-profile-v2-requirement-facts": SCHEMA_SHA256,
}
OBLIGATION_CASES = REPO / "vectors" / "evidence-contract-obligation" / "cases.json"
# Corpora generated against capsule-engine's older copy of the schema (no
# out_of_scope). Their documents still validate here; re-pinning them is a
# vectors change, not this checker's.
OLDER_PINS = {
    "personal-history-basic-v0": "6d10d5eb97e15421db0ab922b5f6d1f0a2e9f453fb64e52fb45306ba029ad480",
}


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
    findings: list[str] = []
    raw = SCHEMA_PATH.read_bytes()
    schema = json.loads(raw)

    # --- 1. PIN ---
    if schema.get("$id") != SCHEMA_ID:
        findings.append(f"ID: $id is {schema.get('$id')!r}, expected {SCHEMA_ID!r}")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SCHEMA_SHA256:
        findings.append(f"PIN: the schema's SHA-256 is {digest}, expected {SCHEMA_SHA256}")
    else:
        print(f"OK  schema SHA-256 = {SCHEMA_SHA256}")
    if SCHEMA_SHA256 not in SPEC_PINNING.read_text(encoding="utf-8"):
        findings.append(f"PIN: {SPEC_PINNING.relative_to(REPO)} does not name {SCHEMA_SHA256}")
    _validator(schema).check_schema(schema)
    validator = _validator(schema)

    # --- 2. VECTORS ---
    corpora = 0
    for path in sorted(REPO.glob("vectors/*/vectors.json")):
        contract = _load(path).get("contract")
        if not isinstance(contract, dict) or "document" not in contract:
            continue
        corpora += 1
        corpus = path.parent.name
        schema_pin = contract.get("schema", {})
        if schema_pin.get("name") != SCHEMA_PATH.name:
            findings.append(f"VECTOR-SCHEMA-NAME {corpus}: names {schema_pin.get('name')!r}")
            continue
        expected = OLDER_PINS.get(corpus, CORPUS_PINS.get(corpus, ENGINE_SHA256))
        if schema_pin.get("sha256") != expected:
            findings.append(f"VECTOR-SCHEMA-PIN {corpus}: pins {schema_pin.get('sha256')}, expected {expected}")
        errors = list(validator.iter_errors(contract["document"]))
        if errors:
            findings.append(f"VECTOR-CONTRACT-REJECTED {corpus}: {errors[0].message}")
        elif corpus in OLDER_PINS:
            print(f"OK  contract.document in {corpus} (NOTE: pinned to the older schema {expected})")
        else:
            print(f"OK  contract.document in {corpus}")
    for corpus in OLDER_PINS:
        if not (REPO / "vectors" / corpus / "vectors.json").is_file():
            findings.append(f"HARNESS: OLDER_PINS names {corpus}, which has no vectors.json")
    for corpus in CORPUS_PINS:
        if not (REPO / "vectors" / corpus / "vectors.json").is_file():
            findings.append(f"HARNESS: CORPUS_PINS names {corpus}, which has no vectors.json")
    if corpora == 0:
        findings.append("HARNESS: no vector corpus carries an Evidence Contract")

    # --- 3. OBLIGATION SHAPE ---
    obligation = _load(OBLIGATION_CASES)
    if obligation.get("schema") != {"name": SCHEMA_PATH.name, "sha256": SCHEMA_SHA256}:
        findings.append(f"OBLIGATION-PIN: pins {obligation.get('schema')}, expected {SCHEMA_SHA256}")
    cases = obligation.get("cases", [])
    if not cases or obligation.get("count") != len(cases):
        findings.append(f"OBLIGATION-HARNESS: count {obligation.get('count')} for {len(cases)} cases")
    if {case.get("accept") for case in cases} != {True, False}:
        findings.append("OBLIGATION-HARNESS: the set needs an accepted and a refused case")
    for case in cases:
        valid = validator.is_valid(case["document"])
        if valid != case["accept"]:
            findings.append(f"OBLIGATION {case['id']}: valid={valid}, the case says accept={case['accept']}")
        else:
            print(f"OK  {case['id']}: {'accepted' if valid else 'refused'}")

    if findings:
        print("\nFAILED:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
