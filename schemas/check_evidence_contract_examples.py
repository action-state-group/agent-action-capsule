#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_evidence_contract_examples.py

Checks schemas/evidence-contract-v0.json against the capsule-engine copy it
was taken from, and validates the contract every vector corpus carries.

What this enforces:

  1. PROVENANCE: the schema is the capsule-engine canonical copy with only its
     $id changed. With the $id line put back to the engine's value, the file's
     SHA-256 MUST be ENGINE_SHA256, the digest spec/interop-profile-v0.md pins
     as EC. Any other edit changes the digest and fails here.
  2. VECTORS: every vectors/*/vectors.json carrying a `contract.document`
     names evidence-contract-v0.json, its document validates, and its pinned
     `contract.schema.sha256` is ENGINE_SHA256 unless OLDER_PINS lists it.
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
ENGINE_ID = "https://github.com/action-state-group/capsule-engine/blob/main/schemas/evidence-contract-v0.json"
ENGINE_SHA256 = "6b969610e6f120a9f5b98555aa5045644c62665f14075bb83fb9e78bab21b770"
# Corpora generated against capsule-engine's older copy of the schema (no
# out_of_scope). Their documents still validate here; re-pinning them is a
# vectors change, not this checker's.
OLDER_PINS = {
    "personal-history-basic-v0": "6d10d5eb97e15421db0ab922b5f6d1f0a2e9f453fb64e52fb45306ba029ad480",
}


def _id_line(value: str) -> bytes:
    return f'  "$id": "{value}",\n'.encode()


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

    # --- 1. PROVENANCE ---
    if schema.get("$id") != SCHEMA_ID:
        findings.append(f"ID: $id is {schema.get('$id')!r}, expected {SCHEMA_ID!r}")
    if raw.count(_id_line(SCHEMA_ID)) != 1:
        findings.append("PROVENANCE: the $id line is not the expected single line")
    engine_bytes = raw.replace(_id_line(SCHEMA_ID), _id_line(ENGINE_ID), 1)
    digest = hashlib.sha256(engine_bytes).hexdigest()
    if digest != ENGINE_SHA256:
        findings.append(f"PROVENANCE: with the engine $id restored the SHA-256 is {digest}, expected {ENGINE_SHA256}")
    else:
        print(f"OK  schema = engine copy {ENGINE_SHA256} with only $id changed")
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
        expected = OLDER_PINS.get(corpus, ENGINE_SHA256)
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
    if corpora == 0:
        findings.append("HARNESS: no vector corpus carries an Evidence Contract")

    if findings:
        print("\nFAILED:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
