# SPDX-License-Identifier: BSD-3-Clause
"""Generate the negative cases for a non-string in a string-typed field.

Check 1 requires REQUIRED fields "present and typed" (§6). The never-reject
rule for unregistered values (§4, §12) covers well-typed strings only: a list
or an object where a string belongs is a type error, not an unknown value, so
every verifier rejects it in check 1 with ``field_not_string``. These cases put
a list and an object in three representative fields (one registry field per
block: disposition.decision, effect.type, chain.relation), and one shape in
each of epoch_id, effect.external_ref and cross_party.correlator. Each is otherwise a
verifying record, sealed with the reference compute_capsule_id; its
expected.json is derived from the reference verify() and then frozen
("reference-derived").

The manifest (vectors.json) and the SHA256SUMS in vectors/capsule/ and
vectors/ are updated in place; existing entries are kept.

Run:  cd python && PYTHONPATH=. python3 scripts/generate_typed_field_vectors.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_v05_vectors import (  # noqa: E402
    OUT,
    VECTORS,
    assurance,
    expected_for,
    ident,
    policy_executed,
    seal,
    update_sums,
    write_json,
)

HEX_1 = "1" * 64
PARENT = "a" * 64


def confirmed_effect(**overrides) -> dict:
    return {
        "status": "confirmed",
        "type": "write_order",
        "request_digest": HEX_1,
        "response_digest": HEX_1,
        "effect_attestation": "gate_executed",
        "irreversibility_class": "two_way",
        **overrides,
    }


def build_cases() -> list[dict]:
    cases = []
    for shape, decision, effect_type, relation in (
        ("list", ["accept"], ["write_order"], ["follows"]),
        ("object", {"value": "accept"}, {"value": "write_order"}, {"value": "follows"}),
    ):
        cases += [
            {
                "name": f"neg-field-not-string-decision-{shape}",
                "description": (
                    f"disposition.decision is a JSON {shape}, not a string: a type error, "
                    "not an unregistered value -> field_not_string (check 1)."
                ),
                "input": seal({
                    **ident(f"typed-decision-{shape}"),
                    "assurance": assurance("not_applicable", "standalone"),
                    "disposition": {**policy_executed(), "decision": decision},
                }),
            },
            {
                "name": f"neg-field-not-string-effect-type-{shape}",
                "description": (
                    f"effect.type is a JSON {shape}, not a string: a type error, "
                    "not an unregistered value -> field_not_string (check 1)."
                ),
                "input": seal({
                    **ident(f"typed-effect-type-{shape}"),
                    "effect": confirmed_effect(type=effect_type),
                    "assurance": assurance("confirmed", "standalone"),
                    "disposition": policy_executed(),
                }),
            },
            {
                "name": f"neg-field-not-string-chain-relation-{shape}",
                "description": (
                    f"chain.relation is a JSON {shape}, not a string: a type error, "
                    "not an unregistered value -> field_not_string (check 1)."
                ),
                "input": seal({
                    **ident(f"typed-chain-relation-{shape}"),
                    "assurance": assurance("not_applicable", "chained"),
                    "disposition": policy_executed(),
                    "chain": {"parent_capsule_id": PARENT, "relation": relation},
                }),
            },
        ]
    cases += [
        {
            "name": "neg-field-not-string-epoch-id-list",
            "description": (
                "epoch_id is a JSON list, not a string -> field_not_string (check 1)."
            ),
            "input": seal({
                **ident("typed-epoch-id-list"),
                "epoch_id": ["epoch-1"],
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
            }),
        },
        {
            "name": "neg-field-not-string-external-ref-object",
            "description": (
                "effect.external_ref is a JSON object, not a string -> field_not_string (check 1)."
            ),
            "input": seal({
                **ident("typed-external-ref-object"),
                "effect": confirmed_effect(external_ref={"value": "order-7"}),
                "assurance": assurance("confirmed", "standalone"),
                "disposition": policy_executed(),
            }),
        },
        {
            "name": "neg-field-not-string-correlator-list",
            "description": (
                "cross_party.correlator is a JSON list, not a string -> field_not_string "
                "(check 1); the derived cross_party_rung is unilateral_fallback."
            ),
            "input": seal({
                **ident("typed-correlator-list"),
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
                "cross_party": {
                    "initiator_ref": HEX_1,
                    "counterparty_ref": "2" * 64,
                    "correlator": ["exchange-corr-1"],
                    "substantive": False,
                },
            }),
        },
    ]
    return cases


def main() -> None:
    manifest_path = OUT / "vectors.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_name = {case["name"]: i for i, case in enumerate(manifest["cases"])}
    touched: list[Path] = []
    cases = build_cases()
    for case in cases:
        expected = expected_for(case["description"], case["input"])
        codes = [(f["check"], f["severity"], f["code"]) for f in expected["findings"] if f["severity"] == "error"]
        if expected["ok"] or codes != [(1, "error", "field_not_string")]:
            raise SystemExit(f"{case['name']}: expected exactly one check-1 field_not_string, got {expected['findings']}")
        case_dir = OUT / case["name"]
        case_dir.mkdir(exist_ok=True)
        write_json(case_dir / "input.json", case["input"])
        write_json(case_dir / "expected.json", expected)
        touched += [case_dir / "input.json", case_dir / "expected.json"]
        entry = {"name": case["name"], "kind": expected["kind"], "description": case["description"],
                 "provenance": expected["provenance"]}
        if case["name"] in by_name:
            manifest["cases"][by_name[case["name"]]] = entry
        else:
            manifest["cases"].append(entry)
    manifest["count"] = len(manifest["cases"])
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    touched.append(manifest_path)

    update_sums(OUT / "SHA256SUMS", OUT, touched)
    update_sums(VECTORS / "SHA256SUMS", VECTORS, touched)
    print(f"wrote {len(cases)} typed-field vectors to {OUT}")


if __name__ == "__main__":
    main()
