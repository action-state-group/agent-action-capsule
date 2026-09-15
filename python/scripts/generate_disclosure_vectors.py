#!/usr/bin/env python3
"""Extend the Disclosure Envelope corpus across every DE result class."""
from __future__ import annotations

import json
from pathlib import Path

from agent_action_capsule import compute_capsule_id, json_digest, verify_disclosure_envelope

OUT = Path(__file__).resolve().parents[2] / "vectors" / "disclosure-envelope"


def expected(result, description: str, kind: str) -> dict:
    capsule = result.capsule_result
    return {
        "description": description,
        "kind": kind,
        "ok": result.ok,
        "capsule": {
            "ok": capsule.ok,
            "derived": capsule.assurance,
            "capsule_id_recomputed": capsule.capsule_id,
            "findings": [
                {"check": item.check, "severity": item.severity, "code": item.code, "detail": item.detail}
                for item in capsule.findings
            ],
        },
        "disclosures_checked": result.disclosures_checked,
        "disclosures_matched": result.disclosures_matched,
        "disclosure_findings": [
            {"member": item.member, "code": item.code} for item in result.disclosure_findings
        ],
    }


def write(name: str, envelope: dict, description: str, kind: str) -> None:
    directory = OUT / name
    directory.mkdir(exist_ok=True)
    wrapped = {"envelope": envelope}
    result = verify_disclosure_envelope(envelope)
    (directory / "input.json").write_text(json.dumps(wrapped, indent=2) + "\n", encoding="utf-8")
    (directory / "expected.json").write_text(
        json.dumps(expected(result, description, kind), indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    base = json.loads(
        (OUT / "pos-disclosure-envelope-match" / "input.json").read_text(encoding="utf-8")
    )["envelope"]["capsule"]

    both = json.loads(json.dumps(base))
    agent_input = {"amount": "500.00", "sku": "PO-9981"}
    agent_output = {"accepted": True, "order_id": "order-7"}
    compute = both["model_attestation"]["compute_attestation"]
    compute["agent_input_digest"] = json_digest(agent_input)
    compute["agent_output_digest"] = json_digest(agent_output)
    both["capsule_id"] = compute_capsule_id(both)
    write(
        "pos-disclosure-envelope-both-fields",
        {"capsule": both, "disclosures": {"agent_output": agent_output, "agent_input": agent_input}},
        "both disclosure-eligible fields match, reported in deterministic member order",
        "positive",
    )
    write(
        "neg-disclosure-envelope-ineligible",
        {"capsule": base, "disclosures": {"unknown": {"value": 1}}},
        "DE-1 rejects a member outside the disclosure-eligibility table",
        "negative",
    )
    write(
        "neg-disclosure-envelope-no-commitment",
        {"capsule": base, "disclosures": {"agent_output": agent_output}},
        "DE-2 requires the matching committed digest field",
        "negative",
    )
    write(
        "neg-disclosure-envelope-uncanonicalizable",
        {"capsule": base, "disclosures": {"agent_input": {"amount": 12.5}}},
        "DE-3 reports an uncanonicalizable disclosure as mismatch",
        "negative",
    )

    cases = []
    for directory in sorted(path for path in OUT.iterdir() if path.is_dir()):
        item = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        cases.append(
            {"name": directory.name, "kind": item["kind"], "description": item["description"]}
        )
    (OUT / "vectors.json").write_text(
        json.dumps(
            {
                "format_version": "1",
                "spec": "draft-mih-scitt-agent-action-capsule-disclosure-envelope-00",
                "count": len(cases),
                "cases": cases,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
