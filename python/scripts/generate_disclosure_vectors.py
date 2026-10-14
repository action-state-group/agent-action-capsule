#!/usr/bin/env python3
"""Generate the Disclosure Envelope corpus across every DE result class.

The base Capsule is the capsule corpus's pos-executed-confirmed case, from
the -04 compatibility set, committing an agent_input digest. The nested
cases are spec-derived: they reuse the nested payload of
generate_spec_derived_vectors.py and keep their hand-written layout.

The manifest lists this script's cases in their released order;
generate_parity_hardening_vectors.py appends its cases after them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_action_capsule import compute_capsule_id, json_digest, verify_disclosure_envelope
from agent_action_capsule.canonical import jcs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_spec_derived_vectors import NESTED, nested_output_capsule, payload_capsule  # noqa: E402
from generate_vectors import c_executed, seal  # noqa: E402
from vector_layout import dumps, hand_dumps, preimage, sort_members  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors" / "disclosure-envelope"
PROVENANCE = "spec-derived"


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
    record = expected(result, description, kind)
    record["provenance"] = PROVENANCE
    record["canonical_preimages"] = {"capsule_id": preimage(envelope["capsule"])}
    (directory / "input.json").write_text(json.dumps(wrapped, indent=2) + "\n", encoding="utf-8")
    (directory / "expected.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def write_nested(name: str, envelope: dict, description: str, kind: str, preimages: dict) -> None:
    """A nested case, in the hand-written layout of the spec-derived cases."""
    directory = OUT / name
    directory.mkdir(exist_ok=True)
    record = sort_members({**expected(verify_disclosure_envelope(envelope), description, kind),
                           "provenance": PROVENANCE})
    record = {"canonical_preimages": preimages, **record}
    expand = [("envelope",), ("envelope", "capsule"), ("envelope", "disclosures")]
    (directory / "input.json").write_text(hand_dumps({"envelope": envelope}, expand), encoding="utf-8")
    (directory / "expected.json").write_text(
        hand_dumps(record, expand=[("canonical_preimages",)]), encoding="utf-8"
    )


def main() -> None:
    agent_input = {"amount": "500.00", "sku": "PO-9981"}
    agent_output = {"accepted": True, "order_id": "order-7"}
    base = seal({**c_executed(), "model_attestation": {"compute_attestation": {"agent_input_digest": json_digest(agent_input)}}})

    both = json.loads(json.dumps(base))
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

    nested_input = payload_capsule("disclosure-nested-input", "2026-09-13T00:00:04Z", "agent_input_digest", NESTED)
    nested_output = nested_output_capsule()
    changed_leaf = json.loads(json.dumps(NESTED))
    changed_leaf["request"]["items"][0]["meta"]["sku"] = "A9"
    canonical = jcs(NESTED).decode("utf-8")
    write_nested(
        "pos-disclosure-envelope-nested-input",
        {"capsule": nested_input, "disclosures": {"agent_input": NESTED}},
        "DE-3 matches a nested agent_input disclosure containing objects inside an array.",
        "positive",
        {"agent_input_digest": canonical, "capsule_id": preimage(nested_input)},
    )
    write_nested(
        "pos-disclosure-envelope-nested-output",
        {"capsule": nested_output, "disclosures": {"agent_output": NESTED}},
        "DE-3 matches a nested agent_output disclosure containing objects inside an array.",
        "positive",
        {"agent_output_digest": canonical, "capsule_id": preimage(nested_output)},
    )
    write_nested(
        "neg-disclosure-envelope-nested-leaf-mismatch",
        {"capsule": nested_input, "disclosures": {"agent_input": changed_leaf}},
        "DE-3 reports a mismatch when one nested agent_input leaf changes.",
        "negative",
        {"committed_agent_input_digest": canonical, "capsule_id": preimage(nested_input)},
    )

    # The released manifest order.
    names = [
        "neg-disclosure-envelope-ineligible",
        "neg-disclosure-envelope-no-commitment",
        "neg-disclosure-envelope-nested-leaf-mismatch",
        "neg-disclosure-envelope-uncanonicalizable",
        "pos-disclosure-envelope-both-fields",
        "pos-disclosure-envelope-nested-input",
        "pos-disclosure-envelope-nested-output",
    ]
    cases = []
    for name in names:
        item = json.loads((OUT / name / "expected.json").read_text(encoding="utf-8"))
        cases.append({"name": name, "kind": item["kind"], "description": item["description"],
                      "provenance": item["provenance"]})
    (OUT / "vectors.json").write_text(
        dumps({
            "format_version": "1",
            "spec": "draft-mih-scitt-agent-action-capsule-disclosure-envelope-00",
            "count": len(cases),
            "cases": cases,
        }),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
