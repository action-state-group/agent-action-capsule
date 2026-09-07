"""Freeze verification outcomes from the unmodified Python 0.2.0 reference."""

import json
from pathlib import Path

from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.verify import verify


def generate():
    cases = []
    for name, effect_type, attestation, relation, adjudication in [
        ("mesh-provisional", "inference_completion", "host_served_observed", "follows", False),
        ("future-unknown", "future-effect", "future-attestation", "future-relation", False),
        ("seeded", "write_order", "gate_executed", "confirms", False),
        ("adjudication-shape", None, None, "adjudicates", True),
    ]:
        capsule = {
            "spec_version": "draft-mih-scitt-agent-action-capsule-04",
            "format_version": "4", "canonicalization_id": "jcs",
            "action_id": "vocabulary/example", "action_type": "fyi",
            "operator": "example-org", "developer": "example-agent@v1",
            "timestamp": "2026-09-07T12:00:00Z",
            "chain": {"parent_capsule_id": "a" * 64, "relation": relation},
        }
        if effect_type:
            capsule["effect"] = {"type": effect_type, "status": "confirmed", "irreversibility_class": "two_way", "response_digest": "b" * 64, "effect_attestation": attestation}
        if adjudication:
            capsule["disposition"] = {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "assessed"}
            capsule["model_attestation"] = {"compute_attestation": {"adjudication": {"source": "twin_comparison", "capture_method": "deterministic_replay", "verdict": "corroborated", "half_a_capsule_id": "a" * 64, "half_b_capsule_id": "b" * 64, "margin": "1", "margin_tau": "0"}}}
        capsule["capsule_id"] = compute_capsule_id(capsule)
        result = verify(capsule)
        cases.append({"name": name, "capsule": capsule, "ok": result.ok, "assurance": result.assurance, "findings": [{"code": f.code, "severity": f.severity} for f in result.findings]})
    Path(__file__).with_name("vocabulary.json").write_text(json.dumps({"source": "Python agent-action-capsule 0.2.0 at bb648e1", "cases": cases}, indent=2) + "\n")


if __name__ == "__main__":
    generate()
