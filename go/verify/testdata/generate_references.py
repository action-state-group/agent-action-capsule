"""Freeze draft-04 reference cases with unmodified Python identity/JCS primitives.

The expected structural findings are specified here from draft-04 §5.5.5.
Python 0.2.0 does not yet implement those structural checks, so its verifier
is deliberately not used as the oracle for them.
"""

import json
from pathlib import Path

from agent_action_capsule.canonical import compute_capsule_id, jcs

PARENT = "a" * 64
REF = {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": "b" * 64}
CASES = [
    ("absent", {}, []),
    ("empty", {"references": []}, []),
    ("vintage-extension", {"format_version": "2", "references": None}, []),
    ("unregistered-capsule-token", {"references": [REF | {"type": "capsule", "digest": PARENT}]}, []),
    ("external-capsule", {"references": [REF | {"citation_purpose": "responds_to"}]}, []),
    ("unknown-type-algorithm", {"references": [{"type": "future-artifact", "digest_alg": "future-hash", "digest": "opaque-digest"}]}, []),
    ("same-hex-other-type", {"references": [REF | {"type": "foreign-artifact", "digest": PARENT}]}, []),
    ("same-hex-other-algorithm", {"references": [REF | {"digest_alg": "future-hash", "digest": PARENT}]}, []),
    ("duplicate-parent", {"references": [REF | {"digest": PARENT}]}, ["reference_duplicates_chain_parent"]),
    ("future-purpose", {"references": [REF | {"citation_purpose": "example-purpose"}]}, ["unknown_registry_value"]),
    ("null-references", {"references": None}, ["references_malformed"]),
    ("object-references", {"references": {}}, ["references_malformed"]),
    ("nonobject-reference", {"references": [False]}, ["reference_malformed"]),
    ("missing-type", {"references": [{"digest_alg": "SHA-256", "digest": "b" * 64}]}, ["reference_malformed"]),
    ("empty-algorithm", {"references": [REF | {"digest_alg": ""}]}, ["reference_malformed"]),
    ("null-digest", {"references": [REF | {"digest": None}]}, ["reference_malformed"]),
    ("empty-digest", {"references": [REF | {"digest": ""}]}, ["reference_malformed"]),
    ("boolean-digest", {"references": [REF | {"digest": False}]}, ["reference_malformed"]),
    ("mixed-checks", {"operator": None, "references": [REF | {"digest": PARENT, "citation_purpose": "example-purpose"}]}, ["field_not_string", "reference_duplicates_chain_parent", "unknown_registry_value"]),
    ("bad-capsule-id", {"references": [REF | {"digest": "bad"}]}, ["reference_malformed"]),
    ("nonstring-purpose", {"references": [REF | {"citation_purpose": False}]}, ["reference_malformed"]),
    ("null-coordinates", {"references": [REF | {"log_coordinates": None}]}, ["reference_log_coordinates_malformed"]),
    ("partial-coordinates", {"references": [REF | {"log_coordinates": {"log_id": "example", "leaf_index": 0}}]}, ["reference_log_coordinates_malformed"]),
    ("opaque-proof", {"references": [REF | {"log_coordinates": {"log_id": "example", "leaf_index": 0, "inclusion_proof": {"future-format": "unverified"}}}]}, []),
    ("future-extension", {"references": [REF | {"future-member": {"value": 1}}]}, []),
]


def generate():
    cases = []
    for name, patch, codes in CASES:
        capsule = {
            "spec_version": "draft-mih-scitt-agent-action-capsule-04",
            "format_version": "4", "canonicalization_id": "jcs",
            "action_id": "reference/example", "action_type": "fyi",
            "operator": "example-org", "developer": "example-agent@v1",
            "timestamp": "2026-09-07T12:00:00Z",
            "chain": {"parent_capsule_id": PARENT, "relation": "confirms"},
            "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "chained"},
        } | patch
        if capsule["format_version"] == "2":
            capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-02"
            capsule.pop("canonicalization_id")
        capsule["capsule_id"] = compute_capsule_id(capsule)
        cases.append({"name": name, "capsule": capsule, "canonical": jcs(capsule).decode(), "ok": not any(c != "unknown_registry_value" for c in codes), "codes": codes})
    target = Path(__file__).with_name("references.json")
    target.write_text(json.dumps({"source": "draft-04 section 5.5.5; Python agent-action-capsule 0.2.0 JCS and identity", "cases": cases}, indent=2) + "\n")


if __name__ == "__main__":
    generate()
