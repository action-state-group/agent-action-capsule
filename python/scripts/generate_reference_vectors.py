#!/usr/bin/env python3
"""Generate draft-04 references[] Capsule-ID and verification vectors."""
from __future__ import annotations

import json
from pathlib import Path

from agent_action_capsule import compute_capsule_id, verify

OUT = Path(__file__).resolve().parents[2] / "vectors" / "capsule"
PARENT = "a" * 64
REF = {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": "b" * 64}

CASES = [
    ("absent", {}, "format 4 commits an absent references member as absent"),
    ("empty", {"references": []}, "format 4 commits a present empty references array"),
    ("vintage-extension", {"format_version": "2", "references": None}, "format 2 retains references as an extension"),
    ("unregistered-capsule-token", {"references": [REF | {"type": "capsule", "digest": PARENT}]}, "foreign artifact type remains open"),
    ("external-capsule", {"references": [REF | {"citation_purpose": "responds_to"}]}, "valid external Capsule citation"),
    ("unknown-type-algorithm", {"references": [{"type": "future-artifact", "digest_alg": "future-hash", "digest": "opaque-digest"}]}, "foreign digest contexts remain open"),
    ("same-hex-other-type", {"references": [REF | {"type": "foreign-artifact", "digest": PARENT}]}, "same digest under another artifact type is not the chain parent"),
    ("same-hex-other-algorithm", {"references": [REF | {"digest_alg": "future-hash", "digest": PARENT}]}, "same digest under another algorithm is not the chain parent"),
    ("duplicate-parent", {"references": [REF | {"digest": PARENT}]}, "AAC SHA-256 reference must not duplicate the chain parent"),
    ("future-purpose", {"references": [REF | {"citation_purpose": "example-purpose"}]}, "unknown citation purpose is informational"),
    ("null-references", {"references": None}, "format-4 references must be an array"),
    ("object-references", {"references": {}}, "format-4 references rejects an object"),
    ("nonobject-reference", {"references": [False]}, "each reference must be an object"),
    ("missing-type", {"references": [{"digest_alg": "SHA-256", "digest": "b" * 64}]}, "reference type is required"),
    ("empty-algorithm", {"references": [REF | {"digest_alg": ""}]}, "reference digest algorithm is non-empty"),
    ("null-digest", {"references": [REF | {"digest": None}]}, "reference digest is a string"),
    ("empty-digest", {"references": [REF | {"digest": ""}]}, "reference digest is non-empty"),
    ("boolean-digest", {"references": [REF | {"digest": False}]}, "reference digest rejects boolean"),
    ("mixed-checks", {"operator": None, "references": [REF | {"digest": PARENT, "citation_purpose": "example-purpose"}]}, "reference findings retain Class-1 check order"),
    ("bad-capsule-id", {"references": [REF | {"digest": "bad"}]}, "AAC SHA-256 reference requires a Capsule ID"),
    ("nonstring-purpose", {"references": [REF | {"citation_purpose": False}]}, "citation purpose is a non-empty string"),
    ("null-coordinates", {"references": [REF | {"log_coordinates": None}]}, "log coordinates must be an object"),
    ("partial-coordinates", {"references": [REF | {"log_coordinates": {"log_id": "example", "leaf_index": 0}}]}, "log coordinates requires all three members"),
    ("opaque-proof", {"references": [REF | {"log_coordinates": {"log_id": "example", "leaf_index": 0, "inclusion_proof": {"future-format": "unverified"}}}]}, "Class 1 preserves opaque inclusion proof contents"),
    ("future-extension", {"references": [REF | {"future-member": {"value": 1}}]}, "reference extension members remain committed and open"),
    ("local-only-envelope-fields", {"signature": "detached-signature", "key_id": "local-key"}, "local Producer Envelope fields are excluded from format-4 Capsule ID"),
]


def expected(result, description: str) -> dict:
    return {
        "description": description,
        "kind": "positive" if result.ok else "negative",
        "ok": result.ok,
        "derived": result.assurance,
        "capsule_id_recomputed": result.capsule_id,
        "findings": [
            {"check": item.check, "severity": item.severity, "code": item.code, "detail": item.detail}
            for item in result.findings
        ],
    }


def main() -> None:
    for name, patch, description in CASES:
        capsule = {
            "spec_version": "draft-mih-scitt-agent-action-capsule-04",
            "format_version": "4",
            "canonicalization_id": "jcs",
            "action_id": "reference/example",
            "action_type": "fyi",
            "operator": "example-org",
            "developer": "example-agent@v1",
            "timestamp": "2026-09-07T12:00:00Z",
            "chain": {"parent_capsule_id": PARENT, "relation": "confirms"},
            "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "chained"},
        } | patch
        if capsule["format_version"] == "2":
            capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-02"
            capsule.pop("canonicalization_id")
        capsule["capsule_id"] = compute_capsule_id(capsule)
        directory = OUT / f"reference-{name}"
        directory.mkdir(exist_ok=True)
        result = verify(capsule)
        (directory / "input.json").write_text(json.dumps(capsule, indent=2) + "\n", encoding="utf-8")
        (directory / "expected.json").write_text(
            json.dumps(expected(result, description), indent=2) + "\n", encoding="utf-8"
        )

    source = OUT / "reference-external-capsule" / "input.json"
    tampered = json.loads(source.read_text(encoding="utf-8"))
    tampered["references"][0]["digest"] = "c" * 64
    description = "changing a format-4 reference after sealing causes Capsule ID mismatch"
    directory = OUT / "reference-tampered-after-seal"
    directory.mkdir(exist_ok=True)
    (directory / "input.json").write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
    (directory / "expected.json").write_text(
        json.dumps(expected(verify(tampered), description), indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
