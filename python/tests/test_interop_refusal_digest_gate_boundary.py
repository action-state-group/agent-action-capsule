"""AAC <-> refusal-digest gate-boundary vector (docs/interop/aac-refusal-digest-gate-boundary/).

A blocked Capsule and a refusal digest over the same attempt. This file runs the
Capsule side: the Class 1 checks each case must fail (by check number), the
manifest-dependent evidence check reported separately, and the cross-format
joins. The digest side runs through the public browser verifier
(check_digest.mjs in the vector directory); its expected results are in the
same vector.json.

A compatibility experiment: no commitment to adoption, integration or
specification change.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from agent_action_capsule.canonical import json_digest
from agent_action_capsule.verify import verify

DIR = Path(__file__).resolve().parents[2] / "docs" / "interop" / "aac-refusal-digest-gate-boundary"
VECTOR = json.loads((DIR / "vector.json").read_text())
MANIFEST = json.loads((DIR / "capsule" / "manifest.json").read_text())
GOLDEN = json.loads((DIR / "digest" / "d-golden.json").read_text())


def _load(rel: str):
    return json.loads((DIR / rel).read_text())


def manifest_dependent(capsule: dict, ev: dict) -> str:
    """Class 2 for this vector: the evidence matches the manifest's schema and the
    constraint's evidence_digest recomputes over it."""
    (record,) = capsule["constraints"]
    schema = MANIFEST["constraints"][record["id"]]["evidence_schema"]
    if any(k not in ev for k in schema["required"]):
        return "fail:evidence_schema"
    if any(k not in ev["refusal_digest"] for k in schema["refusal_digest.required"]):
        return "fail:evidence_schema"
    if json_digest(ev) != record["evidence_digest"]:
        return "fail:evidence_digest"
    return "pass"


def cross_format(capsule: dict, ev: dict, digest: dict) -> str:
    probe = next((p for p in digest["probes"] if p["id"] == ev["probe_id"]), None)
    if (capsule["action_id"] != f"{ev['probe_id']}@{ev['run_seed']}" or probe is None
            or probe["outcome"] != "refused" or digest["run"]["seed"] != ev["run_seed"]):
        return "fail:attempt_join"
    if (ev["refusal_digest"]["digest_hash"] != digest["proof"]["digest_hash"]
            or ev["refusal_ground"] != probe["refusal_ground"]
            or ev["forbidden_event_types"] != probe["forbidden_event_types"]):
        return "fail:digest_binding"
    return "pass"


@pytest.mark.parametrize("row", VECTOR["capsule_cases"], ids=lambda r: r["case"])
def test_class1_fails_at_the_named_checks(row):
    result = verify(_load(row["file"]))
    failed = sorted({f.check for f in result.errors})
    assert result.ok is (row["class1"] == "pass"), [str(f) for f in result.errors]
    assert failed == row["class1_failing_checks"], [str(f) for f in result.errors]


@pytest.mark.parametrize("row", VECTOR["capsule_cases"], ids=lambda r: r["case"])
def test_manifest_dependent_checks_are_reported_separately(row):
    assert manifest_dependent(_load(row["file"]), _load(row["evidence"])) == row["manifest_dependent"]


@pytest.mark.parametrize("row", VECTOR["capsule_cases"], ids=lambda r: r["case"])
def test_cross_format_joins(row):
    if row["cross_format"] == "n/a":  # evidence not trusted once its digest fails
        assert row["manifest_dependent"] != "pass"
        return
    assert cross_format(_load(row["file"]), _load(row["evidence"]), GOLDEN) == row["cross_format"]


def test_the_check5_case_differs_from_the_control_only_by_the_attestation():
    control = _load("capsule/c-blocked-control.json")
    resealed = _load("capsule/c-gate-executed-resealed.json")
    strip = lambda c: {k: v for k, v in c.items() if k not in ("capsule_id", "effect")}  # noqa: E731
    assert strip(control) == strip(resealed)
    assert resealed["effect"] == {"status": "planned", "effect_attestation": "gate_executed"}
    assert verify(control).ok and [f.check for f in verify(resealed).errors] == [5]


def test_every_file_regenerates_byte_for_byte():
    pytest.importorskip("cryptography")
    spec = importlib.util.spec_from_file_location("gate_boundary_generate", DIR / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for name, data in gen.build().items():
        assert (DIR / name).read_bytes() == data, name
