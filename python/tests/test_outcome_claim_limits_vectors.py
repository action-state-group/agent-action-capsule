# SPDX-License-Identifier: BSD-3-Clause
"""The outcome-claim-limit vectors (``vectors/outcome-claim-limits``).

Checks that the committed files are pinned and regenerate byte for byte, that
the Capsule pair runs through the Class-1 verifier with the pinned result,
that a reader applying the ``physical_proof`` rule refuses the negative and
accepts its twin, and that every mutant flips the result. The countersignature
pair is classified by the TypeScript stamp (``ts/test/outcome-claim-limits.test.ts``);
this file checks that its Bundles are the producer-key vectors verbatim and
that their digests are the reference library's.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from agent_action_capsule.bundle import bundle_digest
from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.verify import verify

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "outcome-claim-limits"
GENERATOR = ROOT / "python" / "scripts" / "generate_outcome_claim_limits_vectors.py"

pytestmark = pytest.mark.skipif(not VECTORS.exists(), reason="source-tree vectors not present")


def _corpus() -> dict:
    return json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))


def _cases(kind: str) -> list[dict]:
    return [c for c in _corpus()["cases"] if kind in c]


def _class1(capsule: dict) -> dict:
    result = verify(capsule)
    return {
        "ok": result.ok,
        "derived": dict(result.assurance),
        "finding_codes": [f.code for f in result.findings],
    }


def physical_proof(capsule: dict) -> dict:
    """The ``physical_proof`` rule: the Class-1 result, then the payload grade.

    Unknown and unregistered grades are no stronger than ``runtime_claimed``
    (REGISTRY §5), so only ``gate_executed`` is accepted.
    """
    c1 = _class1(capsule)
    grade = capsule.get("effect", {}).get("effect_attestation")
    if not c1["ok"] or c1["derived"].get("effect_mode") != "confirmed" or grade != "gate_executed":
        return {"accept": False, "reason": "physical_completion_absent"}
    return {"accept": True, "observed_by": "gate"}


def _set(capsule: dict, changes: dict[str, Any]) -> dict:
    out = copy.deepcopy(capsule)
    for path, value in changes.items():
        *parents, leaf = path.split(".")
        node = out
        for name in parents:
            node = node[name]
        node[leaf] = value
    out["capsule_id"] = compute_capsule_id(out)
    return out


def _verdict(expect: dict) -> dict:
    return {k: v for k, v in expect.items() if k in ("accept", "reason", "observed_by")}


def test_files_are_pinned_and_regenerate_byte_for_byte() -> None:
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    on_disk = {p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk == {"README.md", "vectors.json"}
    for name, digest in listed.items():
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in on_disk:
        assert top.get(f"outcome-claim-limits/{name}") == listed[name], name

    spec = importlib.util.spec_from_file_location("gen_outcome_claim_limits", GENERATOR)
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    for name, data in generator.build().items():
        assert data == (VECTORS / name).read_bytes(), name


def test_every_negative_has_a_positive_twin_and_every_case_a_mutant() -> None:
    corpus = _corpus()
    cases = {c["id"]: c for c in corpus["cases"]}
    assert corpus["count"] == len(cases) == 4
    for case in cases.values():
        twin = cases[case["twin"]]
        assert twin["twin"] == case["id"]
        assert {case["kind"], twin["kind"]} == {"negative", "positive"}
        assert twin["consumer_intent"] == case["consumer_intent"]
        assert case["mutants"], case["id"]


@pytest.mark.parametrize("case", _cases("capsule"), ids=lambda c: c["id"])
def test_capsule_case(case: dict) -> None:
    capsule = case["capsule"]
    assert compute_capsule_id(capsule) == capsule["capsule_id"]
    assert _class1(capsule) == case["expect"]["class1"]
    assert capsule["effect"]["effect_attestation"] == case["expect"]["grade"]
    assert physical_proof(capsule) == _verdict(case["expect"])


@pytest.mark.parametrize(
    "case,mutant",
    [(c, m) for c in _cases("capsule") for m in c["mutants"]],
    ids=lambda v: v["id"] if "id" in v else "/".join(v["set"].values()),
)
def test_capsule_mutant_flips(case: dict, mutant: dict) -> None:
    mutated = _set(case["capsule"], mutant["set"])
    # The mutant is still a valid Capsule, so the flip comes from the rule, not
    # from a broken identity or a Class-1 failure.
    assert _class1(mutated)["ok"] is True
    got = physical_proof(mutated)
    assert got["accept"] == mutant["expect"]["accept"]
    assert got.get("reason") == mutant["expect"].get("reason")
    assert got["accept"] != case["expect"]["accept"]


def test_class1_result_does_not_distinguish_the_twins() -> None:
    """What the Class-1 verifier reports is the same for a runtime's claim and a
    gate observation: the grade is in the payload, not in derived assurance.
    A reader that consults only the Class-1 result cannot tell the twins apart."""
    neg, pos = _cases("capsule")
    assert neg["capsule"]["capsule_id"] != pos["capsule"]["capsule_id"]
    strip = lambda c: {k: v for k, v in c.items() if k not in ("capsule_id", "effect")}  # noqa: E731
    assert strip(neg["capsule"]) == strip(pos["capsule"])
    assert {k: v for k, v in neg["capsule"]["effect"].items() if k != "effect_attestation"} == {
        k: v for k, v in pos["capsule"]["effect"].items() if k != "effect_attestation"
    }
    assert _class1(neg["capsule"]) == _class1(pos["capsule"])
    assert "effect_attestation" not in _class1(neg["capsule"])["derived"]


def _bundles(case: dict) -> list[tuple[dict, dict, str]]:
    out = [(case["source"], case["bundle"], case["bundle_digest"])]
    out += [(m["source"], m["bundle"], m["bundle_digest"]) for m in case["mutants"] if "bundle" in m]
    return out


@pytest.mark.parametrize("case", _cases("bundle"), ids=lambda c: c["id"])
def test_bundle_case_is_the_producer_key_vector_verbatim(case: dict) -> None:
    for source, bundle, digest in _bundles(case):
        corpus = json.loads((ROOT / source["file"]).read_text(encoding="utf-8"))
        (original,) = [c for c in corpus["cases"] if c["id"] == source["case"]]
        assert bundle == original["bundle"]
        assert digest == original["bundle_digest"] == bundle_digest(bundle)
