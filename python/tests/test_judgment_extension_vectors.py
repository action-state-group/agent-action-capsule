# SPDX-License-Identifier: BSD-3-Clause
"""The judgment extension vectors (provisional) recompute from the files alone.

Every digest check below is an independent reading of the proposed rules in
``vectors/judgment/README.md``: it uses only the standard library, an
independent RFC 8785 implementation, and the bytes in ``vectors/judgment/``.
Nothing is imported from the generator. The base-profile checks (Capsule ID,
Class 1) use this repository's reference library.
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_action_capsule import compute_capsule_id
from agent_action_capsule.verify import verify

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "judgment"
SCHEMA_PATH = ROOT / "schemas" / "judgment" / "judgment-extension-v1.json"
GENERATOR = ROOT / "python" / "scripts" / "generate_judgment_extension_vectors.py"
HAND_WRITTEN = ("README.md",)
MEMBER = "x-judgment-v1"

DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in DATA["cases"]}
POSITIVE = [c["id"] for c in DATA["cases"] if c["kind"] == "positive"]
ALL = list(CASES)


def _jcs(value: Any) -> str:
    # RFC 8785 for these vectors' value space (ASCII keys, no floats).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_digest(value: Any) -> str:
    return _sha(_jcs(value).encode("utf-8"))


def _raw(name: str) -> str:
    return _sha(DATA["raw_files"][name].encode("utf-8"))


def _member(capsule: dict) -> dict:
    return capsule["model_attestation"]["compute_attestation"].get(MEMBER, {})


def _cites(capsule: dict, purpose: str) -> list[str]:
    return [r["digest"] for r in capsule.get("references", []) if r.get("citation_purpose") == purpose]


def check_judgment(case: dict) -> list[str]:
    """The extension's digest checks, as a verifier holding the preimages runs them."""
    capsule, values = case["capsule"], case["preimages"]["values"]
    member = _member(capsule)
    findings = []
    if member.get("rubric_digest") != _json_digest(values["rubric"]):
        findings.append("rubric_digest_mismatch")
    if member.get("judge_parameters_digest") != _json_digest(values["judge_parameters"]):
        findings.append("judge_parameters_digest_mismatch")
    if capsule["model_attestation"]["compute_attestation"]["agent_output_digest"] != _json_digest(values["agent_output"]):
        findings.append("agent_output_digest_mismatch")
    if len(_cites(capsule, "judged_from")) != 1:
        findings.append("judged_from_count")
    return findings


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    committed = sorted(p.name for p in VECTORS.iterdir() if p.is_file())
    assert committed == sorted(p.name for p in tmp_path.iterdir() if p.is_file())
    for name in committed:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_pin_every_file():
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    on_disk = {p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in on_disk:
        assert top.get(f"judgment/{name}") == _sha((VECTORS / name).read_bytes()), name


def test_cases_and_provisional_status():
    assert DATA["count"] == len(DATA["cases"]) == 4
    assert set(POSITIVE) == {"pos-ai-judge", "pos-human-expert"}
    assert "PROVISIONAL" in DATA["status"] and "unratified" in DATA["status"]
    assert "proposed and unratified" in (VECTORS / "README.md").read_text(encoding="utf-8")
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora["judgment"] == "judgment/manifest.json"


# ---------------------------------------------------------------------------
# Digests recompute from the preimages
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", ALL)
def test_canonical_strings_are_rfc8785(case_id):
    rfc8785 = pytest.importorskip("rfc8785")
    pre = CASES[case_id]["preimages"]
    assert set(pre["values"]) == set(pre["canonical"])
    for name, value in pre["values"].items():
        assert pre["canonical"][name] == _jcs(value), name
        assert pre["canonical"][name].encode("utf-8") == rfc8785.dumps(value), name


@pytest.mark.parametrize("case_id", ALL)
def test_capsule_id_recomputes_and_class1_passes(case_id):
    capsule = CASES[case_id]["capsule"]
    body = {k: v for k, v in capsule.items() if k != "capsule_id"}
    assert capsule["capsule_id"] == _json_digest(body) == compute_capsule_id(capsule)
    assert CASES[case_id]["expect"]["capsule_id"] == capsule["capsule_id"]
    result = verify(capsule)
    assert result.ok, result.findings
    # judged_from / calibrated_against are pending registration: informational only.
    assert {f.code for f in result.findings} <= {"unknown_registry_value"}
    assert all(f.severity == "info" for f in result.findings)


def test_evidence_capsule_verifies():
    evidence = DATA["evidence"]
    assert evidence["capsule_id"] == compute_capsule_id(evidence)
    assert verify(evidence).ok


def test_inner_digests_recompute():
    ai = CASES["pos-ai-judge"]["preimages"]["values"]
    params = ai["judge_parameters"]
    assert params["instruction_template_digest"] == _json_digest(ai["instruction_template"])
    assert params["prompt_file_digest"] == _raw("judge-prompt.md")
    assert params["axes_digest"] == _raw("axes.json")
    for case in DATA["cases"]:
        assert case["preimages"]["values"]["rubric"]["policy_digest"] == _raw("policy.md")
    expert = CASES["pos-human-expert"]["preimages"]["values"]
    assert expert["judge_parameters"]["packet_digest"] == _json_digest(expert["packet"])
    assert expert["packet"]["evidence"] == DATA["evidence"]["capsule_id"]
    assert expert["packet"]["rubric_digest"] == _json_digest(expert["rubric"])


@pytest.mark.parametrize("case_id", POSITIVE)
def test_positive_digests_all_recompute(case_id):
    case = CASES[case_id]
    assert check_judgment(case) == []
    member = _member(case["capsule"])
    expect = case["expect"]["digests"]
    assert expect["rubric_digest"] == member["rubric_digest"]
    assert expect["judge_parameters_digest"] == member["judge_parameters_digest"]
    assert expect["judged_from"] == _cites(case["capsule"], "judged_from") == [DATA["evidence"]["capsule_id"]]


def test_ai_and_expert_judge_the_same_evidence_under_the_same_rubric():
    ai, expert = CASES["pos-ai-judge"]["capsule"], CASES["pos-human-expert"]["capsule"]
    assert _member(ai)["rubric_digest"] == _member(expert)["rubric_digest"]
    assert _member(ai)["rubric_version"] == _member(expert)["rubric_version"]
    assert _cites(ai, "judged_from") == _cites(expert, "judged_from")
    assert _member(ai)["judge_parameters_digest"] != _member(expert)["judge_parameters_digest"]
    assert ai["developer"] != expert["developer"]
    assert _cites(ai, "calibrated_against") == [expert["capsule_id"]]


def test_judge_identity_is_not_in_judge_parameters():
    # developer carries the judge; the parameters never duplicate it.
    for case_id in POSITIVE:
        values = CASES[case_id]["preimages"]["values"]["judge_parameters"]
        assert CASES[case_id]["capsule"]["developer"] not in _jcs(values)


def test_params_mismatch_is_detected_and_only_that():
    case = CASES["neg-judge-parameters-digest-mismatch"]
    assert check_judgment(case) == ["judge_parameters_digest_mismatch"]
    assert case["expect"]["recomputed_judge_parameters_digest"] == _json_digest(
        case["preimages"]["values"]["judge_parameters"])
    assert [f["code"] for f in case["expect"]["findings"]] == ["judge_parameters_digest_mismatch"]


def test_missing_rubric_version_digests_still_recompute():
    case = CASES["neg-missing-rubric-version"]
    assert "rubric_version" not in _member(case["capsule"])
    assert check_judgment(case) == []


@pytest.mark.parametrize("field", ["rubric", "judge_parameters", "agent_output"])
def test_any_preimage_change_is_detected(field):
    case = copy.deepcopy(CASES["pos-ai-judge"])
    value = case["preimages"]["values"][field]
    key = sorted(value)[0]
    value[key] = "changed" if value[key] != "changed" else "changed-again"
    assert check_judgment(case) != []


# ---------------------------------------------------------------------------
# Schema (skipped where jsonschema is not installed; CI runs
# schemas/check_judgment_extension_examples.py with it)
# ---------------------------------------------------------------------------


def _validator(def_name: str | None = None):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if def_name is not None:
        schema = {**schema, "$ref": f"#/$defs/{def_name}"}
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize("case_id", ALL)
def test_schema_verdict_matches_expectation(case_id):
    case = CASES[case_id]
    assert _validator().is_valid(case["capsule"]) is case["expect"]["schema_valid"]


def test_preimages_validate_against_their_defs():
    ai = CASES["pos-ai-judge"]["preimages"]["values"]
    expert = CASES["pos-human-expert"]["preimages"]["values"]
    assert _validator("JudgeParameters").is_valid(ai["judge_parameters"])
    assert _validator("ExpertProtocolParameters").is_valid(expert["judge_parameters"])
    for values in (ai, expert):
        assert _validator("RubricDocument").is_valid(values["rubric"])
        assert _validator("JudgeAnswer").is_valid(values["agent_output"])


@pytest.mark.parametrize("mutation", ["no-judged-from", "two-judged-from", "extra-member", "upper-hex"])
def test_schema_rejects_mutations(mutation):
    capsule = copy.deepcopy(CASES["pos-ai-judge"]["capsule"])
    refs = capsule["references"]
    member = capsule["model_attestation"]["compute_attestation"][MEMBER]
    if mutation == "no-judged-from":
        capsule["references"] = [r for r in refs if r["citation_purpose"] != "judged_from"]
    elif mutation == "two-judged-from":
        refs.append({**refs[0], "digest": "0" * 64})
    elif mutation == "extra-member":
        member["model_id"] = "example-judge-model"
    elif mutation == "upper-hex":
        member["rubric_digest"] = member["rubric_digest"].upper()
    assert not _validator().is_valid(capsule)
