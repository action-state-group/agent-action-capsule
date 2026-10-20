# SPDX-License-Identifier: BSD-3-Clause
"""``verify_bundle(..., strict=True)`` against ``vectors/bundle/non-record-leaves``
and ``vectors/bundle/certificate-mode`` (Evidence Bundle -02)."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cll.checkpoint.index")
pytest.importorskip("scitt_cose")

from agent_action_capsule.bundle import verify_bundle  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DIRS = {name: ROOT / "vectors" / "bundle" / name for name in ("non-record-leaves", "certificate-mode")}
CASES = [
    (name, case)
    for name, directory in DIRS.items()
    for case in json.loads((directory / "vectors.json").read_text())["cases"]
]


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name, directory in DIRS.items():
        (tmp_path / name).mkdir()
        (tmp_path / name / "README.md").write_bytes((directory / "README.md").read_bytes())
    script = ROOT / "python" / "scripts" / "generate_bundle_02_vectors.py"
    subprocess.run([sys.executable, str(script), "--out", str(tmp_path)], check=True)
    for name, directory in DIRS.items():
        assert sorted(p.name for p in (tmp_path / name).iterdir()) == sorted(p.name for p in directory.iterdir())
        for path in directory.iterdir():
            assert (tmp_path / name / path.name).read_bytes() == path.read_bytes(), f"{name}/{path.name}"


@pytest.mark.parametrize("name", sorted(DIRS))
def test_sha256sums_pin_every_file(name):
    directory = DIRS[name]
    lines = (directory / "SHA256SUMS").read_text().splitlines()
    assert {line.split()[1] for line in lines} == {p.name for p in directory.iterdir()} - {"SHA256SUMS"}
    for line in lines:
        digest, file = line.split()
        assert hashlib.sha256((directory / file).read_bytes()).hexdigest() == digest, file
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for path in directory.iterdir():
        if path.name == "SHA256SUMS":  # the top-level list leaves out per-directory lists
            continue
        assert top[f"bundle/{name}/{path.name}"] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("name", sorted(DIRS))
def test_case_ids_are_unique_and_listed_in_the_readme(name):
    readme = (DIRS[name] / "README.md").read_text()
    ids = [case["id"] for n, case in CASES if n == name]
    assert ids and len(ids) == len(set(ids))
    for case_id in ids:
        assert f"`{case_id}`" in readme, case_id
    manifest = json.loads((DIRS[name] / "manifest.json").read_text())
    assert manifest["case_count"] == len(ids)


def test_the_corpus_covers_each_verdict_and_every_leaf_finding():
    verdicts = {case["expect"]["verdict"] for _, case in CASES}
    assert verdicts == {"VALID", "INCOMPLETE", "INVALID"}
    findings = {
        finding.split(":")[0]
        for _, case in CASES
        for claim in case["expect"]["claims"]
        for finding in claim["findings"]
    }
    assert {
        "non_record_leaves_malformed",
        "non_record_leaf_element_invalid",
        "non_record_leaf_seq_invalid",
        "non_record_leaf_malformed",
        "non_record_leaf_type_unsupported",
        "non_record_leaf_mismatch",
        "membership_record_missing",
        "completeness_certificate_invalid",
        "certificate_mode_unsupported",
        "selection_not_checkable",
    } <= findings


def _observed(result) -> dict:
    return {
        "verdict": result.verdict,
        "kind_ok": result.kind_ok,
        "claims": [{"name": n, "status": c.status, "findings": list(c.findings)} for n, c in result.claims],
        "witnesses": {
            "status": result.witnesses.status,
            "findings": list(result.witnesses.findings),
            "receipts": [],
        },
        "records": [
            {"capsule_id": r.capsule_id, "identity_ok": r.identity_ok, "signature": r.signature,
             "key_id": r.key_id, "seq": r.seq}
            for r in result.records
        ],
        "checkpoint_authenticated": bool(result.signed_checkpoint),
        "signer_matches_checkpoint": result.signer_matches_checkpoint,
    }


@pytest.mark.parametrize("case", [c for _, c in CASES], ids=lambda c: c["id"])
def test_strict_case(case):
    assert case["options"] == {"require_signature": False, "witness_directory": False}
    result = verify_bundle(case["bundle"], strict=True)
    assert _observed(result) == {"kind_ok": True, **case["expect"]}


def test_padding_content_is_the_evidence_layer_padding_serialization():
    """Every carried padding content passes the Evidence Layer padding cases'
    rules: the same four members and the same capsule_id preimage."""
    whole = next(c for n, c in CASES if c["id"] == "pos-padded-whole-log")["bundle"]
    for element in whole["completeness_certificate"]["non_record_leaves"]:
        content = element["content"]
        assert sorted(content) == ["capsule_id", "epistemic_type", "record_type", "store_nonce"]
        preimage = json.dumps({k: v for k, v in content.items() if k != "capsule_id"}, sort_keys=True,
                              separators=(",", ":"))
        assert hashlib.sha256(preimage.encode()).hexdigest() == content["capsule_id"]
