# SPDX-License-Identifier: BSD-3-Clause
"""Strict ``verify_bundle`` against ``vectors/bundle/parent-log-witness``."""
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
from agent_action_capsule.parent_witness import PARENT_LOG_WITNESS_KIND  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "vectors" / "bundle" / "parent-log-witness"
VECTORS = json.loads((DIR / "vectors.json").read_text())


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    (tmp_path / "README.md").write_bytes((DIR / "README.md").read_bytes())
    script = ROOT / "python" / "scripts" / "generate_bundle_parent_witness_vectors.py"
    subprocess.run([sys.executable, str(script), "--out", str(tmp_path)], check=True)
    for path in DIR.iterdir():
        assert (tmp_path / path.name).read_bytes() == path.read_bytes(), path.name


def test_sha256sums_pin_every_file():
    lines = (DIR / "SHA256SUMS").read_text().splitlines()
    assert {line.split()[1] for line in lines} == {p.name for p in DIR.iterdir()} - {"SHA256SUMS"}
    for line in lines:
        digest, name = line.split()
        assert hashlib.sha256((DIR / name).read_bytes()).hexdigest() == digest, name


def test_case_ids_are_unique_and_listed_in_the_readme():
    readme = (DIR / "README.md").read_text()
    ids = [c["id"] for c in VECTORS["cases"]]
    assert len(ids) == len(set(ids))
    for case_id in ids:
        assert f"`{case_id}`" in readme, case_id


#: Every finding the draft names for a broken link (-03, "The
#: parent-log-witness/v1 Extension"), each of which needs a failing vector.
LINK_FINDINGS = {
    "parent_witness_malformed",
    "parent_witness_earlier_checkpoint_malformed",
    "parent_witness_earlier_checkpoint_signature_invalid",
    "parent_witness_earlier_checkpoint_not_this_log",
    "parent_witness_earlier_checkpoint_not_a_prefix",
    "parent_witness_leaf_does_not_name_this_checkpoint",
    "parent_witness_path_malformed",
    "parent_witness_leaf_malformed",
    "parent_witness_parent_checkpoint_malformed",
    "parent_witness_parent_checkpoint_signature_invalid",
    "parent_witness_parent_signer_differs",
    "parent_witness_parent_log_id_mismatch",
    "parent_witness_entry_not_included",
}


def test_every_link_finding_has_a_failing_vector():
    failing = {
        f
        for c in VECTORS["cases"]
        if (c["expect"]["parent_witness"] or {}).get("status") == "fail"
        for f in c["expect"]["parent_witness"]["findings"]
    }
    assert LINK_FINDINGS <= failing


def _observed(result) -> dict:
    pw = result.parent_witness
    observed = {
        "verdict": result.verdict,
        "parent_witness": None
        if pw is None
        else {
            "status": pw.status,
            "findings": list(pw.findings),
            "extent": None if pw.extent is None else {"entries": pw.extent[0], "of": pw.extent[1]},
            "receipts": [
                {"ts_url": r.ts_url, "binding": r.binding, "status": r.status, "grade": r.grade,
                 "key_id": r.key_id, "registration_time": r.registration_time,
                 "registration_time_reason": r.registration_time_reason}
                for r in pw.receipts
            ],
        },
        "witnesses": {"status": result.witnesses.status, "findings": list(result.witnesses.findings)},
    }
    statuses = [e.status for e in result.extensions if e.kind == PARENT_LOG_WITNESS_KIND]
    if statuses:
        observed["extension_status"] = statuses[0]
    return observed


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_parent_witness_case(case):
    directory = VECTORS["witness_directory"] if case["options"]["witness_directory"] else None
    result = verify_bundle(case["bundle"], strict=True, witness_directory=directory)
    observed = _observed(result)
    expect = case["expect"]
    for name, value in expect.items():
        assert observed[name] == value, name
    if "extension_status" not in expect:
        assert "extension_status" not in observed


def test_plain_mode_leaves_the_block_uninterpreted():
    case = next(c for c in VECTORS["cases"] if c["id"] == "pos-witnessed-whole")
    result = verify_bundle(case["bundle"])
    assert result.parent_witness is None
    assert [e.status for e in result.extensions if e.kind == PARENT_LOG_WITNESS_KIND] == ["uninterpreted"]


def test_a_salt_jcs_cannot_write_is_a_malformed_leaf():
    case = next(c for c in VECTORS["cases"] if c["id"] == "pos-witnessed-whole")
    bundle = json.loads(json.dumps(case["bundle"]))
    bundle["extensions"][PARENT_LOG_WITNESS_KIND]["salt"] = "\ud800"
    result = verify_bundle(bundle, strict=True, witness_directory=VECTORS["witness_directory"])
    assert result.parent_witness.status == "fail"
    assert result.parent_witness.findings == ("parent_witness_leaf_malformed",)
