# SPDX-License-Identifier: BSD-3-Clause
"""``verify_bundle(..., strict=True)`` against ``vectors/bundle/strict``."""
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
from agent_action_capsule.producer_envelope import verify_record_signature  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "vectors" / "bundle" / "strict"
VECTORS = json.loads((DIR / "vectors.json").read_text())


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    (tmp_path / "README.md").write_bytes((DIR / "README.md").read_bytes())
    script = ROOT / "python" / "scripts" / "generate_bundle_strict_vectors.py"
    subprocess.run([sys.executable, str(script), "--out", str(tmp_path)], check=True)
    for path in DIR.iterdir():
        assert (tmp_path / path.name).read_bytes() == path.read_bytes(), path.name


def test_sha256sums_pin_every_file():
    lines = (DIR / "SHA256SUMS").read_text().splitlines()
    names = {line.split()[1] for line in lines}
    assert names == {p.name for p in DIR.iterdir()} - {"SHA256SUMS"}
    for line in lines:
        digest, name = line.split()
        assert hashlib.sha256((DIR / name).read_bytes()).hexdigest() == digest, name


def test_case_ids_are_unique_and_listed_in_the_readme():
    readme = (DIR / "README.md").read_text()
    ids = [c["id"] for c in VECTORS["cases"]] + [c["id"] for c in VECTORS["record_signatures"]]
    assert len(ids) == len(set(ids))
    for case_id in ids:
        assert f"`{case_id}`" in readme, case_id


def _observed(result) -> dict:
    witnesses = None
    if result.witnesses is not None:
        witnesses = {
            "status": result.witnesses.status,
            "findings": list(result.witnesses.findings),
            "receipts": [
                {"ts_url": r.ts_url, "binding": r.binding, "status": r.status, "grade": r.grade,
                 "key_id": r.key_id, "registration_time": r.registration_time,
                 "registration_time_reason": r.registration_time_reason}
                for r in result.witness_receipts
            ],
        }
    return {
        "verdict": result.verdict,
        "kind_ok": result.kind_ok,
        "claims": [{"name": n, "status": c.status, "findings": list(c.findings)} for n, c in result.claims],
        "witnesses": witnesses,
        "records": [
            {"capsule_id": r.capsule_id, "identity_ok": r.identity_ok, "signature": r.signature,
             "key_id": r.key_id, "seq": r.seq}
            for r in result.records
        ],
        "checkpoint_authenticated": bool(result.signed_checkpoint),
        "signer_matches_checkpoint": result.signer_matches_checkpoint,
    }


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_strict_case(case):
    options = case["options"]
    result = verify_bundle(
        case["bundle"],
        strict=True,
        require_signature=options["require_signature"],
        witness_directory=VECTORS["witness_directory"] if options["witness_directory"] else None,
    )
    expect = {"kind_ok": True, **case["expect"]}
    assert _observed(result) == expect


@pytest.mark.parametrize("case", VECTORS["record_signatures"], ids=lambda c: c["id"])
def test_record_signature_case(case):
    verdict, messages = verify_record_signature(case["record"])
    assert verdict == case["expect"]
    assert bool(messages) == (verdict == "invalid")


def test_non_strict_results_are_unchanged_by_the_strict_fields():
    bundle = VECTORS["cases"][0]["bundle"]
    plain = verify_bundle(bundle)
    assert plain.verdict is None and plain.ok is None and plain.claims == ()
    assert plain.signatures is None and plain.witnesses is None and plain.records == ()
