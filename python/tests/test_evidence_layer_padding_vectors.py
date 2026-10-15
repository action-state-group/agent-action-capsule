# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Layer padding vectors check from the files alone.

The shape rules below are an independent reading of the padding paragraph in
``spec/draft-mih-agent-evidence-layer-00.md`` and of
``vectors/evidence-layer/padding/README.md``. Nothing is imported from the
generator.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "evidence-layer" / "padding"
DRAFT = ROOT / "spec" / "draft-mih-agent-evidence-layer-00.md"
GENERATOR = ROOT / "python" / "scripts" / "generate_evidence_layer_padding_vectors.py"
HAND_WRITTEN = ("README.md",)

DATA = json.loads((VECTORS / "cases.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in DATA["cases"]}
NONCE = re.compile(r"[0-9a-f]{64}")
MEMBERS = {"capsule_id", "record_type", "epistemic_type", "store_nonce"}


def _jcs(value: Any) -> str:
    # RFC 8785 for these vectors' value space (ASCII keys and strings, no floats).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_jcs(value).encode("utf-8")).hexdigest()


def _preimage(record: dict) -> dict:
    return {k: v for k, v in record.items() if k != "capsule_id"}


def _check(record: dict) -> tuple[str, str] | None:
    """The first broken rule as (reason, member), or None for a valid padding record."""
    assert record.get("record_type") == "padding"
    if "store_nonce" not in record:
        return "missing_store_nonce", "store_nonce"
    nonce = record["store_nonce"]
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        return "store_nonce_encoding", "store_nonce"
    extra = sorted(set(record) - MEMBERS)
    if extra:
        return "extra_member", extra[0]
    if record.get("epistemic_type") != "producer_claim":
        return "epistemic_type", "epistemic_type"
    if record.get("capsule_id") != _digest(_preimage(record)):
        return "capsule_id_mismatch", "capsule_id"
    return None


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    committed = sorted(p.name for p in VECTORS.iterdir() if p.is_file())
    assert committed == sorted(p.name for p in tmp_path.iterdir() if p.is_file())
    for name in committed:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_manifest_pin_every_file():
    lines = (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    pinned = dict(reversed(line.split("  ", 1)) for line in lines)
    files = sorted(p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    assert sorted(pinned) == files
    for name, digest in pinned.items():
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name
    manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        assert hashlib.sha256((VECTORS / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    top = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))
    assert top["corpora"]["evidence_layer_padding"] == "evidence-layer/padding/manifest.json"


def test_draft_names_the_member_and_its_encoding():
    text = " ".join(DRAFT.read_text(encoding="utf-8").split())
    assert ("carried in the member `store_nonce` as 32 bytes encoded as 64 lowercase "
            "hexadecimal characters") in text


def test_case_set_covers_every_reason():
    assert DATA["count"] == len(DATA["cases"]) == len(CASES)
    reasons = {c["expected"].get("reason") for c in DATA["cases"]}
    assert reasons == {None, *DATA["reasons"]}
    members = {c["expected"].get("member") for c in DATA["cases"] if c["kind"] == "negative"}
    assert {"store_nonce", "links", "payload_commitments", "subject_ref", "principal_ref",
            "epistemic_type", "capsule_id"} <= members


@pytest.mark.parametrize("case_id", list(CASES))
def test_preimage_is_the_record_without_capsule_id(case_id):
    c = CASES[case_id]
    assert c["capsule_id_preimage"] == _jcs(_preimage(c["record"]))


@pytest.mark.parametrize("case_id", list(CASES))
def test_preimage_is_rfc8785(case_id):
    rfc8785 = pytest.importorskip("rfc8785")
    c = CASES[case_id]
    assert c["capsule_id_preimage"].encode("utf-8") == rfc8785.dumps(_preimage(c["record"]))


@pytest.mark.parametrize("case_id", list(CASES))
def test_verdict_matches_expected(case_id):
    c = CASES[case_id]
    expected = c["expected"]
    assert expected["valid"] is (c["kind"] == "positive")
    got = _check(c["record"])
    if expected["valid"]:
        assert got is None
    else:
        assert got == (expected["reason"], expected["member"])


@pytest.mark.parametrize("case_id", [c for c in CASES if c != "neg-capsule-id-mismatch"])
def test_only_the_mismatch_case_has_a_wrong_id(case_id):
    record = CASES[case_id]["record"]
    assert record["capsule_id"] == _digest(_preimage(record))


def test_distinct_nonces_give_distinct_ids():
    ids = [c["record"]["capsule_id"] for c in DATA["cases"]]
    assert len(set(ids)) == len(ids)
