# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Layer UNDISCLOSED retention vectors check from the files alone.

The rules below are an independent reading of "UNDISCLOSED and policy_uri" in
``spec/draft-mih-agent-evidence-layer-01.md`` and of
``vectors/evidence-layer/retention/README.md``. Nothing is imported from the
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

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "evidence-layer" / "retention"
DRAFT = ROOT / "spec" / "draft-mih-agent-evidence-layer-01.md"
REGISTRY = ROOT / "spec" / "REGISTRY.md"
GENERATOR = ROOT / "python" / "scripts" / "generate_evidence_layer_retention_vectors.py"
HAND_WRITTEN = ("README.md",)

DATA = json.loads((VECTORS / "cases.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in DATA["cases"]}
# RFC 3986 Section 3: a scheme, then ':'. A relative reference has no scheme,
# and no URI contains whitespace.
URI = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:\S*")


def _check(record: dict) -> tuple[str, str] | None:
    """The broken rule as (reason, member), or None for a valid header."""
    if record["retention_state"] != "UNDISCLOSED":
        return None
    if "policy_uri" not in record:
        return "missing_policy_uri", "policy_uri"
    uri = record["policy_uri"]
    if not isinstance(uri, str) or not URI.fullmatch(uri):
        return "policy_uri_form", "policy_uri"
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
    assert top["corpora"]["evidence_layer_retention"] == "evidence-layer/retention/manifest.json"


def test_draft_requires_policy_uri_for_undisclosed():
    text = " ".join(DRAFT.read_text(encoding="utf-8").split())
    assert "`retention_state` `UNDISCLOSED` MUST carry `policy_uri`" in text
    assert "`policy_uri` MAY accompany any other `retention_state`" in text


def test_registry_lists_undisclosed():
    text = REGISTRY.read_text(encoding="utf-8")
    section = text.split("## 19. Evidence Layer retention state", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| `([A-Z_]+)` \|", section, flags=re.M)
    assert rows == ["AVAILABLE", "PARTIAL", "WITHHELD", "DELETED", "LEGAL_HOLD", "UNDISCLOSED"]


def test_case_set_covers_every_reason():
    assert DATA["count"] == len(DATA["cases"]) == len(CASES)
    reasons = {c["expected"].get("reason") for c in DATA["cases"]}
    assert reasons == {None, *DATA["reasons"]}
    assert "neg-undisclosed-missing-policy-uri" in CASES
    assert any(c["kind"] == "positive" and c["record"]["retention_state"] == "UNDISCLOSED"
               for c in DATA["cases"])


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


@pytest.mark.parametrize("case_id", [c for c in CASES if CASES[c]["kind"] == "negative"])
def test_negative_differs_from_a_valid_header_only_in_policy_uri(case_id):
    record = dict(CASES[case_id]["record"])
    record["policy_uri"] = "https://example.com/policies/retention"
    assert _check(record) is None
