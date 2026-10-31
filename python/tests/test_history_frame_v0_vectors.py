# SPDX-License-Identifier: BSD-3-Clause
"""The History frame vectors (``vectors/history-frame-v0/``).

Every case runs through an evaluator of this file's own for ``spec/history-frame-v0.md`` (HF)
§6.2, compared with the case's whole ``expected`` block, which the generator states by hand. The
test also checks that HF §6's instance table, the documents in ``spec/history-frame/`` and the
corpus's ``instances`` agree, regenerates the corpus twice and requires both runs to be
byte-identical to the committed files, and runs defective evaluators, each of which must disagree
with at least one case.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "history-frame-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_history_frame_v0_vectors.py"
SPEC = ROOT / "spec" / "history-frame-v0.md"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
PACK_MEMBERS = {"document", "frame", "instance", "language", "strings"}


def digest(value: object) -> str:
    """SHA-256 of UTF-8 of JCS: these documents carry no numbers and only ASCII member names."""
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                                     sort_keys=True).encode("utf-8")).hexdigest()


def texts(value: object) -> set:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set(value).union(*(texts(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(texts(v) for v in value))
    return set()


def pack_form(table: dict, pack: dict, instance: str) -> bool:
    if set(pack) != PACK_MEMBERS or pack["document"] != "wording_pack" or pack["frame"] != DATA["frame"] \
            or pack["instance"] != instance:
        return False
    strings = pack["strings"]
    if not isinstance(strings, dict) or not strings or not all(isinstance(s, str) and s for s in strings.values()):
        return False
    checked = texts({k: v for k, v in table.items() if k not in ("document", "frame", "instance")})
    return not set(strings.values()) & checked


def evaluate(c: dict, *, form=pack_form, digest_fn=digest) -> dict:
    i = c["inputs"]
    p = {"table_binding": "PASS" if digest_fn(i["table"]) == i["listed"]["table"] else "FAIL",
         "pack_binding": "PASS" if digest_fn(i["pack"]) == i["listed"]["pack"] else "FAIL",
         "pack_form": "PASS" if form(i["table"], i["pack"], i["instance"]) else "FAIL"}
    fails = [k for k in DATA["properties"] if p[k] == "FAIL"]
    return {"properties": p, "accepted": not fails, "fails": fails}


def test_corpus_header() -> None:
    assert DATA["spec"] == "spec/history-frame-v0.md"
    assert DATA["count"] == len(CASES)
    spec = SPEC.read_text(encoding="utf-8")
    for prop in DATA["properties"]:
        assert f"| `{prop}` |" in spec, prop


def test_instances_match_documents_and_spec() -> None:
    """HF §6: the listed digests are the documents' digests, and the spec text lists each one."""
    spec = SPEC.read_text(encoding="utf-8")
    assert [x["instance"] for x in DATA["instances"]] == [
        "standard_history/1", "personal_history_basic/1", "personal_history_outcome/1", "inference-service-history/0"]
    for x in DATA["instances"]:
        table = json.loads((ROOT / x["table"]).read_text(encoding="utf-8"))
        pack = json.loads((ROOT / x["pack"]).read_text(encoding="utf-8"))
        assert digest(table) == x["table_digest"], x["table"]
        assert digest(pack) == x["pack_digest"], x["pack"]
        assert table["instance"] == pack["instance"] == x["instance"]
        assert pack_form(table, pack, x["instance"]), x["pack"]
        for d in (x["table_digest"], x["pack_digest"]):
            assert f"`{d}`" in spec, d


@pytest.mark.parametrize("c", CASES, ids=[c["id"] for c in CASES])
def test_case(c: dict) -> None:
    assert evaluate(c) == c["expected"]


def test_corpus_has_a_mismatched_pack_digest() -> None:
    """HF §6.2, #452 condition 4: a negative whose pack digest is not the listed one."""
    assert any(c["expected"]["fails"] == ["pack_binding"] for c in CASES)


def _ignore_checked_strings(table: dict, pack: dict, instance: str) -> bool:
    return set(pack) == PACK_MEMBERS and pack["instance"] == instance


def _bytes_not_jcs(value: object) -> str:
    return hashlib.sha256(json.dumps(value).encode("utf-8")).hexdigest()


@pytest.mark.parametrize("defect", [
    {"form": _ignore_checked_strings},
    {"digest_fn": _bytes_not_jcs},
    {"form": lambda t, p, i: True},
])
def test_defective_evaluators_disagree(defect: dict) -> None:
    assert any(evaluate(c, **defect) != c["expected"] for c in CASES)


def test_regenerates_byte_identical(tmp_path: Path) -> None:
    for run in ("a", "b"):
        out = tmp_path / run
        out.mkdir()
        for name in HAND_WRITTEN:
            shutil.copy(VECTORS / name, out / name)
        subprocess.run([sys.executable, str(GENERATOR), "--out", str(out)], check=True)
        committed = sorted(p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file())
        written = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
        assert written == committed
        for rel in committed:
            assert (out / rel).read_bytes() == (VECTORS / rel).read_bytes(), rel
