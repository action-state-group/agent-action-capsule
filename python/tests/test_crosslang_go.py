# SPDX-License-Identifier: BSD-3-Clause
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_action_capsule import emit, verify

_REQUIRE_GO = os.environ.get("AAC_REQUIRE_GO") == "1"

# python/tests → python → repo_root
_REPO_ROOT = Path(__file__).resolve().parents[2]
_GO_DIR = _REPO_ROOT / "go"
_VECTORS_DIR = _REPO_ROOT / "test-vectors"


def _skip_or_fail(reason: str) -> None:
    if _REQUIRE_GO:
        pytest.fail(f"AAC_REQUIRE_GO=1 but cross-lang test unavailable: {reason}")
    pytest.skip(reason)


@pytest.fixture(scope="session")
def go_binary(tmp_path_factory):
    go = shutil.which("go")
    if go is None:
        _skip_or_fail("go is not on PATH")

    if not _GO_DIR.is_dir():
        _skip_or_fail(f"go/ directory not found at {_GO_DIR}")

    bin_dir = tmp_path_factory.mktemp("go_bin")
    out_bin = bin_dir / "vector_runner"
    result = subprocess.run(
        [go, "build", "-o", str(out_bin), "./cmd/vector_runner/..."],
        cwd=str(_GO_DIR),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        _skip_or_fail(f"go build failed:\n{result.stderr}")
    return str(out_bin)


def test_go_vectors_all_pass(go_binary):
    if not _VECTORS_DIR.is_dir():
        pytest.skip(f"test-vectors/ not found at {_VECTORS_DIR}")

    result = subprocess.run(
        [go_binary, "--vectors-dir", str(_VECTORS_DIR)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Go vector_runner exited {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "FAIL" not in result.stdout, (
        f"Go vector_runner reported failures:\n{result.stdout}"
    )


def test_go_accepts_fresh_capsule(go_binary, tmp_path):
    cap = emit(
        action_id="crosslang-go-pos-1",
        action_type="fyi",
        operator="test-op",
        developer="test-dev@v1",
    )
    py_result = verify(cap)
    assert py_result.ok, f"Python verify failed: {py_result.findings}"

    capsule_file = tmp_path / "capsule.json"
    capsule_file.write_text(json.dumps(cap))

    vectors_dir = tmp_path / "vectors"
    vectors_dir.mkdir()
    case_dir = vectors_dir / "crosslang-go-pos-1"
    case_dir.mkdir()
    (case_dir / "input.json").write_text(json.dumps(cap))

    derived = py_result.assurance
    expected = {
        "ok": True,
        "derived": derived,
        "capsule_id_recomputed": py_result.capsule_id,
        "findings": [
            {"check": f.check, "severity": f.severity, "code": f.code}
            for f in py_result.findings
        ],
    }
    (case_dir / "expected.json").write_text(json.dumps(expected))
    manifest = {"count": 1, "cases": [{"name": "crosslang-go-pos-1", "kind": "positive"}]}
    (vectors_dir / "vectors.json").write_text(json.dumps(manifest))

    result = subprocess.run(
        [go_binary, "--vectors-dir", str(vectors_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Go verifier rejected a fresh Python capsule.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_go_rejects_tampered_capsule(go_binary, tmp_path):
    cap = emit(
        action_id="crosslang-go-neg-1",
        action_type="fyi",
        operator="test-op",
        developer="test-dev@v1",
    )
    # Flip one nibble of capsule_id to simulate tampering without resealing
    old_cid = cap["capsule_id"]
    flipped_last = "0" if old_cid[-1] != "0" else "1"
    tampered = dict(cap)
    tampered["capsule_id"] = old_cid[:-1] + flipped_last

    py_result = verify(tampered)
    assert not py_result.ok, "Python verify should reject a tampered capsule_id"

    vectors_dir = tmp_path / "vectors"
    vectors_dir.mkdir()
    case_dir = vectors_dir / "crosslang-go-neg-1"
    case_dir.mkdir()
    (case_dir / "input.json").write_text(json.dumps(tampered))

    derived = py_result.assurance
    expected = {
        "ok": False,
        "derived": derived,
        "capsule_id_recomputed": py_result.capsule_id,
        "findings": [
            {"check": f.check, "severity": f.severity, "code": f.code}
            for f in py_result.findings
        ],
    }
    (case_dir / "expected.json").write_text(json.dumps(expected))
    manifest = {"count": 1, "cases": [{"name": "crosslang-go-neg-1", "kind": "negative"}]}
    (vectors_dir / "vectors.json").write_text(json.dumps(manifest))

    result = subprocess.run(
        [go_binary, "--vectors-dir", str(vectors_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Go vector_runner disagreed with Python on tampered capsule.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
