# SPDX-License-Identifier: BSD-3-Clause
"""vectors/vendored-registry/: check-vendored against the shared cases (the Go
tests run the same files), plus the command-line front door."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_action_capsule import __version__
from agent_action_capsule.registries.vendored import check_vendored, main, normalize_ref

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "vendored-registry"
CASES = json.loads((VECTORS / "cases.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_case(case):
    registry = (VECTORS / case["registry"]).read_text(encoding="utf-8")
    got = check_vendored(case["vendored"], registry, case["registry_ref"], case["ref"])
    assert got.to_dict() == case["expected"]
    assert got.ok == (not case["expected"]["problems"])


def test_every_problem_class_has_a_failing_case():
    seen = {p for c in CASES for p in c["expected"]["problems"]}
    assert seen == {"VALUES_DIFFER", "STALE_REF", "UNPINNED", "REF_UNRESOLVABLE", "SECTION_NOT_FOUND",
                    "SECTION_AMBIGUOUS", "DOCUMENT_MISMATCH", "MALFORMED"}


def test_normalize_ref():
    assert normalize_ref("go/v0.6.0") == normalize_ref("v0.6.0") == normalize_ref("0.6.0") == "0.6.0"
    assert normalize_ref("deadbeef") == "deadbeef"


def _write(tmp_path: Path, doc: dict) -> Path:
    p = tmp_path / "vendored.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_cli_bundled_copy_at_installed_version(tmp_path, capsys):
    path = _write(tmp_path, CASES[0]["vendored"])
    assert main(["check-vendored", str(path), "--ref", f"v{__version__}"]) == 0
    assert "ok (epistemic_type, REGISTRY.md section 17" in capsys.readouterr().out


def test_cli_bundled_copy_refuses_other_ref(tmp_path, capsys):
    path = _write(tmp_path, CASES[0]["vendored"])
    assert main(["check-vendored", str(path), "--ref", "v0.0.1", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out[0]["problems"] == ["REF_UNRESOLVABLE"]


def test_cli_supplied_registry_and_added_value(tmp_path, capsys):
    doc = json.loads(json.dumps(CASES[0]["vendored"]))
    doc["values"].append("VERIFIED_FACT")
    path = _write(tmp_path, doc)
    rc = main(["check-vendored", str(path), "--ref", "abc123",
               "--registry", str(VECTORS / "REGISTRY.fixture.md"), "--json"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out[0]["added"] == ["VERIFIED_FACT"] and out[0]["ref"] == "abc123"


def test_module_entry_point(tmp_path):
    path = _write(tmp_path, CASES[0]["vendored"])
    proc = subprocess.run(
        [sys.executable, "-W", "error::RuntimeWarning", "-m", "agent_action_capsule.registries",
         "check-vendored", str(path), "--ref", __version__],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
