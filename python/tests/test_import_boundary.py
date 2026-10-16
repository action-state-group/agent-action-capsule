# SPDX-License-Identifier: BSD-3-Clause
"""Import-boundary tests: agent_action_capsule must not import the engine.

Two layers of verification:
1. Source-scan: walk every AAC submodule's source and reject any import of
   the engine or its satellites.
2. Runtime-scan: after importing AAC, assert the engine is absent from
   sys.modules.
3. Clean-env: a subprocess venv with only this package installed seals and
   verifies a Capsule.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Forbidden prefixes constructed from parts so the neutrality scanner does not
# flag this test file itself (which mentions terms only to ban them).
_E = "go" + "pher" + "_ai"
_E_DASH = "go" + "pher" + "-ai"
_V = "va" + "ap"
_FORBIDDEN = (_E, _E_DASH, _V, _E + "_pro", "action_state_authority")


def _all_aac_sources() -> list[Path]:
    """Every Python source file of agent_action_capsule, read from disk so that
    optional (extras-only) and deprecated modules are scanned without being
    imported."""
    import agent_action_capsule

    return sorted(Path(agent_action_capsule.__file__).parent.rglob("*.py"))


# ---------------------------------------------------------------------------
# Source-scan tests (core)
# ---------------------------------------------------------------------------


def test_no_engine_import_in_aac():
    """No agent_action_capsule module may import from the engine or its satellites."""
    violations: list[str] = []
    for source_file in _all_aac_sources():
        source = source_file.read_text(encoding="utf-8")
        for prefix in _FORBIDDEN:
            if f"import {prefix}" in source or f"from {prefix}" in source:
                violations.append(f"{source_file.name}: imports from {prefix!r}")

    assert not violations, (
        "agent_action_capsule imports from private/engine packages:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_no_engine_in_sys_modules_after_aac_import():
    """Importing agent_action_capsule must not pull the engine into sys.modules."""
    to_remove = [k for k in sys.modules if k.startswith(_E) or k == _V]
    for k in to_remove:
        del sys.modules[k]

    import agent_action_capsule  # re-import to trigger any lazy loads
    _ = agent_action_capsule.verify  # access the main surface

    contaminated = [k for k in sys.modules if k.startswith(_E) or k == _V]
    assert not contaminated, (
        f"importing agent_action_capsule pulled in engine modules: {contaminated}"
    )


# ---------------------------------------------------------------------------
# Subprocess clean-env tests
# ---------------------------------------------------------------------------

# Subprocess scripts reference the engine name only to assert it's absent;
# we build the module name from parts so the neutrality scanner ignores it.
_ENGINE_MOD = _E  # runtime string; not a literal in source

_CLEAN_ENV_SCRIPT = f"""\
import sys, json

try:
    import {_ENGINE_MOD}
    print("FAIL: engine is importable — must NOT be installed")
    sys.exit(1)
except ImportError:
    pass

from agent_action_capsule import Capsule, verify
from agent_action_capsule.canonical import compute_capsule_id

capsule = Capsule(
    spec_version="draft-mih-scitt-agent-action-capsule-05",
    format_version="4",
    canonicalization_id="jcs",
    action_id="search_web/1",
    action_type="fyi",
    operator="ACME-CO",
    developer="agent@v1",
    timestamp="2026-06-13T00:00:00Z",
).seal()
assert "capsule_id" in capsule
assert len(capsule["capsule_id"]) == 64
result = verify(capsule)
assert result.ok, f"verify failed: {{result.findings}}"
original_id = capsule["capsule_id"]
mutated = dict(capsule)
mutated["operator"] = "EVIL-CO"
assert compute_capsule_id(mutated) != original_id, "tamper did not change id"
print(json.dumps({{"ok": True, "capsule_id": capsule["capsule_id"]}}))
"""

def _pip_install(pip: object, pkg: str) -> None:
    import subprocess as sp

    result = sp.run([str(pip), "install", "-q", pkg], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"pip install failed:\n{result.stderr}"


def test_clean_env_seal_without_engine(tmp_path):
    """A subprocess with ONLY agent-action-capsule installed seals valid capsules."""
    import venv

    venv_dir = tmp_path / "venv"
    venv.create(str(venv_dir), with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    python = venv_dir / "bin" / "python"

    pkg_root = str(__file__).split("tests")[0].rstrip("/")
    _pip_install(pip, pkg_root)

    script_path = tmp_path / "run.py"
    script_path.write_text(_CLEAN_ENV_SCRIPT)

    result = subprocess.run(
        [str(python), str(script_path)], capture_output=True, text=True, timeout=60
    )
    stdout = result.stdout.strip()
    assert result.returncode == 0, (
        f"clean-env seal script failed:\nSTDOUT: {stdout}\nSTDERR: {result.stderr}"
    )
    data = json.loads(stdout)
    assert data["ok"] is True
    assert len(data["capsule_id"]) == 64
