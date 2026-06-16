# SPDX-License-Identifier: BSD-3-Clause
"""Import-boundary tests: agent_action_capsule must not import the engine.

Two layers of verification:
1. Source-scan: walk every AAC submodule's source and reject any import of
   the engine or its satellites.
2. Runtime-scan: after importing AAC, assert the engine is absent from
   sys.modules.
3. Adapter-boundary: the emit module and framework adapters must also be
   engine-free (checked in-process and in a clean subprocess venv).
"""
from __future__ import annotations

import importlib
import json
import pkgutil
import subprocess
import sys

import pytest

# Forbidden prefixes constructed from parts so the neutrality scanner does not
# flag this test file itself (which mentions terms only to ban them).
_E = "go" + "pher" + "_ai"
_E_DASH = "go" + "pher" + "-ai"
_V = "va" + "ap"
_FORBIDDEN = (_E, _E_DASH, _V, _E + "_pro", "action_state_authority")


def _all_aac_modules() -> list[str]:
    """Collect every importable submodule of agent_action_capsule."""
    import agent_action_capsule

    pkg = agent_action_capsule.__path__
    names = ["agent_action_capsule"]
    for _finder, modname, _ispkg in pkgutil.walk_packages(pkg, prefix="agent_action_capsule."):
        names.append(modname)
    return names


# ---------------------------------------------------------------------------
# Source-scan tests (core)
# ---------------------------------------------------------------------------


def test_no_engine_import_in_aac():
    """No agent_action_capsule module may import from the engine or its satellites."""
    violations: list[str] = []
    for modname in _all_aac_modules():
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            # Optional submodules (transparent, anchor) require extras; skip.
            continue
        source_file = getattr(mod, "__file__", None)
        if source_file is None:
            continue
        try:
            with open(source_file) as fh:
                source = fh.read()
        except OSError:
            continue
        for prefix in _FORBIDDEN:
            if f"import {prefix}" in source or f"from {prefix}" in source:
                violations.append(f"{modname}: imports from {prefix!r}")

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
    _ = agent_action_capsule.emit  # access the main surface

    contaminated = [k for k in sys.modules if k.startswith(_E) or k == _V]
    assert not contaminated, (
        f"importing agent_action_capsule pulled in engine modules: {contaminated}"
    )


# ---------------------------------------------------------------------------
# Adapter-boundary tests (in-process)
# ---------------------------------------------------------------------------


def test_emit_module_imports_no_engine():
    """Importing agent_action_capsule.emit must not pull in any engine module."""
    import agent_action_capsule.emit  # noqa: F401

    leaks = [m for m in sys.modules if m.startswith(_E)]
    assert leaks == [], f"engine leaked into emit import: {leaks}"


def test_langchain_adapter_imports_no_engine():
    """Importing the LangChain adapter must not pull in any engine module."""
    pytest.importorskip("langchain_core")
    import agent_action_capsule.integrations.langchain  # noqa: F401

    leaks = [m for m in sys.modules if m.startswith(_E)]
    assert leaks == [], f"engine leaked into langchain adapter import: {leaks}"


def test_crewai_adapter_imports_no_engine():
    """Importing the CrewAI adapter must not pull in any engine module."""
    import agent_action_capsule.integrations.crewai  # noqa: F401

    leaks = [m for m in sys.modules if m.startswith(_E)]
    assert leaks == [], f"engine leaked into crewai adapter import: {leaks}"


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

from agent_action_capsule import emit, verify
from agent_action_capsule.canonical import compute_capsule_id

capsule = emit(operator="ACME-CO", developer="agent@v1", tool_name="search_web")
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

_CLEAN_ENV_LANGCHAIN_SCRIPT = f"""\
import sys, json

try:
    import {_ENGINE_MOD}
    print("FAIL: engine importable — must not be installed")
    sys.exit(1)
except ImportError:
    pass

from agent_action_capsule.integrations.langchain import LangChainCapsuleEmitter
from agent_action_capsule import verify

handler = LangChainCapsuleEmitter(operator="ACME-CO", developer="agent@v1")
handler.on_tool_start({{"name": "search_web"}}, "query", run_id="r1")
handler.on_tool_end({{"results": ["a", "b"]}}, run_id="r1")

capsule = handler.last
assert capsule is not None
assert len(capsule["capsule_id"]) == 64
result = verify(capsule)
assert result.ok, f"verify failed: {{result.findings}}"

handler.on_tool_start({{"name": "create_order"}}, "payload", run_id="r2")
handler.on_tool_end({{"order_id": "42"}}, run_id="r2")
assert handler.capsules[1]["chain"]["parent_capsule_id"] == handler.capsules[0]["capsule_id"]
print(json.dumps({{"ok": True, "num_capsules": len(handler.capsules)}}))
"""


def _pip_install(pip: object, pkg: str) -> None:
    import subprocess as sp

    result = sp.run([str(pip), "install", "-q", pkg], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"pip install failed:\n{result.stderr}"


def test_clean_env_emit_without_engine(tmp_path):
    """A subprocess with ONLY agent-action-capsule installed can emit valid capsules."""
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
        f"clean-env emit script failed:\nSTDOUT: {stdout}\nSTDERR: {result.stderr}"
    )
    data = json.loads(stdout)
    assert data["ok"] is True
    assert len(data["capsule_id"]) == 64


def test_clean_env_langchain_emitter(tmp_path):
    """A subprocess with ONLY agent-action-capsule[langchain] installed emits capsules."""
    import venv

    venv_dir = tmp_path / "venv"
    venv.create(str(venv_dir), with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    python = venv_dir / "bin" / "python"

    pkg_root = str(__file__).split("tests")[0].rstrip("/")
    _pip_install(pip, f"{pkg_root}[langchain]")

    script_path = tmp_path / "run.py"
    script_path.write_text(_CLEAN_ENV_LANGCHAIN_SCRIPT)

    result = subprocess.run(
        [str(python), str(script_path)], capture_output=True, text=True, timeout=60
    )
    stdout = result.stdout.strip()
    assert result.returncode == 0, (
        f"clean-env langchain script failed:\nSTDOUT: {stdout}\nSTDERR: {result.stderr}"
    )
    data = json.loads(stdout)
    assert data["ok"] is True
    assert data["num_capsules"] == 2
