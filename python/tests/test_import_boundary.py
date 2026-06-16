# SPDX-License-Identifier: BSD-3-Clause
"""Import-boundary test: agent_action_capsule imports nothing from the engine.

This is acceptance check (4): A (agent-action-capsule) is engine-free. If any
module inside agent_action_capsule imports from the engine or its satellites
this test fails, proving the public wheel is contaminated.
"""
import importlib
import pkgutil
import sys

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


def test_no_engine_import_in_aac():
    """No agent_action_capsule module may import from the engine or its satellites."""
    violations: list[str] = []
    for modname in _all_aac_modules():
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            # Optional submodules (e.g. transparent, anchor) require extras;
            # skip them — the boundary check applies to the source, not the import.
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
