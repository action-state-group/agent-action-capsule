# SPDX-License-Identifier: BSD-3-Clause
"""Import-boundary test: agent_action_capsule imports NOTHING from gopher_ai.

This is acceptance check (4): A (agent-action-capsule) is engine-free. If any
module inside agent_action_capsule imports from gopher_ai (or gopher-ai, vaap,
etc.) this test fails, proving the public wheel is contaminated.
"""
import importlib
import pkgutil
import sys

import pytest


def _all_aac_modules() -> list[str]:
    """Collect every importable submodule of agent_action_capsule."""
    import agent_action_capsule

    pkg = agent_action_capsule.__path__
    names = ["agent_action_capsule"]
    for finder, modname, ispkg in pkgutil.walk_packages(pkg, prefix="agent_action_capsule."):
        names.append(modname)
    return names


def test_no_gopher_ai_import_in_aac():
    """No agent_action_capsule module may import from gopher_ai or vaap."""
    forbidden_prefixes = ("gopher_ai", "gopher-ai", "vaap", "gopher_ai_pro", "action_state_authority")

    violations: list[str] = []
    for modname in _all_aac_modules():
        mod = importlib.import_module(modname)
        source_file = getattr(mod, "__file__", None)
        if source_file is None:
            continue
        # Inspect the actual source for any forbidden import.
        try:
            with open(source_file) as fh:
                source = fh.read()
        except OSError:
            continue
        for prefix in forbidden_prefixes:
            # Match "import <prefix>" or "from <prefix>"
            if f"import {prefix}" in source or f"from {prefix}" in source:
                violations.append(f"{modname}: imports from {prefix!r}")

    assert not violations, (
        "agent_action_capsule imports from private/engine packages:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_no_gopher_ai_in_sys_modules_after_aac_import():
    """Importing agent_action_capsule must not pull gopher_ai into sys.modules."""
    # Remove any existing gopher_ai from sys.modules (in case a prior test loaded it).
    to_remove = [k for k in sys.modules if k.startswith("gopher_ai") or k == "vaap"]
    for k in to_remove:
        del sys.modules[k]

    import agent_action_capsule  # re-import to trigger any lazy loads
    _ = agent_action_capsule.emit  # access the main surface

    contaminated = [k for k in sys.modules if k.startswith("gopher_ai") or k == "vaap"]
    assert not contaminated, (
        f"importing agent_action_capsule pulled in engine modules: {contaminated}"
    )
