# SPDX-License-Identifier: BSD-3-Clause
"""The deprecated producer surface still works and says what replaces it.

``agent_action_capsule.emit()`` and ``agent_action_capsule.integrations`` are
deprecated in 0.9.0 and removed in the next minor release; producing Capsules
belongs to capsule-emit. This is the only AAC test that calls them. The
version constants moved to ``agent_action_capsule.versions`` and stay
importable from their old locations without a warning.
"""
from __future__ import annotations

import importlib
import sys
import warnings

import pytest

import agent_action_capsule
from agent_action_capsule import verify, versions


def test_deprecated_producer_surface_warns_and_still_works(monkeypatch):
    # The constants: same values from every location, and no warning.
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        from agent_action_capsule.emit import (
            ACCEPTED_SPEC_VERSIONS,
            DEFAULT_FORMAT_VERSION,
            DEFAULT_SPEC_VERSION,
            FORMAT_VERSION,
            SPEC_VERSION,
        )
    for name, value in [
        ("ACCEPTED_SPEC_VERSIONS", ACCEPTED_SPEC_VERSIONS),
        ("DEFAULT_FORMAT_VERSION", DEFAULT_FORMAT_VERSION),
        ("DEFAULT_SPEC_VERSION", DEFAULT_SPEC_VERSION),
        ("FORMAT_VERSION", FORMAT_VERSION),
        ("SPEC_VERSION", SPEC_VERSION),
    ]:
        assert getattr(versions, name) == value
        assert getattr(agent_action_capsule, name) == value

    # emit(): warns, names capsule-emit's seal(), and still seals a verifying Capsule.
    with pytest.warns(DeprecationWarning, match=r"capsule_emit\.seal") as record:
        capsule = agent_action_capsule.emit(operator="ACME-CO", developer="agent@v1")
    assert record[0].filename == __file__  # attributed to the caller
    result = verify(capsule)
    assert result.ok, [f.code for f in result.findings]

    # The integrations warn on import, naming capsule-emit's adapters.
    for name in list(sys.modules):
        if name.startswith("agent_action_capsule.integrations"):
            monkeypatch.delitem(sys.modules, name)
    with pytest.warns(DeprecationWarning, match=r"capsule_emit\.adapters"):
        crewai = importlib.import_module("agent_action_capsule.integrations.crewai")

    # ... and on use; the adapter's own capsules carry no second emit() warning.
    with pytest.warns(DeprecationWarning, match=r"capsule_emit\.adapters\.crewai"):
        emitter = crewai.CrewAICapsuleEmitter(operator="ACME-CO", developer="agent@v1")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert emitter.wrap(lambda payload: payload, name="echo")({"q": 1}) == {"q": 1}
    assert verify(emitter.last).ok

    try:
        import langchain_core  # noqa: F401
    except ImportError:
        return
    langchain = importlib.import_module("agent_action_capsule.integrations.langchain")
    with pytest.warns(DeprecationWarning, match=r"capsule_emit\.adapters\.langchain"):
        langchain.LangChainCapsuleEmitter(operator="ACME-CO", developer="agent@v1")
