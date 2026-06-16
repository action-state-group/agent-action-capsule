# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the CrewAI emit-tier adapter (framework-free paths).

These tests exercise ``emit_tool`` and ``CrewAICapsuleEmitter.wrap()``, both of
which are framework-free — no ``crewai`` package needed.
"""
from __future__ import annotations

from agent_action_capsule import verify
from agent_action_capsule.integrations.crewai import CrewAICapsuleEmitter, emit_tool

OPERATOR = "ACME-CO"
DEVELOPER = "test-agent@v1"


def _emitter(**kwargs) -> CrewAICapsuleEmitter:
    return CrewAICapsuleEmitter(operator=OPERATOR, developer=DEVELOPER, **kwargs)


# ---------------------------------------------------------------------------
# CrewAICapsuleEmitter.wrap()
# ---------------------------------------------------------------------------


def test_wrap_emits_capsule_and_returns_value():
    emitter = _emitter()

    def my_tool(payload: dict) -> dict:
        return {"total": payload.get("amount", 0) * 2}

    wrapped = emitter.wrap(my_tool)
    result = wrapped({"amount": 50})

    assert result == {"total": 100}
    assert len(emitter.capsules) == 1


def test_wrap_capsule_verifies():
    emitter = _emitter()

    def my_tool(x: str) -> str:
        return x.upper()

    emitter.wrap(my_tool)("hello")
    assert verify(emitter.last).ok


def test_wrap_chains_capsules_by_default():
    emitter = _emitter()

    def t1(x):
        return x

    def t2(x):
        return x

    emitter.wrap(t1)("a")
    emitter.wrap(t2)("b")

    c1, c2 = emitter.capsules
    assert "chain" not in c1
    assert c2["chain"]["parent_capsule_id"] == c1["capsule_id"]


def test_wrap_no_chain_when_disabled():
    emitter = _emitter(chain_capsules=False)

    def t(x):
        return x

    emitter.wrap(t)("a")
    emitter.wrap(t)("b")

    c1, c2 = emitter.capsules
    assert "chain" not in c1
    assert "chain" not in c2


def test_wrap_action_type_is_fyi():
    emitter = _emitter()

    def create_invoice(payload: dict) -> dict:
        return payload

    emitter.wrap(create_invoice)({"x": 1})
    assert emitter.last["action_type"] == "fyi"
    assert emitter.last["disposition"]["decision"] == "accept"


def test_wrap_tool_name_in_action_id():
    emitter = _emitter()

    def create_invoice(payload: dict) -> dict:
        return payload

    emitter.wrap(create_invoice)({"x": 1})
    assert "create_invoice" in emitter.last["action_id"]


# ---------------------------------------------------------------------------
# emit_tool decorator
# ---------------------------------------------------------------------------


def test_emit_tool_decorator():
    emitter = _emitter()

    @emit_tool(emitter)
    def create_invoice(payload: dict) -> dict:
        return {"total": 100}

    result = create_invoice({"customer": "Dana"})
    assert result == {"total": 100}
    assert len(emitter.capsules) == 1


def test_emit_tool_decorator_capsule_verifies():
    emitter = _emitter()

    @emit_tool(emitter)
    def search(query: str) -> list:
        return ["result1", "result2"]

    search("python SCITT")
    assert verify(emitter.last).ok


def test_emit_tool_decorator_chains():
    emitter = _emitter()

    @emit_tool(emitter)
    def t1(x):
        return x

    @emit_tool(emitter)
    def t2(x):
        return x

    t1("a")
    t2("b")

    c1, c2 = emitter.capsules
    assert c2["chain"]["parent_capsule_id"] == c1["capsule_id"]
