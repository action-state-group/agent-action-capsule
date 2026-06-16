# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the LangChain emit-tier adapter.

All tests are gated behind ``pytest.importorskip("langchain_core")`` so the
suite stays green in a plain agent-action-capsule install without the extra.
"""
from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")

from agent_action_capsule import verify
from agent_action_capsule.integrations.langchain import LangChainCapsuleEmitter

OPERATOR = "ACME-CO"
DEVELOPER = "test-agent@v1"


def _make_handler(**kwargs) -> LangChainCapsuleEmitter:
    return LangChainCapsuleEmitter(operator=OPERATOR, developer=DEVELOPER, **kwargs)


def test_emitter_produces_capsule_on_tool_end():
    handler = _make_handler()
    handler.on_tool_start({"name": "search_web"}, "query", run_id="r1")
    handler.on_tool_end({"results": ["a", "b"]}, run_id="r1")

    assert len(handler.capsules) == 1
    capsule = handler.last
    assert capsule is not None
    assert "capsule_id" in capsule
    assert len(capsule["capsule_id"]) == 64


def test_emitter_capsule_verifies():
    """Each emitted capsule passes the Class 1 verifier."""
    handler = _make_handler()
    handler.on_tool_start({"name": "search_web"}, "query", run_id="r1")
    handler.on_tool_end({"results": []}, run_id="r1")

    result = verify(handler.last)
    assert result.ok, result.findings


def test_emitter_chains_capsules_by_default():
    """By default, each capsule chains onto the previous one."""
    handler = _make_handler()
    handler.on_tool_start({"name": "t1"}, "a", run_id="r1")
    handler.on_tool_end("out1", run_id="r1")
    handler.on_tool_start({"name": "t2"}, "b", run_id="r2")
    handler.on_tool_end("out2", run_id="r2")

    c1, c2 = handler.capsules
    assert "chain" not in c1
    assert c2["chain"]["parent_capsule_id"] == c1["capsule_id"]


def test_emitter_no_chain_when_disabled():
    handler = _make_handler(chain_capsules=False)
    handler.on_tool_start({"name": "t1"}, "a", run_id="r1")
    handler.on_tool_end("out1", run_id="r1")
    handler.on_tool_start({"name": "t2"}, "b", run_id="r2")
    handler.on_tool_end("out2", run_id="r2")

    c1, c2 = handler.capsules
    assert "chain" not in c1
    assert "chain" not in c2


def test_emitter_disposition_is_accept():
    handler = _make_handler()
    handler.on_tool_start({"name": "create_invoice"}, "in", run_id="r1")
    handler.on_tool_end({"total": 100}, run_id="r1")

    assert handler.last["disposition"]["decision"] == "accept"
    assert handler.last["action_type"] == "fyi"


def test_emitter_tool_error_no_capsule_by_default():
    """Tool errors do NOT emit a capsule (emit_on_error=False by default)."""
    handler = _make_handler()
    handler.on_tool_start({"name": "create_invoice"}, "in", run_id="r1")
    handler.on_tool_error(RuntimeError("fail"), run_id="r1")
    assert len(handler.capsules) == 0


def test_emitter_tool_error_emits_when_enabled():
    handler = _make_handler(emit_on_error=True)
    handler.on_tool_start({"name": "create_invoice"}, "in", run_id="r1")
    handler.on_tool_error(RuntimeError("fail"), run_id="r1")
    assert len(handler.capsules) == 1


def test_emitter_operator_developer_stamped():
    handler = _make_handler()
    handler.on_tool_start({"name": "t"}, "in", run_id="r1")
    handler.on_tool_end("out", run_id="r1")

    capsule = handler.last
    assert capsule["operator"] == OPERATOR
    assert capsule["developer"] == DEVELOPER


def test_emitter_multiple_concurrent_runs():
    """Pending inputs are correctly matched even if runs interleave."""
    handler = _make_handler()
    handler.on_tool_start({"name": "t1"}, "a", run_id="ra")
    handler.on_tool_start({"name": "t2"}, "b", run_id="rb")
    handler.on_tool_end("out_b", run_id="rb")
    handler.on_tool_end("out_a", run_id="ra")

    assert len(handler.capsules) == 2
    # Tool name is encoded in the action_id (rb completed first, then ra).
    assert "t2" in handler.capsules[0]["action_id"]
    assert "t1" in handler.capsules[1]["action_id"]
