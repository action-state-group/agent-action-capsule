# SPDX-License-Identifier: BSD-3-Clause
"""Emit-tier framework adapters — the thin "just record it happened" on-ramp.

.. deprecated:: 0.9.0
   These adapters are deprecated and will be removed in the next minor
   release. Use capsule-emit's adapters instead:
   ``capsule_emit.adapters.langchain.LangChainCapsuleEmitter`` and
   ``capsule_emit.adapters.crewai.CrewAICapsuleEmitter`` (whose ``wrap()``
   replaces ``emit_tool``). Importing this package or constructing an
   emitter raises a :class:`DeprecationWarning`.

These adapters hook into a framework's callback or tool-wrap interface and emit a
signed Agent Action Capsule for every tool call. They depend only on CORE A
(this package); they run NO constraints and carry NO engine logic.

For constraint-running (rung-4, the differentiating tier), see
``agent-action-capsule[langchain]`` / ``agent-action-capsule[crewai]`` — the verify-tier adapters.

Adapters are re-exported lazily so importing this package never requires
LangChain or CrewAI to be installed.
"""
from __future__ import annotations

import importlib
import warnings
from typing import TYPE_CHECKING

DEPRECATION_MESSAGE = (
    "agent_action_capsule.integrations is deprecated and will be removed in the "
    "next minor release; use capsule-emit's adapters instead "
    "(capsule_emit.adapters.langchain.LangChainCapsuleEmitter, "
    "capsule_emit.adapters.crewai.CrewAICapsuleEmitter)"
)


def _warn_deprecated(stacklevel: int) -> None:
    warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=stacklevel + 1)


# Importing any adapter imports this package first, so this one warning covers
# every import route; the emitters' constructors warn again on use.
_warn_deprecated(2)

_LAZY_EXPORTS = {
    "LangChainCapsuleEmitter": "agent_action_capsule.integrations.langchain",
    "CrewAICapsuleEmitter": "agent_action_capsule.integrations.crewai",
    "emit_tool": "agent_action_capsule.integrations.crewai",
}


def __getattr__(name: str):
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)


if TYPE_CHECKING:
    from agent_action_capsule.integrations.crewai import CrewAICapsuleEmitter, emit_tool
    from agent_action_capsule.integrations.langchain import LangChainCapsuleEmitter

__all__ = [
    "LangChainCapsuleEmitter",
    "CrewAICapsuleEmitter",
    "emit_tool",
]
