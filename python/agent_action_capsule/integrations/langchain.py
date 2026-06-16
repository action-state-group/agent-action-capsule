# SPDX-License-Identifier: BSD-3-Clause
"""LangChain emit-tier adapter — observe tool calls, emit capsules.

Drop this handler onto any LangChain agent/chain. On every completed tool call
it builds and seals an Agent Action Capsule (§5.1) recording the event. No
constraints run, no action is blocked — this is the emit-only on-ramp.

For constraint-running (rung-4, the verify tier), see
``agent-action-capsule[langchain]`` — ``LangChainVerifier``.

    from agent_action_capsule.integrations.langchain import LangChainCapsuleEmitter

    emitter = LangChainCapsuleEmitter(operator="ACME-CO", developer="my-agent@v1")
    agent.invoke(..., config={"callbacks": [emitter]})
    # emitter.capsules holds the sealed dicts; emitter.last is the latest.

Capsules are emitted sequentially and chain-linked by default (each capsule's
``chain.parent_capsule_id`` references the previous one). Pass
``chain_capsules=False`` to emit unlinked standalone capsules.

Requires ``pip install agent-action-capsule[langchain]``.
"""
from __future__ import annotations

from typing import Any

from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as exc:
    raise ImportError(
        "LangChainCapsuleEmitter needs langchain-core. "
        "Install it with `pip install agent-action-capsule[langchain]`."
    ) from exc


class LangChainCapsuleEmitter(BaseCallbackHandler):
    """A LangChain callback handler that emits an Agent Action Capsule per tool call.

    Emits a sealed capsule dict on every ``on_tool_end`` (and on tool errors,
    if ``emit_on_error=True``). Each capsule is appended to :attr:`capsules` and
    the latest is available as :attr:`last`.

    Args:
        operator: Tenant/org identifier stamped on every capsule.
        developer: Agent identifier and version.
        chain_capsules: When ``True`` (default), each capsule's ``chain`` block
            references the previous capsule, threading them into a sequence.
        emit_on_error: When ``True``, emit a capsule even if the tool itself
            raised (tool_output is ``None`` in that case). Defaults to ``False``.
    """

    def __init__(
        self,
        *,
        operator: str,
        developer: str,
        chain_capsules: bool = True,
        emit_on_error: bool = False,
    ) -> None:
        super().__init__()
        self._operator = operator
        self._developer = developer
        self._chain = chain_capsules
        self._emit_on_error = emit_on_error
        self._pending: dict[Any, tuple[str, Any]] = {}
        self.capsules: list[dict] = []

    @property
    def last(self) -> dict | None:
        """The most recently emitted capsule dict, or ``None`` if none emitted yet."""
        return self.capsules[-1] if self.capsules else None

    def _emit(self, tool_name: str, tool_input: Any, tool_output: Any) -> dict:
        prior = self.last.get("capsule_id") if (self._chain and self.last) else None
        capsule = emit(
            operator=self._operator,
            developer=self._developer,
            action_type="fyi",
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
            prior_capsule_id=prior,
            chain_relation="sequence",
            disposition=Disposition(
                decision="accept",
                approver="policy",
                human_disposed=False,
                verdict_class="executed",
            ),
        )
        self.capsules.append(capsule)
        return capsule

    def on_tool_start(
        self,
        serialized: dict | None,
        input_str: str,
        *,
        run_id: Any = None,
        inputs: dict | None = None,
        **kwargs: Any,
    ) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        self._pending[run_id] = (name, inputs if inputs is not None else input_str)

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        name, tool_input = self._pending.pop(run_id, ("tool", None))
        self._emit(name, tool_input, output)

    def on_tool_error(
        self, error: BaseException, *, run_id: Any = None, **kwargs: Any
    ) -> None:
        name, tool_input = self._pending.pop(run_id, ("tool", None))
        if self._emit_on_error:
            self._emit(name, tool_input, None)
