# SPDX-License-Identifier: BSD-3-Clause
"""CrewAI emit-tier adapter — wrap a tool so each call emits a capsule.

Two entry points:

* :func:`emit_tool` — a decorator for a plain tool function. Framework-free;
  no CrewAI import required. The most robust, thinnest on-ramp.
* :class:`CrewAICapsuleEmitter` — holds one emitter and wraps many tools.
  ``.wrap(fn)`` is the function-level wrap above; ``.as_crewai_tool(tool)`` is a
  best-effort wrapper for a ``crewai.tools.BaseTool`` instance (lazy import).

Unlike LangChain's post-hoc callback, wrapping runs **in-line with the tool**,
so the capsule is emitted before the result is returned to the agent.

For constraint-running (rung-4, the verify tier), see
``gopher-ai[crewai]`` — ``CrewAIVerifier`` / ``verified_tool``.

Requires ``pip install agent-action-capsule[crewai]`` only for
``.as_crewai_tool()``; the decorator and ``.wrap()`` need nothing beyond CORE A.

    from agent_action_capsule.integrations.crewai import emit_tool, CrewAICapsuleEmitter

    emitter = CrewAICapsuleEmitter(operator="ACME-CO", developer="my-agent@v1")

    @emit_tool(emitter)
    def create_invoice(payload: dict) -> dict:
        ...
"""
from __future__ import annotations

import functools
from typing import Any, Callable

from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit as _emit_capsule

__all__ = ["CrewAICapsuleEmitter", "emit_tool"]


def _first_input(args: tuple, kwargs: dict) -> Any:
    if args:
        return args[0]
    return kwargs or None


class CrewAICapsuleEmitter:
    """Wrap tool functions so each call emits an Agent Action Capsule.

    Args:
        operator: Tenant/org identifier stamped on every capsule.
        developer: Agent identifier and version.
        chain_capsules: When ``True`` (default), each capsule's ``chain`` block
            references the previous capsule, threading them into a sequence.
    """

    def __init__(
        self,
        *,
        operator: str,
        developer: str,
        chain_capsules: bool = True,
    ) -> None:
        self._operator = operator
        self._developer = developer
        self._chain = chain_capsules
        self.capsules: list[dict] = []

    @property
    def last(self) -> dict | None:
        return self.capsules[-1] if self.capsules else None

    def _emit(self, tool_name: str, tool_input: Any, tool_output: Any) -> dict:
        prior = self.last.get("capsule_id") if (self._chain and self.last) else None
        capsule = _emit_capsule(
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

    def wrap(self, fn: Callable, *, name: str | None = None) -> Callable:
        """Wrap a tool function: call it, then emit a capsule. Framework-free."""
        tool_name = (
            name
            or getattr(fn, "name", None)
            or getattr(fn, "__name__", None)
            or "tool"
        )

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            output = fn(*args, **kwargs)
            self._emit(tool_name, _first_input(args, kwargs), output)
            return output

        wrapped._capsule_emitter = self  # type: ignore[attr-defined]
        return wrapped

    def as_crewai_tool(self, tool: Any, *, name: str | None = None) -> Any:
        """Wrap a ``crewai.tools.BaseTool`` so each call emits a capsule.

        Lazily imports ``crewai`` — only needed for this method. Prefer
        :meth:`wrap` when you have the raw tool function.
        """
        try:
            import crewai  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "CrewAICapsuleEmitter.as_crewai_tool() needs crewai. "
                "Install it with `pip install crewai`."
            ) from exc

        inner_run = tool._run
        tool_name = name or getattr(tool, "name", None) or type(tool).__name__
        _emit = self._emit

        def _run(_self: Any, *args: Any, **kwargs: Any) -> Any:
            output = inner_run(*args, **kwargs)
            _emit(tool_name, _first_input(args, kwargs), output)
            return output

        wrapped_cls = type(f"Emitting{type(tool).__name__}", (type(tool),), {"_run": _run})
        return wrapped_cls.model_construct(
            **{n: getattr(tool, n) for n in type(tool).model_fields}
        )


def emit_tool(
    emitter: CrewAICapsuleEmitter, *, name: str | None = None
) -> Callable[[Callable], Callable]:
    """Decorator: emit a capsule for every call of a tool function.

    Equivalent to ``emitter.wrap(fn)`` in decorator form.

        emitter = CrewAICapsuleEmitter(operator="ACME", developer="agent@v1")

        @emit_tool(emitter)
        def create_invoice(payload: dict) -> dict:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        return emitter.wrap(fn, name=name)
    return decorator
