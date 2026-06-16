# SPDX-License-Identifier: BSD-3-Clause
"""Rung 6 — anchor CLIENT: async, non-blocking, digest-only transparency-log post.

The anchor client posts a capsule_id digest to a transparency-log endpoint.
Three design constraints drive the implementation:

1. **Non-blocking** — the agent's critical path must not wait on the post.
   ``anchor()`` returns immediately; the HTTP request runs in a daemon thread.
2. **Digest-only** — only the ``capsule_id`` (a SHA-256 hex string) crosses the
   wire. No action payload, no business content, no personal data.
3. **Default-but-repointable** — ``DEFAULT_ANCHOR_ENDPOINT`` is the out-of-box
   destination. Pass ``endpoint=`` to redirect to any compatible server (a
   self-hosted instance, a different transparency log, a test stub).

Usage::

    from agent_action_capsule import emit
    from agent_action_capsule.anchor import anchor

    sealed = emit(action_id="act-001", ...)
    anchor(sealed["capsule_id"])          # fire-and-forget; returns immediately

    # Repoint to a self-hosted server:
    anchor(sealed["capsule_id"], endpoint="https://my-log.example.com/v1/digest")

    # Capture failures (optional — by default errors are silently dropped):
    anchor(sealed["capsule_id"], on_error=lambda exc: logging.warning("anchor: %s", exc))
"""
from __future__ import annotations

import json
import threading
import urllib.request
from collections.abc import Callable
from typing import Any

__all__ = ["anchor", "DEFAULT_ANCHOR_ENDPOINT"]

DEFAULT_ANCHOR_ENDPOINT = "https://anchor.agent-action-capsule.org/v1/digest"


def anchor(
    capsule_id: str,
    *,
    endpoint: str = DEFAULT_ANCHOR_ENDPOINT,
    timeout: float = 10.0,
    on_error: Callable[[Exception], None] | None = None,
    _extra: dict[str, Any] | None = None,
) -> None:
    """Post the capsule_id digest to a transparency log, non-blocking.

    Returns immediately. The HTTP POST runs in a background daemon thread so
    the agent's critical path is never blocked. Only the ``capsule_id`` hex
    string is sent — no business content crosses the wire.

    Args:
        capsule_id: 64-character lowercase-hex SHA-256 capsule_id (from
            ``emit()`` or ``Capsule.seal()``).
        endpoint: Transparency-log URL. Defaults to
            ``DEFAULT_ANCHOR_ENDPOINT``; repoint to any compatible server.
        timeout: HTTP request timeout in seconds (default 10). The background
            thread waits at most this long before raising.
        on_error: Optional callback invoked on the background thread when the
            POST fails. Called with the exception as its only argument. Default
            is to silently drop errors (the anchor is non-critical path).
        _extra: Internal — additional JSON fields merged into the POST body.
            Not part of the public API; reserved for the server protocol.
    """
    body: dict[str, Any] = {"capsule_id": capsule_id}
    if _extra:
        body.update(_extra)
    payload = json.dumps(body, separators=(",", ":")).encode()

    def _post() -> None:
        try:
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp.read()  # consume response body to release connection
        except Exception as exc:
            if on_error is not None:
                on_error(exc)

    t = threading.Thread(target=_post, daemon=True, name="anchor-post")
    t.start()
