# SPDX-License-Identifier: BSD-3-Clause
"""Anchor client (rung 6): two surfaces for different assurance levels.

**Simple anchor** (``anchor()``) — stdlib-only, fire-and-forget HTTP POST of the
``capsule_id`` digest to any compatible endpoint. No optional deps. Use for quick
non-blocking submission to a custom or in-house transparency log.

**SCITT anchor** (``submit_anchor()`` / ``async_anchor()``) — full COSE Signed
Statement workflow: build a COSE_Sign1 statement over the capsule_id digest,
submit it to a SCITT-compliant Transparency Service (TS), receive a COSE Receipt,
and embed it into a Transparent Statement that ``transparent.py`` can verify as
``attestation_tier='anchored'``. Requires ``pip install 'agent-action-capsule[anchor]'``.

Both surfaces are digest-only — only the ``capsule_id`` hex string crosses the
wire. No business content, no action payload, no personal data.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import threading
from collections.abc import Callable
from typing import Any
from urllib.request import Request, urlopen

__all__ = [
    # Simple surface (stdlib-only)
    "anchor",
    "DEFAULT_ANCHOR_ENDPOINT",
    # SCITT surface (requires [anchor] extra)
    "AnchorResult",
    "AnchorError",
    "AnchorFuture",
    "submit_anchor",
    "async_anchor",
    "generate_issuer_keypair",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default endpoint for the simple ``anchor()`` call (digest-only HTTP POST).
DEFAULT_ANCHOR_ENDPOINT = "https://anchor.agent-action-capsule.org/v1/digest"

#: Default SCITT TS URL for ``submit_anchor`` / ``async_anchor``.
_DEFAULT_TS_URL = "https://as-authority-1020437450833.us-central1.run.app"

#: Env-var for overriding the SCITT TS URL without changing code.
AUTHORITY_HINT_ENV = "AAC_ANCHOR_URL"

_PUBKEY_PATH = "/anchor/authority-pubkey"
_REGISTER_PATH = "/transparency/register-statement"

_CONTENT_TYPE_DIGEST = "application/vnd.agent-action-capsule.id+hex"
_ISSUER = "urn:agent-action-capsule:core:free-anchor"


# ---------------------------------------------------------------------------
# Simple surface (stdlib-only)
# ---------------------------------------------------------------------------


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
        capsule_id: 64-character lowercase-hex SHA-256 capsule_id.
        endpoint: Transparency-log URL (default ``DEFAULT_ANCHOR_ENDPOINT``).
        timeout: HTTP request timeout in seconds (default 10).
        on_error: Optional callback invoked on failure (called with the exception).
        _extra: Internal — additional JSON fields merged into the POST body.
    """
    body: dict[str, Any] = {"capsule_id": capsule_id}
    if _extra:
        body.update(_extra)
    payload = json.dumps(body, separators=(",", ":")).encode()

    def _post() -> None:
        try:
            req = Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=timeout) as resp:
                resp.read()
        except Exception as exc:
            if on_error is not None:
                on_error(exc)

    t = threading.Thread(target=_post, daemon=True, name="anchor-post")
    t.start()


# ---------------------------------------------------------------------------
# SCITT surface — result types
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class AnchorResult:
    """Outcome of a successful SCITT TS submission."""

    capsule_id: str
    signed_statement: bytes
    receipt: bytes
    transparent_statement: bytes
    entry_hash: str
    issuer_pubkey_pem: bytes
    log_pubkey_pem: bytes
    ts_url: str


@dataclasses.dataclass
class AnchorError:
    """Captures a SCITT TS submission failure without raising."""

    capsule_id: str
    error: str
    ts_url: str


# ---------------------------------------------------------------------------
# SCITT surface — internal helpers
# ---------------------------------------------------------------------------


def _resolved_ts_url(override: str | None) -> str:
    if override:
        return override.rstrip("/")
    return os.environ.get(AUTHORITY_HINT_ENV, _DEFAULT_TS_URL).rstrip("/")


def _raw_ed25519_to_pem(pubkey_hex: str) -> bytes:
    raw = bytes.fromhex(pubkey_hex)
    if len(raw) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 public key, got {len(raw)} bytes")
    spki_prefix = bytes.fromhex("302a300506032b6570032100")
    der = spki_prefix + raw
    b64 = base64.encodebytes(der).strip().decode("ascii")
    return (
        b"-----BEGIN PUBLIC KEY-----\n"
        + b64.encode("ascii")
        + b"\n-----END PUBLIC KEY-----\n"
    )


def _fetch_log_pubkey_pem(ts_url: str, timeout: float) -> bytes:
    req = Request(ts_url + _PUBKEY_PATH, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return _raw_ed25519_to_pem(data["pubkey_hex"])


def _post_statement(statement_bytes: bytes, ts_url: str, timeout: float) -> dict:
    body = json.dumps(
        {"signed_statement_b64": base64.b64encode(statement_bytes).decode("ascii")}
    ).encode("utf-8")
    req = Request(
        ts_url + _REGISTER_PATH,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# SCITT surface — public API (requires [anchor] extra: scitt-cose + cryptography)
# ---------------------------------------------------------------------------


def generate_issuer_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ephemeral Ed25519 keypair.

    Returns ``(private_key_pem, public_key_pem)``. Requires the ``[anchor]`` extra.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
    from cryptography.hazmat.primitives.serialization import (  # type: ignore
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def submit_anchor(
    capsule_id: str,
    *,
    signing_key_pem: bytes | None = None,
    ts_url: str | None = None,
    timeout: float = 30.0,
) -> AnchorResult:
    """Submit ``capsule_id`` to the SCITT TS (synchronous).

    Builds a COSE Signed Statement over the capsule_id digest (no business
    content), submits to the TS, receives a COSE Receipt, and embeds it into
    a Transparent Statement. Requires the ``[anchor]`` extra.

    Args:
        capsule_id: 64-char hex capsule_id to anchor.
        signing_key_pem: PEM PKCS-8 Ed25519 private key; ``None`` generates ephemeral.
        ts_url: Override the TS base URL (else reads ``AAC_ANCHOR_URL`` env var).
        timeout: Per-request HTTP timeout in seconds.

    Returns:
        :class:`AnchorResult` with the Transparent Statement and verification artefacts.
    """
    from cryptography.hazmat.primitives.serialization import (  # type: ignore
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )
    from scitt_cose.statement import attach_receipts, build_signed_statement  # type: ignore

    if signing_key_pem is None:
        signing_key_pem, issuer_pubkey_pem = generate_issuer_keypair()
    else:
        priv = load_pem_private_key(signing_key_pem, password=None)
        issuer_pubkey_pem = priv.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

    resolved = _resolved_ts_url(ts_url)
    log_pubkey_pem = _fetch_log_pubkey_pem(resolved, timeout)

    statement_bytes = build_signed_statement(
        capsule_id.encode("ascii"),
        alg="EdDSA",
        private_key_pem=signing_key_pem,
        issuer=_ISSUER,
        subject=capsule_id,
        content_type=_CONTENT_TYPE_DIGEST,
    )

    resp = _post_statement(statement_bytes, resolved, timeout)
    receipt_bytes = base64.b64decode(resp["receipt_b64"])
    entry_hash: str = resp["entry_hash"]

    expected_entry_hash = hashlib.sha256(statement_bytes).hexdigest()
    if entry_hash != expected_entry_hash:
        raise ValueError(
            f"TS entry_hash mismatch: got {entry_hash!r}, "
            f"expected SHA-256(statement) = {expected_entry_hash!r}"
        )

    transparent = attach_receipts(statement_bytes, [receipt_bytes])

    return AnchorResult(
        capsule_id=capsule_id,
        signed_statement=statement_bytes,
        receipt=receipt_bytes,
        transparent_statement=transparent,
        entry_hash=entry_hash,
        issuer_pubkey_pem=issuer_pubkey_pem,
        log_pubkey_pem=log_pubkey_pem,
        ts_url=resolved,
    )


class AnchorFuture:
    """Lightweight one-shot future for an async SCITT anchor submission."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._value: AnchorResult | AnchorError | None = None

    def _set(self, value: AnchorResult | AnchorError) -> None:
        self._value = value
        self._event.set()

    def done(self) -> bool:
        """``True`` once the submission has completed or failed."""
        return self._event.is_set()

    def result(
        self, timeout: float | None = None
    ) -> AnchorResult | AnchorError | None:
        """Return the result, blocking up to ``timeout`` seconds."""
        self._event.wait(timeout=timeout)
        return self._value


def async_anchor(
    capsule_id: str,
    *,
    signing_key_pem: bytes | None = None,
    ts_url: str | None = None,
    on_result: Callable[[AnchorResult | AnchorError], None] | None = None,
    submit_timeout: float = 30.0,
) -> AnchorFuture:
    """Fire-and-forget SCITT anchor — returns an :class:`AnchorFuture` immediately.

    Dispatches the TS submission on a daemon thread. Requires the ``[anchor]`` extra.

    Args:
        capsule_id: The capsule digest to anchor.
        signing_key_pem: Optional PKCS-8 PEM private key; ``None`` generates ephemeral.
        ts_url: TS base URL override; ``None`` reads ``AAC_ANCHOR_URL`` env var.
        on_result: Optional callback with the :class:`AnchorResult` or :class:`AnchorError`.
        submit_timeout: Per-request HTTP timeout in seconds.

    Returns:
        :class:`AnchorFuture` — already running in the background.
    """
    future: AnchorFuture = AnchorFuture()

    def _worker() -> None:
        try:
            result = submit_anchor(
                capsule_id,
                signing_key_pem=signing_key_pem,
                ts_url=ts_url,
                timeout=submit_timeout,
            )
            future._set(result)
        except Exception as exc:
            error = AnchorError(
                capsule_id=capsule_id,
                error=repr(exc),
                ts_url=_resolved_ts_url(ts_url),
            )
            future._set(error)
            return

        if on_result is not None:
            try:
                on_result(result)
            except Exception:  # noqa: BLE001
                pass

    t = threading.Thread(
        target=_worker,
        daemon=True,
        name=f"aac-anchor-{capsule_id[:8]}",
    )
    t.start()
    return future
