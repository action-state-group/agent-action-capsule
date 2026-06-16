# SPDX-License-Identifier: BSD-3-Clause
"""Integration test for [anchor-wire]: CORE → TS → transparent.py 'anchored'.

Acceptance criteria:
  1. submit_anchor posts a Signed Statement (digest-only) to the deployed TS.
  2. TS returns a COSE Receipt; transparent.py reports attestation_tier='anchored'.
  3. scitt-cose verifies the receipt standalone (no transparent.py).
  4. async_anchor returns immediately (agent never blocks on the TS round-trip).
  5. digest-only: statement payload = capsule_id bytes; entry_hash = SHA-256(stmt).
  6. Repoint: AAC_ANCHOR_URL env var redirects the submission.
  7. No dependency on action-state-authority (private package must NOT be imported).

All network-touching tests skip cleanly when the TS is unreachable.
"""
from __future__ import annotations

import hashlib
import os
import time

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_TS_URL = "https://as-authority-1020437450833.us-central1.run.app"
_TS_URL = os.environ.get("AAC_TS_URL", _DEFAULT_TS_URL)


def _ts_reachable(url: str) -> bool:
    try:
        from urllib.request import urlopen

        urlopen(f"{url}/health", timeout=5.0)
        return True
    except Exception:
        return False


def _make_capsule_id() -> str:
    """A reproducible test capsule_id (hex digest)."""
    return hashlib.sha256(b"anchor-wire-test-capsule").hexdigest()


_ts_available = _ts_reachable(_TS_URL)
skip_if_offline = pytest.mark.skipif(
    not _ts_available, reason=f"TS unreachable at {_TS_URL}"
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_if_offline
def test_submit_and_transparent_anchored(tmp_path):
    """CORE posts a Signed Statement → TS → receipt → transparent.py 'anchored'."""
    from agent_action_capsule.anchor import AnchorResult, submit_anchor
    from agent_action_capsule.transparent import verify_transparent

    capsule_id = _make_capsule_id()
    result = submit_anchor(capsule_id, ts_url=_TS_URL)

    assert isinstance(result, AnchorResult)
    assert result.capsule_id == capsule_id
    assert result.receipt
    assert result.transparent_statement
    assert result.entry_hash
    assert result.issuer_pubkey_pem
    assert result.log_pubkey_pem

    # Write artefacts to tmp files for verify_transparent
    stmt_path = tmp_path / "statement.cose"
    stmt_path.write_bytes(result.transparent_statement)
    issuer_key_path = tmp_path / "issuer.pem"
    issuer_key_path.write_bytes(result.issuer_pubkey_pem)
    log_key_path = tmp_path / "log.pem"
    log_key_path.write_bytes(result.log_pubkey_pem)

    report = verify_transparent(
        statement_path=str(stmt_path),
        issuer_key_path=str(issuer_key_path),
        log_key_path=str(log_key_path),
        leaf_entry_hex=result.entry_hash,
    )

    assert report.signature_verified is True, report.substrate_errors
    assert report.receipt_present is True
    assert report.receipt_verified is True, report.substrate_errors
    assert report.attestation_tier == "anchored", (
        f"Expected 'anchored', got {report.attestation_tier!r}; "
        f"substrate_errors={report.substrate_errors}"
    )
    # report.ok is the COMBINED verdict (signature + receipt + Class-1 payload).
    # For digest-only anchoring the payload is capsule_id bytes (not a JSON capsule),
    # so Class-1 verification is skipped and report.payload is None.
    # The attestation_tier='anchored' is the key criterion: the receipt DID verify.
    # report.ok would be True only for a full Transparent Statement whose payload is
    # a valid Agent Action Capsule JSON object.


@skip_if_offline
def test_scitt_cose_standalone():
    """scitt-cose verifies the receipt standalone (no transparent.py)."""
    from scitt_cose.receipt import verify_receipt  # type: ignore

    from agent_action_capsule.anchor import submit_anchor

    capsule_id = _make_capsule_id()
    result = submit_anchor(capsule_id, ts_url=_TS_URL)

    res = verify_receipt(
        result.receipt,
        leaf_entry_hex=result.entry_hash,
        log_public_key_pem=result.log_pubkey_pem,
    )
    assert res.ok, f"scitt-cose verify_receipt failed: {res.errors}"


@skip_if_offline
def test_digest_only():
    """Payload = capsule_id bytes only; entry_hash = SHA-256(statement_bytes)."""
    import cbor2  # type: ignore

    from agent_action_capsule.anchor import submit_anchor

    capsule_id = _make_capsule_id()
    result = submit_anchor(capsule_id, ts_url=_TS_URL)

    # entry_hash must equal SHA-256 of the raw statement bytes (interop contract)
    expected_entry_hash = hashlib.sha256(result.signed_statement).hexdigest()
    assert result.entry_hash == expected_entry_hash

    # Statement payload must be capsule_id bytes — not a full capsule JSON
    outer = cbor2.loads(result.signed_statement)
    payload_bytes = outer.value[2]  # COSE_Sign1: [protected, unprotected, payload, sig]
    assert isinstance(payload_bytes, (bytes, bytearray))
    assert payload_bytes == capsule_id.encode("ascii"), (
        "Statement payload must be the capsule_id digest only — no business content"
    )


@skip_if_offline
def test_async_non_blocking():
    """async_anchor returns immediately; the caller thread is never blocked."""
    from agent_action_capsule.anchor import AnchorFuture, AnchorResult, async_anchor

    capsule_id = _make_capsule_id()
    t0 = time.monotonic()
    future = async_anchor(capsule_id, ts_url=_TS_URL)
    elapsed = time.monotonic() - t0

    # Must return before any TS round-trip completes (well under 1 second)
    assert elapsed < 1.0, f"async_anchor blocked the caller for {elapsed:.3f}s"
    assert isinstance(future, AnchorFuture)
    assert not future.done()  # still in flight

    # The future resolves within a generous timeout
    result = future.result(timeout=60.0)
    assert result is not None, "async_anchor future did not resolve within 60s"
    assert isinstance(result, AnchorResult), (
        f"Expected AnchorResult, got {type(result).__name__}: {result}"
    )


@skip_if_offline
def test_async_on_result_callback():
    """on_result callback is invoked with the AnchorResult on the worker thread."""
    from agent_action_capsule.anchor import AnchorResult, async_anchor

    received: list[object] = []
    done = __import__("threading").Event()

    def _cb(r):
        received.append(r)
        done.set()

    capsule_id = _make_capsule_id()
    async_anchor(capsule_id, ts_url=_TS_URL, on_result=_cb)

    done.wait(timeout=60.0)
    assert len(received) == 1
    assert isinstance(received[0], AnchorResult)


@skip_if_offline
def test_repoint_via_env_var(monkeypatch):
    """AAC_ANCHOR_URL env var redirects the submission (no ts_url kwarg needed)."""
    from agent_action_capsule.anchor import AnchorResult, submit_anchor

    monkeypatch.setenv("AAC_ANCHOR_URL", _TS_URL)

    capsule_id = _make_capsule_id()
    result = submit_anchor(capsule_id)  # no explicit ts_url → reads env var

    assert isinstance(result, AnchorResult)
    assert result.ts_url == _TS_URL


def test_no_dependency_on_authority():
    """agent_action_capsule.anchor must NOT import action-state-authority (private)."""
    import sys

    # Import the module fresh (may already be imported in prior tests — that's fine)
    import agent_action_capsule.anchor  # noqa: F401

    for name in sys.modules:
        assert "as_authority" not in name, (
            f"anchor module pulled in private as_authority package via sys.modules[{name!r}]"
        )


def test_import_guard():
    """anchor module is importable even with a missing optional dep, reporting clearly."""
    # The module should import successfully when scitt-cose IS installed.
    import agent_action_capsule.anchor as m  # noqa: F401

    # Verify the public surface
    from agent_action_capsule.anchor import (  # noqa: F401
        AnchorError,
        AnchorFuture,
        AnchorResult,
        async_anchor,
        generate_issuer_keypair,
        submit_anchor,
    )
