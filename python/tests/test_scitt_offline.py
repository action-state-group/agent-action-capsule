# SPDX-License-Identifier: BSD-3-Clause
"""Offline anchor → verify pipeline test with an in-process SCITT TS stub.

No network calls — the TS stub runs on localhost:0 in a daemon thread.
Acceptance criteria (from [land-anchor-client]):
  1. anchor → verify: attestation_tier == 'anchored' (VALID).
  2. Tamper the Transparent Statement → signature_verified is not True (INVALID).
  3. anchor CLI subcommand parses and executes correctly against the stub.

Requires the [anchor] extra (scitt-cose + cryptography).
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import socketserver
import threading
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# In-process SCITT TS stub
# ---------------------------------------------------------------------------


class _InProcessTS:
    """Minimal SCITT TS stub: accepts Signed Statements, mints COSE Receipts."""

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
        from cryptography.hazmat.primitives.serialization import (  # type: ignore
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        priv = Ed25519PrivateKey.generate()
        self._priv_pem: bytes = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        self._pub_pem: bytes = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        raw_pub: bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._pubkey_hex: str = raw_pub.hex()

        self._log: list[str] = []
        self._lock = threading.Lock()

        ts = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                pass  # silence server output during tests

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/anchor/authority-pubkey":
                    body = json.dumps({"pubkey_hex": ts._pubkey_hex}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self) -> None:  # noqa: N802
                if self.path == "/transparency/register-statement":
                    length = int(self.headers.get("Content-Length", 0))
                    data = json.loads(self.rfile.read(length))
                    stmt_bytes = base64.b64decode(data["signed_statement_b64"])
                    entry_hash = hashlib.sha256(stmt_bytes).hexdigest()

                    with ts._lock:
                        ts._log.append(entry_hash)
                        log_snapshot = list(ts._log)
                        leaf_idx = len(log_snapshot) - 1

                    from scitt_cose.receipt import build_receipt  # type: ignore

                    receipt_bytes = build_receipt(
                        leaf_entry_hex=entry_hash,
                        leaf_index=leaf_idx,
                        tree_entries_hex=log_snapshot,
                        alg="EdDSA",
                        log_private_key_pem=ts._priv_pem,
                    )
                    body = json.dumps(
                        {
                            "receipt_b64": base64.b64encode(receipt_bytes).decode(),
                            "entry_hash": entry_hash,
                        }
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

        self._server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        self._server.allow_reuse_address = True
        port = self._server.server_address[1]
        self.url: str = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> _InProcessTS:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()

    @property
    def log_pubkey_pem(self) -> bytes:
        return self._pub_pem


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ts_stub():
    ts = _InProcessTS().start()
    yield ts
    ts.stop()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_anchor_verify_offline(ts_stub, tmp_path):
    """anchor → verify runs entirely offline; attestation_tier == 'anchored'."""
    from agent_action_capsule.anchor import AnchorResult, submit_anchor
    from agent_action_capsule.transparent import verify_transparent

    # Use a stable test capsule_id (no emit.py needed — anchor is digest-only)
    capsule_id = hashlib.sha256(b"aac-offline-anchor-test").hexdigest()

    result = submit_anchor(capsule_id, ts_url=ts_stub.url)
    assert isinstance(result, AnchorResult)
    assert result.capsule_id == capsule_id
    assert result.receipt
    assert result.transparent_statement
    assert result.entry_hash == hashlib.sha256(result.signed_statement).hexdigest()

    # Write artefacts to tmp files for verify_transparent
    stmt_path = tmp_path / "statement.cose"
    stmt_path.write_bytes(result.transparent_statement)
    issuer_key_path = tmp_path / "issuer.pem"
    issuer_key_path.write_bytes(result.issuer_pubkey_pem)
    log_key_path = tmp_path / "log.pem"
    log_key_path.write_bytes(ts_stub.log_pubkey_pem)

    report = verify_transparent(
        statement_path=str(stmt_path),
        issuer_key_path=str(issuer_key_path),
        log_key_path=str(log_key_path),
        leaf_entry_hex=result.entry_hash,
    )

    assert report.signature_verified is True, report.substrate_errors
    assert report.receipt_present is True
    assert report.receipt_verified is True, report.substrate_errors
    # Digest-only payload (capsule_id bytes) is not a JSON capsule, so
    # report.ok is False (Class-1 skipped), but attestation_tier is the key.
    assert report.attestation_tier == "anchored", (
        f"Expected 'anchored', got {report.attestation_tier!r}; "
        f"substrate_errors={report.substrate_errors}"
    )


def test_tamper_invalid(ts_stub, tmp_path):
    """Tamper with the Transparent Statement → signature_verified is not True."""
    from agent_action_capsule.anchor import submit_anchor
    from agent_action_capsule.transparent import verify_transparent

    capsule_id = hashlib.sha256(b"aac-tamper-test").hexdigest()
    result = submit_anchor(capsule_id, ts_url=ts_stub.url)

    # Flip a bit in the protected header / payload / signature region.
    # The transparent statement structure is: protected_hdr | unprotected_hdr |
    # payload | signature. We flip near the start (past the 2-byte CBOR tag+array)
    # which reliably lands in the protected header — covered by the signature.
    tampered = bytearray(result.transparent_statement)
    tampered[4] ^= 0xFF

    stmt_path = tmp_path / "tampered.cose"
    stmt_path.write_bytes(bytes(tampered))
    issuer_key_path = tmp_path / "issuer.pem"
    issuer_key_path.write_bytes(result.issuer_pubkey_pem)
    log_key_path = tmp_path / "log.pem"
    log_key_path.write_bytes(ts_stub.log_pubkey_pem)

    report = verify_transparent(
        statement_path=str(stmt_path),
        issuer_key_path=str(issuer_key_path),
        log_key_path=str(log_key_path),
        leaf_entry_hex=result.entry_hash,
    )

    assert report.signature_verified is not True, (
        "Expected tampered statement to fail signature verification"
    )
    assert report.attestation_tier != "anchored", (
        f"Expected tampered statement NOT to be 'anchored', got {report.attestation_tier!r}"
    )


def test_anchor_cli_submit(ts_stub, capsys):
    """anchor submit subcommand reaches the in-process TS and prints a result."""
    from agent_action_capsule.cli import main

    capsule_id = hashlib.sha256(b"aac-cli-test").hexdigest()
    rc = main(["anchor", "submit", capsule_id, "--ts-url", ts_stub.url])
    out = capsys.readouterr().out
    assert rc == 0, f"expected exit 0, got {rc}\noutput: {out}"
    assert "entry_hash" in out
    assert capsule_id in out


def test_anchor_cli_submit_json(ts_stub, capsys):
    """anchor submit --json returns machine-readable output."""
    from agent_action_capsule.cli import main

    capsule_id = hashlib.sha256(b"aac-cli-json-test").hexdigest()
    rc = main(["anchor", "submit", "--json", capsule_id, "--ts-url", ts_stub.url])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert doc["ok"] is True
    assert doc["capsule_id"] == capsule_id
    assert doc["entry_hash"]
    assert doc["receipt_size"] > 0


def test_anchor_cli_rejects_bad_capsule_id(capsys):
    """anchor submit rejects a malformed capsule_id without calling the TS."""
    from agent_action_capsule.cli import main

    rc = main(["anchor", "submit", "not-a-hex-id"])
    assert rc == 2
