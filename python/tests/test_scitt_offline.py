# SPDX-License-Identifier: BSD-3-Clause
"""Offline anchor → verify pipeline test with an in-process SCITT TS stub.

No network calls — the TS stub runs on localhost:0 in a daemon thread.
Acceptance criteria:
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


def _entry_preimage(stmt_bytes: bytes, scheme: str | None) -> bytes:
    """What capsule-anchor hashes for ``entry_hash`` (its
    ``_entry_hash_preimage``): the Sig_structure of an embedded-payload
    COSE_Sign1 under ``sig_structure``, the statement bytes otherwise. An
    unknown scheme hashes the Sig_structure, so only the label is wrong."""
    if scheme in (None, "legacy"):
        return stmt_bytes
    import cbor2

    outer = cbor2.loads(stmt_bytes)
    protected_bstr, _unprotected, payload, _signature = outer.value
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload])


class _InProcessTS:
    """Minimal SCITT TS stub: accepts Signed Statements, mints COSE Receipts."""

    def __init__(self, *, scheme: str | None = "sig_structure", receipt_claims: dict | None = None) -> None:
        """``scheme`` is the ``entry_hash_scheme`` the stub hashes under and
        declares (``None``: hashes the statement bytes and omits the field, as
        a service from before the field). ``receipt_claims`` are the
        ``build_receipt`` keyword arguments ``iss``/``sub``/``kid``/``iat``;
        the default carries all three RFC 9943 headers and the current time,
        as the fixed witness does (capsule-anchor#103)."""
        import time

        self.scheme = scheme
        self.receipt_claims = (
            receipt_claims
            if receipt_claims is not None
            else {"iss": "did:web:ts.example", "sub": "stub-subject", "kid": b"stub-key-id", "iat": int(time.time())}
        )
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
                    entry_hash = hashlib.sha256(_entry_preimage(stmt_bytes, ts.scheme)).hexdigest()

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
                        **ts.receipt_claims,
                    )
                    answer = {
                        "receipt_b64": base64.b64encode(receipt_bytes).decode(),
                        "entry_hash": entry_hash,
                    }
                    if ts.scheme is not None:
                        answer["entry_hash_scheme"] = ts.scheme
                    body = json.dumps(answer).encode()
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

    # Use a stable test capsule_id (no Capsule needed — anchor is digest-only)
    capsule_id = hashlib.sha256(b"aac-offline-anchor-test").hexdigest()

    result = submit_anchor(capsule_id, ts_url=ts_stub.url)
    assert isinstance(result, AnchorResult)
    assert result.capsule_id == capsule_id
    assert result.receipt
    assert result.transparent_statement
    import cbor2

    # The stub hashes the Sig_structure, as capsule-anchor does, and says so.
    assert result.entry_hash == hashlib.sha256(_entry_preimage(result.signed_statement, "sig_structure")).hexdigest()
    assert result.entry_hash != hashlib.sha256(result.signed_statement).hexdigest()

    outer = cbor2.loads(result.signed_statement)
    protected = cbor2.loads(outer.value[0])
    assert protected[3] == "application/agent-action-capsule-id"
    assert protected[15][1] == "urn:agent-action-capsule:core:free-anchor"
    assert protected[15][2] == capsule_id

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
    # Registration authenticates the raw Capsule ID. Class-1 Capsule
    # verification remains a separate operation over the Capsule JSON.
    assert report.ok
    assert report.receipt_findings == []
    assert report.payload is None
    assert report.authenticated_capsule_id == capsule_id
    assert report.attestation_tier == "anchored", (
        f"Expected 'anchored', got {report.attestation_tier!r}; "
        f"substrate_errors={report.substrate_errors}"
    )


def test_submit_anchor_validates_capsule_id_before_network():
    from agent_action_capsule.anchor import submit_anchor

    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        submit_anchor("not-a-capsule-id", ts_url="http://127.0.0.1:1")


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


# ---------------------------------------------------------------------------
# entry_hash under the declared scheme (agent-action-capsule#683, bug 1)
# ---------------------------------------------------------------------------


def _anchor_and_verify(tmp_path, ts, label: bytes):
    from agent_action_capsule.anchor import submit_anchor
    from agent_action_capsule.transparent import verify_transparent

    result = submit_anchor(hashlib.sha256(label).hexdigest(), ts_url=ts.url)
    stmt_path = tmp_path / "statement.cose"
    stmt_path.write_bytes(result.transparent_statement)
    issuer_key_path = tmp_path / "issuer.pem"
    issuer_key_path.write_bytes(result.issuer_pubkey_pem)
    log_key_path = tmp_path / "log.pem"
    log_key_path.write_bytes(ts.log_pubkey_pem)
    return result, verify_transparent(
        statement_path=str(stmt_path),
        issuer_key_path=str(issuer_key_path),
        log_key_path=str(log_key_path),
        leaf_entry_hex=result.entry_hash,
    )


@pytest.mark.parametrize("scheme", ["legacy", None])
def test_submit_anchor_legacy_scheme(tmp_path, scheme):
    """A service hashing the statement bytes, declaring ``legacy`` or (from
    before the field) nothing, is accepted."""
    ts = _InProcessTS(scheme=scheme).start()
    try:
        result, report = _anchor_and_verify(tmp_path, ts, b"legacy-scheme")
    finally:
        ts.stop()
    assert result.entry_hash == hashlib.sha256(result.signed_statement).hexdigest()
    assert report.ok and report.attestation_tier == "anchored", report.substrate_errors


def test_submit_anchor_refuses_unknown_scheme():
    from agent_action_capsule.anchor import submit_anchor

    ts = _InProcessTS(scheme="merkle-of-the-week").start()
    try:
        with pytest.raises(ValueError, match="unknown entry_hash_scheme 'merkle-of-the-week'"):
            submit_anchor(hashlib.sha256(b"unknown-scheme").hexdigest(), ts_url=ts.url)
    finally:
        ts.stop()


@pytest.mark.parametrize("declared,hashed", [("sig_structure", "legacy"), ("legacy", "sig_structure")])
def test_submit_anchor_refuses_entry_hash_mismatch(monkeypatch, declared, hashed):
    """An entry_hash that is not the declared scheme's digest of our statement
    is refused, whichever scheme is declared."""
    import importlib

    # The package's ``anchor`` attribute is the function; take the module.
    anchor_mod = importlib.import_module("agent_action_capsule.anchor")

    real_post = anchor_mod._post_statement

    def lying_post(statement_bytes, ts_url, timeout):
        answer = real_post(statement_bytes, ts_url, timeout)
        answer["entry_hash"] = hashlib.sha256(_entry_preimage(statement_bytes, hashed)).hexdigest()
        answer["entry_hash_scheme"] = declared
        return answer

    monkeypatch.setattr(anchor_mod, "_post_statement", lying_post)
    ts = _InProcessTS().start()
    try:
        with pytest.raises(ValueError, match=f"under entry_hash_scheme '{declared}'"):
            anchor_mod.submit_anchor(hashlib.sha256(b"mismatch").hexdigest(), ts_url=ts.url)
    finally:
        ts.stop()


# ---------------------------------------------------------------------------
# Receipts must carry iss, sub and kid (agent-action-capsule#683, bug 2)
# ---------------------------------------------------------------------------

_FULL = {"iss": "did:web:ts.example", "sub": "stub-subject", "kid": b"stub-key-id"}


def _after_cutoff() -> int:
    from agent_action_capsule.transparent import LEGACY_RECEIPT_IAT_CUTOFF

    return LEGACY_RECEIPT_IAT_CUTOFF


def _before_cutoff() -> int:
    return _after_cutoff() - 1


@pytest.mark.parametrize("dropped", ["iss", "sub", "kid"])
def test_receipt_missing_header_fails(tmp_path, dropped):
    """From the cutoff on, a receipt lacking any of iss/sub/kid is not
    verified, so the statement is never reported anchored."""
    claims = {k: v for k, v in _FULL.items() if k != dropped}
    claims["iat"] = _after_cutoff()
    ts = _InProcessTS(receipt_claims=claims).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"missing-" + dropped.encode())
    finally:
        ts.stop()
    assert report.receipt_verified is False
    assert report.attestation_tier == "self_attested"
    assert not report.ok
    assert any(f"receipt lacks {dropped}" in e for e in report.substrate_errors), report.substrate_errors
    assert report.receipt_findings == []


@pytest.mark.parametrize("bad", [{"iss": ""}, {"sub": ""}, {"kid": b""}, {"iss": 7}])
def test_receipt_empty_or_mistyped_header_fails(tmp_path, bad):
    claims = {**_FULL, **bad, "iat": _after_cutoff()}
    ts = _InProcessTS(receipt_claims=claims).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"bad-header")
    finally:
        ts.stop()
    assert report.receipt_verified is False and not report.ok, report.substrate_errors


def test_pre_fix_receipt_is_a_finding(tmp_path):
    """A receipt the witness issued before the fix (no iss/sub/kid, iat
    before the cutoff) still verifies, with a finding, so published interop
    runs keep their verdict."""
    ts = _InProcessTS(receipt_claims={"iat": _before_cutoff()}).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"pre-fix")
    finally:
        ts.stop()
    assert report.ok and report.attestation_tier == "anchored", report.substrate_errors
    assert len(report.receipt_findings) == 1
    assert "receipt lacks iss, sub, kid" in report.receipt_findings[0]
    assert "before the cutoff" in report.receipt_findings[0]


@pytest.mark.parametrize("claims", [{}, {"iat": True}], ids=["no-iat", "bool-iat"])
def test_headerless_receipt_without_integer_iat_fails(tmp_path, claims):
    """No signed integer iat, no exception: the receipt fails."""
    ts = _InProcessTS(receipt_claims=claims).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"no-iat")
    finally:
        ts.stop()
    assert report.receipt_verified is False and not report.ok


def test_full_receipt_has_no_finding(tmp_path):
    ts = _InProcessTS(receipt_claims={**_FULL, "iat": _before_cutoff()}).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"full")
    finally:
        ts.stop()
    assert report.ok and report.receipt_findings == []


# The Signed Statement of the interop's case 06 and the entry_hash the live
# witness returned for it, from Laurent-Lemonnier/dps-scitt-decision-layer
# (Apache-2.0) at e444fff, interop/aac/cases/06-transparency-receipt/
# signed-statement.cose and ts-response.json.
_CASE06_STATEMENT = bytes.fromhex(
    "d284589aa30378236170706c69636174696f6e2f6167656e742d616374696f6e2d63617073756c652d69640fa2"
    "01782975726e3a6167656e742d616374696f6e2d63617073756c653a636f72653a667265652d616e63686f7202"
    "7840353334663461613833363733373430636563663136653138333030363265306133313661346261633532"
    "343063633032623933656666663938303333313436360127a05820534f4aa83673740cecf16e1830062e0a316a"
    "4bac5240cc02b93efff98033146658403ffeb5278ed902f5132516a747b9f2fcb2a4951e8e68d68972d0378f3a"
    "4a8223448970feb85d9bcbf194903790016b3abe0427dc06decdecf29c102a30c9520c"
)
_CASE06_ENTRY_HASH = "5086d1f277ead4809b792733575661f399a4e6b8fa0a02c0ea5c2607eb0098b6"


def test_sig_structure_entry_hash_matches_live_witness():
    """The client's sig_structure digest of case 06's statement is the
    entry_hash the live witness returned, and the legacy digest is not."""
    import importlib

    anchor_mod = importlib.import_module("agent_action_capsule.anchor")
    assert anchor_mod._expected_entry_hash(_CASE06_STATEMENT, "sig_structure") == _CASE06_ENTRY_HASH
    assert anchor_mod._expected_entry_hash(_CASE06_STATEMENT, "legacy") != _CASE06_ENTRY_HASH


def test_submit_anchor_refuses_receipt_for_another_entry(monkeypatch):
    """A correct entry_hash next to a receipt that does not prove it is refused."""
    import importlib

    anchor_mod = importlib.import_module("agent_action_capsule.anchor")
    real_post = anchor_mod._post_statement
    first: dict = {}

    def swapping_post(statement_bytes, ts_url, timeout):
        answer = real_post(statement_bytes, ts_url, timeout)
        if not first:
            first.update(answer)
            return answer
        answer["receipt_b64"] = first["receipt_b64"]  # the receipt of the first entry
        return answer

    monkeypatch.setattr(anchor_mod, "_post_statement", swapping_post)
    ts = _InProcessTS().start()
    try:
        anchor_mod.submit_anchor(hashlib.sha256(b"first").hexdigest(), ts_url=ts.url)
        with pytest.raises(ValueError, match="TS receipt does not verify"):
            anchor_mod.submit_anchor(hashlib.sha256(b"second").hexdigest(), ts_url=ts.url)
    finally:
        ts.stop()


def test_headerless_receipt_at_the_cutoff_fails(tmp_path):
    ts = _InProcessTS(receipt_claims={"iat": _after_cutoff()}).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"at-cutoff")
    finally:
        ts.stop()
    assert report.receipt_verified is False and not report.ok
    assert report.receipt_findings == []


@pytest.mark.parametrize("bad", [{"iss": b"did:web:ts.example"}, {"sub": b"subject"}, {"kid": "text-kid"}])
def test_receipt_header_of_wrong_type_fails(tmp_path, bad):
    claims = {**_FULL, **bad, "iat": _after_cutoff()}
    ts = _InProcessTS(receipt_claims=claims).start()
    try:
        _result, report = _anchor_and_verify(tmp_path, ts, b"wrong-type")
    finally:
        ts.stop()
    assert report.receipt_verified is False and not report.ok, report.substrate_errors


def test_second_receipt_complete_passes(tmp_path):
    """A headerless receipt first and a complete one second: the first is
    reported, the second verifies the statement."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
    from scitt_cose.receipt import build_receipt
    from scitt_cose.statement import attach_receipts, build_signed_statement

    from agent_action_capsule.transparent import verify_transparent

    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    capsule_id = hashlib.sha256(b"two-receipts").hexdigest()
    stmt = build_signed_statement(
        bytes.fromhex(capsule_id), alg="EdDSA", private_key_pem=priv, issuer="urn:example:issuer",
        subject=capsule_id, content_type="application/agent-action-capsule-id",
    )
    leaf = hashlib.sha256(stmt).hexdigest()
    common = {"leaf_entry_hex": leaf, "leaf_index": 0, "tree_entries_hex": [leaf], "alg": "EdDSA", "log_private_key_pem": priv}
    bare = build_receipt(**common, iat=_after_cutoff())
    full = build_receipt(**common, **_FULL, iat=_after_cutoff())
    (tmp_path / "s.cose").write_bytes(attach_receipts(stmt, [bare, full]))
    (tmp_path / "k.pem").write_bytes(pub)
    report = verify_transparent(
        statement_path=str(tmp_path / "s.cose"), issuer_key_path=str(tmp_path / "k.pem"),
        log_key_path=str(tmp_path / "k.pem"), leaf_entry_hex=leaf,
    )
    assert report.ok and report.attestation_tier == "anchored"
    assert any("receipt lacks iss, sub, kid" in e for e in report.substrate_errors)


@pytest.mark.parametrize(
    "ext,missing",
    [
        ({4: b"k"}, []),
        ({34: [-16, b"\x00" * 32]}, []),  # x5t in place of kid
        ({33: b"cert"}, []),  # x5chain in place of kid
        ({33: [b"leaf", b"ca"]}, []),
        ({34: 0}, ["kid"]),  # placeholders do not stand in
        ({34: [-16, b""]}, ["kid"]),
        ({33: b""}, ["kid"]),
        ({33: []}, ["kid"]),
        ({33: [b"leaf", 7]}, ["kid"]),
        ({}, ["kid"]),
        ({4: "k"}, ["kid"]),
    ],
)
def test_kid_or_x509_header_satisfies_key_identification(ext, missing):
    """RFC 9943 Section 6: kid is required only when neither x5t nor x5chain
    is in the protected header."""
    from types import SimpleNamespace

    from agent_action_capsule.transparent import _missing_receipt_headers

    res = SimpleNamespace(issuer="did:web:ts.example", subject="s", protected_header_ext=ext)
    assert _missing_receipt_headers(res) == missing
