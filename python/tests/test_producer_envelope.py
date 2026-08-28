# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import sign_sign1

from agent_action_capsule.producer_envelope import CONTENT_TYPE, verify_producer_envelope

VECTORS = Path(__file__).resolve().parents[2] / "producer-envelope-vectors"


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_key(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _envelope(*, content_type: str = CONTENT_TYPE, unprotected: dict | None = None) -> tuple[str, bytes]:
    key = _key()
    payload = bytes(range(32, 64))
    encoded = sign_sign1(
        payload,
        alg="EdDSA",
        private_key_pem=_pem(key),
        protected={3: content_type, 4: _public_key(key)},
        unprotected=unprotected or {},
    )
    return payload.hex(), encoded


def test_verify_producer_envelope() -> None:
    capsule_id, encoded = _envelope()
    result = verify_producer_envelope(capsule_id, encoded)
    assert result.ok, result.findings
    assert result.public_key == _public_key(_key())


def test_verify_producer_envelope_rejects_payload_mismatch() -> None:
    _, encoded = _envelope()
    result = verify_producer_envelope(bytes(range(64, 96)).hex(), encoded)
    assert not result.ok
    assert result.findings[0].code == "envelope_payload_mismatch"


@pytest.mark.parametrize("capsule_id", ["", "A" * 64, "0" * 63, "z" * 64, None, 7])
def test_verify_producer_envelope_rejects_malformed_capsule_id(capsule_id) -> None:
    result = verify_producer_envelope(capsule_id, b"")
    assert not result.ok
    assert result.findings[0].code == "capsule_id_malformed"


@pytest.mark.parametrize("encoded", [b"", b"not-cbor", b"\xd2\x80", None, 7])
def test_verify_producer_envelope_never_raises_on_malformed_input(encoded) -> None:
    result = verify_producer_envelope("00" * 32, encoded)
    assert not result.ok
    assert result.findings[0].code == "envelope_malformed"


def test_verify_producer_envelope_rejects_wrong_content_type() -> None:
    capsule_id, encoded = _envelope(content_type="application/octet-stream")
    result = verify_producer_envelope(capsule_id, encoded)
    assert not result.ok
    assert result.findings[0].code == "envelope_content_type_mismatch"


def test_verify_producer_envelope_rejects_unprotected_header() -> None:
    capsule_id, encoded = _envelope(unprotected={9: True})
    result = verify_producer_envelope(capsule_id, encoded)
    assert not result.ok
    assert result.findings[0].code == "envelope_malformed"


def test_producer_envelope_vectors() -> None:
    manifest = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
    assert manifest["count"] == len(manifest["cases"])
    for case in manifest["cases"]:
        directory = VECTORS / case["name"]
        capsule_id = (directory / "capsule_id.txt").read_text(encoding="ascii").strip()
        encoded = (directory / "envelope.cose").read_bytes()
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        result = verify_producer_envelope(capsule_id, encoded)
        assert result.ok is expected["ok"], (case["name"], result.findings)
        assert [finding.code for finding in result.findings] == expected["finding_codes"]
        public_key_hex = result.public_key.hex() if result.public_key is not None else None
        assert public_key_hex == expected["public_key_hex"]
