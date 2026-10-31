# SPDX-License-Identifier: BSD-3-Clause
"""Strict Ed25519 (``agent_action_capsule._ed25519_strict``) and the paths
that verify under a pinned, registered or trusted key with it."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from agent_action_capsule._ed25519_strict import strict_encoding, verify_strict  # noqa: E402

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "cross-language" / "cll-ed25519-vectors.json"

# The identity key and its forgery (R the identity, S = 0), which plain
# cofactorless verification accepts over any message, and the non-canonical
# encoding of y = p + 2, which strict verification refuses as an R.
IDENTITY = bytes([1]) + bytes(31)
FORGERY = IDENTITY + bytes(32)
NON_CANONICAL_R = bytes([0xEF]) + b"\xff" * 30 + bytes([0x7F])

KEY = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
KEY_RAW = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _lenient(key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except Exception:  # noqa: BLE001 -- any refusal is "does not verify"
        return False
    return True


def _cases() -> list[dict]:
    cases = json.loads(VECTORS.read_text())["ed25519_cases"]
    assert len(cases) == 54
    return cases


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_strict_matches_the_cll_vectors(case):
    """checkpointed-local-log's shared strict Ed25519 cases
    (``vectors/cross-language/cll-ed25519-vectors.json``, a verbatim copy):
    ``verify_strict``, and the pre-check followed by ``cryptography``'s verify
    as the witness receipt check runs them, accept exactly the valid ones."""
    key, signature = bytes.fromhex(case["public_key_hex"]), bytes.fromhex(case["signature_hex"])
    message = bytes.fromhex(case["message_hex"])
    assert verify_strict(key, message, signature) is case["valid"]
    assert (strict_encoding(key, signature) and _lenient(key, signature, message)) is case["valid"]


def test_the_identity_forgery_is_refused():
    assert _lenient(IDENTITY, FORGERY, b"any message")
    assert not verify_strict(IDENTITY, b"any message", FORGERY)


def test_malformed_input_is_false():
    assert not verify_strict(bytes(31), b"", bytes(64))
    assert not verify_strict(KEY_RAW, b"", bytes(63))
    assert not verify_strict("00" * 32, b"", bytes(64))  # type: ignore[arg-type]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_settlement_wrapped_jws_is_strict():
    """``wrapped_resigned`` asks whether a wrapped JWS verifies under the leg
    key; the identity forgery and a non-canonical R do not."""
    from agent_action_capsule.settlement import _jws_verifies

    signing_input = (_b64u(b'{"alg":"EdDSA"}') + "." + _b64u(b"{}")).encode("ascii")

    def compact(signature: bytes) -> bytes:
        return signing_input + b"." + _b64u(signature).encode("ascii")

    assert _lenient(IDENTITY, FORGERY, signing_input)
    assert not _jws_verifies(compact(FORGERY), IDENTITY.hex())
    honest = KEY.sign(signing_input)
    assert _jws_verifies(compact(honest), KEY_RAW.hex())
    assert not _jws_verifies(compact(NON_CANONICAL_R + honest[32:]), KEY_RAW.hex())


def test_interop_profile_verify_is_strict():
    """Every interop-profile signature check (envelope, refusal, acceptance,
    lifecycle, CLL checkpoint, native JWS) goes through ``ed25519_verify``."""
    from agent_action_capsule.interop_profile._common import ed25519_verify, ed25519_verify_hex

    assert not ed25519_verify(IDENTITY, FORGERY, b"any message")
    assert not ed25519_verify_hex(IDENTITY.hex(), FORGERY.hex(), b"any message")
    honest = KEY.sign(b"m")
    assert ed25519_verify(KEY_RAW, honest, b"m")
    assert not ed25519_verify(KEY_RAW, NON_CANONICAL_R + honest[32:], b"m")


def test_interop_native_jws_is_strict():
    """The native JWS check verifies under a trust-policy foreign key: listing
    the identity key does not make its forgery pass."""
    from agent_action_capsule.interop_profile._common import FAIL, PASS, TrustPolicy
    from agent_action_capsule.interop_profile.native import check_jws_eddsa

    def compact(kid: bytes, sign) -> str:
        signing_input = _b64u(json.dumps({"alg": "EdDSA", "kid": kid.hex()}).encode()) + "." + _b64u(b"{}")
        return signing_input + "." + _b64u(sign(signing_input.encode("ascii")))

    forged = compact(IDENTITY, lambda _: FORGERY)
    assert _lenient(IDENTITY, FORGERY, forged.rsplit(".", 1)[0].encode("ascii"))
    trust = TrustPolicy(foreign_keys=frozenset({IDENTITY.hex()}))
    assert check_jws_eddsa(forged, trust, "2026-10-16T00:00:00Z").status == FAIL
    trust = TrustPolicy(foreign_keys=frozenset({KEY_RAW.hex()}))
    assert check_jws_eddsa(compact(KEY_RAW, KEY.sign), trust, "2026-10-16T00:00:00Z").status == PASS
    bad_r = compact(KEY_RAW, lambda m: NON_CANONICAL_R + KEY.sign(m)[32:])
    assert check_jws_eddsa(bad_r, trust, "2026-10-16T00:00:00Z").status == FAIL


def _ed25519_pem(raw: bytes) -> bytes:
    return Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def test_transparent_signed_statement_is_strict(tmp_path):
    """``verify --transparent`` checks the Signed Statement under the issuer
    key file; ``scitt_cose`` alone accepts the identity forgery."""
    pytest.importorskip("scitt_cose")
    import cbor2
    from scitt_cose import parse_signed_statement

    from agent_action_capsule.media_types import CAPSULE_ID_MEDIA_TYPE
    from agent_action_capsule.transparent import verify_transparent

    protected = cbor2.dumps({1: -8, 3: CAPSULE_ID_MEDIA_TYPE})
    statement = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, bytes(32), FORGERY]))
    pem = _ed25519_pem(IDENTITY)
    assert parse_signed_statement(statement, public_key_pem=pem)["signature_verified"] is True
    (tmp_path / "statement.cbor").write_bytes(statement)
    (tmp_path / "issuer.pem").write_bytes(pem)
    report = verify_transparent(statement_path=str(tmp_path / "statement.cbor"),
                                issuer_key_path=str(tmp_path / "issuer.pem"))
    assert report.signature_verified is False
    assert report.attestation_tier == "signature-invalid"
    assert not report.ok
