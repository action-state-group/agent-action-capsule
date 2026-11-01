# SPDX-License-Identifier: BSD-3-Clause
"""Strict Ed25519 (``agent_action_capsule._ed25519_strict``) and the paths
that verify under a pinned, registered or trusted key with it.

Each path test uses the two kinds of signature ``cryptography`` accepts and
strict Ed25519 refuses (``_ed25519_forgeries``: the "small-order A" and
"identity R" cases of ``cll-ed25519-vectors.json``, over the path's own
message), and checks first that ``cryptography`` does accept it, so the
path's refusal is the strict check's doing."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from _ed25519_forgeries import IDENTITY, IDENTITY_FORGERY, identity_r, lenient  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from agent_action_capsule._ed25519_strict import strict_encoding, verify_strict  # noqa: E402

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "cross-language" / "cll-ed25519-vectors.json"

KEY = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
KEY_RAW = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _forgery(message: bytes) -> bytes:
    assert lenient(IDENTITY, IDENTITY_FORGERY, message)
    return IDENTITY_FORGERY


def _small_r(message: bytes, key: Ed25519PrivateKey = KEY) -> bytes:
    signature = identity_r(key, message)
    assert lenient(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), signature, message)
    return signature


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
    assert (strict_encoding(key, signature) and lenient(key, signature, message)) is case["valid"]


def test_the_lenient_forgeries_are_refused():
    assert not verify_strict(IDENTITY, b"any message", _forgery(b"any message"))
    assert not verify_strict(KEY_RAW, b"any message", _small_r(b"any message"))
    assert verify_strict(KEY_RAW, b"any message", KEY.sign(b"any message"))


def test_malformed_input_is_false():
    assert not verify_strict(bytes(31), b"", bytes(64))
    assert not verify_strict(KEY_RAW, b"", bytes(63))


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_interop_profile_verify_is_strict():
    """Every interop-profile signature check (envelope, refusal, acceptance,
    lifecycle, CLL checkpoint, native JWS) goes through ``ed25519_verify``."""
    from agent_action_capsule.interop_profile._common import ed25519_verify, ed25519_verify_hex

    assert not ed25519_verify(IDENTITY, _forgery(b"m"), b"m")
    assert not ed25519_verify_hex(IDENTITY.hex(), _forgery(b"m").hex(), b"m")
    assert ed25519_verify(KEY_RAW, KEY.sign(b"m"), b"m")
    assert not ed25519_verify(KEY_RAW, _small_r(b"m"), b"m")


def test_interop_native_jws_is_strict():
    """The native JWS check verifies under a trust-policy foreign key: listing
    a key does not make either forgery pass."""
    from agent_action_capsule.interop_profile._common import FAIL, PASS, TrustPolicy
    from agent_action_capsule.interop_profile.native import check_jws_eddsa

    def compact(kid: bytes, sign) -> str:
        signing_input = _b64u(json.dumps({"alg": "EdDSA", "kid": kid.hex()}).encode()) + "." + _b64u(b"{}")
        return signing_input + "." + _b64u(sign(signing_input.encode("ascii")))

    trust = TrustPolicy(foreign_keys=frozenset({IDENTITY.hex()}))
    assert check_jws_eddsa(compact(IDENTITY, _forgery), trust, "2026-10-16T00:00:00Z").status == FAIL
    trust = TrustPolicy(foreign_keys=frozenset({KEY_RAW.hex()}))
    assert check_jws_eddsa(compact(KEY_RAW, KEY.sign), trust, "2026-10-16T00:00:00Z").status == PASS
    assert check_jws_eddsa(compact(KEY_RAW, _small_r), trust, "2026-10-16T00:00:00Z").status == FAIL


def _ed25519_pem(raw: bytes) -> bytes:
    return Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _statement(sign, unprotected: dict | None = None) -> bytes:
    import cbor2

    from agent_action_capsule.media_types import CAPSULE_ID_MEDIA_TYPE

    protected = cbor2.dumps({1: -8, 3: CAPSULE_ID_MEDIA_TYPE})
    payload = bytes(32)
    signature = sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected or {}, payload, signature]))


def _transparent(tmp_path, statement: bytes, issuer_pem: bytes, log_pem: bytes | None = None, leaf: str | None = None):
    from agent_action_capsule.transparent import verify_transparent

    (tmp_path / "statement.cbor").write_bytes(statement)
    (tmp_path / "issuer.pem").write_bytes(issuer_pem)
    log_path = None
    if log_pem is not None:
        (tmp_path / "log.pem").write_bytes(log_pem)
        log_path = str(tmp_path / "log.pem")
    return verify_transparent(statement_path=str(tmp_path / "statement.cbor"),
                              issuer_key_path=str(tmp_path / "issuer.pem"),
                              log_key_path=log_path, leaf_entry_hex=leaf)


@pytest.mark.parametrize("forgery", ["small-order A", "identity R"])
def test_transparent_signed_statement_is_strict(tmp_path, forgery):
    """``verify --transparent`` checks the Signed Statement under the issuer
    key file; ``scitt_cose`` alone accepts both forgeries."""
    pytest.importorskip("scitt_cose")
    from scitt_cose import parse_signed_statement

    if forgery == "small-order A":
        statement, pem = _statement(_forgery), _ed25519_pem(IDENTITY)
    else:
        statement, pem = _statement(_small_r), _ed25519_pem(KEY_RAW)
    assert parse_signed_statement(statement, public_key_pem=pem)["signature_verified"] is True
    report = _transparent(tmp_path, statement, pem)
    assert report.signature_verified is False
    assert report.attestation_tier == "signature-invalid"
    assert not report.ok


def test_transparent_receipt_is_strict(tmp_path):
    """Each receipt is checked under the log key file: a receipt forged under
    the identity key, which ``scitt_cose`` accepts, does not anchor the
    statement."""
    pytest.importorskip("scitt_cose")
    pytest.importorskip("cll.checkpoint")
    import sys

    from scitt_cose import verify_receipt

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import generate_bundle_strict_vectors as g

    leaf = "ab" * 32
    receipt = base64.b64decode(g.small_order_receipt(leaf, "https://small-order-witness.example")["receipt_b64"])
    log_pem = _ed25519_pem(IDENTITY)
    assert verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=log_pem).ok
    statement = _statement(KEY.sign, {394: [receipt]})
    report = _transparent(tmp_path, statement, _ed25519_pem(KEY_RAW), log_pem, leaf)
    assert report.signature_verified is True
    assert report.receipt_verified is False
    assert report.attestation_tier == "self_attested"
    assert "receipt EdDSA signature is not strict Ed25519" in report.substrate_errors
