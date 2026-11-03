# SPDX-License-Identifier: BSD-3-Clause
"""The settlement re-signing test (``agent_action_capsule._ed25519_cofactored``,
draft-mih-agent-settlement-records-01 Section "Wrapping Existing Signed
Objects", rule 3): the cofactored equation with any canonical R, A canonical
and not of small order, S < L. It is checked against an independent affine
implementation (``_ed25519_forgeries.cofactored``) over the shared Ed25519
cases, and on the settlement path with the key holder's identity-R and
mixed-order-R signatures, which it counts, and the identity key's forgery,
which it does not."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from _ed25519_forgeries import (  # noqa: E402
    IDENTITY,
    IDENTITY_FORGERY,
    cofactored,
    identity_r,
    lenient,
    mixed_order_r,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from agent_action_capsule._ed25519_cofactored import verify_cofactored  # noqa: E402
from agent_action_capsule.settlement import _jws_verifies  # noqa: E402

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "cross-language" / "cll-ed25519-vectors.json"

KEY = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
KEY_RAW = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_L = (1 << 252) + 27742317777372353535851937790883648493


@pytest.mark.parametrize("case", json.loads(VECTORS.read_text())["ed25519_cases"], ids=lambda c: c["name"])
def test_agrees_with_the_independent_reading(case):
    key, message, signature = (bytes.fromhex(case[k]) for k in ("public_key_hex", "message_hex", "signature_hex"))
    assert verify_cofactored(key, message, signature) is cofactored(key, signature, message)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


SIGNING_INPUT = (_b64u(b'{"alg":"EdDSA"}') + "." + _b64u(b"{}")).encode("ascii")


def _compact(signature: bytes) -> bytes:
    return SIGNING_INPUT + b"." + _b64u(signature).encode("ascii")


def test_settlement_counts_the_key_holders_odd_r():
    """Identity R passes ``cryptography`` and fails strict Ed25519; mixed-order
    R fails both. Only the key's holder can make either, so both count."""
    small_r = identity_r(KEY, SIGNING_INPUT)
    mixed_r = mixed_order_r(KEY, SIGNING_INPUT)
    assert lenient(KEY_RAW, small_r, SIGNING_INPUT)
    assert not lenient(KEY_RAW, mixed_r, SIGNING_INPUT)
    assert _jws_verifies(_compact(KEY.sign(SIGNING_INPUT)), KEY_RAW.hex())
    assert _jws_verifies(_compact(small_r), KEY_RAW.hex())
    assert _jws_verifies(_compact(mixed_r), KEY_RAW.hex())


def test_settlement_refuses_what_others_can_make():
    """The identity key's forgery verifies over any message for anyone; the
    test refuses a small-order A. It also refuses another key's signature, a
    non-canonical R (y not below p; x zero with the sign bit) and S + L."""
    assert lenient(IDENTITY, IDENTITY_FORGERY, SIGNING_INPUT)
    assert not _jws_verifies(_compact(IDENTITY_FORGERY), IDENTITY.hex())
    other = Ed25519PrivateKey.from_private_bytes(b"\x06" * 32)
    assert not _jws_verifies(_compact(other.sign(SIGNING_INPUT)), KEY_RAW.hex())
    small_r = identity_r(KEY, SIGNING_INPUT)
    sign_bit = small_r[:31] + bytes([small_r[31] | 0x80]) + small_r[32:]
    assert not _jws_verifies(_compact(sign_bit), KEY_RAW.hex())
    above_p = bytes.fromhex("ee" + "ff" * 30 + "7f") + small_r[32:]
    assert not _jws_verifies(_compact(above_p), KEY_RAW.hex())
    s_plus_l = small_r[:32] + (int.from_bytes(small_r[32:], "little") + _L).to_bytes(32, "little")
    assert not _jws_verifies(_compact(s_plus_l), KEY_RAW.hex())


def test_wrong_lengths_are_refused():
    assert not verify_cofactored(bytes(31), b"", bytes(64))
    assert not verify_cofactored(KEY_RAW, b"", bytes(63))
