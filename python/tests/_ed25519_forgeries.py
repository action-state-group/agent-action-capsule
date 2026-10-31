# SPDX-License-Identifier: BSD-3-Clause
"""The two kinds of signature in checkpointed-local-log's
``ed25519-vectors.json`` that ``cryptography`` accepts and strict Ed25519
refuses, built over any message: a small-order key A ("small-order A
identity") and a small-order R ("identity R"). Tests of a verify path use
them to show the path is strict."""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

_L = (1 << 252) + 27742317777372353535851937790883648493

#: The identity point, the small-order A of "small-order A identity".
IDENTITY = bytes([1]) + bytes(31)
#: R the identity and S = 0: under IDENTITY it verifies over any message.
IDENTITY_FORGERY = IDENTITY + bytes(32)


def identity_r(key: Ed25519PrivateKey, message: bytes) -> bytes:
    """``key``'s signature over ``message`` with R the identity, as the
    "identity R" case: S = k * a mod L, k = SHA-512(R || A || M). Then
    [S]B = [k]A = R + [k]A, so the cofactorless equation holds, but R has
    small order. Only the key's holder can make it."""
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h, "little")
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    r = IDENTITY
    k = int.from_bytes(hashlib.sha512(r + public + message).digest(), "little")
    return r + (k * a % _L).to_bytes(32, "little")


def lenient(key: bytes, signature: bytes, message: bytes) -> bool:
    """``cryptography``'s verify alone."""
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except Exception:  # noqa: BLE001 -- any refusal is "does not verify"
        return False
    return True
