# SPDX-License-Identifier: BSD-3-Clause
"""Ed25519 signatures that a lenient (cofactorless, no point check) verifier
accepts and strict Ed25519 refuses, built over any message, for the vector
generators' negative cases.

"Identity R" is a key holder's signature whose R is the identity point:
S = k * a mod L with k = SHA-512(R || A || M). [S]B = [k]A = R + [k]A, so the
equation holds, but R has small order. Only the key's holder can make it. It
is one of the kinds in checkpointed-local-log's ``ed25519-vectors.json`` that
``cryptography`` accepts; ``python/tests/_ed25519_forgeries.py`` builds the
same signature with its own code for the unit tests.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

_L = (1 << 252) + 27742317777372353535851937790883648493

#: The identity point, a small-order point: the R of an "identity R" signature.
IDENTITY = bytes([1]) + bytes(31)


def identity_r(key: Ed25519PrivateKey, message: bytes) -> bytes:
    """``key``'s signature over ``message`` with R the identity point."""
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h, "little")
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    k = int.from_bytes(hashlib.sha512(IDENTITY + public + message).digest(), "little")
    return IDENTITY + (k * a % _L).to_bytes(32, "little")
