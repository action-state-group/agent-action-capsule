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

"Mixed-order R" is a key holder's signature whose R is [r]B + T, T a point
of order 8, with S = r + k * a mod L. The cofactored equation holds and the
cofactorless one does not, so ``cryptography`` refuses it too. Only the key's
holder can make it.
"""
from __future__ import annotations

import hashlib

from agent_action_capsule._ed25519_cofactored import BASE, add, decode, encode, mul
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

_L = (1 << 252) + 27742317777372353535851937790883648493

#: The identity point, a small-order point: the R of an "identity R" signature.
IDENTITY = bytes([1]) + bytes(31)
#: A point of order 8, the T of a "mixed-order R" signature.
ORDER_8 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")


def _scalar(key: Ed25519PrivateKey) -> tuple[int, bytes, bytes]:
    """The key's secret scalar a, its nonce prefix and its public key."""
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    digest = hashlib.sha512(seed).digest()
    h = bytearray(digest[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(h, "little"), digest[32:], key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def identity_r(key: Ed25519PrivateKey, message: bytes) -> bytes:
    """``key``'s signature over ``message`` with R the identity point."""
    a, _, public = _scalar(key)
    k = int.from_bytes(hashlib.sha512(IDENTITY + public + message).digest(), "little")
    return IDENTITY + (k * a % _L).to_bytes(32, "little")


def mixed_order_r(key: Ed25519PrivateKey, message: bytes) -> bytes:
    """``key``'s signature over ``message`` with R = [r]B + ORDER_8, r derived
    from the key's nonce prefix and the message as RFC 8032 derives it."""
    a, prefix, public = _scalar(key)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    big_r = encode(add(mul(r, BASE), decode(ORDER_8)))  # type: ignore[arg-type]
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little")
    return big_r + ((r + k * a) % _L).to_bytes(32, "little")
