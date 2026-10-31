# SPDX-License-Identifier: BSD-3-Clause
"""Strict Ed25519, as checkpointed-local-log's ``ed25519-vectors.json`` pins
it: A and R canonical (y < p) and not of small order, S < L, then the
cofactorless equation. ``cryptography`` checks the equation but accepts a
small-order A, and a small-order A verifies a forged signature over any
message. Shared by the modules that need it, so each does not keep its own
copy."""
from __future__ import annotations

# The y coordinates (mod p) of the eight small-order points of edwards25519:
# order 4 (0), the identity (1), order 2 (p - 1) and order 8 (Y8, p - Y8).
# Either sign of x gives the same set.
_P25519 = (1 << 255) - 19
_Y8 = int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little")
_SMALL_ORDER_Y = frozenset({0, 1, _P25519 - 1, _Y8, _P25519 - _Y8})
_ED25519_L = (1 << 252) + 27742317777372353535851937790883648493


def strict_encoding(public_key: bytes, signature: bytes) -> bool:
    """The strict conditions that do not need the message: A and R canonical
    and not of small order, and S < L."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    for point in (public_key, signature[:32]):
        y = int.from_bytes(point, "little") & ((1 << 255) - 1)
        if y >= _P25519 or y in _SMALL_ORDER_Y:
            return False
    return int.from_bytes(signature[32:], "little") < _ED25519_L


def verify_strict(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """:func:`strict_encoding`, then the equation. Needs the ``cryptography``
    package; without it this raises :class:`ImportError` rather than report a
    signature as not verifying."""
    if not strict_encoding(public_key, signature):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
