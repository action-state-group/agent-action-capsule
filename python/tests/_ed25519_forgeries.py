# SPDX-License-Identifier: BSD-3-Clause
"""The two kinds of signature in checkpointed-local-log's
``ed25519-vectors.json`` that ``cryptography`` accepts and strict Ed25519
refuses, built over any message: a small-order key A ("small-order A
identity") and a small-order R ("identity R"). Tests of a verify path use
them to show the path is strict.

Also a key holder's "mixed-order R" signature, which only the cofactored
equation accepts, and :func:`cofactored`, the settlement re-signing test
written apart from the library's (affine coordinates here, extended there),
so the settlement vector test derives its expectations independently."""
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


_P = (1 << 255) - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_ZERO = (0, 1)


def _add(p: tuple, q: tuple) -> tuple:
    """Affine twisted Edwards addition (a = -1)."""
    (x1, y1), (x2, y2) = p, q
    t = _D * x1 * x2 * y1 * y2 % _P
    x = (x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P
    y = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return x, y


def _mul(n: int, p: tuple) -> tuple:
    out = _ZERO
    for bit in bin(n)[2:]:
        out = _add(out, out)
        if bit == "1":
            out = _add(out, p)
    return out


def _point(encoded: bytes) -> tuple | None:
    """RFC 8032 Section 5.1.3 decoding, or ``None``."""
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if x * x % _P != xx:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x * x % _P != xx or (x == 0 and sign):
        return None
    return (_P - x if x % 2 != sign else x), y


def _encode(p: tuple) -> bytes:
    return (p[1] | (p[0] & 1) << 255).to_bytes(32, "little")


_BASE = _point(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))
#: A point of order 8, the T of a "mixed-order R" signature.
ORDER_8 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")


def cofactored(key: bytes, signature: bytes, message: bytes) -> bool:
    """Settlement -01's re-signing test: A decodes and is not of small order,
    R decodes, S < L, and [8][S]B = [8]R + [8][k]A."""
    if len(key) != 32 or len(signature) != 64:
        return False
    a, r = _point(key), _point(signature[:32])
    if a is None or r is None or _mul(8, a) == _ZERO:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + key + message).digest(), "little") % _L
    return _mul(8, _mul(s, _BASE)) == _mul(8, _add(r, _mul(k, a)))


def mixed_order_r(key: Ed25519PrivateKey, message: bytes) -> bytes:
    """``key``'s signature over ``message`` with R = [r]B + T, T of order 8,
    and S = r + k * a mod L: the cofactored equation holds, the cofactorless
    one does not. Only the key's holder can make it."""
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    digest = hashlib.sha512(seed).digest()
    h = bytearray(digest[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h, "little")
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    big_r = _encode(_add(_mul(r, _BASE), _point(ORDER_8)))
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little")
    return big_r + ((r + k * a) % _L).to_bytes(32, "little")
