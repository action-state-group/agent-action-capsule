# SPDX-License-Identifier: BSD-3-Clause
"""Ed25519 under the cofactored equation, for the settlement
``wrapped_resigned`` test (draft-mih-agent-settlement-records-01, Section
"Wrapping Existing Signed Objects", rule 3): A a canonical encoding (RFC 8032,
Section 5.1.3) of a point not of small order, R a canonical encoding of any
point, S < L, and ``[8][S]B = [8]R + [8][k]A``.

This is deliberately not strict Ed25519 (:mod:`._ed25519_strict`). The test
looks for the leg key's own signature, and only that key's holder can make one
whose R has small or mixed order, so refusing those would let a re-signer evade
it. ``cryptography`` offers neither the cofactored equation nor point
arithmetic, so this module does the arithmetic on integers, in extended
coordinates (RFC 8032, Section 5.1.4). It handles public values only and is
not constant-time.
"""
from __future__ import annotations

import hashlib

_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

Point = tuple  # (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z
IDENTITY: Point = (0, 1, 1, 0)


def add(p: Point, q: Point) -> Point:
    """Point addition, RFC 8032 Section 5.1.4."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def neg(p: Point) -> Point:
    return (-p[0] % _P, p[1], p[2], -p[3] % _P)


def mul(scalar: int, p: Point) -> Point:
    """``[scalar]p``, double-and-add."""
    out = IDENTITY
    while scalar > 0:
        if scalar & 1:
            out = add(out, p)
        p = add(p, p)
        scalar >>= 1
    return out


def is_identity(p: Point) -> bool:
    return p[0] % _P == 0 and (p[1] - p[2]) % _P == 0


def decode(encoded: bytes) -> Point | None:
    """RFC 8032 Section 5.1.3 decoding: ``None`` when y is not below p, when
    no x exists, or when x is zero and the sign bit is set."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if v * x * x % _P == (-u) % _P:
        x = x * _SQRT_M1 % _P
    elif v * x * x % _P != u:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def encode(p: Point) -> bytes:
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | (x & 1) << 255).to_bytes(32, "little")


#: The base point B.
BASE: Point = decode(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))  # type: ignore[assignment]


def verify_cofactored(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is ``public_key``'s over ``message`` under the
    conditions in the module docstring."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = decode(public_key), decode(signature[:32])
    if a is None or r is None or is_identity(mul(8, a)):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return is_identity(mul(8, add(mul(s, BASE), neg(add(r, mul(k, a))))))
