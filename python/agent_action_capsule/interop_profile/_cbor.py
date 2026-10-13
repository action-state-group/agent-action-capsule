# SPDX-License-Identifier: BSD-3-Clause
"""A strict CBOR decoder for the objects of the interop profile (RFC 8949).

The profile needs more than a generic decoder gives. A duplicate map key makes an object not
well-formed (profile §5.2), and some octets are required to be deterministic CBOR
(RFC 8949 §4.2.1): the stream binding frame and the CLL peak lists (profile §6.2.1). A generic
decoder silently keeps one of two duplicate keys and accepts any encoding, so this module decodes
by hand and records every irregularity it sees.

The data model decoded is integers, byte and text strings, arrays, maps, tags, ``null``,
``true``, ``false`` and floats. A float, or a map key that is an array or a map, is outside the
profile's data model (§5.2): it is decoded and flagged as ``irregular``, so a caller can still
classify the object by its members. Undefined, other simple values and indefinite lengths are
malformed.
"""
from __future__ import annotations

import struct
from typing import Any

__all__ = ["CborError", "Tag", "Decoded", "decode", "encode_head"]


class CborError(ValueError):
    """The octets are not one well-formed CBOR data item of the supported data model."""


class Tag:
    """A tagged item: ``Tag(18, [...])`` is a COSE_Sign1."""

    __slots__ = ("number", "value")

    def __init__(self, number: int, value: Any):
        self.number, self.value = number, value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Tag) and (self.number, self.value) == (other.number, other.value)

    def __repr__(self) -> str:
        return f"Tag({self.number}, {self.value!r})"


class Decoded:
    """The decoded value, and what made the encoding irregular.

    ``duplicate_keys`` is set when any map repeats a key; the first occurrence is kept.
    ``deterministic`` is False when any head is not in shortest form or any map's keys are not in
    the bytewise lexicographic order of their encodings (RFC 8949 §4.2.1).
    """

    __slots__ = ("value", "duplicate_keys", "deterministic", "irregular")

    def __init__(self, value: Any, duplicate_keys: bool, deterministic: bool, irregular: bool = False):
        self.value, self.duplicate_keys, self.deterministic = value, duplicate_keys, deterministic
        self.irregular = irregular

    @property
    def well_formed(self) -> bool:
        return not (self.duplicate_keys or self.irregular)


class _State:
    __slots__ = ("data", "dup", "det", "odd")

    def __init__(self, data: bytes):
        self.data, self.dup, self.det, self.odd = data, False, True, False


_MAX_DEPTH = 64


def _item(st: _State, i: int, depth: int) -> tuple[Any, int]:
    if depth > _MAX_DEPTH:
        raise CborError("nesting too deep")
    data = st.data
    if i >= len(data):
        raise CborError("truncated")
    initial = data[i]
    major, info = initial >> 5, initial & 31
    i += 1
    if major == 7 and info in (25, 26, 27):
        width = 1 << (info - 24)
        if i + width > len(data):
            raise CborError("truncated")
        st.odd = True  # a float is outside the profile's data model (§5.2)
        return struct.unpack(">" + {2: "e", 4: "f", 8: "d"}[width], data[i:i + width])[0], i + width
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        width = 1 << (info - 24)
        if i + width > len(data):
            raise CborError("truncated")
        arg = int.from_bytes(data[i:i + width], "big")
        i += width
        if arg < (24 if width == 1 else 1 << (4 * width)):
            st.det = False  # not the shortest head
    else:
        raise CborError("indefinite length or reserved additional information")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(data):
            raise CborError("truncated")
        chunk = data[i:i + arg]
        if major == 2:
            return bytes(chunk), i + arg
        try:
            return chunk.decode("utf-8"), i + arg
        except UnicodeDecodeError as exc:
            raise CborError("text string is not UTF-8") from exc
    if major == 4:
        out = []
        for _ in range(arg):
            value, i = _item(st, i, depth + 1)
            out.append(value)
        return out, i
    if major == 5:
        result: dict[Any, Any] = {}
        encoded_keys = []
        for _ in range(arg):
            start = i
            key, i = _item(st, i, depth + 1)
            encoded_keys.append(data[start:i])
            value, i = _item(st, i, depth + 1)
            if not isinstance(key, (int, str, bytes)) or isinstance(key, bool):
                st.odd = True  # an unhashable or non-scalar key: kept out of the map, flagged
                continue
            if key in result:
                st.dup = True
                continue
            result[key] = value
        if encoded_keys != sorted(encoded_keys):
            st.det = False
        return result, i
    if major == 6:
        value, i = _item(st, i, depth + 1)
        return Tag(arg, value), i
    if initial == 0xF4:
        return False, i
    if initial == 0xF5:
        return True, i
    if initial == 0xF6:
        return None, i
    raise CborError("unsupported data item")


def decode(data: bytes) -> Decoded:
    """Decode exactly one data item. Raises :class:`CborError` when the octets are not one."""
    st = _State(bytes(data))
    value, end = _item(st, 0, 0)
    if end != len(st.data):
        raise CborError("trailing octets after the data item")
    return Decoded(value, st.dup, st.det, st.odd)


def encode_head(major: int, arg: int) -> bytes:
    """The shortest head for ``major`` with argument ``arg`` (RFC 8949 §4.2.1)."""
    if arg < 24:
        return bytes([major << 5 | arg])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * width):
            return bytes([major << 5 | info]) + arg.to_bytes(width, "big")
    raise ValueError("argument does not fit in a CBOR head")
