# SPDX-License-Identifier: BSD-3-Clause
"""Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule, §2, §5.1).

JSON-DIGEST is ``HEX(SHA-256(JCS(v)))`` using plain RFC 8785 JCS.

This module implements JCS for the value domain the profile permits: strings,
booleans, null, integers, arrays, and objects. The profile forbids JSON
floating-point numbers in any digest-bearing field (§5.1: "Monetary and quantity
values ... MUST be exact decimal strings, never JSON floating-point numbers"), so
a float reaching the serializer is a producer error and is rejected here rather
than serialized by a best-effort number algorithm.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

__all__ = [
    "FloatInDigestError",
    "UnsafeIntegerError",
    "NestingTooDeepError",
    "MAX_SAFE_INTEGER",
    "MAX_NESTING_DEPTH",
    "too_deep",
    "json_text_too_deep",
    "loads_bounded",
    "jcs",
    "normalize",
    "json_digest",
    "compute_capsule_id",
    "LOCAL_ONLY_FIELDS",
    "CANONICALIZATION_JCS",
]

# Plain RFC 8785 JCS is the only algorithm new Capsules may declare.
CANONICALIZATION_JCS = "jcs"

# Producer-envelope bookkeeping fields that are NEVER part of any capsule_id
# preimage, under ANY format. The COSE_Sign1 producer envelope (``signature``)
# and its signing ``key_id`` are attached to a ledger line AFTER the capsule_id
# is computed — you cannot hash a signature into the id it signs — so they MUST
# be excluded before recomputing the id, regardless of the declared format.
# This mirrors capsule-emit's ``_LOCAL_ONLY_FIELDS`` (the producer of these
# capsules); omitting it makes every emitted capsule fail check-2 with
# capsule_id_mismatch.
LOCAL_ONLY_FIELDS = ("signature", "key_id")

# IEEE-754 double "safe integer" bound (ECMAScript Number.MAX_SAFE_INTEGER). A
# JSON integer whose magnitude exceeds this cannot be round-tripped through an
# ECMAScript-Number-based reader, so two conforming verifiers could derive
# different digests from the same bytes. §5.1 already mandates exact decimal
# STRINGS for monetary/quantity values; this bound additionally catches ANY
# other integer outside the safe range in a digest-bearing position; the -05
# text states this bound alongside the float prohibition (§5.1).
MAX_SAFE_INTEGER = 2**53 - 1  # 9007199254740991


class FloatInDigestError(ValueError):
    """A JSON float reached a digest-bearing field. §5.1 forbids this."""


class UnsafeIntegerError(ValueError):
    """An integer outside the ±(2^53 - 1) JS-safe range reached a digest-bearing
    field. Not reproducible across ECMAScript-Number-based readers; represent
    large integers as exact decimal strings instead (§5.1)."""


# The deepest nesting of objects and arrays a reader or verifier accepts:
# ``[]`` is one level, ``[[]]`` two. Go (``canonical.MaxNestingDepth``),
# TypeScript and Rust refuse the same documents (vectors/json-nesting/), so one
# value never reads differently across implementations, and every recursive
# walk here stays far below the interpreter's recursion limit.
MAX_NESTING_DEPTH = 128


class NestingTooDeepError(ValueError):
    """A value nests objects and arrays more than MAX_NESTING_DEPTH levels deep."""


def too_deep(v: Any) -> bool:
    """Whether ``v`` nests dicts and lists more than MAX_NESTING_DEPTH levels deep.

    The walk is iterative and depth first, so it never recurses and stops on a
    value that contains itself, which is infinitely deep.
    """
    stack = [(v, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth >= MAX_NESTING_DEPTH:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


# The characters that change the scan's state: brackets, quotes, backslashes.
_JSON_SIGNIFICANT = re.compile(r'[\[\]{}"\\]')


def json_text_too_deep(text: str) -> bool:
    """Whether JSON text opens more than MAX_NESTING_DEPTH objects and arrays.

    Run before ``json.loads``, whose decoder recurses once per level, so a
    reader refuses such text as malformed instead of raising RecursionError.
    Brackets inside strings do not count. Text that is not JSON gives some
    answer; the decoder refuses it either way.

    One left-to-right pass over the significant characters, tracking whether
    it is inside a string and whether the previous character was an escaping
    backslash, so the cost is linear in the text whatever it holds (an
    unterminated string full of escaped quotes included).
    """
    depth = 0
    in_string = False
    escaped_at = -1  # the index of the character a backslash escapes
    for match in _JSON_SIGNIFICANT.finditer(text):
        at = match.start()
        if at == escaped_at:
            continue
        char = match.group()
        if in_string:
            if char == "\\":
                escaped_at = at + 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                return True
        elif char in "]}":
            depth -= 1
    return False


def loads_bounded(data: str | bytes | bytearray, **kwargs: Any) -> Any:
    """``json.loads`` for text nested at most MAX_NESTING_DEPTH levels deep.

    Deeper text raises NestingTooDeepError (a ValueError) before
    ``json.loads`` runs, so it never raises RecursionError.
    """
    # Scan the text exactly as json.loads would decode bytes (it detects UTF-8, UTF-16
    # and UTF-32), then hand it the original so the accepted encodings do not change.
    text = data if isinstance(data, str) else bytes(data).decode(json.detect_encoding(data), "surrogatepass")
    if json_text_too_deep(text):
        raise NestingTooDeepError(f"JSON text is nested more than {MAX_NESTING_DEPTH} levels deep")
    return json.loads(data, **kwargs)


def _jcs_string(s: str) -> str:
    # RFC 8785 §3.2.2.2 string serialization: minimal escaping, the two-char
    # shortcuts for the known control characters, \u00XX for the rest, no
    # escaping of '/' or non-control code points.
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x09:
            out.append("\\t")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0D:
            out.append("\\r")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_value(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, int):
        # Canonical integers serialize as their decimal form. (bool is a subclass
        # of int but is handled above.) Guard the JS-safe range: a magnitude
        # beyond 2^53-1 is not reproducible across ECMAScript-Number readers, so
        # reject it rather than emit a digest a conforming reader can't match.
        if v > MAX_SAFE_INTEGER or v < -MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(
                f"integer {v} is outside the safe range +/-{MAX_SAFE_INTEGER}; "
                "represent large integers as exact decimal strings (§5.1)"
            )
        return str(v)
    if isinstance(v, float):
        raise FloatInDigestError(
            "JSON floating-point value in a digest-bearing field; §5.1 requires "
            "exact decimal strings for monetary/quantity values"
        )
    if isinstance(v, list):
        return "[" + ",".join(_jcs_value(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785 §3.2.3: object members sorted by the UTF-16 code units of the
        # member name. encode('utf-16-be') yields the UTF-16 code-unit sequence
        # whose byte order matches code-unit order.
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs_value(val) for k, val in items) + "}"
    raise TypeError(f"value of type {type(v).__name__!r} is not JSON-serializable here")


def jcs(v: Any) -> bytes:
    """RFC 8785 JCS serialization of ``v`` as UTF-8 bytes (no normalization).

    Raises NestingTooDeepError for a value nested more than MAX_NESTING_DEPTH
    levels deep.
    """
    if too_deep(v):
        raise NestingTooDeepError(f"value is nested more than {MAX_NESTING_DEPTH} levels deep")
    return _jcs_value(v).encode("utf-8")


def normalize(v: Any) -> Any:
    """Absent-field normalization (§2): remove members whose value is null, an
    empty array, or an empty object, bottom-up. Returns a normalized copy.

    Applied bottom-up so that, e.g., an object that becomes empty only after its
    own null/empty members are removed is itself removed by its parent.

    Retained as a compat export for the vintage ``jcs-n`` canonicalization
    (older records that normalize absent fields before JCS). Format-4 ``jcs``
    above deliberately does NOT normalize; this function is for callers that
    still read the pre-format-4 ``jcs-n`` shape.

    Raises NestingTooDeepError for a value nested more than MAX_NESTING_DEPTH
    levels deep.
    """
    if too_deep(v):
        raise NestingTooDeepError(f"value is nested more than {MAX_NESTING_DEPTH} levels deep")
    return _normalize(v)


def _normalize(v: Any) -> Any:
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for key, val in v.items():
            nv = _normalize(val)
            if nv is None:
                continue
            if isinstance(nv, (dict, list)) and len(nv) == 0:
                continue
            out[key] = nv
        return out
    if isinstance(v, list):
        return [_normalize(x) for x in v]
    return v


def json_digest(v: Any) -> str:
    """JSON-DIGEST (§2): lowercase-hex SHA-256 of plain JCS."""
    return hashlib.sha256(jcs(v)).hexdigest()


def compute_capsule_id(capsule: dict) -> str:
    """Recompute a format-4 Capsule ID with plain RFC 8785 JCS.

    ``capsule_id`` and the local-only producer-envelope fields are removed. All
    other members, including ``chain``, ``references``, and
    ``canonicalization_id``, participate in the preimage.
    """
    if not isinstance(capsule, dict):
        raise TypeError("capsule must be a JSON object")
    if capsule.get("format_version") != "4":
        raise ValueError("format_version must be '4'")
    if "canonicalization_id" not in capsule:
        raise ValueError("canonicalization_id is required")
    algorithm = capsule["canonicalization_id"]
    if not isinstance(algorithm, str):
        raise TypeError("canonicalization_id must be a string")
    if algorithm != CANONICALIZATION_JCS:
        raise ValueError(f"unsupported canonicalization_id {algorithm!r}")
    excluded = {"capsule_id", *LOCAL_ONLY_FIELDS}
    canonical = {k: val for k, val in capsule.items() if k not in excluded}
    return json_digest(canonical)
