# SPDX-License-Identifier: BSD-3-Clause
"""Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule, §2, §5.1).

JSON-DIGEST := HEX(SHA-256(JCS(normalize(v)))) — the lowercase-hex SHA-256 of the
RFC 8785 JSON Canonicalization Scheme serialization of a value after absent-field
normalization (§2).

This module implements JCS for the value domain the profile permits: strings,
booleans, null, integers, arrays, and objects. The profile forbids JSON
floating-point numbers in any digest-bearing field (§5.1: "Monetary and quantity
values ... MUST be exact decimal strings, never JSON floating-point numbers"), so
a float reaching the serializer is a producer error and is rejected here rather
than serialized by a best-effort number algorithm.
"""
from __future__ import annotations

import hashlib
from typing import Any

__all__ = [
    "FloatInDigestError",
    "UnsafeIntegerError",
    "MAX_SAFE_INTEGER",
    "normalize",
    "jcs",
    "json_digest",
    "compute_capsule_id",
    "CHAIN_LINKAGE_FIELDS",
]

# Fields excluded from the canonical capsule form (§5.1): capsule_id (the digest
# cannot contain itself) and the chain-linkage block (so a Capsule's
# content-address is stable regardless of what later chains to it).
CHAIN_LINKAGE_FIELDS = ("capsule_id", "chain")

# IEEE-754 double "safe integer" bound (ECMAScript Number.MAX_SAFE_INTEGER). A
# JSON integer whose magnitude exceeds this cannot be round-tripped through an
# ECMAScript-Number-based reader, so two conforming verifiers could derive
# different digests from the same bytes. §5.1 already mandates exact decimal
# STRINGS for monetary/quantity values; this bound additionally catches ANY
# other integer outside the safe range in a digest-bearing position. (The -00
# text forbids floats but does not yet state this integer bound; see the -01
# flag in test-vectors/README.md.)
MAX_SAFE_INTEGER = 2**53 - 1  # 9007199254740991


class FloatInDigestError(ValueError):
    """A JSON float reached a digest-bearing field. §5.1 forbids this."""


class UnsafeIntegerError(ValueError):
    """An integer outside the ±(2^53 - 1) JS-safe range reached a digest-bearing
    field. Not reproducible across ECMAScript-Number-based readers; represent
    large integers as exact decimal strings instead (§5.1)."""


def normalize(v: Any) -> Any:
    """Absent-field normalization (§2): remove members whose value is null, an
    empty array, or an empty object, bottom-up. Returns a normalized copy.

    Applied bottom-up so that, e.g., an object that becomes empty only after its
    own null/empty members are removed is itself removed by its parent.
    """
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for key, val in v.items():
            nv = normalize(val)
            if nv is None:
                continue
            if isinstance(nv, (dict, list)) and len(nv) == 0:
                continue
            out[key] = nv
        return out
    if isinstance(v, list):
        return [normalize(x) for x in v]
    return v


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
    if isinstance(v, bool):  # pragma: no cover - handled above
        return "true" if v else "false"
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
    """RFC 8785 JCS serialization of ``v`` as UTF-8 bytes (no normalization)."""
    return _jcs_value(v).encode("utf-8")


def json_digest(v: Any) -> str:
    """JSON-DIGEST (§2): lowercase-hex SHA-256 of JCS(normalize(v))."""
    return hashlib.sha256(jcs(normalize(v))).hexdigest()


def compute_capsule_id(capsule: dict) -> str:
    """Recompute ``capsule_id`` (§5.1): the JSON-DIGEST of the canonical capsule
    form — the envelope minus ``capsule_id`` and chain-linkage fields, after
    absent-field normalization.
    """
    if not isinstance(capsule, dict):
        raise TypeError("capsule must be a JSON object")
    canonical = {k: val for k, val in capsule.items() if k not in CHAIN_LINKAGE_FIELDS}
    return json_digest(canonical)
