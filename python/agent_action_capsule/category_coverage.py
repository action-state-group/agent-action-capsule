# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Bundle ``category_coverage`` member (Bundle -02).

A producer's signed declaration of what it offers in each category of a
named category set. It declares; it does not prove. A verifier reports five
properties, each on its own, and never combines them:

- ``category_coverage_form``: the member is well formed;
- ``category_coverage_signature``: its Ed25519 signature verifies;
- ``category_coverage_set_registered``: its set, and every name in it, is
  known to the verifier;
- ``category_coverage_request``: it declares every category the Evidence
  Request asked for;
- ``category_coverage_consistency``: no category declared ``ABSENT`` or
  ``WITHHELD`` has a record in the Bundle.

Each property is ``PASS``, ``FAIL``, ``NOT_PRESENT``, ``NOT_CHECKED`` or
``INCONCLUSIVE``.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .canonical import FloatInDigestError, UnsafeIntegerError, jcs

__all__ = ["CATEGORY_STATUSES", "PROPERTIES", "GATING", "category_coverage_signing_input", "check_category_coverage"]

PASS, FAIL, NOT_PRESENT, NOT_CHECKED, INCONCLUSIVE = "PASS", "FAIL", "NOT_PRESENT", "NOT_CHECKED", "INCONCLUSIVE"

#: The per-category statuses: the Evidence Layer -00 retention states
#: AVAILABLE, PARTIAL, WITHHELD and DELETED, and UNDISCLOSED and ABSENT, which
#: Bundle -02 defines.
CATEGORY_STATUSES = ("AVAILABLE", "PARTIAL", "WITHHELD", "DELETED", "ABSENT", "UNDISCLOSED")

PROPERTIES = (
    "category_coverage_form",
    "category_coverage_signature",
    "category_coverage_set_registered",
    "category_coverage_request",
    "category_coverage_consistency",
)

#: The properties whose ``FAIL`` makes a strict verdict INVALID.
GATING = ("category_coverage_form", "category_coverage_signature", "category_coverage_consistency")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
# RFC 3986 Section 4.3 absolute-URI, checked at the character level: a scheme,
# ":", then only unreserved, sub-delims, ":", "@", "/", "?" and well-formed
# percent-encodings. ASCII only; no fragment ("#"), so no relative reference.
_ABSOLUTE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$")
_PRIVATE_SET = "x-"
# A UTF-16 surrogate code point. Strict UTF-8 decoding admits none and json
# joins an escaped pair into one character, so one left over came from an
# unpaired escape such as "\ud800", which I-JSON (RFC 7493 Section 2.1)
# forbids.
_SURROGATE = re.compile("[\ud800-\udfff]")
# A record in one of these categories contradicts the declaration.
_CONTRADICTED_BY_A_RECORD = ("ABSENT", "WITHHELD")


def category_coverage_signing_input(member: Mapping[str, Any], root: Any) -> bytes:
    """``UTF8(JCS({"category_coverage": <member without signature>, "root": root}))``."""
    unsigned = {k: v for k, v in member.items() if k != "signature"}
    return jcs({"category_coverage": unsigned, "root": root})


def _well_formed(member: Any) -> bool:
    if not isinstance(member, Mapping):
        return False
    if not isinstance(member.get("set"), str) or not member["set"]:
        return False
    categories = member.get("categories")
    if not isinstance(categories, Mapping) or not categories:
        return False
    for name, entry in categories.items():
        if not name or not isinstance(entry, Mapping) or entry.get("status") not in CATEGORY_STATUSES:
            return False
        uri = entry.get("policy_uri")
        if "policy_uri" in entry and not (isinstance(uri, str) and _ABSOLUTE_URI.fullmatch(uri)):
            return False
        if entry["status"] == "UNDISCLOSED" and "policy_uri" not in entry:
            return False
    if "request_digest" in member and not (
        isinstance(member["request_digest"], str) and _HEX64.fullmatch(member["request_digest"])
    ):
        return False
    if ("signer" in member) != ("signature" in member):
        return False
    if "signer" in member:
        signer = member["signer"]
        if not isinstance(signer, Mapping) or not isinstance(signer.get("key_id"), str):
            return False
        if not _HEX64.fullmatch(signer["key_id"]):
            return False
        if not isinstance(member["signature"], str) or not _HEX128.fullmatch(member["signature"]):
            return False
    return True


def _signature(member: Mapping[str, Any], root: Any) -> str:
    if "signature" not in member:
        return NOT_PRESENT
    try:
        signing_input = category_coverage_signing_input(member, root)
    except (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError, RecursionError):
        return FAIL  # no canonical signing input, so nothing the signature can cover
    try:
        from .evidence_request import _ed25519_verifies

        verified = _ed25519_verifies(member["signer"]["key_id"], member["signature"], signing_input)
    except ImportError:  # no Ed25519 implementation installed
        return NOT_CHECKED
    return PASS if verified else FAIL


def _set_registered(member: Mapping[str, Any], category_sets: Mapping[str, Sequence[str]] | None) -> str:
    set_id = member["set"]
    if set_id.startswith(_PRIVATE_SET):
        return NOT_PRESENT
    known = (category_sets or {}).get(set_id)
    if known is None:
        return INCONCLUSIVE
    return PASS if set(member["categories"]) <= set(known) else FAIL


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate member {key!r}")
        out[key] = value
    return out


def _holds_lone_surrogate(value: Any) -> bool:
    """Whether any string in ``value``, member names included, holds a
    surrogate code point."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _SURROGATE.search(item):
                return True
        elif isinstance(item, Mapping):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _request(member: Mapping[str, Any], request: bytes | None) -> str:
    if request is None:
        return NOT_CHECKED
    request = bytes(request)
    # The digest is over the octets as received, so it is checked before (and
    # whether or not) they parse.
    if "request_digest" in member and member["request_digest"] != hashlib.sha256(request).hexdigest():
        return FAIL
    try:
        parsed = json.loads(request.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return NOT_CHECKED
    if _holds_lone_surrogate(parsed) or not isinstance(parsed, Mapping):
        return NOT_CHECKED
    if "categories" not in parsed:
        return NOT_PRESENT
    asked = parsed["categories"]
    names = asked.get("names") if isinstance(asked, Mapping) else None
    if (
        not isinstance(asked.get("set") if isinstance(asked, Mapping) else None, str)
        or not isinstance(names, list)
        or not names
        or not all(isinstance(n, str) for n in names)
        or len(set(names)) != len(names)
    ):
        return NOT_CHECKED  # a malformed request is the requester's to fix, not the producer's failure
    if asked["set"] != member["set"]:
        return FAIL
    return PASS if all(n in member["categories"] for n in names) else FAIL


def _consistency(
    member: Mapping[str, Any], record_ids: Sequence[str], record_categories: Mapping[str, str] | None
) -> str:
    if record_categories is None or any(cid not in record_categories for cid in record_ids):
        return NOT_CHECKED  # a record the caller could not assign could be in any category
    carried = {record_categories[cid] for cid in record_ids}
    contradicted = [
        name
        for name, entry in member["categories"].items()
        if entry["status"] in _CONTRADICTED_BY_A_RECORD and name in carried
    ]
    return FAIL if contradicted else PASS


def check_category_coverage(
    bundle: Mapping[str, Any],
    *,
    category_sets: Mapping[str, Sequence[str]] | None = None,
    category_request: bytes | None = None,
    record_categories: Mapping[str, str] | None = None,
) -> dict[str, str] | None:
    """The five properties of ``bundle["category_coverage"]``, in report
    order, or ``None`` when the Bundle carries no such member.

    ``category_sets`` maps each category set the caller knows to its names (a
    set starting ``x-`` is never looked up). ``category_request`` is the
    Evidence Request's octets as received. ``record_categories`` maps each
    carried record's ``capsule_id`` to its category, as the set's rule
    assigns it (``None`` for a record in no category). Without it, or when a
    carried record is not in it, consistency is ``NOT_CHECKED``. When the member is
    malformed, every other property is ``NOT_CHECKED``."""
    if "category_coverage" not in bundle:
        return None
    member = bundle["category_coverage"]
    if not _well_formed(member):
        return {PROPERTIES[0]: FAIL, **{name: NOT_CHECKED for name in PROPERTIES[1:]}}
    records = bundle.get("records") if isinstance(bundle.get("records"), list) else []
    record_ids = [r["capsule_id"] for r in records if isinstance(r, Mapping) and isinstance(r.get("capsule_id"), str)]
    return {
        "category_coverage_form": PASS,
        "category_coverage_signature": _signature(member, bundle.get("root")),
        "category_coverage_set_registered": _set_registered(member, category_sets),
        "category_coverage_request": _request(member, category_request),
        "category_coverage_consistency": _consistency(member, record_ids, record_categories),
    }
