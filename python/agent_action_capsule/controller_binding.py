# SPDX-License-Identifier: BSD-3-Clause
"""Controller Binding v0: the one verifier for a binding record.

A port of ``go/controllerbinding`` (``spec/controller-binding-v0.md``, cited
as CB). :func:`verify` checks a binding record's form (CB §3), both signatures
over the one signing input, each by its key's type (§4, §4.1), its window, the
revocation statements the caller received (§5), a revocation list a using
profile declared complete (§5.1) and, for ``same_organization_credentialed``,
a credential through a verifier the caller passes. It reports the binding
properties of §6.1 in the profile's §7.1 vocabulary, what the binding proves
(§7 item 2) and whether it applies to a pair of keys (§6.2).

A binding shows only that whoever held each private key signed the record.
Nothing here establishes who controls a key. No trust anchor, accepted
credential issuer or credential verifier ships: no credential format is
registered (CB-3), and accepting an issuer is the caller's trust policy.

Ed25519 signatures need the ``cryptography`` package (as the strict Ed25519
check in :mod:`agent_action_capsule._ed25519_strict` does); BIP-340 is
verified here in pure Python.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Union

from ._ed25519_strict import verify_strict
from .canonical import jcs, json_text_too_deep
from .evidence_request import _json_float, _json_object, _reject_constant, parse_utc

VERSION = "controller-binding/0"
REVOCATION_VERSION = "controller-binding-revocation/0"
REVOCATION_METHOD = "revocation_statement/0"

CLAIM_SAME_CONTROLLER = "same_controller_asserted"
CLAIM_DELEGATED_BY = "delegated_by"
CLAIM_SAME_ORGANIZATION = "same_organization_credentialed"
METHOD_DUAL_SIGNATURE = "dual_signature/0"
METHOD_DUAL_SIGNATURE_CREDIT = "dual_signature_credential/0"

KEY_ED25519 = "ed25519"
KEY_BIP340 = "bip340"
NOSTR_KIND = 3374
MAX_CREATED_AT = (1 << 53) - 1

PROPERTY_FORM = "controller_binding_form"
PROPERTY_SIGNATURES = "controller_binding_signatures"
PROPERTY_WINDOW = "controller_binding_window"
PROPERTY_REVOCATION = "controller_binding_revocation"
PROPERTY_CREDENTIAL = "controller_binding_credential"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_NOT_PRESENT = "NOT_PRESENT"
STATUS_NOT_CHECKED = "NOT_CHECKED"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"

_PROVES_CONTROL = "control of both keys at the ceremony"
_PROVES_CREDENTIALED = "a trusted issuer key states that both keys are held within one organization"

# Each claim type's method, added member and what the two key holders state (CB §3.2).
_CLAIMS = {
    CLAIM_SAME_CONTROLLER: (METHOD_DUAL_SIGNATURE, "", "both key holders state that one controller holds both keys"),
    CLAIM_DELEGATED_BY: (
        METHOD_DUAL_SIGNATURE,
        "delegator",
        "both key holders state that the delegator delegated to the other key",
    ),
    CLAIM_SAME_ORGANIZATION: (
        METHOD_DUAL_SIGNATURE_CREDIT,
        "credential",
        "both key holders state that both keys are held within one organization",
    ),
}
_COMMON = (
    "binding_version", "claim", "method", "keys", "issued_at", "not_before", "not_after", "revocation", "nonce", "sigs"
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_NONCE32 = re.compile(r"[0-9a-f]{32,}")
_PROFILE_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

#: An instant: ``(epoch_seconds, nanoseconds)``, which orders as time does.
Instant = tuple
_Time = Union[Instant, datetime]


def instant_of(value: _Time) -> Instant:
    """An :data:`Instant` from a timezone-aware ``datetime`` (or one already)."""
    if isinstance(value, tuple):
        return value
    delta = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86_400 + delta.seconds, delta.microseconds * 1000


# --- decoding ----------------------------------------------------------------


class _Token(int):
    """A JSON integer read from its token, so ``created_at`` is judged as
    written. A fraction or an exponent is not an integer here."""


def _decode(data: bytes) -> Any:
    """One JSON value from ``data``: UTF-8, no duplicate member, no lone
    surrogate, no float or constant, nested at most MAX_NESTING_DEPTH levels.
    Raises ``ValueError`` otherwise."""
    text = data.decode("utf-8")
    if json_text_too_deep(text):
        raise ValueError("nested too deep")
    value = json.loads(
        text,
        object_pairs_hook=_json_object,
        parse_int=_Token,
        parse_float=_json_float,
        parse_constant=_reject_constant,
    )
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item)
            stack.extend(item.values())
    return value


def _decode_or_none(data: bytes) -> Any:
    try:
        return _decode(data)
    except (ValueError, TypeError):  # UnicodeError and JSON errors are ValueErrors
        return None


def _jcs(value: Any) -> bytes | None:
    try:
        return jcs(value)
    except (ValueError, TypeError):
        return None


def _without(value: Mapping[str, Any], name: str) -> dict:
    return {k: v for k, v in value.items() if k != name}


def _has_members(value: Mapping[str, Any], names: Sequence[str]) -> bool:
    return len(value) == len(names) and all(name in value for name in names)


def _is_key(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _instant(value: Any) -> Instant | None:
    """A §5.2 time: RFC 3339 UTC, seconds precision, a real calendar instant."""
    if not isinstance(value, str) or _PROFILE_TIME.fullmatch(value) is None:
        return None
    return parse_utc(value)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- BIP-340 -----------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _tagged(tag: str, message: bytes) -> bytes:
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + message).digest()


def _add(a: Any, b: Any) -> Any:
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(point: Any, n: int) -> Any:
    result = None
    for i in range(256):
        if (n >> i) & 1:
            result = _add(result, point)
        point = _add(point, point)
    return result


def verify_bip340(key: bytes, message: bytes, signature: bytes) -> bool:
    """BIP-340 ``Verify(pk, m, sig)`` with an x-only public key."""
    if len(key) != 32 or len(signature) != 64:
        return False
    x = int.from_bytes(key, "big")
    if x >= _P:
        return False
    y_squared = (pow(x, 3, _P) + 7) % _P
    y = pow(y_squared, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_squared:
        return False
    point = (x, y if y % 2 == 0 else _P - y)
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", signature[:32] + key + message), "big") % _N
    rr = _add(_mul(_G, s), _mul(point, _N - e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


# --- signatures --------------------------------------------------------------


def _verify_hex(key: str, sig: Any, message: bytes) -> bool:
    """An ed25519 key's hex sig, with strict Ed25519: a small-order key would
    sign any record or revocation for anyone."""
    if not isinstance(sig, str) or _HEX128.fullmatch(sig) is None:
        return False
    return verify_strict(bytes.fromhex(key), message, bytes.fromhex(sig))


def _verify_nostr(key: str, sig: Any, version: str, signed: bytes) -> bool:
    """A bip340 key's ``{created_at, sig}``: the BIP-340 signature over the id
    of the Nostr event (NIP-01) of kind 3374, no tags, and content
    ``<version>:<SHA-256 of signed>`` (CB §4.1)."""
    if not isinstance(sig, dict) or not _has_members(sig, ("created_at", "sig")):
        return False
    text = sig["sig"]
    if not isinstance(text, str) or _HEX128.fullmatch(text) is None:
        return False
    created_at = sig["created_at"]
    if not isinstance(created_at, _Token) or not 0 <= created_at <= MAX_CREATED_AT:
        return False
    event = f'[0,"{key}",{int(created_at)},{NOSTR_KIND},[],"{version}:{_sha256_hex(signed)}"]'
    return verify_bip340(bytes.fromhex(key), hashlib.sha256(event.encode()).digest(), bytes.fromhex(text))


def _verify_sig(key: str, key_type: str, sig: Any, version: str, signed: bytes) -> bool:
    if key_type == KEY_ED25519:
        return _verify_hex(key, sig, signed)
    if key_type == KEY_BIP340:
        return _verify_nostr(key, sig, version, signed)
    return False  # a key type §3.3 does not list never verifies


# --- report ------------------------------------------------------------------


@dataclass
class Credential:
    """The credential member of a ``same_organization_credentialed`` record."""

    issuer: str
    method: str
    digest: str


#: Checks a delivered credential (octets as transmitted) against the record's
#: credential member and its two bound keys; returns ``PASS``, ``FAIL`` or
#: ``INCONCLUSIVE``. It owns the native method and the caller's trust policy.
CredentialVerifier = Callable[[bytes, Credential, "tuple[str, str]"], str]


@dataclass
class Declaration:
    """What a using profile gives beside a revocation list it declares
    complete (CB §5.1): the asserting party's statement, not a finding."""

    profile: str = ""
    asserted_by: str = ""
    binding: str = ""
    list_digest: str = ""
    as_of: str = ""
    max_age: int = 0


_DECLARATION_MEMBERS = ("profile", "asserted_by", "binding", "list_digest", "as_of", "max_age")


def parse_declaration(octets: bytes) -> tuple[Declaration, str]:
    """Read a declaration from its JSON object: exactly the six members, each
    in its form. A non-empty second value is why it does not count; the
    returned declaration still holds profile, asserted_by and as_of where each
    is a text string."""
    value = _decode_or_none(octets)
    if not isinstance(value, dict):
        return Declaration(), "the declaration is not a JSON object"
    d = Declaration()
    for name in ("profile", "asserted_by", "as_of"):
        if isinstance(value.get(name), str):
            setattr(d, name, value[name])
    if not _has_members(value, _DECLARATION_MEMBERS):
        return d, (
            "the declaration does not have exactly profile, asserted_by, binding, list_digest, as_of and max_age"
        )
    if not isinstance(value["profile"], str):
        return d, "profile is not a text string"
    if not isinstance(value["asserted_by"], str):
        return d, "asserted_by is not a text string"
    d.binding = value["binding"] if isinstance(value["binding"], str) else ""
    d.list_digest = value["list_digest"] if isinstance(value["list_digest"], str) else ""
    if not _is_key(d.binding) or not _is_key(d.list_digest):
        return d, "binding or list_digest is not 64 lowercase hex characters"
    if _instant(d.as_of) is None:
        return d, "as_of is not a time"
    max_age = value["max_age"]
    if not isinstance(max_age, _Token) or not 0 <= max_age <= MAX_CREATED_AT:
        return d, "max_age is not an integer from 0 to 2^53 - 1"
    d.max_age = int(max_age)
    return d, ""


@dataclass
class RevocationList:
    """A revocation list (a JSON array of revocation statements) with the
    declaration a using profile gave beside it (CB §5.1). The caller takes the
    declaration only through the using profile's own channel; it is unsigned,
    and ``asserted_by`` is reported as delivered, not as authenticated."""

    declaration: bytes
    list: bytes
    evaluated_at: _Time


@dataclass
class ListReport:
    """How a verifier reports a declaration (CB §6.1)."""

    profile: str = ""
    asserted_by: str = ""
    list_digest: str = ""
    as_of: str = ""
    counts: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        """The vectors' form: ``reason`` is a diagnostic and is left out."""
        return {
            "profile": self.profile,
            "asserted_by": self.asserted_by,
            "list_digest": self.list_digest,
            "as_of": self.as_of,
            "counts": self.counts,
        }


@dataclass
class Options:
    """What the caller received beside the binding record."""

    #: Revocation statements as received (CB §5).
    revocations: Sequence[bytes] = ()
    revocation_list: RevocationList | None = None
    #: The credential as transmitted, or ``None`` when none was delivered.
    credential: bytes | None = None
    #: Checks a credential by its ``credential.method``; a method with no
    #: entry is not implemented: ``NOT_CHECKED``.
    credential_verifiers: Mapping[str, CredentialVerifier] = field(default_factory=dict)


@dataclass
class Report:
    """What a verifier reports for one binding record (CB §7)."""

    claim: str = ""
    keys: tuple[str, ...] = ()
    delegator: str = ""
    not_before: str = ""
    not_after: str = ""
    binding_digest: str = ""
    properties: dict = field(default_factory=dict)
    proves: list = field(default_factory=list)
    revocation_list: ListReport | None = None

    def applies(self) -> bool:
        """Form, signatures and window PASS, and revocation not FAIL (CB §6.2).
        The credential never decides it."""
        p = self.properties
        return (
            p.get(PROPERTY_FORM) == STATUS_PASS
            and p.get(PROPERTY_SIGNATURES) == STATUS_PASS
            and p.get(PROPERTY_WINDOW) == STATUS_PASS
            and p.get(PROPERTY_REVOCATION) != STATUS_FAIL
        )

    def binds(self, key: str) -> bool:
        return key in self.keys

    def binds_pair(self, a: str, b: str) -> bool:
        """Whether the record's two keys are exactly ``a`` and ``b``, in either order."""
        return len(self.keys) == 2 and (
            (self.keys[0] == a and self.keys[1] == b) or (self.keys[0] == b and self.keys[1] == a)
        )

    def applies_to(self, a: str, b: str) -> bool:
        """Whether the binding applies to the pair ``a``, ``b``. The report
        must have been made at the pair's times."""
        return self.binds_pair(a, b) and self.applies()


def pair_independence(a: str, b: str, *reports: Report) -> dict:
    """The ``issuer_independence`` of a pair signed under keys ``a`` and ``b``,
    given every binding report the verifier received for it (CB §9.1). A
    binding never gives PASS (§6.2)."""
    if a == b:
        return {"status": STATUS_FAIL, "shown_as": "redundant, not corroborating", "reason": "same key"}
    for report in reports:
        if report.applies_to(a, b):
            return {
                "status": STATUS_FAIL,
                "shown_as": "redundant, not corroborating",
                "reason": f"controller binding {report.claim} {report.binding_digest}",
            }
    return {"status": STATUS_NOT_CHECKED, "shown_as": "not corroborating", "reason": None}


# --- verification ------------------------------------------------------------


def _well_formed(r: Mapping[str, Any]) -> bool:
    """``controller_binding_form`` (CB §3.1, §3.2)."""
    claim = r.get("claim")
    if not isinstance(claim, str) or claim not in _CLAIMS:
        return False
    method_for_claim, added, _ = _CLAIMS[claim]
    names = list(_COMMON)
    if added:
        names.append(added)
    if "key_types" in r:
        names.append("key_types")  # OPTIONAL (§3.1)
    if not _has_members(r, names) or r["binding_version"] != VERSION:
        return False
    # A method that §3.2 defines for another claim type is malformed; one it
    # does not define at all is well formed and NOT_CHECKED.
    method = r["method"]
    if not isinstance(method, str):
        return False
    if any(other[0] == method and method != method_for_claim for other in _CLAIMS.values()):
        return False
    keys = r["keys"]
    if not isinstance(keys, list) or len(keys) != 2 or not _is_key(keys[0]) or not _is_key(keys[1]) or keys[0] >= keys[1]:
        return False  # ascending, so also distinct
    issued, not_before, not_after = (_instant(r[n]) for n in ("issued_at", "not_before", "not_after"))
    if issued is None or not_before is None or not_after is None or not_before > issued or not issued < not_after:
        return False
    if r["revocation"] != REVOCATION_METHOD:
        return False
    nonce = r["nonce"]
    if not isinstance(nonce, str):
        return False
    if "key_types" in r:
        types = r["key_types"]
        if not isinstance(types, list) or len(types) != 2 or not all(isinstance(t, str) for t in types):
            return False
        # A bip340 key is often a public Nostr identity, so the nonce alone
        # keeps a listed binding digest from being matched to guessed keys.
        if KEY_BIP340 in types and _NONCE32.fullmatch(nonce) is None:
            return False
    sigs = r["sigs"]
    if not isinstance(sigs, list):
        return False
    for entry in sigs:
        if not isinstance(entry, dict) or not _has_members(entry, ("key_id", "sig")):
            return False
    if added == "delegator":
        return r["delegator"] == keys[0] or r["delegator"] == keys[1]
    if added == "credential":
        c = r["credential"]
        return (
            isinstance(c, dict)
            and _has_members(c, ("issuer", "method", "digest"))
            and _is_key(c["issuer"])
            and isinstance(c["method"], str)
            and _is_key(c["digest"])
        )
    return True


def _key_types(r: Mapping[str, Any]) -> tuple[str, str]:
    types = r.get("key_types")
    if not isinstance(types, list):
        return KEY_ED25519, KEY_ED25519
    return types[0], types[1]


def _signatures(r: Mapping[str, Any], keys: tuple[str, str], types: tuple[str, str]) -> str:
    """``controller_binding_signatures`` (CB §4)."""
    if r["method"] != _CLAIMS[r["claim"]][0]:
        return STATUS_NOT_CHECKED  # a method this revision does not define
    if any(t not in (KEY_ED25519, KEY_BIP340) for t in types):
        return STATUS_NOT_CHECKED  # a key type §3.3 does not list
    signing_input = _jcs(_without(r, "sigs"))
    sigs = r["sigs"]
    if signing_input is None or len(sigs) != 2:
        return STATUS_FAIL
    for i, entry in enumerate(sigs):
        if entry["key_id"] != keys[i] or not _verify_sig(keys[i], types[i], entry["sig"], VERSION, signing_input):
            return STATUS_FAIL
    return STATUS_PASS


def _revocation(digest: str, keys: tuple[str, str], types: tuple[str, str], times: list[Instant],
                statements: Sequence[bytes]) -> str:
    """``controller_binding_revocation`` (CB §5, §6.1) before any declaration:
    FAIL when a received statement applies with ``revoked_at`` at or before
    some T, otherwise NOT_CHECKED, since a statement not received cannot be
    excluded (CB-1)."""
    for octets in statements:
        s = _decode_or_none(octets)
        if (
            not isinstance(s, dict)
            or not _has_members(s, ("revocation_version", "binding", "key_id", "revoked_at", "sig"))
            or s["revocation_version"] != REVOCATION_VERSION
            or s["binding"] != digest
            or s["key_id"] not in keys
        ):
            continue
        key_type = types[1] if s["key_id"] == keys[1] else types[0]
        signed = _jcs(_without(s, "sig"))
        if signed is None or not _verify_sig(s["key_id"], key_type, s["sig"], REVOCATION_VERSION, signed):
            continue
        revoked_at = _instant(s["revoked_at"])
        if revoked_at is None:
            continue
        if any(revoked_at <= t for t in times):
            return STATUS_FAIL
    return STATUS_NOT_CHECKED


def _list_entries(data: bytes) -> list[bytes] | None:
    """A revocation list's entries, each re-encoded as its own octets; ``None``
    when the list is not a JSON array (CB §5.1)."""
    value = _decode_or_none(data)
    if not isinstance(value, list):
        return None
    entries = []
    for item in value:
        encoded = _jcs(item)
        if encoded is not None:
            entries.append(encoded)
    return entries


def _why_not(d: Declaration, error: str, received: str, lst: RevocationList, digest: str,
             times: list[Instant]) -> str:
    """Why a declaration does not count (CB §5.1), or ``""`` when it does."""
    if error:
        return error
    if d.binding != digest:
        return "the declaration names another binding"
    if d.list_digest != received:
        return "list_digest is not the digest of the list received"
    if _list_entries(lst.list) is None:
        return "the list is not a JSON array"
    if not times:
        return "no time T was asked about"
    as_of = _instant(d.as_of)
    assert as_of is not None
    if any(as_of < t for t in times):
        return "as_of is earlier than a time asked about"
    evaluated = instant_of(lst.evaluated_at)
    if as_of > evaluated:
        return "as_of is later than the evaluation time"
    if evaluated[0] - as_of[0] > d.max_age:
        return "the evaluation time is more than max_age after as_of"
    return ""


def _list_report(lst: RevocationList, digest: str, times: list[Instant]) -> ListReport:
    d, error = parse_declaration(lst.declaration)
    report = ListReport(d.profile, d.asserted_by, _sha256_hex(lst.list), d.as_of)
    report.reason = _why_not(d, error, report.list_digest, lst, digest, times)
    report.counts = report.reason == ""
    return report


def _credential(c: Credential, keys: tuple[str, str], opts: Options) -> str:
    """``controller_binding_credential`` (CB §6.1)."""
    if opts.credential is None:
        return STATUS_NOT_PRESENT
    verify = opts.credential_verifiers.get(c.method)
    if verify is None:
        return STATUS_NOT_CHECKED
    if _sha256_hex(opts.credential) != c.digest:
        return STATUS_FAIL
    status = verify(opts.credential, c, keys)
    if status in (STATUS_PASS, STATUS_FAIL, STATUS_INCONCLUSIVE):
        return status
    return STATUS_FAIL  # a verifier that returns no status vouches for nothing


def verify(record: bytes, times: Sequence[_Time] = (), opts: Options | None = None) -> Report:
    """Check one binding record, given as the octets received, at ``times``:
    for a pair under IP §6.7.4, each member's ``issued_at``. With no time the
    window is NOT_CHECKED, so the binding does not apply."""
    opts = opts or Options()
    instants = [instant_of(t) for t in times]
    report = Report()
    r = _decode_or_none(record)
    if not isinstance(r, dict):
        report.properties[PROPERTY_FORM] = STATUS_FAIL
        return report
    signing_input = _jcs(_without(r, "sigs"))
    if signing_input is not None:
        report.binding_digest = _sha256_hex(signing_input)
    if isinstance(r.get("claim"), str):
        report.claim = r["claim"]
    # The keys a record names are reported even when it is malformed, so a
    # pair can be told it is named by a binding that does not apply (§6.2).
    named = r.get("keys")
    if isinstance(named, list) and len(named) == 2 and all(isinstance(k, str) for k in named):
        report.keys = (named[0], named[1])
    if not _well_formed(r):
        report.properties[PROPERTY_FORM] = STATUS_FAIL
        return report
    report.properties[PROPERTY_FORM] = STATUS_PASS
    keys = (report.keys[0], report.keys[1])
    delegator = r.get("delegator")
    report.delegator = delegator if isinstance(delegator, str) else ""
    report.not_before, report.not_after = r["not_before"], r["not_after"]

    types = _key_types(r)
    report.properties[PROPERTY_SIGNATURES] = _signatures(r, keys, types)
    report.properties[PROPERTY_WINDOW] = STATUS_PASS if instants else STATUS_NOT_CHECKED
    not_before, not_after = _instant(report.not_before), _instant(report.not_after)
    for t in instants:
        if t < not_before or not t < not_after:
            report.properties[PROPERTY_WINDOW] = STATUS_FAIL
    statements = list(opts.revocations)
    if opts.revocation_list is not None:
        statements += _list_entries(opts.revocation_list.list) or []
    report.properties[PROPERTY_REVOCATION] = _revocation(report.binding_digest, keys, types, instants, statements)
    if opts.revocation_list is not None:
        report.revocation_list = _list_report(opts.revocation_list, report.binding_digest, instants)
        if report.revocation_list.counts and report.properties[PROPERTY_REVOCATION] != STATUS_FAIL:
            report.properties[PROPERTY_REVOCATION] = STATUS_PASS
    if report.claim == CLAIM_SAME_ORGANIZATION:
        c = r["credential"]
        report.properties[PROPERTY_CREDENTIAL] = _credential(
            Credential(c["issuer"], c["method"], c["digest"]), keys, opts
        )
    if report.properties[PROPERTY_SIGNATURES] == STATUS_PASS:
        report.proves += [_PROVES_CONTROL, _CLAIMS[report.claim][2]]
        if report.properties.get(PROPERTY_CREDENTIAL) == STATUS_PASS:
            report.proves.append(_PROVES_CREDENTIALED)
    return report


__all__ = [
    "Credential", "CredentialVerifier", "Declaration", "ListReport", "Options", "Report", "RevocationList",
    "instant_of", "pair_independence", "parse_declaration", "verify", "verify_bip340",
]
