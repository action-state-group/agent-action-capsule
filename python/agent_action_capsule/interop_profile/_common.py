# SPDX-License-Identifier: BSD-3-Clause
"""Vocabulary, value forms and the trust and verification policies (profile §4, §5.2, §7.1).

Nothing here reads the clock or the network. Every time a check is made "as of" is passed in:
an object's own ``issued_at`` for as-of-event checks, and the caller's evaluation time for
as-of-evaluation checks (PRD FR-31, profile §11.1.7).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .._ed25519_strict import verify_strict
from ..canonical import MAX_NESTING_DEPTH, jcs, json_text_too_deep
from ._cbor import Tag

__all__ = [
    "PROFILE_ID",
    "PROFILE_V1",
    "PROFILE_IDS",
    "DEFAULT_REQUEST_PROFILE",
    "REFUSAL_REASONS_BY_PROFILE",
    "refusal_reasons_for",
    "PASS",
    "FAIL",
    "NOT_PRESENT",
    "NOT_CHECKED",
    "INCONCLUSIVE",
    "STATUSES",
    "MEDIA_CBOR",
    "MEDIA_JSON",
    "PropertyReport",
    "TrustPolicy",
    "VerificationPolicy",
    "KeyStatusResolver",
]

#: ``spec/interop-profile-v0.md``, frozen; the name keeps its meaning for existing callers.
PROFILE_ID = "evidence-interop/0"
#: ``spec/interop-profile-v1.md``: ER -02 and its two refusal reasons (P-65).
PROFILE_V1 = "evidence-interop/1"
#: Every identifier this verifier implements, each checked under its own rules.
PROFILE_IDS = frozenset({PROFILE_ID, PROFILE_V1})
#: §3.3 step 2, both revisions: a request with no ``profile`` asks for evidence-interop/0.
DEFAULT_REQUEST_PROFILE = PROFILE_ID

# §7.1: the five property statuses.
PASS = "PASS"
FAIL = "FAIL"
NOT_PRESENT = "NOT_PRESENT"
NOT_CHECKED = "NOT_CHECKED"
INCONCLUSIVE = "INCONCLUSIVE"
STATUSES = (PASS, FAIL, NOT_PRESENT, NOT_CHECKED, INCONCLUSIVE)

# §11.4.1 rule 7: the two carried media types, compared as exact strings.
MEDIA_CBOR = "application/cbor"
MEDIA_JSON = "application/json"

# v0 §9.1: the eight refusal reasons of the ER -01 registry [ER §13].
REFUSAL_REASONS = frozenset({
    "not_authorized", "no_such_subject", "coverage_unsatisfiable", "derivation_unsupported",
    "policy_declined", "deadline_unmet", "request_malformed", "retention_expired",
})
# §9.1 of each revision: v1 pins ER -02, which adds two.
REFUSAL_REASONS_BY_PROFILE = {
    PROFILE_ID: REFUSAL_REASONS,
    PROFILE_V1: REFUSAL_REASONS | {"capacity_exceeded", "request_unauthenticated"},
}


def refusal_reasons_for(asked: Any, implemented: Iterable[str]) -> frozenset:
    """v1 §6.3: a refusal carries no ``profile``, so its reason is checked against the tokens of the
    identifier its request asks for, or, when the verifier does not implement that one, against
    every token of those it does."""
    implemented = [p for p in implemented if p in REFUSAL_REASONS_BY_PROFILE]
    if asked in implemented:
        return REFUSAL_REASONS_BY_PROFILE[asked]
    return frozenset().union(*(REFUSAL_REASONS_BY_PROFILE[p] for p in implemented))

# §6.2.1: the three verification material kinds this revision registers.
CLL_KINDS = ("cll-checkpoint", "cll-inclusion-proof", "cll-consistency-proof")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
# RFC 3339 DIGIT is ASCII (%x30-39): without re.ASCII, \d would also match other scripts' digits.
_PROFILE_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", re.ASCII)
_RFC3339 = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)[Tt](\d\d):(\d\d):(\d\d)(\.\d+)?([Zz]|[+-]\d\d:\d\d)", re.ASCII)
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_B64ANY = re.compile(r"[A-Za-z0-9+/_-]*={0,2}")
_MAX_SAFE = 2**53 - 1


@dataclass(frozen=True)
class PropertyReport:
    """One checked property: ``{property, status, method}`` and an optional ``detail`` (§7.1)."""

    property: str
    status: str
    method: str
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"not a §7.1 status: {self.status!r}")

    def to_dict(self) -> dict[str, str]:
        out = {"property": self.property, "status": self.status, "method": self.method}
        if self.detail is not None:
            out["detail"] = self.detail
        return out


# ---------------------------------------------------------------------------
# Value forms (§5.2)
# ---------------------------------------------------------------------------


def is_digest(value: Any) -> bool:
    """A SHA-256 digest: 64 lowercase hexadecimal characters."""
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


is_key_id = is_digest  # a raw Ed25519 public key in the same 64-hex form


def is_signature(value: Any) -> bool:
    return isinstance(value, str) and _HEX128.fullmatch(value) is not None


def is_uint(value: Any) -> bool:
    """An unsigned integer the profile allows: 0 to 2^53 - 1, and never a boolean."""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_SAFE


def is_text(value: Any) -> bool:
    return isinstance(value, str)


def is_profile_time(value: Any) -> bool:
    """The §5.2 time form, ``YYYY-MM-DDTHH:MM:SSZ``, naming a real calendar instant."""
    return isinstance(value, str) and _PROFILE_TIME.fullmatch(value) is not None and \
        parse_time(value) is not None


def parse_time(value: Any) -> datetime | None:
    """Any RFC 3339 date-time as an aware UTC datetime, or None when it is not one."""
    if not isinstance(value, str):
        return None
    m = _RFC3339.fullmatch(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(m.group(k)) for k in range(1, 7))
    if second > 60:
        return None
    try:
        base = datetime(year, month, day, hour, minute, min(second, 59), tzinfo=timezone.utc)
    except ValueError:
        return None
    if second == 60:  # a leap second names the instant after second 59
        base += timedelta(seconds=1)
    if m.group(7):
        frac = m.group(7)[1:7].ljust(6, "0")
        base += timedelta(microseconds=int(frac))
    offset = m.group(8)
    if offset not in ("Z", "z"):
        sign = 1 if offset[0] == "+" else -1
        base -= sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
    return base


def to_profile_time(moment: datetime) -> str:
    """``moment`` in UTC with any fractional seconds dropped, in the §5.2 form."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def floor_seconds(moment: datetime) -> datetime:
    return moment.replace(microsecond=0)


def ceil_seconds(moment: datetime) -> datetime:
    return moment if moment.microsecond == 0 else moment.replace(microsecond=0) + timedelta(seconds=1)


# ---------------------------------------------------------------------------
# Digests, encodings and signatures
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# JCS raises these for a value it cannot represent: a float, an unsafe integer, bytes, a
# non-text map key (AttributeError from the key sort), or nesting too deep.
_JCS_ERRORS = (TypeError, ValueError, AttributeError, RecursionError)


def jcs_or_none(value: Any) -> bytes | None:
    """UTF-8 of JCS of ``value`` (RFC 8785), or None when JCS cannot represent it."""
    try:
        return jcs(value)
    except _JCS_ERRORS:
        return None


def json_value_digest(value: Any) -> str | None:
    """SHA-256 over UTF-8 of JCS of a JSON value (§5.1), or None when JCS cannot represent it."""
    body = jcs_or_none(value)
    return None if body is None else sha256_hex(body)


def member_of(value: Any, allowed: Any) -> bool:
    """``value in allowed`` for a value an adversary chose: an unhashable value is never a member."""
    try:
        return value in allowed
    except TypeError:
        return False


def numbers_in_domain(value: Any, depth: int = 0) -> bool:
    """§5.2: every number is an unsigned integer from 0 to 2^53 - 1, never a float or boolean
    standing in for one, and every map key is text."""
    if depth > MAX_NESTING_DEPTH:
        return False
    if isinstance(value, bool) or value is None or isinstance(value, (str, bytes)):
        return True
    if isinstance(value, int):
        return 0 <= value <= _MAX_SAFE
    if isinstance(value, list):
        return all(numbers_in_domain(v, depth + 1) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and numbers_in_domain(v, depth + 1) for k, v in value.items())
    return isinstance(value, Tag) and numbers_in_domain(value.value, depth + 1)


def b64url_decode(text: Any) -> bytes | None:
    """Base64url without padding (RFC 4648 §5), as §4 writes opaque bytes; None otherwise."""
    if not isinstance(text, str) or _B64URL.fullmatch(text) is None or len(text) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def b64_any_decode(text: Any) -> bytes | None:
    """ProtoJSON bytes, as A2A's JSON bindings write them: base64, standard or URL-safe
    alphabet, padded or not [A2A §5.5]. None when the text is not one of those."""
    if not isinstance(text, str) or _B64ANY.fullmatch(text) is None:
        return None
    body = text.rstrip("=")
    if len(body) % 4 == 1 or ("+" in body or "/" in body) and ("-" in body or "_" in body):
        return None
    try:
        return base64.urlsafe_b64decode(body.replace("+", "-").replace("/", "_") + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        return None


class _JsonIrregular:
    """Records what makes a JSON text not well-formed under §5.2."""

    def __init__(self) -> None:
        self.duplicates = False
        self.bad_number = False

    def pairs(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                self.duplicates = True
                continue
            out[key] = value
        return out

    def number(self, _text: str) -> int:
        self.bad_number = True
        return 0

    def integer(self, text: str) -> int:
        # §5.2 allows 0 to 2^53 - 1 only; checking the text first also keeps a huge literal
        # from reaching int() at all.
        if text.startswith("-") or len(text) > 16 or int(text) > _MAX_SAFE:
            self.bad_number = True
            return 0
        return int(text)


@dataclass
class ParsedJson:
    value: Any
    duplicate_keys: bool
    bad_number: bool

    @property
    def well_formed(self) -> bool:
        return not (self.duplicate_keys or self.bad_number)


def parse_json(data: bytes) -> ParsedJson | None:
    """Parse UTF-8 JSON, recording duplicate members and numbers outside 0 to 2^53 - 1 (§5.2).

    The first occurrence of a duplicated member is kept. None when the octets are not JSON.
    """
    irregular = _JsonIrregular()
    try:
        text = data.decode("utf-8")
        if json_text_too_deep(text):
            return None
        value = json.loads(text, object_pairs_hook=irregular.pairs,
                           parse_float=irregular.number, parse_constant=irregular.number,
                           parse_int=irregular.integer)
    except (UnicodeDecodeError, ValueError):
        return None
    return ParsedJson(value, irregular.duplicates, irregular.bad_number)


def parse_json_text(text: str) -> ParsedJson | None:
    return parse_json(text.encode("utf-8"))


def _load_ed25519() -> Any:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised only without the dependency
        raise ImportError(
            "agent_action_capsule.interop_profile verifies Ed25519 signatures and needs the "
            "'cryptography' package; install it, for example with the 'transparent' extra") from exc
    return Ed25519PublicKey, InvalidSignature


def ed25519_verify(key: bytes, signature: bytes, message: bytes) -> bool:
    """True when ``signature`` is a valid Ed25519 signature by ``key`` over ``message`` (RFC 8032),
    under strict Ed25519: A and R canonical and not of small order, and S < L. Every key checked
    here is one the trust policy accepts, and a small-order key would verify any message."""
    _load_ed25519()
    return verify_strict(key, message, signature)


def ed25519_verify_hex(key_hex: Any, sig_hex: Any, message: bytes) -> bool:
    """As :func:`ed25519_verify`, for the §5.2 hex forms; False when either form is wrong."""
    if not is_key_id(key_hex) or not is_signature(sig_hex):
        return False
    return ed25519_verify(bytes.fromhex(key_hex), bytes.fromhex(sig_hex), message)


def unsigned_jcs(record: Mapping[str, Any], exclude: Iterable[str] = ("sig",)) -> bytes | None:
    """UTF-8 of JCS over every member except ``exclude``: the signing input of §6.4, §11.1 and §11.2."""
    skip = set(exclude)
    return jcs_or_none({k: v for k, v in record.items() if k not in skip})


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

# Called only when the verification policy is online. It answers the as-of-now status of a key
# (responder_key_current, §7.2) with one of the §7.1 statuses and a method naming how it decided.
# The verifier never performs that lookup itself (NFR-7): the caller supplies it.
KeyStatusResolver = Callable[[str, str], "tuple[str, str]"]


@dataclass(frozen=True)
class _Window:
    not_before: datetime | None
    not_after: datetime | None


def _window(entry: Mapping[str, Any]) -> _Window:
    nb, na = entry.get("not_before"), entry.get("not_after")
    window = _Window(parse_time(nb) if nb is not None else None, parse_time(na) if na is not None else None)
    if (nb is not None and window.not_before is None) or (na is not None and window.not_after is None):
        raise ValueError(f"key validity window is not RFC 3339: {dict(entry)!r}")
    return window


@dataclass
class TrustPolicy:
    """The relying party's trust roots and key-to-party map (§6.2.1, §7.2, §11.1.7, §11.2.3).

    The shape is the ``trust_policy`` pin of the conformance vectors (§11.5), plus two optional
    members those vectors do not use:

    - ``key_validity``: ``{key: {"not_before": time, "not_after": time}}``. A key outside its
      window is not accepted at that instant. It is how one policy answers differently as of an
      event and as of evaluation (FR-31).
    - ``resolvers``: ``[{"scheme": text, "id": text or null, "key": key}]``, the keys accepted as
      the resolving process for a ``process`` reference (§11.2.4); ``id`` null covers every case of
      that scheme.

    A key absent from every list is not accepted. The policy never decides on its own that a key
    is current now; that is an online check (§7.2 ``responder_key_current``).
    """

    responder_keys: frozenset = frozenset()
    log_keys: frozenset = frozenset()  # (iss, sub, kid hex)
    foreign_keys: frozenset = frozenset()
    parties: Mapping[str, str] = field(default_factory=dict)
    successions: frozenset = frozenset()  # (successor key, predecessor key)
    resolvers: tuple = ()
    require_action_time_from_other_party: bool = False
    key_validity: Mapping[str, _Window] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, pin: Mapping[str, Any]) -> TrustPolicy:
        return cls(
            responder_keys=frozenset(pin.get("responder_keys", ())),
            log_keys=frozenset((e["iss"], e["sub"], e["kid"]) for e in pin.get("log_keys", ())),
            foreign_keys=frozenset(pin.get("foreign_keys", ())),
            parties=dict(pin.get("parties", {})),
            successions=frozenset((e["key"], e["succeeds"]) for e in pin.get("successions", ())),
            resolvers=tuple((e["scheme"], e.get("id"), e["key"]) for e in pin.get("resolvers", ())),
            require_action_time_from_other_party=bool(pin.get("require_action_time_from_other_party", False)),
            key_validity={k: _window(v) for k, v in pin.get("key_validity", {}).items()},
        )

    def valid_at(self, key: str, at: str | None) -> str:
        """PASS when ``key`` has no window or ``at`` falls in it; FAIL when ``at`` falls outside;
        INCONCLUSIVE when the key has a window and ``at`` is not a time, so the status at that
        instant cannot be resolved (§7.1)."""
        window = self.key_validity.get(key)
        if window is None:
            return PASS
        moment = parse_time(at)
        if moment is None:
            return INCONCLUSIVE
        if window.not_before is not None and moment < window.not_before:
            return FAIL
        if window.not_after is not None and moment > window.not_after:
            return FAIL
        return PASS

    def _accepts(self, listed: bool, key: str, at: str | None) -> str:
        return self.valid_at(key, at) if listed else FAIL

    def accepts_responder(self, key: Any, at: str | None) -> str:
        return self._accepts(isinstance(key, str) and key in self.responder_keys, key, at)

    def accepts_log_key(self, iss: Any, sub: Any, kid: str, at: str | None) -> str:
        return self._accepts(member_of((iss, sub, kid), self.log_keys), kid, at)

    def accepts_foreign_key(self, key: Any, at: str | None) -> str:
        return self._accepts(isinstance(key, str) and key in self.foreign_keys, key, at)

    def party_of(self, key: Any, at: str | None) -> tuple[str, str | None]:
        """The status of trusting ``key`` at ``at``, and the party it maps to when trusted."""
        if not isinstance(key, str) or key not in self.parties:
            return FAIL, None
        status = self.valid_at(key, at)
        return status, (self.parties[key] if status == PASS else None)

    def accepts_in_role(self, key: Any, counterpart: Any, at: str | None) -> str:
        """§11.1.7 "accepts a key as the proposer/acceptor": the policy trusts ``key``, maps it to
        a party, and that party is not the one it maps ``counterpart`` to."""
        status, party = self.party_of(key, at)
        if status != PASS:
            return status
        other = self.parties.get(counterpart) if isinstance(counterpart, str) else None
        return FAIL if party == other else PASS

    def succeeds(self, key: str, predecessor: str) -> bool:
        """True when the policy states that ``key`` succeeds ``predecessor``, directly or through
        a sequence of successions (§11.2.3). Succession runs one way."""
        seen: set = set()
        frontier = {predecessor}
        while frontier:
            successors = {k for k, prev in self.successions if prev in frontier and k not in seen}
            if key in successors:
                return True
            seen |= successors
            frontier = successors
        return False

    def accepts_resolver(self, key: Any, process: Mapping[str, Any], at: str | None) -> str:
        listed = any(scheme == process.get("scheme") and (case is None or case == process.get("id"))
                     and k == key for scheme, case, k in self.resolvers)
        return self._accepts(listed, key, at)


@dataclass
class VerificationPolicy:
    """What the verifier implements and whether it may go online (§3.3, §6.2, NFR-7).

    The shape is the ``verification_policy`` pin of the conformance vectors (§11.5). When
    ``online`` is true, ``key_status`` answers ``responder_key_current``; the verifier itself
    never fetches anything.
    """

    online: bool = False
    profiles_implemented: frozenset = PROFILE_IDS
    kinds_implemented: frozenset = frozenset(CLL_KINDS)
    key_status: KeyStatusResolver | None = None

    @classmethod
    def from_dict(cls, pin: Mapping[str, Any], key_status: KeyStatusResolver | None = None) -> VerificationPolicy:
        return cls(online=bool(pin.get("online", False)),
                   profiles_implemented=frozenset(pin.get("profiles_implemented", PROFILE_IDS)),
                   kinds_implemented=frozenset(pin.get("kinds_implemented", CLL_KINDS)),
                   key_status=key_status)
