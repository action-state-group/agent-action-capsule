# SPDX-License-Identifier: Apache-2.0
"""The evidence request interaction of ``draft-mih-agent-evidence-request-00``.

A requester asks a responder for evidence about a **subject**, under a
**coverage** constraint. The interaction ends in exactly one of three
outcomes: an artifact, a signed refusal, or the requester's own record that
nothing arrived (a recorded absence). This module implements what both sides
must agree on, and the responder's decision logic:

* :func:`parse_request`: the request map in its JSON or CBOR binding, checked
  against -00 (the six subject forms, exactly one coverage member, the
  optional fields), raising :class:`RequestError` with the exact refusal
  reason when it is not well formed.
* :func:`request_digest`: SHA-256 over the request bytes as received.
* :func:`resolve`: exact-match resolution against an :class:`EvidenceStore`,
  giving the anchor to serve under or the most specific refusal reason.
* :func:`answer`: one request in, one :class:`Artifact` or signed
  :class:`Refusal` out.
* :func:`sign_refusal`, :func:`check_refusal`, :func:`verify_refusal_offline`:
  the signed refusal.
* :func:`sign_envelope`: the signed :class:`Envelope` an artifact travels in
  under the interop profile (:data:`PROFILE`). -00 fixes no members for the
  artifact response, so the envelope is the profile's
  (``spec/interop-profile-v0.md`` §6.2), not a reading of -00.
* :func:`record_outcome`, :func:`compare_observations`,
  :func:`classify_refusal`, :func:`classify_absence` and
  :func:`commitment_well_formed`: the three-state discipline, caller
  invariance and retention commitments, as a requester or auditor applies them.

**Wire shapes.** -00 leaves several shapes open; this module follows the
readings the conformance vectors in ``vectors/evidence-request/`` document
(their README lists them as A1 to A14):

* A subject is a map with exactly one member, named by the form token:
  ``{"full_history": null}``, ``{"checkpoints": null}``, ``{"record":
  <digest>}``, ``{"range": [a, b]}`` (unsigned, ``a <= b``),
  ``{"correlation": "<id>"}``, ``{"exchange": <digest>}`` (A1, A6).
* A digest is SHA-256 as 64 lowercase hex characters, as text in both
  bindings (A2). Nothing is ever matched by prefix or with case folding.
* ``coverage`` is ``{"expected_pin": <digest>}`` or ``{"min_freshness":
  <size or time>}``: an unsigned integer is a log size, text an RFC 3339 UTC
  time (A3). Each member present is checked first, so a non-conforming value
  is ``request_malformed`` even beside the other member; only then is both,
  or neither (an absent ``coverage`` included), ``coverage_unsatisfiable``
  (A4). A ``coverage`` that is not a map is ``request_malformed``.
* ``deadline`` is an RFC 3339 UTC time; ``nonce`` and ``route`` are text
  (A5). ``derivation`` is a registered token (``name/N``) or the digest of a
  definition (A14). Members -00 does not define are ignored (§3).
* A refusal is ``{request_digest, reason, issued_at, key_id, sig}``: Ed25519
  over the RFC 8785 serialization of ``issued_at``, ``reason`` and
  ``request_digest``, with ``key_id`` the raw public key and ``sig`` in
  lowercase hex (A7).

**Bindings.** The JSON binding is UTF-8 JSON; a duplicate member name makes
it not well formed. The CBOR binding is accepted only in core deterministic
encoding (RFC 8949 §4.2.1, as -00 §10 requires of the stream binding's
frames), so the same request has one encoding and one digest: shortest
arguments, definite lengths, text map keys in bytewise order with no
repeats, and no tags, floats, byte strings, negative integers or integers
above 2^53 - 1, at any depth. In both bindings an integer a defined member
reads must be in 0 to 2^53 - 1.

**Caller invariance by construction.** :func:`answer` asks the store for the
artifact with the subject, the derivation and the resolved anchor only: the
store never sees the requester, the nonce, the route, the deadline or the
time. Two requesters asking for the same subject under the same anchor get
the same artifact (§5); only a refusal's ``request_digest`` differs.

**Checkpoint writes are pull-only by default.** A ``min_freshness`` request
that no held anchor satisfies makes :func:`answer` call
:meth:`EvidenceStore.force_checkpoint` (a write, the work §3.2 permits) only
when the request carries a ``deadline`` and the node opted in with
``allow_forced_checkpoint=True``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from .canonical import jcs
from .interop_profile import _cbor
from .interop_profile._common import is_profile_time

__all__ = [
    "DRAFT",
    "SUBPROTOCOL",
    "DERIVATION_HISTORY_CARD",
    "SUBJECT_FORMS",
    "COVERAGE_MEMBERS",
    "REASON_NOT_AUTHORIZED",
    "REASON_NO_SUCH_SUBJECT",
    "REASON_COVERAGE_UNSATISFIABLE",
    "REASON_DERIVATION_UNSUPPORTED",
    "REASON_POLICY_DECLINED",
    "REASON_DEADLINE_UNMET",
    "REASON_REQUEST_MALFORMED",
    "REASON_RETENTION_EXPIRED",
    "REFUSAL_REASONS",
    "OUTCOMES",
    "REQUEST_STATES",
    "SIGNED_MEMBERS",
    "RequestError",
    "Decline",
    "Subject",
    "Coverage",
    "Request",
    "Anchor",
    "Resolution",
    "EvidenceStore",
    "Signer",
    "Artifact",
    "PROFILE",
    "Envelope",
    "sign_envelope",
    "Refusal",
    "RefusalCheck",
    "is_digest",
    "parse_utc",
    "parse_request",
    "request_digest",
    "resolve",
    "answer",
    "sign_refusal",
    "check_refusal",
    "check_refusal_cbor",
    "verify_refusal_offline",
    "record_outcome",
    "compare_observations",
    "classify_refusal",
    "classify_absence",
    "commitment_well_formed",
]

DRAFT = "draft-mih-agent-evidence-request-00"

#: The stream binding's subprotocol identifier (§10, §13).
SUBPROTOCOL = "evidence-request/1"

#: The interoperability profile whose artifact envelope :class:`Envelope`
#: implements (``spec/interop-profile-v0.md`` §6.2). -00 says what an artifact
#: response carries but fixes no wire members (§4.1); the profile does.
PROFILE = "evidence-interop/0"

#: The one derivation -00 registers (§8.1, §13).
DERIVATION_HISTORY_CARD = "history_card/1"

#: The six subject forms (§3.1), in the draft's order.
SUBJECT_FORMS = ("full_history", "checkpoints", "record", "range", "correlation", "exchange")

#: The two coverage members (§3.2).
COVERAGE_MEMBERS = ("expected_pin", "min_freshness")

REASON_NOT_AUTHORIZED = "not_authorized"
REASON_NO_SUCH_SUBJECT = "no_such_subject"
REASON_COVERAGE_UNSATISFIABLE = "coverage_unsatisfiable"
REASON_DERIVATION_UNSUPPORTED = "derivation_unsupported"
REASON_POLICY_DECLINED = "policy_declined"
REASON_DEADLINE_UNMET = "deadline_unmet"
REASON_REQUEST_MALFORMED = "request_malformed"
REASON_RETENTION_EXPIRED = "retention_expired"

#: The eight registered refusal reasons (§4.2, §13). Matching is exact: a
#: different case, or a token such as ``no_such_record``, is not registered.
REFUSAL_REASONS = frozenset(
    {
        REASON_NOT_AUTHORIZED,
        REASON_NO_SUCH_SUBJECT,
        REASON_COVERAGE_UNSATISFIABLE,
        REASON_DERIVATION_UNSUPPORTED,
        REASON_POLICY_DECLINED,
        REASON_DEADLINE_UNMET,
        REASON_REQUEST_MALFORMED,
        REASON_RETENTION_EXPIRED,
    }
)

#: The three outcomes (§4) and the one request state that is not an outcome
#: (§4.3).
OUTCOMES = ("artifact", "refusal", "recorded_absence")
REQUEST_STATES = ("pending",)

#: The refusal members the signature covers (A7).
SIGNED_MEMBERS = ("issued_at", "reason", "request_digest")

_MAX_UINT = (1 << 53) - 1
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z\Z")
_DERIVATION_TOKEN = re.compile(r".+/[0-9]+\Z", re.DOTALL)


# --- values ----------------------------------------------------------------


def is_digest(value: Any) -> bool:
    """True for a digest as the vectors read -00: SHA-256 as 64 lowercase hex (A2)."""
    return isinstance(value, str) and _HEX64.match(value) is not None


def _is_uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_UINT


def _is_hex_of_len(value: Any, nbytes: int) -> bool:
    return isinstance(value, str) and len(value) == 2 * nbytes and re.fullmatch(r"[0-9a-f]*", value) is not None


def parse_utc(value: Any) -> tuple[int, int] | None:
    """Parse ``YYYY-MM-DDTHH:MM:SS[.fraction]Z`` (upper-case ``T`` and ``Z``, UTC
    only, at most nine fraction digits) to ``(epoch_seconds, nanoseconds)``,
    which order as instants. Anything else, including an impossible date, is
    ``None``."""
    if not isinstance(value, str):
        return None
    m = _UTC.match(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days_in_month = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if not (1 <= month <= 12 and 1 <= day <= days_in_month[month - 1] and hour <= 23 and minute <= 59
            and second <= 59):
        return None
    # Days since 1970-01-01 in the proleptic Gregorian calendar (Hinnant's
    # days_from_civil), so years 0000 to 9999 all order correctly.
    y = year - 1 if month <= 2 else year
    era, yoe = divmod(y, 400)
    doy = (153 * (month - 3 if month > 2 else month + 9) + 2) // 5 + day - 1
    days = era * 146_097 + yoe * 365 + yoe // 4 - yoe // 100 + doy - 719_468
    seconds = days * 86_400 + hour * 3_600 + minute * 60 + second
    return seconds, int((m.group(7) or "").ljust(9, "0"))


class _OutsideModel:
    """A received JSON number no defined member accepts (negative, or too
    large to be read exactly). Kept, so an unknown member holding one is
    still ignored."""


_OUTSIDE = _OutsideModel()


class _DuplicateMember(ValueError):
    pass


def _json_object(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateMember(key)
        out[key] = value
    return out


def _json_int(text: str) -> Any:
    # Checking the text first keeps a huge literal from reaching int().
    if text.startswith("-") or len(text) > 16:
        _json_float(text)  # still a number a double can hold, or malformed
        return _OUTSIDE
    return int(text)


def _json_float(text: str) -> Any:
    # A number beyond the range of a double (1e999) is not one JSON readers
    # agree on: malformed, as in the reference implementations.
    if math.isinf(float(text)):
        raise ValueError(f"number {text[:20]} is out of range")
    return _OUTSIDE


def _reject_constant(text: str) -> Any:
    raise ValueError(f"{text} is not JSON")


def _decode_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_int=_json_int,
            parse_float=_json_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RequestError(REASON_REQUEST_MALFORMED, f"not well-formed JSON: {exc}") from exc


def _cbor_in_model(value: Any, request: bool) -> bool:
    if value is None or isinstance(value, (bool, str)):
        return True
    if type(value) is int:
        return 0 <= value <= _MAX_UINT or not request
    if isinstance(value, list):
        return all(_cbor_in_model(v, request) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _cbor_in_model(v, request) for k, v in value.items())
    return False  # a tag, a byte string or a float


def _decode_cbor(data: bytes, *, request: bool) -> Any:
    """Decode one CBOR item with text map keys and no duplicates. A request
    (``request=True``) must also be in core deterministic encoding with every
    integer in 0 to 2^53 - 1; a refusal frame need not be, since its signature
    covers the RFC 8785 body, not the frame."""
    try:
        decoded = _cbor.decode(data)
    except _cbor.CborError as exc:
        raise RequestError(REASON_REQUEST_MALFORMED, f"not well-formed CBOR: {exc}") from exc
    if decoded.duplicate_keys:
        raise RequestError(REASON_REQUEST_MALFORMED, "a duplicate map key")
    if decoded.irregular or not _cbor_in_model(decoded.value, request):
        raise RequestError(REASON_REQUEST_MALFORMED, "a value outside the request data model")
    if request and not decoded.deterministic:
        raise RequestError(REASON_REQUEST_MALFORMED, "not in core deterministic encoding")
    return decoded.value


# --- the request -------------------------------------------------------------


class RequestError(ValueError):
    """A request is not well formed. ``reason`` is the refusal reason to answer
    with: ``request_malformed``, or ``coverage_unsatisfiable`` for a coverage
    carrying both members or neither (§3.2)."""

    def __init__(self, reason: str, message: str):
        super().__init__(f"{reason}: {message}")
        self.reason = reason


def _malformed(message: str) -> RequestError:
    return RequestError(REASON_REQUEST_MALFORMED, message)


@dataclass(frozen=True)
class Subject:
    """What a request asks about (§3.1). ``content`` is ``None`` for
    ``full_history`` and ``checkpoints``, a digest for ``record`` and
    ``exchange``, ``(a, b)`` for ``range``, the identifier for ``correlation``."""

    form: str
    content: None | str | tuple[int, int] = None

    def to_wire(self) -> dict:
        content = list(self.content) if isinstance(self.content, tuple) else self.content
        return {self.form: content}


@dataclass(frozen=True)
class Coverage:
    """The coverage constraint (§3.2): exactly one member is set.
    ``min_freshness`` is a log size (``int``) or an RFC 3339 UTC time (``str``)."""

    expected_pin: str | None = None
    min_freshness: None | int | str = None


@dataclass(frozen=True)
class Request:
    """A well-formed request (§3)."""

    subject: Subject
    coverage: Coverage
    derivation: str | None = None
    deadline: str | None = None
    nonce: str | None = None
    route: str | None = None


def _parse_subject(value: Any) -> Subject:
    if not isinstance(value, dict):
        raise _malformed("subject is not a map")
    if len(value) != 1:
        raise _malformed("subject must have exactly one member")
    ((form, content),) = value.items()
    if form not in SUBJECT_FORMS:
        raise _malformed("subject form is not one of the six")
    if form in ("full_history", "checkpoints"):
        if content is not None:
            raise _malformed("this subject form carries no content")
        return Subject(form)
    if form in ("record", "exchange"):
        if not is_digest(content):
            raise _malformed("subject digest is not 64 lowercase hex")
        return Subject(form, content)
    if form == "correlation":
        if not isinstance(content, str) or not content:
            raise _malformed("correlation is not non-empty text")
        return Subject(form, content)
    if not (isinstance(content, list) and len(content) == 2 and all(_is_uint(v) for v in content)):
        raise _malformed("range is not two unsigned integers")
    a, b = content
    if a > b:
        raise _malformed("range start is after its end")
    return Subject(form, (a, b))


def _parse_derivation(value: Any) -> str:
    if not isinstance(value, str):
        raise _malformed("derivation is not text")
    if is_digest(value) or _DERIVATION_TOKEN.match(value):
        return value
    raise _malformed("derivation is neither a registered token nor a digest")


def _parse_coverage(value: Any) -> Coverage:
    if not isinstance(value, dict):
        raise _malformed("coverage is not a map")
    pin, freshness = value.get("expected_pin"), value.get("min_freshness")
    # Each member present is checked before the exactly-one rule (A4 ruling).
    if "expected_pin" in value and not is_digest(pin):
        raise _malformed("expected_pin is not a digest")
    if "min_freshness" in value and not (_is_uint(freshness) or parse_utc(freshness) is not None):
        raise _malformed("min_freshness is neither a size nor an RFC 3339 UTC time")
    if ("expected_pin" in value) == ("min_freshness" in value):
        raise RequestError(
            REASON_COVERAGE_UNSATISFIABLE, "coverage must carry exactly one of expected_pin, min_freshness"
        )
    return Coverage(expected_pin=pin, min_freshness=freshness)


def _optional_text(data: dict, key: str) -> str | None:
    value = data.get(key)
    if key in data and not isinstance(value, str):
        raise _malformed(f"{key} is not text")
    return value


def parse_request(request_bytes: bytes, *, binding: str = "json") -> Request:
    """Parse and check a request from its bytes as received.

    ``binding`` is ``"json"`` or ``"cbor"`` (core deterministic encoding only).
    Raises :class:`RequestError` carrying the refusal reason when the request
    is not well formed.
    """
    if binding == "json":
        data = _decode_json(request_bytes)
    elif binding == "cbor":
        data = _decode_cbor(request_bytes, request=True)
    else:
        raise ValueError(f"binding must be 'json' or 'cbor', not {binding!r}")
    if not isinstance(data, dict):
        raise _malformed("the request is not a map")
    if "subject" not in data:
        raise _malformed("subject is missing")
    subject = _parse_subject(data["subject"])
    derivation = _parse_derivation(data["derivation"]) if "derivation" in data else None
    deadline = _optional_text(data, "deadline")
    if deadline is not None and parse_utc(deadline) is None:
        raise _malformed("deadline is not an RFC 3339 UTC time")
    nonce = _optional_text(data, "nonce")
    route = _optional_text(data, "route")
    # An absent coverage carries neither member (A4); a present one that is
    # not a map, null included, is malformed.
    coverage = _parse_coverage(data.get("coverage", {}))
    return Request(subject, coverage, derivation, deadline, nonce, route)


def request_digest(request_bytes: bytes) -> str:
    """The request digest (§4.2 item 1): SHA-256 of the request bytes **as
    received**, never of a re-serialized form, as lowercase hex."""
    return hashlib.sha256(request_bytes).hexdigest()


# --- resolution --------------------------------------------------------------


@dataclass(frozen=True)
class Anchor:
    """A coverage anchor the responder holds: a commitment (for example a
    checkpoint) over its log of ``size`` records, issued at ``issued_at``
    (RFC 3339 UTC), identified by ``digest``."""

    digest: str
    size: int
    issued_at: str


@dataclass(frozen=True)
class Resolution:
    """The resolution of a well-formed request: refuse with ``reason``, or
    serve under ``anchor`` (one the responder holds) or ``exchange_half`` (the
    requester's own exchange half, pinned by its digest, §3.2)."""

    reason: str | None = None
    anchor: Anchor | None = None
    exchange_half: str | None = None

    @property
    def anchor_digest(self) -> str | None:
        """The digest of the anchor served under, as the response identifies it."""
        return self.anchor.digest if self.anchor is not None else self.exchange_half


class Decline(Exception):
    """Raised by :meth:`EvidenceStore.artifact` to refuse instead of serving,
    for example ``policy_declined`` for a subject larger than the node serves.
    ``reason`` must be a registered token; :func:`answer` signs the refusal."""

    def __init__(self, reason: str, message: str = ""):
        if reason not in REFUSAL_REASONS:
            raise ValueError(f"{reason!r} is not a registered refusal reason")
        super().__init__(f"{reason}: {message}" if message else reason)
        self.reason = reason


class Signer(Protocol):
    """The node key that signs refusals."""

    key_id: str

    def sign(self, body: bytes) -> tuple[str, str]:
        """Return ``(sig_hex, key_id)`` for ``body``: an Ed25519 signature and the
        raw public key, both lowercase hex."""
        ...


class EvidenceStore(Protocol):
    """What :func:`resolve` and :func:`answer` read. Every lookup is exact: a
    store never matches by prefix, case folding or any other approximation."""

    def holds_record(self, digest: str) -> bool:
        """True when a record with exactly this digest is held."""
        ...

    def holds_correlation(self, correlation_id: str) -> bool:
        """True when any held record carries exactly this correlation identifier."""
        ...

    def cites_exchange(self, half_digest: str) -> bool:
        """True when any held record cites exactly this exchange half."""
        ...

    def positional_ordering(self) -> bool:
        """True when the coverage mechanism defines record positions (``range``)."""
        ...

    def anchors(self) -> Sequence[Anchor]:
        """The coverage anchors held."""
        ...

    def derivation_forms(self, derivation: str) -> Collection[str] | None:
        """For a supported derivation (a token or a definition digest), the
        subject forms it is supported for; ``None`` when it is not supported."""
        ...

    def artifact(self, subject: Subject, derivation: str | None, resolution: Resolution) -> Any:
        """The artifact for ``subject`` (and ``derivation``) under the resolved
        anchor, with its verification material: opaque to this module, and a
        function of these arguments and the store's contents only (§5). Raises
        :class:`Decline` to refuse instead."""
        ...

    def force_checkpoint(self, signer: Signer) -> None:
        """Issue a fresh commitment now. Called only when the request carries a
        deadline and the node passed ``allow_forced_checkpoint=True``."""
        ...


def _freshest(anchors: Iterable[Anchor], floor: int | str) -> Anchor | None:
    """Among the anchors meeting ``floor``, the one covering the largest log,
    then the latest issued (the last such on a tie), so the choice depends
    only on the anchors held, never on the caller."""
    best, best_key = None, None
    floor_time = parse_utc(floor) if isinstance(floor, str) else None
    for anchor in anchors:
        issued = parse_utc(anchor.issued_at)
        meets = anchor.size >= floor if floor_time is None else issued is not None and issued >= floor_time
        if not meets:
            continue
        key = (anchor.size, issued or (-(1 << 63), 0))
        if best_key is None or key >= best_key:
            best, best_key = anchor, key
    return best


def resolve(request: Request, store: EvidenceStore, *, uniform_policy_declined: bool = False) -> Resolution:
    """Resolve a well-formed ``request`` against ``store`` exactly (§3.1-§3.3, §4.2).

    The checks run in this order, each giving the most specific reason it can:

    1. the derivation: not supported at all is ``derivation_unsupported``;
       supported but not for this subject form is ``no_such_subject``;
    2. the subject: not held is ``no_such_subject``; a ``range`` under a
       mechanism with no positional ordering is ``coverage_unsatisfiable``;
    3. the coverage: an ``expected_pin`` must be a held anchor, or for an
       ``exchange`` subject the requester's own half; a ``min_freshness`` needs
       an anchor at least that large, or issued no earlier than that time; a
       ``range`` must end inside the anchor. Otherwise
       ``coverage_unsatisfiable``: never an artifact under weaker coverage.

    ``uniform_policy_declined`` is the responder posture of §4.2 and §12:
    answer ``policy_declined`` wherever ``no_such_subject`` would disclose
    whether a subject is held.
    """
    subject = request.subject
    not_held = Resolution(REASON_POLICY_DECLINED if uniform_policy_declined else REASON_NO_SUCH_SUBJECT)

    if request.derivation is not None:
        forms = store.derivation_forms(request.derivation)
        if forms is None:
            return Resolution(REASON_DERIVATION_UNSUPPORTED)
        if subject.form not in forms:
            return not_held

    if subject.form == "record":
        held = store.holds_record(subject.content)
    elif subject.form == "correlation":
        held = store.holds_correlation(subject.content)
    elif subject.form == "exchange":
        held = store.cites_exchange(subject.content)
    elif subject.form == "range":
        if not store.positional_ordering():
            return Resolution(REASON_COVERAGE_UNSATISFIABLE)
        held = True
    else:  # full_history, checkpoints
        held = True
    if not held:
        return not_held

    pin = request.coverage.expected_pin
    if pin is not None:
        if subject.form == "exchange" and subject.content == pin:
            return Resolution(exchange_half=pin)
        anchor = next((a for a in store.anchors() if a.digest == pin), None)
    else:
        anchor = _freshest(store.anchors(), request.coverage.min_freshness)
    if anchor is None:
        return Resolution(REASON_COVERAGE_UNSATISFIABLE)
    if subject.form == "range" and subject.content[1] >= anchor.size:
        return Resolution(REASON_COVERAGE_UNSATISFIABLE)
    return Resolution(anchor=anchor)


# --- the answer ----------------------------------------------------------------


@dataclass(frozen=True)
class Artifact:
    """The granting outcome (§4.1): ``body`` is what the store built for
    ``subject`` under the resolved anchor ``anchor`` (its digest)."""

    subject: Subject
    anchor: str
    body: Any
    derivation: str | None = None


def _json_model(value: Any) -> Any:
    """The JSON binding of the profile's data model: byte strings as unpadded
    base64url (profile §4)."""
    if isinstance(value, (bytes, bytearray)):
        return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")
    if isinstance(value, (list, tuple)):
        return [_json_model(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_model(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class Envelope:
    """The artifact response in the interop profile's form
    (``spec/interop-profile-v0.md`` §6.2, profile :data:`PROFILE`): the
    artifact octets and each item of verification material travel beside the
    signed members, which carry their digests. ``sig`` is Ed25519 by
    ``responder`` over the JCS of the signed members (:meth:`signing_body`).
    Build one with :func:`sign_envelope`."""

    request_digest: str
    subject: Subject
    anchor_digest: str
    artifact: bytes
    responder: str
    issued_at: str
    derivation: str | None = None
    #: Under ``min_freshness``: the size or time the anchor attains, in the
    #: type the request used.
    freshness: int | str | None = None
    #: ``(kind, octets)`` per item of verification material, in order.
    verification: tuple[tuple[str, bytes], ...] = ()
    profile: str = PROFILE
    sig: str = ""

    def signed_members(self) -> dict:
        """The members the signature covers (§6.2), as a JSON-model map."""
        anchor: dict[str, Any] = {"digest": self.anchor_digest}
        if self.freshness is not None:
            anchor["freshness"] = self.freshness
        out: dict[str, Any] = {
            "profile": self.profile,
            "request_digest": self.request_digest,
            "subject": self.subject.to_wire(),
            "anchor": anchor,
            "artifact_digest": hashlib.sha256(self.artifact).hexdigest(),
            "responder": self.responder,
            "issued_at": self.issued_at,
        }
        if self.derivation is not None:
            out["derivation"] = self.derivation
        if self.verification:
            out["verification"] = [
                {"kind": kind, "digest": hashlib.sha256(octets).hexdigest()} for kind, octets in self.verification
            ]
        return out

    def signing_body(self) -> bytes:
        """The bytes the signature covers: RFC 8785 of :meth:`signed_members`,
        whatever the frame's encoding (profile §5.1)."""
        return jcs(self.signed_members())

    def to_value(self) -> dict:
        """The whole envelope in the profile's data model (byte strings as
        ``bytes``)."""
        out = dict(self.signed_members(), sig=self.sig, artifact=bytes(self.artifact))
        if self.verification:
            out["verification_content"] = [bytes(octets) for _, octets in self.verification]
        return out

    def encode(self, binding: str = "json") -> bytes:
        """The reply octets in ``binding``: JCS JSON with byte strings as
        unpadded base64url, or core deterministic CBOR with byte strings."""
        if binding == "json":
            return jcs(_json_model(self.to_value()))
        if binding == "cbor":
            return _cbor.encode(self.to_value())
        raise ValueError(f"binding must be 'json' or 'cbor', not {binding!r}")


def sign_envelope(
    request_bytes: bytes,
    subject: Subject,
    anchor_digest: str,
    artifact: bytes,
    *,
    signer: Signer,
    issued_at: str,
    derivation: str | None = None,
    freshness: int | str | None = None,
    verification: Iterable[tuple[str, bytes]] = (),
) -> Envelope:
    """Build and sign the profile envelope (§6.2) for an artifact served under
    ``anchor_digest`` in answer to the request whose octets as received are
    ``request_bytes``. ``artifact`` is the canonical artifact's octets, the
    same for every requester (ER §5). Raises :class:`ValueError`, before
    anything is signed, for an envelope the profile does not allow: a subject
    or derivation a request could not carry, an ``anchor_digest`` that is not
    a digest, an empty ``artifact`` (§6.2), an ``issued_at`` not in the §5.2
    time form, or a ``freshness`` that is neither a size nor a §5.2 time."""
    try:
        _parse_subject(subject.to_wire())
        if derivation is not None:
            _parse_derivation(derivation)
    except RequestError as err:
        raise ValueError(f"not an envelope a request could ask for: {err}") from None
    if not is_digest(anchor_digest):
        raise ValueError("anchor_digest must be 64 lowercase hex")
    if not artifact:
        raise ValueError("artifact must not be empty (profile §6.2)")
    if not is_profile_time(issued_at):
        raise ValueError("issued_at must be YYYY-MM-DDTHH:MM:SSZ (profile §5.2)")
    if freshness is not None and not (_is_uint(freshness) or is_profile_time(freshness)):
        raise ValueError("freshness must be a size (0 to 2^53 - 1) or a YYYY-MM-DDTHH:MM:SSZ time")
    stub = Envelope(
        request_digest=request_digest(request_bytes),
        subject=subject,
        anchor_digest=anchor_digest,
        artifact=bytes(artifact),
        responder=signer.key_id,
        issued_at=issued_at,
        derivation=derivation,
        freshness=freshness,
        verification=tuple((kind, bytes(octets)) for kind, octets in verification),
    )
    sig, key_id = signer.sign(stub.signing_body())
    if key_id != stub.responder:
        raise ValueError("the signer signed under a key other than its key_id")
    return replace(stub, sig=sig)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def answer(
    request_bytes: bytes,
    *,
    store: EvidenceStore,
    signer: Signer,
    binding: str = "json",
    now: str | None = None,
    allow_forced_checkpoint: bool = False,
    uniform_policy_declined: bool = False,
) -> Artifact | Refusal:
    """Answer one evidence request from ``store``: an :class:`Artifact`, or a
    :class:`Refusal` signed by ``signer`` over the digest of ``request_bytes``
    as received. Never raises for any request bytes.

    ``now`` overrides the refusal's issuance time (for deterministic tests).
    ``allow_forced_checkpoint`` is the node's opt-in to writing in response to
    a read (see the module docstring); ``uniform_policy_declined`` is passed to
    :func:`resolve`.
    """
    digest = request_digest(request_bytes)
    issued_at = now or _now_iso()

    def refuse(reason: str) -> Refusal:
        return sign_refusal(digest, reason, signer=signer, issued_at=issued_at)

    try:
        request = parse_request(request_bytes, binding=binding)
    except RequestError as exc:
        return refuse(exc.reason)

    resolution = resolve(request, store, uniform_policy_declined=uniform_policy_declined)
    if (
        resolution.reason == REASON_COVERAGE_UNSATISFIABLE
        and request.coverage.min_freshness is not None
        and request.deadline is not None
        and allow_forced_checkpoint
    ):
        # min_freshness under a deadline licenses the work, and this node
        # opted in: commit now and resolve once more.
        store.force_checkpoint(signer)
        resolution = resolve(request, store, uniform_policy_declined=uniform_policy_declined)
    if resolution.reason is not None:
        return refuse(resolution.reason)

    try:
        body = store.artifact(request.subject, request.derivation, resolution)
    except Decline as exc:
        return refuse(exc.reason)
    return Artifact(request.subject, resolution.anchor_digest, body, request.derivation)


# --- the signed refusal -----------------------------------------------------------


def _signing_body(members: Mapping[str, Any]) -> bytes:
    return jcs({k: members[k] for k in SIGNED_MEMBERS if k in members})


@dataclass(frozen=True)
class Refusal:
    """A signed refusal (§4.2) in the vectors' profile (A7)."""

    request_digest: str
    reason: str
    issued_at: str
    key_id: str
    sig: str

    def signing_body(self) -> bytes:
        """The bytes the signature covers: RFC 8785 of ``issued_at``,
        ``reason`` and ``request_digest``. For text members that are ASCII, as
        every conforming refusal's are, this is the same bytes as sorted,
        compact JSON."""
        return _signing_body(self.to_dict())

    def to_dict(self) -> dict:
        """The refusal object in the JSON binding."""
        return {
            "request_digest": self.request_digest,
            "reason": self.reason,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "sig": self.sig,
        }

    def to_cbor(self) -> bytes:
        """The refusal map in the CBOR binding, in core deterministic encoding
        (§10): keys in the bytewise order of their encodings. The signature is
        still over the RFC 8785 body."""
        entries = []
        for key, value in self.to_dict().items():
            k, v = key.encode("utf-8"), value.encode("utf-8")
            entries.append((_cbor.encode_head(3, len(k)) + k, _cbor.encode_head(3, len(v)) + v))
        entries.sort()
        return _cbor.encode_head(5, len(entries)) + b"".join(k + v for k, v in entries)


def sign_refusal(request_digest: str, reason: str, *, signer: Signer, issued_at: str) -> Refusal:
    """Build and sign one :class:`Refusal`. Raises :class:`ValueError` unless
    ``reason`` is a registered token, ``request_digest`` a digest and
    ``issued_at`` an RFC 3339 UTC time: a responder never signs a
    non-conforming refusal."""
    if reason not in REFUSAL_REASONS:
        raise ValueError(f"{reason!r} is not a registered refusal reason")
    if not is_digest(request_digest):
        raise ValueError("request_digest must be 64 lowercase hex")
    if parse_utc(issued_at) is None:
        raise ValueError("issued_at must be an RFC 3339 UTC time")
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    return Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)


# The y coordinates (mod p) of the eight small-order points of edwards25519:
# the identity (1), order 2 (p - 1), order 4 (0) and order 8 (Y8, p - Y8).
# Either sign of x gives the same set.
_P25519 = (1 << 255) - 19
_Y8 = int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little")
_SMALL_ORDER_Y = frozenset({0, 1, _P25519 - 1, _Y8, _P25519 - _Y8})


def _small_order(key: bytes) -> bool:
    """True for a public key encoding a small-order point, canonically or not.
    Such a key "verifies" signatures over any message, so it is refused, as
    strict verification (RFC 8032 with a small-order check) does."""
    y = int.from_bytes(key, "little") & ((1 << 255) - 1)
    return y % _P25519 in _SMALL_ORDER_Y


def _ed25519_verifies(key_hex: Any, sig_hex: Any, body: bytes) -> bool:
    if not _is_hex_of_len(key_hex, 32) or not _is_hex_of_len(sig_hex, 64):
        return False
    if _small_order(bytes.fromhex(key_hex)):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), body)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_refusal_offline(refusal: Refusal) -> bool:
    """True when ``refusal.sig`` is an Ed25519 signature by the key whose raw
    public bytes are ``refusal.key_id`` over the refusal's signing body.
    Malformed input is a verification failure, never an exception.

    This is the signature alone, under the key the refusal names. To accept a
    refusal as a responder's answer to your request, also require that
    ``key_id`` is that responder's key, ``request_digest`` the digest of the
    bytes you sent, and :func:`check_refusal` conformant. Needs the
    ``cryptography`` package (the ``envelope`` extra); without it this raises
    :class:`ImportError` rather than report a refusal as unsigned.
    """
    try:
        return _ed25519_verifies(refusal.key_id, refusal.sig, refusal.signing_body())
    except (TypeError, ValueError, RecursionError):  # members that have no RFC 8785 form
        return False


@dataclass(frozen=True)
class RefusalCheck:
    """Three separate answers about a received refusal object (§4.2, A13):
    whether the signature verifies under the object's own ``key_id``, whether
    ``reason`` is exactly one registered token, and both of these plus every
    member §4.2 requires present and well formed. A valid signature over an
    unregistered reason is not a conforming refusal, and is still the
    responder's signed act."""

    signature_valid: bool
    reason_registered: bool
    conformant: bool


def check_refusal(obj: Any) -> RefusalCheck:
    """Check a refusal object in the JSON binding (a decoded map): its shape
    and self-consistency, not who signed it (see :func:`verify_refusal_offline`)."""
    if not isinstance(obj, Mapping):
        return RefusalCheck(False, False, False)
    try:
        signature_valid = _ed25519_verifies(obj.get("key_id"), obj.get("sig"), _signing_body(obj))
    except (TypeError, ValueError, RecursionError):
        signature_valid = False
    reason = obj.get("reason")
    reason_registered = isinstance(reason, str) and reason in REFUSAL_REASONS
    well_formed = is_digest(obj.get("request_digest")) and parse_utc(obj.get("issued_at")) is not None
    return RefusalCheck(signature_valid, reason_registered, signature_valid and reason_registered and well_formed)


def check_refusal_cbor(frame: bytes) -> RefusalCheck:
    """:func:`check_refusal` for a refusal frame in the CBOR binding."""
    try:
        obj = _decode_cbor(frame, request=False)
    except RequestError:
        return RefusalCheck(False, False, False)
    return check_refusal(obj)


# --- outcomes, invariance, retention -------------------------------------------------


def record_outcome(received: str, *, window_open: bool, artifact_verified: bool = False,
                   refusal: RefusalCheck | None = None) -> str:
    """The one state a requester records an interaction as (§4, §4.5).

    ``received`` is ``"artifact"``, ``"refusal"``, ``"nothing"``,
    ``"transport_error"`` or ``"subprotocol_not_offered"``; for a refusal,
    ``refusal`` is its :func:`check_refusal` result. A signed refusal is the
    responder's act and is never an absence, whatever the window:
    ``"refusal"`` when conforming, ``"refusal_nonconformant"`` when signed but
    not conforming (an unregistered reason, A13, or a required member missing
    or malformed). A refusal whose signature does not verify is not the
    responder's act (``"refusal_signature_invalid"``). Silence, a transport
    error or a peer not offering the subprotocol is never a refusal: it is
    ``"pending"`` while the waiting window is open (§4.3, A8) and
    ``"recorded_absence"`` once it closes.
    """
    if received == "artifact":
        return "artifact_verified" if artifact_verified else "artifact_verification_failed"
    if received == "refusal":
        if refusal is None or not refusal.signature_valid:
            return "refusal_signature_invalid"
        return "refusal" if refusal.conformant else "refusal_nonconformant"
    if received in ("nothing", "transport_error", "subprotocol_not_offered"):
        return "pending" if window_open else "recorded_absence"
    raise ValueError(f"unknown observation {received!r}")


def compare_observations(observations: Iterable[tuple[str, bytes]]) -> str:
    """Caller invariance (§5) over ``(resolved_anchor, artifact_bytes)`` pairs
    for one subject: ``"holds"`` when every artifact is byte-identical,
    ``"violated"`` when not, ``"not_comparable"`` when the anchors differ.
    Verification material may differ and is not compared (A12)."""
    pairs = list(observations)
    if len({anchor for anchor, _ in pairs}) > 1:
        return "not_comparable"
    return "holds" if len({bytes(artifact) for _, artifact in pairs}) <= 1 else "violated"


_ABOUT_THE_REQUEST = frozenset(
    {REASON_NOT_AUTHORIZED, REASON_COVERAGE_UNSATISFIABLE, REASON_DERIVATION_UNSUPPORTED, REASON_REQUEST_MALFORMED}
)


def classify_refusal(commitment: str, reason: str) -> str:
    """How a refusal with ``reason`` stands against a retention commitment (§9)
    that is ``"in_force"``, ``"lapsed"`` or ``"none"``.

    Inside ``until`` only the four reasons about the request or the
    responder's capability keep the promise (``"no_breach"``); any other is a
    ``"breach"`` (A9). After it, ``retention_expired`` is ``"correct"``,
    ``no_such_subject`` the ``"wrong_token"`` (a lapsed promise must not read
    as never held), and the rest ``"no_breach"`` (A10).
    """
    if commitment == "none":
        return "no_commitment"
    if commitment == "in_force":
        return "no_breach" if reason in _ABOUT_THE_REQUEST else "breach"
    if commitment == "lapsed":
        if reason == REASON_RETENTION_EXPIRED:
            return "correct"
        return "wrong_token" if reason == REASON_NO_SUCH_SUBJECT else "no_breach"
    raise ValueError(f"unknown commitment state {commitment!r}")


def classify_absence(commitment: str) -> str:
    """A recorded absence under a commitment in force is attributable to the
    committed party; otherwise it records only the attempt (§4.4, §9). Either
    way it stays a recorded absence, never a refusal."""
    return "attributable_absence" if commitment == "in_force" else "attempt_only"


def commitment_well_formed(commitment: Any) -> bool:
    """A retention commitment (§9): non-empty ``evidence_stream`` text, an
    ``until`` RFC 3339 UTC time, and a ``subject`` a digest or a position
    under a checkpoint identifies: ``record``, ``exchange`` or ``range``
    (A11)."""
    if not isinstance(commitment, Mapping):
        return False
    stream = commitment.get("evidence_stream")
    if not isinstance(stream, str) or not stream or parse_utc(commitment.get("until")) is None:
        return False
    try:
        subject = _parse_subject(commitment.get("subject"))
    except RequestError:
        return False
    return subject.form in ("record", "exchange", "range")
