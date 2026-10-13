# SPDX-License-Identifier: BSD-3-Clause
"""The evidence-request responder: parse a request, decide the answer, sign refusals.

``answer()`` turns one request map into exactly one answer: an
:class:`Artifact` or a signed :class:`Refusal`. It owns the responder's
decision logic only. Where the evidence comes from is the caller's
:class:`EvidenceStore`: the store resolves subjects to records, builds the
offline-verifiable bundles, and (if the node allows it) forces a checkpoint.
This module never invents an artifact format of its own.

**Wire shape and the draft.** The request map is a JSON object
``{subject, coverage?, derivation?, deadline?, nonce?, page?}``. This is the
shape the deployed responder speaks, which predates
``draft-mih-agent-evidence-request-00`` in three places: the subject forms,
whether coverage is required, and the coverage value shapes. How a subject
id matches a record is the store's: -00 requires an exact match, and a
store that also accepts a prefix differs from the draft there.
``vectors/evidence-request/DIFFS.md`` lists these differences against the
draft and the vectors that catch each one. The refusal reason tokens and the
refusal signature profile already match the draft.

**Subject kinds.** :data:`SUBJECT_KINDS` names four. ``record``, ``range``
and ``correlation`` share the draft's names and meanings. ``chain_segment``
(``{last: N}`` or ``{from_size, to_size}``) answers the question the draft's
``checkpoints`` form asks (commitments only, no records) under a different
name. There is no ``full_history`` or ``exchange`` subject kind.

Every well-formed request gets exactly one of three answers, never a bare,
unsigned absence:

  * an :class:`Artifact`: one or more offline-verifiable bundles;
  * a :class:`Refusal` with ``reason="request_malformed"`` or
    ``reason="derivation_unsupported"``: a decline about the request itself;
  * a :class:`Refusal` with ``reason="no_such_subject"`` or
    ``reason="coverage_unsatisfiable"``: this node holds nothing (yet) for
    the named subject at the requested coverage. The draft's status-mapping
    table groups these two as "evidence not found, or not yet committed".

``no_such_subject`` is the registry token for "I hold nothing for this
subject". It is not the draft's *recorded absence* outcome, which is never a
``reason`` or any other message field: absence is the requester's own record
that no answer arrived by a deadline. This module always answers and signs
what it sends, so it never produces an absence.

Every refusal is the same signed object, ``{request_digest, reason,
issued_at, key_id, sig}``. It verifies offline against the node's own key
(:func:`verify_refusal_offline`), so "I asked and it was not there" is
citable in a way an HTTP 404 is not.

**Caller invariance by construction.** The answer is a function of
``request_bytes`` and the store's contents only. There is no
requester-identity parameter. Two requesters sending byte-identical
``(subject, coverage, derivation, page)`` (their ``nonce`` may differ)
against an unchanged store get a byte-identical :class:`Artifact`. Only a
refusal's ``request_digest`` varies with the nonce.

**Caps and paging.** A ``range`` or ``correlation`` subject can name an
arbitrarily large selection. ``answer()`` never returns more than
:data:`MAX_PAGE_SIZE` bundles for one request, and uses
:data:`DEFAULT_PAGE_SIZE` when the request names no ``page.size``. When more
of the selection remains, the :class:`Artifact` carries ``next_page_token``,
which the requester echoes back as ``request.page.token``. Its absence means
the selection ended. A ``record`` or ``chain_segment`` subject never produces
more than one answer object, so ``page`` is accepted and ignored there.

**Correlation subjects.** ``{kind: "correlation", by, value}`` asks about a
correlator this node's own records carry, with ``by`` one of
:data:`CORRELATION_BY_VALUES`. Correlator fields are free-form extension data
inside a record, not a registered schema position, so matching walks the
record for the correlator's key names at any depth
(:func:`_entry_matches_correlation`). A ``counterparty`` correlation also
matches an adjudication whose verdict names that counterparty.

**Checkpoint writes are pull-only by default.** A ``min_freshness`` request
against a stale or uncovered subject makes ``answer()`` call
:meth:`EvidenceStore.force_checkpoint` (a write) only when both the request
carries a ``deadline`` and the node opted in with
``allow_forced_checkpoint=True``. The node-side opt-in defaults to ``False``.
"""
from __future__ import annotations

import hashlib
import json
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

__all__ = [
    "REASON_REQUEST_MALFORMED",
    "REASON_COVERAGE_UNSATISFIABLE",
    "REASON_NO_SUCH_SUBJECT",
    "REASON_DERIVATION_UNSUPPORTED",
    "REASON_NO_SUCH_RECORD",
    "REFUSAL_REASONS",
    "LEGACY_REFUSAL_REASON_ALIASES",
    "SUBJECT_KINDS",
    "CORRELATION_BY_VALUES",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "RequestMalformedError",
    "NotYetCovered",
    "EvidenceStore",
    "Signer",
    "RequestMap",
    "Artifact",
    "Refusal",
    "parse_request",
    "answer",
    "request_digest",
    "sign_refusal",
    "verify_refusal_offline",
    "normalize_refusal_reason",
]

#: Refusal-reason tokens from the registry
#: ``draft-mih-agent-evidence-request-00`` establishes. This responder never
#: checks requester authorization or retention undertakings, so it has no
#: occasion to emit ``not_authorized``, ``policy_declined``,
#: ``deadline_unmet`` or ``retention_expired``: emitting one without the
#: mechanism behind it would be fabrication.
REASON_REQUEST_MALFORMED = "request_malformed"
REASON_COVERAGE_UNSATISFIABLE = "coverage_unsatisfiable"
REASON_NO_SUCH_SUBJECT = "no_such_subject"
REASON_DERIVATION_UNSUPPORTED = "derivation_unsupported"
REFUSAL_REASONS = frozenset(
    {
        REASON_REQUEST_MALFORMED,
        REASON_COVERAGE_UNSATISFIABLE,
        REASON_NO_SUCH_SUBJECT,
        REASON_DERIVATION_UNSUPPORTED,
    }
)

#: Deprecated pre-registry spelling of ``no_such_subject``. ``answer()``
#: never emits it. Kept so a caller can still recognize a peer running a
#: pre-alignment responder; see :func:`normalize_refusal_reason`.
REASON_NO_SUCH_RECORD = "no_such_record"

#: Pre-registry reason spellings mapped to their current registry token.
#: Never consulted by :func:`answer`, which only emits
#: :data:`REFUSAL_REASONS` members.
LEGACY_REFUSAL_REASON_ALIASES: dict[str, str] = {REASON_NO_SUCH_RECORD: REASON_NO_SUCH_SUBJECT}

SUBJECT_KINDS = frozenset({"record", "range", "chain_segment", "correlation"})

#: A ``range``/``correlation`` answer never exceeds this many bundles absent
#: an explicit ``page.size``.
DEFAULT_PAGE_SIZE = 50

#: The hard ceiling on ``page.size``: a requester cannot ask past it.
MAX_PAGE_SIZE = 200

#: ``subject.by`` values a ``correlation`` subject accepts.
CORRELATION_BY_VALUES = frozenset({"nonce", "exchange_id", "counterparty", "deal_id"})

#: The record key name(s) that carry each correlator. More than one name
#: exists per correlator because correlators are free-form extension data,
#: and different producers have named the same concept differently.
_CORRELATION_KEY_ALIASES: dict[str, frozenset[str]] = {
    "nonce": frozenset({"nonce", "client_nonce"}),
    "exchange_id": frozenset({"exchange_id"}),
    "deal_id": frozenset({"deal_id"}),
    "counterparty": frozenset({"counterparty_ref"}),
}


class RequestMalformedError(RuntimeError):
    """A request map failed to parse. :func:`answer` turns it into a signed
    ``request_malformed`` refusal and never raises it."""


class NotYetCovered(Exception):
    """Raised by an :class:`EvidenceStore` when a record it holds is not yet
    covered by any checkpoint, or a chain segment it was asked for is not
    available. :func:`answer` turns it into ``coverage_unsatisfiable``."""


class Signer(Protocol):
    """The node key that signs refusals: the same identity the node's
    records are signed with."""

    key_id: str

    def sign(self, body: bytes) -> tuple[str, str]:
        """Return ``(sig_hex, key_id)`` for ``body``."""
        ...


class EvidenceStore(Protocol):
    """Where :func:`answer` gets evidence from.

    Bundles are opaque to this module except for ``to_dict()`` and a
    ``checkpoint`` with ``mmr_size``, ``root`` and ``timestamp`` (an RFC 3339
    UTC string), which the coverage checks read.
    """

    def holds(self, capsule_id: str) -> bool:
        """True when this store holds a record under ``capsule_id``."""
        ...

    def bundle(self, capsule_id: str) -> Any:
        """The offline-verifiable bundle for one held record. Raises
        :class:`NotYetCovered` when no checkpoint covers it yet."""
        ...

    def select_range(self, selector: str) -> list[str] | None:
        """Resolve a ``range`` selector to capsule ids in append order, or
        ``None`` when it selects nothing this store holds."""
        ...

    def records(self) -> list[dict]:
        """Every capsule record this store holds, in append order. Read by
        ``correlation`` subjects."""
        ...

    def chain_segment(self, subject: dict, *, self_owner_id: str) -> Any | None:
        """The checkpoint-chain answer for a ``chain_segment`` subject, or
        ``None`` when the store holds nothing at all. Raises
        :class:`NotYetCovered` when the requested segment is not available."""
        ...

    def force_checkpoint(self, signer: Signer) -> None:
        """Checkpoint the store now. Called only when the request carries a
        deadline and the node passed ``allow_forced_checkpoint=True``."""
        ...


@dataclass(frozen=True)
class RequestMap:
    """The parsed request; see the module docstring for the wire shape.

    ``has_deadline`` records the deadline's presence, not its value: its
    presence is one of the two conditions :func:`answer` requires before it
    forces a checkpoint. How long the requester waits is a transport concern.

    ``page`` is ``{token?: str, size?: int}``. Only ``range`` and
    ``correlation`` subjects read it.
    """

    subject: dict
    coverage: dict
    derivation: str | None
    has_deadline: bool
    nonce: str | None
    page: dict


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise RequestMalformedError(message)


def _is_size_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _valid_chain_segment_subject(subject: dict) -> bool:
    """``{last: <positive int>}`` XOR ``{from_size, to_size}`` (each a
    non-negative int, ``to_size >= from_size``): never both, never neither.
    A bad shape is caught here as ``request_malformed`` rather than inside
    the store."""
    has_last = "last" in subject
    has_range = "from_size" in subject or "to_size" in subject
    if has_last and has_range:
        return False
    if has_last:
        last = subject["last"]
        return isinstance(last, int) and not isinstance(last, bool) and last > 0
    if has_range:
        return (
            "from_size" in subject
            and "to_size" in subject
            and _is_size_int(subject["from_size"])
            and _is_size_int(subject["to_size"])
            and subject["to_size"] >= subject["from_size"]
        )
    return False


def parse_request(request_bytes: bytes) -> RequestMap:
    """Parse ``request_bytes`` into a :class:`RequestMap`.

    Raises :class:`RequestMalformedError` for anything that is not a JSON
    object shaped like ``{subject, coverage?, derivation?, deadline?,
    nonce?, page?}``. Unknown fields are ignored.
    """
    try:
        data = json.loads(request_bytes)
    except Exception as exc:  # any parse failure is malformed
        raise RequestMalformedError(f"request is not valid JSON: {exc}") from exc
    _require(isinstance(data, dict), "request must be a JSON object")

    subject = data.get("subject")
    _require(isinstance(subject, dict), "subject is required and must be an object")
    kind = subject.get("kind")
    _require(isinstance(kind, str) and kind in SUBJECT_KINDS, f"subject.kind must be one of {sorted(SUBJECT_KINDS)}")
    if kind == "record":
        _require(isinstance(subject.get("capsule_id"), str) and subject["capsule_id"], "subject.kind='record' requires a non-empty subject.capsule_id")
    elif kind == "range":
        _require(isinstance(subject.get("selector"), str) and subject["selector"], "subject.kind='range' requires a non-empty subject.selector")
    elif kind == "correlation":
        by = subject.get("by")
        _require(
            isinstance(by, str) and by in CORRELATION_BY_VALUES,
            f"subject.kind='correlation' requires subject.by to be one of {sorted(CORRELATION_BY_VALUES)}",
        )
        _require(isinstance(subject.get("value"), str) and subject["value"], "subject.kind='correlation' requires a non-empty subject.value")
    else:  # "chain_segment"
        _require(
            _valid_chain_segment_subject(subject),
            "subject.kind='chain_segment' requires either {last: <positive int>} or "
            "{from_size: <non-negative int>, to_size: <int >= from_size>} — never both",
        )

    coverage = data.get("coverage") or {}
    _require(isinstance(coverage, dict), "coverage must be an object")
    if "expected_pin" in coverage:
        pin = coverage["expected_pin"]
        _require(
            isinstance(pin, dict) and isinstance(pin.get("root"), str) and isinstance(pin.get("mmr_size"), int),
            "coverage.expected_pin requires root (string) and mmr_size (int)",
        )
    if "min_freshness" in coverage:
        mf = coverage["min_freshness"]
        _require(
            isinstance(mf, dict) and isinstance(mf.get("max_age_seconds"), (int, float)) and not isinstance(mf.get("max_age_seconds"), bool),
            "coverage.min_freshness requires max_age_seconds (a number)",
        )

    derivation = data.get("derivation")
    _require(derivation is None or isinstance(derivation, str), "derivation must be a string when present")

    nonce = data.get("nonce")
    _require(nonce is None or isinstance(nonce, str), "nonce must be a string when present")

    page = data.get("page") or {}
    _require(isinstance(page, dict), "page must be an object")
    if "token" in page:
        token = page["token"]
        _require(
            isinstance(token, str) and token.isdigit(),
            "page.token must be a token this responder issued as a prior answer's next_page_token",
        )
    if "size" in page:
        size = page["size"]
        _require(
            isinstance(size, int) and not isinstance(size, bool) and size > 0,
            "page.size must be a positive int",
        )

    return RequestMap(
        subject=subject,
        coverage=coverage,
        derivation=derivation,
        has_deadline=data.get("deadline") is not None,
        nonce=nonce,
        page=page,
    )


@dataclass(frozen=True)
class Artifact:
    """One well-formed answer: one bundle for a ``record`` subject, one per
    selected or matched record for ``range`` and ``correlation``, one chain
    segment for ``chain_segment``. Digests only: a stranger and a trusted
    counterparty receive the same object for the same request."""

    v: int
    subject_kind: str
    bundles: tuple[Any, ...]
    next_page_token: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "v": self.v,
            "subject_kind": self.subject_kind,
            "bundles": [b.to_dict() for b in self.bundles],
        }
        if self.next_page_token is not None:
            d["next_page_token"] = self.next_page_token
        return d


@dataclass(frozen=True)
class Refusal:
    """A signed refusal that verifies offline. ``no_such_subject`` and
    ``coverage_unsatisfiable`` say "I hold nothing (yet) for this subject at
    this coverage"; ``request_malformed`` and ``derivation_unsupported`` are
    declines about the request itself. Same object either way."""

    request_digest: str
    reason: str
    issued_at: str
    key_id: str
    sig: str

    def signing_body(self) -> bytes:
        """The bytes the signature covers: the three signed fields as JSON
        with sorted keys and no whitespace, so an offline verifier rebuilds
        the body from the object alone."""
        return json.dumps(
            {"request_digest": self.request_digest, "reason": self.reason, "issued_at": self.issued_at},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def to_dict(self) -> dict:
        return {
            "request_digest": self.request_digest,
            "reason": self.reason,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "sig": self.sig,
        }


def verify_refusal_offline(refusal: Refusal) -> bool:
    """Check offline that ``refusal.sig`` is an Ed25519 signature by the key
    whose raw public bytes are ``refusal.key_id`` (hex) over this refusal's
    own signing body. Never raises: malformed input is a verification
    failure. Needs the ``cryptography`` package (pulled in by the
    ``envelope`` extra)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(refusal.key_id))
        public_key.verify(bytes.fromhex(refusal.sig), refusal.signing_body())
        return True
    except Exception:  # a pure verifier never raises
        return False


def normalize_refusal_reason(reason: str) -> str:
    """Translate a pre-registry refusal-reason spelling to its current
    registry token; anything else passes through unchanged.

    For a caller reading ``reason`` off a peer's :class:`Refusal` during a
    mixed-version rollout. Apply it after :func:`verify_refusal_offline`,
    never before: the signature covers the reason as sent.

    Emits a :class:`DeprecationWarning` when it translates.
    """
    current = LEGACY_REFUSAL_REASON_ALIASES.get(reason)
    if current is None:
        return reason
    warnings.warn(
        f"refusal reason {reason!r} is the pre-registry spelling of {current!r} "
        "(draft-mih-agent-evidence-request-00) -- update the caller to compare "
        "against the new token; this alias is removed after one release",
        DeprecationWarning,
        stacklevel=2,
    )
    return current


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def request_digest(request_bytes: bytes) -> str:
    """The ``request_digest`` a refusal carries: SHA-256 of the request
    bytes as received, lowercase hex."""
    return hashlib.sha256(request_bytes).hexdigest()


def sign_refusal(request_digest: str, reason: str, *, signer: Signer, issued_at: str) -> Refusal:
    """Build and sign one :class:`Refusal` with ``signer``."""
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    return Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)


def _iter_values_by_key(obj: Any, keys: frozenset[str]) -> Iterator[str]:
    """Yield every string value found under a key in ``keys``, at any depth
    of a JSON-decoded record."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str):
                yield v
            yield from _iter_values_by_key(v, keys)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_values_by_key(item, keys)


def _iter_dicts_by_key(obj: Any, key: str) -> Iterator[dict]:
    """Like :func:`_iter_values_by_key`, but yields dict values found under
    ``key`` at any depth: used to find an ``adjudication`` block wherever a
    producer nested it."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, dict):
                yield v
            yield from _iter_dicts_by_key(v, key)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_dicts_by_key(item, key)


def _entry_names_counterparty_in_adjudication(entry: dict, value: str) -> bool:
    """A ``counterparty`` correlation also matches an adjudication whose
    verdict names ``value`` as the divergent owner
    (``"contradicted:<owner_id>"``). ``corroborated`` and ``inconclusive``
    verdicts name no owner."""
    return any(
        adjudication.get("verdict") == f"contradicted:{value}"
        for adjudication in _iter_dicts_by_key(entry, "adjudication")
    )


def _entry_matches_correlation(entry: dict, by: str, value: str) -> bool:
    if by == "counterparty" and _entry_names_counterparty_in_adjudication(entry, value):
        return True
    return any(v == value for v in _iter_values_by_key(entry, _CORRELATION_KEY_ALIASES[by]))


def _correlation_capsule_ids(store: EvidenceStore, by: str, value: str) -> list[str] | None:
    """Every capsule id in ``store`` carrying ``value`` under ``by``'s
    correlator key(s), in append order so paging is stable, or ``None`` when
    nothing matches."""
    matched = [r["capsule_id"] for r in store.records() if _entry_matches_correlation(r, by, value)]
    return matched or None


def _page_slice(capsule_ids: list[str], page: dict) -> tuple[list[str], str | None]:
    """Slice the resolved ``capsule_ids`` to the requested page.
    ``page.token`` is the offset the previous answer stopped at;
    ``page.size`` overrides :data:`DEFAULT_PAGE_SIZE`, capped at
    :data:`MAX_PAGE_SIZE` either way. Returns ``(this_page_ids,
    next_page_token)``; the token is ``None`` exactly when this page reaches
    the end."""
    offset = int(page["token"]) if "token" in page else 0
    size = min(page.get("size", DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE)
    offset = min(offset, len(capsule_ids))
    page_ids = capsule_ids[offset : offset + size]
    next_offset = offset + size
    next_token = str(next_offset) if next_offset < len(capsule_ids) else None
    return page_ids, next_token


def _build_bundles(
    store: EvidenceStore, req: RequestMap, *, self_owner_id: str
) -> tuple[tuple[Any, ...] | None, str | None, str | None]:
    """Build the bundles this request's subject names.

    Returns ``(bundles, None, next_page_token)`` on success, or ``(None,
    reason, None)``: ``no_such_subject`` when the subject names nothing this
    store holds, ``coverage_unsatisfiable`` when it holds the subject but no
    checkpoint covers it yet.
    """
    kind = req.subject["kind"]
    if kind == "chain_segment":
        try:
            segment = store.chain_segment(req.subject, self_owner_id=self_owner_id)
        except NotYetCovered:
            return None, REASON_COVERAGE_UNSATISFIABLE, None
        if segment is None:
            return None, REASON_NO_SUCH_SUBJECT, None
        return (segment,), None, None

    next_page_token = None
    if kind == "record":
        capsule_ids = [req.subject["capsule_id"]]
    elif kind == "range":
        resolved = store.select_range(req.subject["selector"])
        if not resolved:
            return None, REASON_NO_SUCH_SUBJECT, None
        capsule_ids, next_page_token = _page_slice(resolved, req.page)
    else:  # "correlation"
        resolved = _correlation_capsule_ids(store, req.subject["by"], req.subject["value"])
        if not resolved:
            return None, REASON_NO_SUCH_SUBJECT, None
        capsule_ids, next_page_token = _page_slice(resolved, req.page)

    if not all(store.holds(cid) for cid in capsule_ids):
        return None, REASON_NO_SUCH_SUBJECT, None

    try:
        bundles = tuple(store.bundle(cid) for cid in capsule_ids)
    except NotYetCovered:
        return None, REASON_COVERAGE_UNSATISFIABLE, None
    return bundles, None, next_page_token


def _checkpoint_age_seconds(timestamp: str, issued_at: str) -> float:
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    now = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    return (now - ts).total_seconds()


def answer(
    request_bytes: bytes,
    *,
    store: EvidenceStore,
    signer: Signer,
    now: str | None = None,
    allow_forced_checkpoint: bool = False,
) -> Artifact | Refusal:
    """Answer one evidence request from ``store``.

    A request naming a ``derivation`` is refused ``derivation_unsupported``:
    this responder supports none itself, and a caller that supports one
    intercepts the request before calling ``answer()``. Otherwise the
    subject resolves through ``store`` and the coverage constraints are
    checked against the bundles' checkpoints. Returns exactly one of:

      * :class:`Artifact`: one or more offline-verifiable bundles or chain
        segments;
      * :class:`Refusal`: signed by ``signer``, one of
        :data:`REFUSAL_REASONS`.

    ``now`` overrides the wall clock (for deterministic tests).
    ``allow_forced_checkpoint`` is the node's own opt-in to writing in
    response to a read; see the module docstring.
    """
    digest = request_digest(request_bytes)
    issued_at = now or _now_iso()

    def refuse(reason: str) -> Refusal:
        return sign_refusal(digest, reason, signer=signer, issued_at=issued_at)

    try:
        req = parse_request(request_bytes)
    except RequestMalformedError:
        return refuse(REASON_REQUEST_MALFORMED)

    if req.derivation is not None:
        # Any derivation reaching here is one this responder cannot honor:
        # refused, never silently served as a plain bundle.
        return refuse(REASON_DERIVATION_UNSUPPORTED)

    bundles, reason, next_page_token = _build_bundles(store, req, self_owner_id=signer.key_id)

    min_freshness = req.coverage.get("min_freshness")
    may_force_checkpoint = req.has_deadline and allow_forced_checkpoint
    if bundles is None and reason == REASON_COVERAGE_UNSATISFIABLE and min_freshness and may_force_checkpoint:
        # min_freshness under a deadline licenses the work, and this node
        # opted in: checkpoint now and retry once.
        store.force_checkpoint(signer)
        bundles, reason, next_page_token = _build_bundles(store, req, self_owner_id=signer.key_id)

    if bundles is None:
        return refuse(reason)

    expected_pin = req.coverage.get("expected_pin")
    if expected_pin is not None:
        pin_matches = all(
            b.checkpoint.mmr_size == expected_pin["mmr_size"] and b.checkpoint.root == expected_pin["root"]
            for b in bundles
        )
        if not pin_matches:
            # The pinned checkpoint does not (or no longer) cover this
            # subject: refuse rather than serve under a different anchor.
            return refuse(REASON_COVERAGE_UNSATISFIABLE)
    elif min_freshness is not None:
        max_age = min_freshness["max_age_seconds"]
        stale = any(_checkpoint_age_seconds(b.checkpoint.timestamp, issued_at) > max_age for b in bundles)
        if stale:
            if may_force_checkpoint:
                store.force_checkpoint(signer)
                bundles, reason, next_page_token = _build_bundles(store, req, self_owner_id=signer.key_id)
                if bundles is None:
                    return refuse(reason)
                stale = any(_checkpoint_age_seconds(b.checkpoint.timestamp, issued_at) > max_age for b in bundles)
            if stale:
                return refuse(REASON_COVERAGE_UNSATISFIABLE)

    return Artifact(v=1, subject_kind=req.subject["kind"], bundles=bundles, next_page_token=next_page_token)
