# SPDX-License-Identifier: BSD-3-Clause
"""The ``composed/v1`` Evidence Bundle extension, verified.

A port of ``go/bundle/composed.go`` and ``go/bundle/composed_binding.go``
(draft-mih-zhang-agent-disclosure-bundle-02, "The composed/v1 Extension"). The
block's own result, each member's, composition closure, each join's declared
and derived state and what a derived agreement is worth are reported with the
same tokens as the Go reference.

The ``controller_binding`` join basis reads its binding record through the one
binding verifier, :mod:`agent_action_capsule.controller_binding`, at both root
records' timestamps. Bundle -02's own rules sit on top of it and nowhere else
(:func:`_binding_report`): an empty ``nonce`` is malformed, ``ed25519`` is the
one key type, and a ``sig`` under ed25519 keys is a ``sig-hex``.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

from . import controller_binding as cb
from .canonical import FloatInDigestError, UnsafeIntegerError, jcs, json_digest
from .evidence_request import parse_utc

COMPOSED_KIND = "composed/v1"

REFUSAL_SIGNATURE_VERIFIED = "verified"
REFUSAL_SIGNATURE_INVALID = "invalid"
REFUSAL_SIGNATURE_UNVERIFIED = "signature_unverified"

_LABEL = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_RECORD_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")

_OUTCOMES = {"artifact": "bundle", "refusal": "refusal", "absence": "absence"}
_JOIN_BASES = frozenset(
    {"pre_agreed_identifier", "shared_artifact_digest", "issued_receipt", "same_interval", "controller_binding"}
)
_JOIN_STATES = frozenset({"agree", "mismatch", "unjoined", "one_sided"})

_DIGEST_ERRORS = (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError)

#: Checks a carried signed refusal (or a response envelope) under the
#: deployment's signature profile and returns one of the ``REFUSAL_SIGNATURE_*``
#: states. The neutral core ships no profile: without a verifier every refusal
#: is signature-unverified, which is neither failed nor absent.
SignatureVerifier = Callable[[Mapping[str, Any]], str]


@dataclass
class ComposedOptions:
    """What a composed/v1 verification takes beside the Bundle."""

    refusal_signature: SignatureVerifier | None = None
    response_signature: SignatureVerifier | None = None
    #: Binding records delivered beside the Bundle, and the revocation
    #: statements, that a controller_binding join is derived from (-02,
    #: "Controller Binding Records"). A join whose record was not delivered is
    #: not derivable.
    controller_bindings: Sequence[Mapping[str, Any]] = ()
    binding_revocations: Sequence[Mapping[str, Any]] = ()


@dataclass
class ComposedDigestResult:
    declared: str
    recomputed: str
    matches: bool


@dataclass
class ComposedMemberResult:
    """One member: its outcome, whether its body is carried or declared
    missing, whether the body reproduces its digest and, for a carried
    artifact, the member Evidence Bundle's own verification. The member's
    claims are its own; they are never merged into another member's."""

    id: str
    observer: str
    outcome: str
    #: ``carried``, ``declared_missing`` or ``absent``.
    body: str = ""
    #: ``reproduced``, ``mismatch`` or ``not_shown``.
    digest: str = "not_shown"
    findings: list = field(default_factory=list)
    bundle: Any = None
    refusal_signature: str = ""
    response_signature: str = ""


@dataclass
class CompositionClosureResult:
    status: str
    findings: list
    missing: list


@dataclass
class JoinValue:
    member: str
    resolved: bool
    value: Any


@dataclass
class JoinDifference:
    pointer: str
    values: list


@dataclass
class ComposedJoinResult:
    members: tuple[str, str]
    basis: str
    declared: str
    #: ``""`` when the state is not derivable.
    derived: str = ""
    #: ``derived_matches``, ``join_state_mismatch`` or ``not_derivable``.
    result: str = ""
    differences: list = field(default_factory=list)


@dataclass
class CorroborationResult:
    members: tuple[str, str]
    #: ``corroborating``, ``redundant`` or ``not_applicable``.
    result: str = ""
    reason: str = ""
    reasons: list = field(default_factory=list)
    report: str = ""
    qualifier: str = ""


@dataclass
class ComposedResult:
    """The verification of one composed/v1 block. ``status`` is ``fail`` when
    the block is malformed, the composed digest does not recompute, a member
    body fails its checks, composition closure fails or a declared join state
    does not match its derivation; ``withheld`` when nothing failed but
    something is not shown; otherwise ``pass``."""

    status: str
    findings: list = field(default_factory=list)
    malformed: bool = False
    composed_digest: ComposedDigestResult | None = None
    members: list = field(default_factory=list)
    composition_closure: CompositionClosureResult | None = None
    joins: list = field(default_factory=list)
    corroboration: list = field(default_factory=list)


@dataclass
class _Member:
    id: str = ""
    observer: str = ""
    request_digest: str = ""
    outcome: str = ""
    digest: str = ""
    body: dict | None = None
    response: dict | None = None


@dataclass
class _Observer:
    id: str
    role: str
    custody: str


@dataclass
class _Join:
    members: tuple[str, str] = ("", "")
    basis: str = ""
    state: str = ""
    pointer: str | None = None
    identifier: str | None = None
    compare: list = field(default_factory=list)
    compare_carried: bool = False


@dataclass
class _Block:
    members: list = field(default_factory=list)
    observers: list = field(default_factory=list)
    joins: list = field(default_factory=list)
    not_requested: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    digest: str = ""


# --- the block ---------------------------------------------------------------


def verify_composed(raw: Any, opts: ComposedOptions | None = None) -> ComposedResult:
    """Verify a composed/v1 block as carried in a Bundle's extensions. Carried
    member bundles are verified recursively with ``opts``."""
    opts = opts or ComposedOptions()
    block, reason = _parse_composed(raw)
    if reason:
        return ComposedResult("fail", [f"composed_block_malformed:{reason}"], malformed=True)
    result = ComposedResult("")
    failed: list = []
    withheld: list = []

    recomputed = ""
    try:
        recomputed = composed_digest(raw)
    except _Malformed:
        pass
    result.composed_digest = ComposedDigestResult(block.digest, recomputed, recomputed == block.digest)
    if not result.composed_digest.matches:
        failed.append("composed_digest_mismatch")

    missing: dict = {}
    declared = {m.id for m in block.members}
    closure_findings: list = []
    for member_id in block.missing:
        if member_id in missing:
            closure_findings.append(f"missing_duplicate:{member_id}")
        missing[member_id] = True
        if member_id not in declared:
            closure_findings.append(f"missing_names_undeclared_member:{member_id}")

    by_id: dict = {}
    for m in block.members:
        by_id[m.id] = m
        member, member_closure, member_failed, member_withheld = _verify_member(m, missing.get(m.id, False), opts)
        result.members.append(member)
        closure_findings += member_closure
        failed += member_failed
        withheld += member_withheld

    missing_ids = sorted(set(block.missing))
    if closure_findings:
        closure = CompositionClosureResult("fail", closure_findings, missing_ids)
        failed.append("composition_closure_fail")
    elif block.missing:
        closure = CompositionClosureResult("withheld", ["declared_incomplete"], missing_ids)
        withheld.append("declared_incomplete")
    else:
        closure = CompositionClosureResult("pass", [], missing_ids)
    result.composition_closure = closure

    observers = {o.id: o for o in block.observers}
    for j in block.joins:
        join_result = _derive_join(j, by_id, missing, opts)
        result.joins.append(join_result)
        pair = f"{j.members[0]},{j.members[1]}"
        if join_result.result == "join_state_mismatch":
            failed.append(f"join_state_mismatch:{pair}")
        elif join_result.result == "not_derivable":
            withheld.append(f"join_not_derivable:{pair}")
        result.corroboration.append(_corroboration(j, join_result.derived, by_id, observers))

    if failed:
        result.status, result.findings = "fail", failed + withheld
    elif withheld:
        result.status, result.findings = "withheld", withheld
    else:
        result.status = "pass"
    return result


def _verify_member(m: _Member, declared_missing: bool, opts: ComposedOptions):
    from .bundle import bundle_digest, verify_bundle

    out = ComposedMemberResult(m.id, m.observer, m.outcome)
    closure: list = []
    failed: list = []
    withheld: list = []
    if declared_missing and m.body is not None:
        out.body = "carried"
        closure.append(f"missing_member_carries_body:{m.id}")
    elif declared_missing:
        out.body = "declared_missing"
        return out, [], [], []
    elif m.body is None:
        out.body = "absent"
        out.findings.append("member_body_absent")
        return out, [f"member_body_absent:{m.id}"], [], []
    else:
        out.body = "carried"

    computed = ""
    if m.outcome == "artifact":
        try:
            computed = bundle_digest(m.body)
        except _DIGEST_ERRORS:
            computed = ""
        out.bundle = verify_bundle(m.body, composed_options=opts)
        # A carried response binds the artifact to the request it answered:
        # the request digest it signs is the member's, and the artifact digest
        # it signs is the member's bundle digest.
        if m.response is not None:
            if m.response.get("request_digest") != m.request_digest:
                out.findings.append("response_request_digest_mismatch")
                failed.append(f"member_response_request_digest_mismatch:{m.id}")
            if m.response.get("artifact_digest") != m.digest:
                out.findings.append("response_artifact_digest_mismatch")
                failed.append(f"member_response_artifact_digest_mismatch:{m.id}")
            out.response_signature = _signature_state(opts.response_signature, m.response)
            if out.response_signature == REFUSAL_SIGNATURE_INVALID:
                out.findings.append("response_signature_invalid")
                failed.append(f"response_signature_invalid:{m.id}")
            elif out.response_signature == REFUSAL_SIGNATURE_UNVERIFIED:
                withheld.append(f"response_signature_unverified:{m.id}")
    else:
        try:
            computed = json_digest(m.body)
        except _DIGEST_ERRORS:
            computed = ""
        if m.body.get("request_digest") != m.request_digest:
            out.findings.append("request_digest_mismatch")
            failed.append(f"member_request_digest_mismatch:{m.id}")
    if computed and computed == m.digest:
        out.digest = "reproduced"
    else:
        out.digest = "mismatch"
        out.findings.append("member_digest_mismatch")
        closure.append(f"member_digest_mismatch:{m.id}")
    if m.outcome == "refusal":
        out.refusal_signature = _signature_state(opts.refusal_signature, m.body)
        if out.refusal_signature == REFUSAL_SIGNATURE_INVALID:
            out.findings.append("refusal_signature_invalid")
            failed.append(f"refusal_signature_invalid:{m.id}")
        elif out.refusal_signature == REFUSAL_SIGNATURE_UNVERIFIED:
            withheld.append(f"refusal_signature_unverified:{m.id}")
    return out, closure, failed, withheld


def _signature_state(verifier: SignatureVerifier | None, value: Mapping[str, Any]) -> str:
    if verifier is not None:
        state = verifier(value)
        if state in (REFUSAL_SIGNATURE_VERIFIED, REFUSAL_SIGNATURE_INVALID):
            return state
    return REFUSAL_SIGNATURE_UNVERIFIED


def _root_record(m: _Member) -> dict | None:
    """The carried member bundle's root record, or ``None``."""
    if m.body is None:
        return None
    root = m.body.get("root")
    if not isinstance(root, str):
        return None
    records = m.body.get("records")
    for record in records if isinstance(records, list) else ():
        if isinstance(record, dict) and record.get("capsule_id") == root:
            return record
    return None


def _derive_join(j: _Join, by_id: dict, missing: dict, opts: ComposedOptions) -> ComposedJoinResult:
    out = ComposedJoinResult(j.members, j.basis, j.state)
    out.derived, out.differences = _derived_state(j, by_id, missing, opts)
    if out.derived == "":
        out.result = "not_derivable"
    elif out.derived == j.state:
        out.result = "derived_matches"
    else:
        out.result = "join_state_mismatch"
    return out


def _derived_state(j: _Join, by_id: dict, missing: dict, opts: ComposedOptions):
    from .bundle import is_empty_history

    a, b = by_id[j.members[0]], by_id[j.members[1]]
    # An artifact member counts as having records unless its carried Bundle is
    # an empty-history Bundle, which shows no history.
    with_records: list = []
    empty: list = []
    for m in (a, b):
        if m.outcome != "artifact":
            continue
        if not missing.get(m.id) and m.body is not None and is_empty_history(m.body):
            empty.append(m)
        else:
            with_records.append(m)
    if not with_records:
        return "unjoined", []
    if len(with_records) == 1:
        if not empty or j.basis != "controller_binding":
            return "one_sided", []
        # controller_binding still derives against an empty-history member,
        # from the key that signed its checkpoint at that checkpoint's time.
        full = with_records[0]
        if missing.get(full.id) or j.pointer is None:
            return "", []
        record = _root_record(full)
        side = _checkpoint_side(empty[0].body)
        if record is None or side is None:
            return "", []
        linked, derivable = _controller_binding_link(j, _record_side(record, j.pointer), side, opts)
        if not derivable:
            return "", []
        return ("one_sided" if linked else "unjoined"), []
    if missing.get(a.id) or missing.get(b.id):
        return "", []
    ra, rb = _root_record(a), _root_record(b)
    if ra is None or rb is None:
        return "", []
    if j.basis == "pre_agreed_identifier":
        linked = (
            j.pointer is not None
            and j.identifier is not None
            and _identifier_matches(ra, j.pointer, j.identifier)
            and _identifier_matches(rb, j.pointer, j.identifier)
        )
    elif j.basis == "shared_artifact_digest":
        linked = False
        if j.pointer is not None:
            okay_a, va = _resolve_pointer(ra, j.pointer)
            okay_b, vb = _resolve_pointer(rb, j.pointer)
            linked = okay_a and okay_b and isinstance(va, str) and isinstance(vb, str) and va == vb
    elif j.basis == "controller_binding":
        if j.pointer is None:
            return "", []
        linked, derivable = _controller_binding_link(j, _record_side(ra, j.pointer), _record_side(rb, j.pointer), opts)
        if not derivable:
            return "", []
    else:
        return "", []
    if not linked:
        return "unjoined", []
    differences = []
    for pointer in j.compare:
        okay_a, va = _resolve_pointer(ra, pointer)
        okay_b, vb = _resolve_pointer(rb, pointer)
        if okay_a and okay_b:
            try:
                if jcs(va) == jcs(vb):
                    continue
            except _DIGEST_ERRORS:
                pass
        differences.append(
            JoinDifference(pointer, [JoinValue(a.id, okay_a, va), JoinValue(b.id, okay_b, vb)])
        )
    if differences:
        return "mismatch", differences
    return "agree", []


def _identifier_matches(record: Mapping[str, Any], pointer: str, digest: str) -> bool:
    okay, value = _resolve_pointer(record, pointer)
    if not okay or not isinstance(value, str):
        return False
    return hashlib.sha256(value.encode("utf-8")).hexdigest() == digest


def _corroboration(j: _Join, derived: str, by_id: dict, observers: dict) -> CorroborationResult:
    out = CorroborationResult(j.members)
    if derived != "agree":
        out.result = "not_applicable"
        return out
    a, b = by_id[j.members[0]], by_id[j.members[1]]
    if a.observer == b.observer:
        out.reasons.append("same_observer")
    if observers[a.observer].custody == observers[b.observer].custody:
        out.reasons.append("same_custody_domain")
    key_a = (_root_record(a) or {}).get("key_id")
    key_b = (_root_record(b) or {}).get("key_id")
    if isinstance(key_a, str) and isinstance(key_b, str) and key_a == key_b:
        out.reasons.append("same_key_id")
    # A controller_binding agreement is the bound keys' holders agreeing:
    # their keys are not independent issuers (bundle -02).
    if j.basis == "controller_binding":
        out.reasons.append("controller_binding")
    if out.reasons:
        out.result = "redundant"
        out.reason = out.reasons[0]
        out.report = "redundant, not corroborating"
        return out
    out.result = "corroborating"
    out.qualifier = "custody_declared"
    return out


# --- the controller_binding join basis ---------------------------------------


@dataclass
class _Side:
    """One member's side of a controller_binding join: the key identifier the
    binding must name and the time T it must cover."""

    key: str = ""
    ok_key: bool = False
    at: tuple[int, int] = (0, 0)
    ok_at: bool = False


def _record_time(value: Any) -> tuple[int, int] | None:
    """A root record's timestamp, which may carry fractional seconds. Times
    compare as instants."""
    if not isinstance(value, str) or _RECORD_TIME.fullmatch(value) is None:
        return None
    if "." in value:
        head, fraction = value[:-1].split(".", 1)
        value = f"{head}.{fraction[:9]}Z"
    return parse_utc(value)


def _record_side(record: Mapping[str, Any], pointer: str) -> _Side:
    """The key identifier ``pointer`` selects in a root record, and the
    record's timestamp. Asserted as a string: two resolved objects would not
    compare."""
    _, raw = _resolve_pointer(record, pointer)
    at = _record_time(record.get("timestamp"))
    return _Side(raw if isinstance(raw, str) else "", isinstance(raw, str), at or (0, 0), at is not None)


def _checkpoint_side(body: Mapping[str, Any]) -> _Side | None:
    """An empty-history member's side from its signed checkpoint: the key that
    signed checkpoint.cose and its timestamp. A member without a checkpoint
    that verifies has no key, so the join is not derivable."""
    from .bundle import _strict_checkpoint

    stated = body.get("checkpoint")
    if not isinstance(stated, Mapping):
        return None
    certificate = body.get("completeness_certificate")
    claim, signed, _ = _strict_checkpoint(stated, certificate if isinstance(certificate, Mapping) else {})
    if claim.status != "pass" or not signed:
        return None
    at = _record_time(signed.get("timestamp"))
    return _Side(signed["key_id"], True, at or (0, 0), at is not None)


def _ed25519_keys(record: Mapping[str, Any]) -> bool:
    """Both bound keys are Ed25519 keys: ``key_types`` is absent, or names
    ed25519 twice. -02 defines no other key type, so a record under one is
    skipped like a record under an unimplemented method."""
    if "key_types" not in record:
        return True
    types = record["key_types"]
    return isinstance(types, list) and len(types) == 2 and types[0] == "ed25519" and types[1] == "ed25519"


def _binding_report(record: Mapping[str, Any], times: list, statements: list):
    """Verify one delivered record through the one binding verifier at
    ``times``. Returns the verifier's report and whether the record is well
    formed as -02 states it.

    -02 differs from Controller Binding v0 in two places, both applied here
    and nowhere else: an empty nonce is malformed, and a key type other than
    ed25519 is well formed without CB v0's rule for it (the 32-character
    bip340 nonce), because -02 does not define that type."""
    subject = record
    if not _ed25519_keys(record):
        subject = {k: v for k, v in record.items() if k != "key_types"}
    try:
        octets = jcs(record)
    except _DIGEST_ERRORS:
        return cb.Report(), False
    report = cb.verify(octets, times, cb.Options(revocations=statements))
    if "key_types" in record:
        types = record["key_types"]
        if not isinstance(types, list) or len(types) != 2 or not all(isinstance(t, str) for t in types):
            return report, False
    nonce = record.get("nonce")
    if not isinstance(nonce, str) or nonce == "":
        return report, False
    # Under ed25519 keys a sig is a sig-hex; -02 makes a record that fails
    # this malformed, where CB v0 reads it as a signature that does not verify.
    sigs = record.get("sigs")
    if isinstance(sigs, list) and _ed25519_keys(record):
        for entry in sigs:
            sig = entry.get("sig") if isinstance(entry, dict) else None
            if not isinstance(sig, str) or _HEX128.fullmatch(sig) is None:
                return report, False
    form = report
    if subject is not record:
        try:
            form = cb.verify(jcs(subject), (), cb.Options())
        except _DIGEST_ERRORS:
            pass
    return report, form.properties.get(cb.PROPERTY_FORM) == cb.STATUS_PASS


def _implemented(record: Mapping[str, Any]) -> bool:
    """This verifier implements the record's method and key types: a method
    -02 defines for the record's claim, and ed25519 keys."""
    want = "dual_signature_credential/0" if record.get("claim") == "same_organization_credentialed" else "dual_signature/0"
    return record.get("method") == want and _ed25519_keys(record)


def _controller_binding_link(j: _Join, a: _Side, b: _Side, opts: ComposedOptions):
    """The linkage of a controller_binding join between two root records, as
    ``(linked, derivable)``. ``derivable`` is false when no delivered binding
    record has the join's identifier_digest, or when every one that does names
    a method or key type this verifier does not implement. Otherwise ``linked``
    is true when one such record applies: well formed, signed by both bound
    keys, its keys exactly the two values the pointer selects, in effect at
    both root records' timestamps, and revoked by no delivered statement at or
    before either. A join without pointer or identifier_digest names no
    record: not derivable. The record checks are the binding verifier's; only
    the join's reading of its report is here."""
    if j.identifier is None:
        return False, False
    times = [a.at, b.at] if a.ok_at and b.ok_at else []
    statements = []
    for statement in opts.binding_revocations:
        try:
            statements.append(jcs(statement))
        except _DIGEST_ERRORS:
            pass
    derivable = False
    for record in opts.controller_bindings:
        report, well_formed = _binding_report(record, times, statements)
        if report.binding_digest != j.identifier:
            continue
        if not well_formed:
            # A malformed record does not apply: the join derives, unjoined.
            derivable = True
            continue
        if not _implemented(record):
            continue
        derivable = True
        if a.ok_key and b.ok_key and report.applies_to(a.key, b.key):
            return True, True
    return False, derivable


# --- the digest --------------------------------------------------------------


class _Malformed(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"composed/v1 block malformed: {reason}")
        self.reason = reason


def composed_digest(raw: Any) -> str:
    """Recompute a composed/v1 block's composed digest from its declarations
    alone: lowercase-hex SHA-256 of the JCS serialization of the digest input
    ``{kind, members, observers, joins, not_requested}``, each array reduced
    to its declared fields and sorted. Member bodies, ``missing`` and
    ``composed_digest`` are excluded. Raises on a malformed block."""
    return hashlib.sha256(composed_digest_preimage(raw)).hexdigest()


def composed_digest_preimage(raw: Any) -> bytes:
    """The UTF-8 JCS bytes of the digest input."""
    block, reason = _parse_composed(raw)
    if reason:
        raise _Malformed(reason)
    members = sorted(block.members, key=lambda m: m.id)
    observers = sorted(block.observers, key=lambda o: o.id)
    joins = sorted(block.joins, key=_join_key)
    join_values = []
    for j in joins:
        value: dict = {"members": [j.members[0], j.members[1]], "basis": j.basis, "state": j.state}
        if j.pointer is not None:
            value["pointer"] = j.pointer
        if j.identifier is not None:
            value["identifier_digest"] = j.identifier
        if j.compare_carried:
            value["compare"] = list(j.compare)
        join_values.append(value)
    return jcs(
        {
            "kind": COMPOSED_KIND,
            "members": [
                {"id": m.id, "observer": m.observer, "request_digest": m.request_digest, "outcome": m.outcome,
                 "digest": m.digest}
                for m in members
            ],
            "observers": [{"id": o.id, "role": o.role, "custody_domain": o.custody} for o in observers],
            "joins": join_values,
            "not_requested": sorted(block.not_requested),
        }
    )


def _join_key(j: _Join) -> str:
    """Joins order by members[0], members[1], basis, then pointer (the empty
    string when absent). Label and basis tokens exclude NUL, so a NUL
    separator keeps the tuple order."""
    return "\x00".join((j.members[0], j.members[1], j.basis, j.pointer or ""))


# --- parsing -----------------------------------------------------------------


def _parse_composed(raw: Any) -> tuple[_Block, str]:
    block = _Block()
    if not isinstance(raw, dict):
        return block, "not_an_object"
    digest = raw.get("composed_digest")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        return block, "composed_digest"
    block.digest = digest

    observer_list = raw.get("observers")
    if not isinstance(observer_list, list) or not observer_list:
        return block, "observers"
    observer_ids: set = set()
    for i, item in enumerate(observer_list):
        if not (
            isinstance(item, dict)
            and isinstance(item.get("id"), str) and _LABEL.fullmatch(item["id"])
            and isinstance(item.get("role"), str)
            and isinstance(item.get("custody_domain"), str)
        ):
            return block, f"observer:{i}"
        if item["id"] in observer_ids:
            return block, f"observer_id_duplicate:{item['id']}"
        observer_ids.add(item["id"])
        block.observers.append(_Observer(item["id"], item["role"], item["custody_domain"]))

    member_list = raw.get("members")
    if not isinstance(member_list, list) or not member_list:
        return block, "members"
    member_ids: set = set()
    for i, item in enumerate(member_list):
        member, reason = _parse_member(item, observer_ids)
        if reason:
            return block, f"member:{i}:{reason}"
        if member.id in member_ids:
            return block, f"member_id_duplicate:{member.id}"
        member_ids.add(member.id)
        block.members.append(member)

    join_list = raw.get("joins", [])
    if not isinstance(join_list, list):
        return block, "joins"
    seen: set = set()
    for i, item in enumerate(join_list):
        join, reason = _parse_join(item, member_ids)
        if reason:
            return block, f"join:{i}:{reason}"
        key = _join_key(join)
        if join.pointer is None:
            key += "\x00absent"
        if key in seen:
            return block, f"join_duplicate:{i}"
        seen.add(key)
        block.joins.append(join)

    labels = _label_array(raw, "not_requested")
    if labels is None:
        return block, "not_requested"
    block.not_requested = labels
    for label in labels:
        if label in member_ids:
            return block, f"not_requested_is_member:{label}"
    labels = _label_array(raw, "missing")
    if labels is None:
        return block, "missing"
    block.missing = labels
    return block, ""


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _parse_member(raw: Any, observers: set) -> tuple[_Member, str]:
    m = _Member()
    if not isinstance(raw, dict):
        return m, "not_an_object"
    m.id = raw.get("id")
    m.observer = raw.get("observer")
    m.request_digest = raw.get("request_digest")
    m.outcome = raw.get("outcome")
    m.digest = raw.get("digest")
    if not isinstance(m.id, str) or not _LABEL.fullmatch(m.id):
        return m, "id"
    if not isinstance(m.observer, str) or not _LABEL.fullmatch(m.observer):
        return m, "observer"
    if m.observer not in observers:
        return m, "observer_undeclared"
    if not _is_digest(m.request_digest):
        return m, "request_digest"
    if not _is_digest(m.digest):
        return m, "digest"
    if not isinstance(m.outcome, str) or m.outcome not in _OUTCOMES:
        return m, "outcome"
    body_key = _OUTCOMES[m.outcome]
    # A body under another outcome's member name would convert one outcome
    # into another; the outcomes are never converted.
    for other in _OUTCOMES.values():
        if other in raw and other != body_key:
            return m, "body_outcome_conflict"
    if "response" in raw:
        response = raw["response"]
        if (m.outcome != "artifact" or not isinstance(response, dict) or not _is_digest(response.get("request_digest"))
                or not _is_digest(response.get("artifact_digest"))):
            return m, "response"
        m.response = response
    if body_key not in raw:
        return m, ""
    body = raw[body_key]
    if not isinstance(body, dict):
        return m, "body"
    if m.outcome == "refusal":
        if not _is_digest(body.get("request_digest")) or not isinstance(body.get("reason"), str) \
                or not isinstance(body.get("issued_at"), str):
            return m, "refusal_body"
    elif m.outcome == "absence":
        window = body.get("window")
        if (not _is_digest(body.get("request_digest")) or not isinstance(window, dict)
                or not isinstance(window.get("from"), str) or not isinstance(window.get("to"), str)):
            return m, "absence_body"
        if "route" in body and not isinstance(body["route"], str):
            return m, "absence_body"
        if "commitment" in body and not _is_digest(body["commitment"]):
            return m, "absence_body"
    m.body = body
    return m, ""


def _parse_join(raw: Any, members: set) -> tuple[_Join, str]:
    j = _Join()
    if not isinstance(raw, dict):
        return j, "not_an_object"
    pair = raw.get("members")
    if not isinstance(pair, list) or len(pair) != 2:
        return j, "members"
    ids = []
    for item in pair:
        if not isinstance(item, str) or not _LABEL.fullmatch(item) or item not in members:
            return j, "members"
        ids.append(item)
    j.members = (ids[0], ids[1])
    if j.members[0] >= j.members[1]:
        return j, "members_order"
    j.basis, j.state = raw.get("basis"), raw.get("state")
    if not isinstance(j.basis, str) or j.basis not in _JOIN_BASES:
        return j, "basis"
    if not isinstance(j.state, str) or j.state not in _JOIN_STATES:
        return j, "state"
    if "pointer" in raw:
        pointer = raw["pointer"]
        if not isinstance(pointer, str) or not _valid_pointer(pointer):
            return j, "pointer"
        j.pointer = pointer
    if "identifier_digest" in raw:
        digest = raw["identifier_digest"]
        if not _is_digest(digest):
            return j, "identifier_digest"
        j.identifier = digest
    if "compare" in raw:
        compare = raw["compare"]
        if not isinstance(compare, list) or not compare:
            return j, "compare"
        for pointer in compare:
            if not isinstance(pointer, str) or not _valid_pointer(pointer):
                return j, "compare"
            j.compare.append(pointer)
        j.compare_carried = True
    return j, ""


def _label_array(value: Mapping[str, Any], key: str) -> list | None:
    items = value.get(key, [])
    if not isinstance(items, list):
        return None
    labels = []
    for item in items:
        if not isinstance(item, str) or not _LABEL.fullmatch(item):
            return None
        labels.append(item)
    return labels


# --- JSON Pointer ------------------------------------------------------------


def _valid_pointer(pointer: str) -> bool:
    """An RFC 6901 JSON Pointer: empty, or ``/``-prefixed reference tokens in
    which ``~`` appears only as ``~0`` or ``~1``."""
    if pointer == "":
        return True
    if pointer[0] != "/":
        return False
    for i, ch in enumerate(pointer):
        if ch == "~" and (i + 1 >= len(pointer) or pointer[i + 1] not in "01"):
            return False
    return True


def _resolve_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    """Evaluate an RFC 6901 JSON Pointer against a decoded JSON value:
    ``(resolved, value)``."""
    if not _valid_pointer(pointer):
        return False, None
    if pointer == "":
        return True, document
    current = document
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not (token.isascii() and token.isdigit()) or (len(token) > 1 and token[0] == "0"):
                return False, None
            index = int(token)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current
