# SPDX-License-Identifier: BSD-3-Clause
"""Verify evidence-request exchanges and map them to Evidence Result claims (profile §1, §3.3,
§5 to §8).

The input is what the requester holds: the octets of each request it transmitted, the octets of
each reply it received, and any absence record it wrote. The output is, per reply, one report per
property of §7.2 with the method used, and, per requirement evaluated, the §8.1 row with its
status, sufficiency and verdict and the claim's ``evidence[]`` and ``proofs[]`` (§8.3).

The verifier is offline (NFR-7). It reads no clock: trust in the responder's key is checked as of
the message's own ``issued_at``, the log key as of the checkpoint's ``issued_at``, and anything
"now" as of the caller's evaluation time, through the caller's resolver when the verification
policy is online (FR-31).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ._cbor import CborError, decode
from ._common import (
    FAIL,
    INCONCLUSIVE,
    MEDIA_CBOR,
    MEDIA_JSON,
    NOT_CHECKED,
    NOT_PRESENT,
    PASS,
    PROFILE_ID,
    REFUSAL_REASONS,
    PropertyReport,
    TrustPolicy,
    VerificationPolicy,
    b64url_decode,
    ed25519_verify_hex,
    is_digest,
    is_key_id,
    is_profile_time,
    is_text,
    is_uint,
    jcs_or_none,
    json_value_digest,
    member_of,
    numbers_in_domain,
    parse_json,
    parse_time,
    sha256_hex,
    unsigned_jcs,
)
from .cll import INCLUSION, check_anchor_inclusion
from .native import NativeChecker, default_native_checkers

__all__ = [
    "Message",
    "Exchange",
    "ForeignObject",
    "RequirementResult",
    "ReplyResult",
    "AbsenceResult",
    "ExchangeResult",
    "VerificationResult",
    "ContentEvaluator",
    "InteropVerifier",
    "ENVELOPE_PROPERTIES",
    "REFUSAL_PROPERTIES",
    "contract_ref_of",
]

ENVELOPE_PROPERTIES = (
    "profile_version", "envelope_signature", "responder_trust", "responder_key_current", "issued_at_form",
    "request_binding", "subject_binding", "artifact_digest", "verification_binding", "anchor_match",
    "anchor_inclusion",
)
REFUSAL_PROPERTIES = (
    "refusal_signature", "responder_trust", "responder_key_current", "request_binding", "reason_registered",
    "issued_at_form",
)
# §6.2: the members covered by the envelope signature, when present.
_ENVELOPE_SIGNED = ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest",
                    "verification", "responder", "issued_at")
_ABSENCE_MEMBERS = frozenset({"outcome", "request_digest", "route", "window", "recorded_at", "retention",
                              "key_id", "sig"})

# §8: the Evidence Contract projection [EC contractResult].
_PROJECTION = {"SATISFIED": "SATISFIED", "NOT_FOUND": "GAP", "NOT_COMMITTED": "GAP", "WITHHELD": "GAP",
               "CONTRADICTED": "GAP", "INSUFFICIENT": "INSUFFICIENT", "UNKNOWN": "UNKNOWN"}
_EVIDENCE_STATUSES = frozenset(_PROJECTION) | {"NOT_APPLICABLE"}
# §8.1 rows, by the label the conformance vectors give them, and the status each contributes.
_ROW_STATUS = {
    "envelope-1": "CONTRADICTED", "envelope-2": "INSUFFICIENT", "envelope-3": "INSUFFICIENT",
    "envelope-4": "UNKNOWN", "envelope-5": "SATISFIED", "envelope-6": "INSUFFICIENT",
    "refusal-no_such_subject": "NOT_FOUND", "refusal-retention_expired": "UNKNOWN",
    "refusal-coverage_unsatisfiable": "UNKNOWN", "refusal-withheld": "WITHHELD",
    "refusal-deadline_or_malformed": "UNKNOWN", "refusal-failed": "UNKNOWN", "received-and-failed": "UNKNOWN",
    "absence": "UNKNOWN",
}
# §8: the rows a contract's uncertainty.on_missing applies to.
_MISSING_ROWS = frozenset({"envelope-3", "envelope-4", "refusal-no_such_subject", "refusal-retention_expired",
                           "refusal-coverage_unsatisfiable", "refusal-deadline_or_malformed", "absence"})
_ROW_7_NOTE = ("§8.1 row 7: the contract evaluates the Artifact's content; met or not_met only if that gives "
               "SATISFIED, else not_evaluable [RES §1]. This profile fixes no content rule.")


@dataclass(frozen=True)
class Message:
    """Octets as carried, with the media type they were carried under (§11.4.1 rule 7)."""

    octets: bytes
    media_type: str


@dataclass
class Exchange:
    """One request the requester transmitted, every reply it received for it, and the absence
    record it wrote if its window closed with no reply."""

    request: Message
    replies: Sequence[Message] = ()
    absence_record: Message | None = None


@dataclass(frozen=True)
class ForeignObject:
    """Where a foreign signed object sits in a JSON Artifact (a dotted member path), and the
    media type that selects its native check (§5.1, §7.2 ``native_check``)."""

    path: str
    media_type: str


# Row 7: (requirement, artifact octets, native_check report or None) -> (status, verdict), or None
# to leave the requirement unevaluated. The status is one of the eight Evidence Contract values.
ContentEvaluator = Callable[[Mapping[str, Any], bytes, Optional[PropertyReport]], "tuple[str, str] | None"]


@dataclass
class RequirementResult:
    """One requirement's §8 result: the row, status, sufficiency and verdict, and the claim."""

    requirement_ref: str
    contract_ref: str | None
    row: str
    status: str | None
    sufficiency: str | None
    verdict: str | None
    evidence: list = field(default_factory=list)
    proofs: list = field(default_factory=list)
    note: str | None = None

    @property
    def presentation_kinds_allowed(self) -> list | None:
        """§8.2 invariant 4: WITHHELD and NOT_COMMITTED never use the ``disclosure`` carrier."""
        return ["analysis", "story"] if self.status in ("WITHHELD", "NOT_COMMITTED") else None

    def claim(self) -> dict[str, Any]:
        """The claim fields this profile fills (§8.3). ``tier``, ``grade`` and the carrier's
        prose are the evaluator's [RES §1]."""
        return {"contract_ref": self.contract_ref, "requirement_ref": self.requirement_ref,
                "sufficiency": self.sufficiency, "verdict": self.verdict, "status": self.status,
                "evidence": list(self.evidence), "proofs": list(self.proofs)}


@dataclass
class ReplyResult:
    """One reply: its message type (§1), its property reports (§7) and its §8 results."""

    message_type: str  # envelope | refusal | received_and_failed | not_a_response
    properties: list = field(default_factory=list)
    native_check: PropertyReport | None = None
    requirements: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    proofs: list = field(default_factory=list)
    detail: str | None = None
    _envelope: dict | None = field(default=None, repr=False)
    _row: str | None = field(default=None, repr=False)
    _octets: bytes = field(default=b"", repr=False)

    def status(self, prop: str) -> str | None:
        for r in self.properties:
            if r.property == prop:
                return r.status
        return None

    @property
    def artifact(self) -> bytes | None:
        """An envelope's artifact octets as carried, decoded from their encoding (§4); None when
        the reply is not an envelope or its ``artifact`` is not opaque bytes."""
        return self._envelope["value"].get("artifact") if self._envelope is not None else None


@dataclass
class AbsenceResult:
    """An absence record: its form (§6.4, §7.3) and its §8 result."""

    form: str  # conforming | not_conforming
    detail: str | None
    requirements: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    presentation_kind_recommended: str = "story"


@dataclass
class ExchangeResult:
    request_digest: str
    replies: list = field(default_factory=list)
    absence: AbsenceResult | None = None

    @property
    def pending(self) -> bool:
        """No reply and no conforming absence: the request is pending, and no claim is emitted
        (§8.1)."""
        return not any(r.message_type != "not_a_response" for r in self.replies) and \
            (self.absence is None or self.absence.form != "conforming")


@dataclass
class VerificationResult:
    exchanges: list
    caller_invariance: PropertyReport


def contract_ref_of(contract: Mapping[str, Any]) -> str:
    """``id``, ``@``, ``version``, built from the document held (§11.3.7); never split."""
    return f"{contract['id']}@{contract['version']}"


def _strict_equal(a: Any, b: Any) -> bool:
    """Equality by value with no bool/int conflation, for ``subject_binding``."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_strict_equal(x, y) for x, y in zip(a, b))
    return a == b


def _decode_map(message: Message) -> tuple[dict | None, bool, str]:
    """A reply's map, whether it is well-formed (§5.2), and why not. None when it is no map."""
    if message.media_type == MEDIA_JSON:
        parsed = parse_json(message.octets)
        if parsed is None or not isinstance(parsed.value, dict):
            return None, False, "not a JSON object"
        why = "duplicate member" if parsed.duplicate_keys else \
            "a number outside 0 to 2^53 - 1" if parsed.bad_number else ""
        return parsed.value, parsed.well_formed, why
    if message.media_type == MEDIA_CBOR:
        try:
            d = decode(message.octets)
        except CborError:
            return None, False, "not a CBOR data item"
        if not isinstance(d.value, dict):
            return None, False, "not a CBOR map"
        # Classified by its members whatever else is wrong with it (§1). The signature is over
        # JCS whatever the frame (§5.1), so a frame that is not deterministic CBOR is not, by
        # itself, a reason to fail it.
        in_domain = numbers_in_domain(d.value)
        why = "duplicate map key" if d.duplicate_keys else "" if d.well_formed and in_domain else \
            "a value outside the §5.2 data model (a float, a non-text key, or a number out of range)"
        return d.value, d.well_formed and in_domain, why
    return None, False, f"unknown media type {message.media_type!r}"


def _opaque(value: Any, media_type: str) -> bytes | None:
    """Opaque bytes: a byte string in CBOR, base64url without padding in JSON (§4)."""
    if media_type == MEDIA_CBOR:
        return value if isinstance(value, bytes) else None
    return b64url_decode(value)


def _requirement_shape(req: Mapping[str, Any]) -> str:
    """Which Evidence Contract shape a requirement takes (§11.3.2)."""
    profile = req.get("profile", "outcome")
    if profile in ("outcome", "obligation"):
        native = "evidence_rule" in req or "profile" not in req
        return f"{'native' if native else 'abstract'}-{profile}"
    return profile


def _apply_uncertainty(req: Mapping[str, Any] | None, row: str, status: str) -> str:
    """§8 and §11.3.7: ``uncertainty`` changes the defaults only where the schema types it, the
    abstract outcome and quality shapes."""
    if not req or _requirement_shape(req) not in ("abstract-outcome", "quality"):
        return status
    u = req.get("uncertainty")
    if not isinstance(u, dict):
        return status
    if row in _MISSING_ROWS:
        return {"insufficient": "INSUFFICIENT", "unknown": "UNKNOWN"}.get(u.get("on_missing"), status)
    if row == "envelope-1" and u.get("on_conflict") == "contradicted":
        return "CONTRADICTED"
    return status


class InteropVerifier:
    """A verifier for ``evidence-interop/0`` exchanges.

    ``evaluation_time`` is required and is the only "now" the verifier knows. ``contract`` is the
    contract version document evaluated; the claims carry its ``contract_ref``. Requirements are
    identified by their ``id``; a contract with two requirements of one ``id`` is not evaluated
    (§11.3.7).
    """

    def __init__(self, trust: TrustPolicy, verification: VerificationPolicy, evaluation_time: str,
                 contract: Mapping[str, Any] | None = None,
                 native_checkers: Mapping[str, NativeChecker] | None = None):
        if parse_time(evaluation_time) is None:
            raise ValueError("evaluation_time must be an RFC 3339 time; the verifier never reads the clock")
        self.trust, self.policy, self.evaluation_time = trust, verification, evaluation_time
        self.contract = contract
        self.contract_ref: str | None = None
        self.contract_digest: str | None = None
        self._requirements: dict[str, Mapping[str, Any]] = {}
        if contract is not None:
            ids = [r.get("id") for r in contract.get("requirements", [])]
            if len(ids) != len(set(ids)):
                raise ValueError("two requirements share one id; the contract version is not evaluated (§11.3.7)")
            self.contract_digest = json_value_digest(contract) if numbers_in_domain(contract) else None
            if self.contract_digest is None:
                raise ValueError("the contract carries a value JCS cannot represent; no contract_digest (§11.3.7)")
            self.contract_ref = contract_ref_of(contract)
            self._requirements = {r["id"]: r for r in contract.get("requirements", [])}
        self.native_checkers = dict(default_native_checkers() if native_checkers is None else native_checkers)

    # ------------------------------------------------------------------ requests

    @staticmethod
    def _request_map(request: Message) -> dict:
        if request.media_type == MEDIA_JSON:
            parsed = parse_json(request.octets)
            value = parsed.value if parsed is not None and parsed.well_formed else None
        elif request.media_type == MEDIA_CBOR:
            try:
                value = decode(request.octets).value
            except CborError:
                value = None
        else:
            value = None
        if not isinstance(value, dict):
            raise ValueError("the retained request octets are not a request map")
        return value

    # ------------------------------------------------------------------ envelope (§6.2, §7.2, §7.3)

    def _responder_key_current(self, key: Any) -> PropertyReport:
        name = "responder_key_current"
        if not self.policy.online:
            return PropertyReport(name, NOT_CHECKED, "online key-status check (§7.2)",
                                  "the verifier is offline; an online check is not made (NFR-7)")
        if self.policy.key_status is None or not is_key_id(key):
            return PropertyReport(name, NOT_CHECKED, "online key-status check (§7.2)",
                                  "no key-status resolver was supplied")
        status, method = self.policy.key_status(key, self.evaluation_time)
        return PropertyReport(name, status, method, f"as of the evaluation time {self.evaluation_time}")

    def _envelope_properties(self, env: dict, well_formed: bool, why: str, media_type: str,
                             request_octets: bytes, request: dict) -> tuple[dict, list | None]:
        props: dict[str, PropertyReport] = {}
        asked = request.get("profile", PROFILE_ID)
        # §3.3 step 5. This verifier implements evidence-interop/0 rules only, whatever else the
        # policy lists.
        implemented = self.policy.profiles_implemented & {PROFILE_ID}
        method = "§3.3 step 5: the envelope's profile against the identifier requested"
        if "profile" not in env:
            pv = PropertyReport("profile_version", NOT_PRESENT, method, "no profile member: ER alone (§3.3)")
        elif env["profile"] != asked:
            pv = PropertyReport("profile_version", FAIL, method, f"requested {asked!r}, got {env['profile']!r}")
        elif not member_of(env["profile"], implemented):
            pv = PropertyReport("profile_version", NOT_CHECKED, method,
                                f"{env['profile']!r} is not implemented; not checked under any other version")
        else:
            pv = PropertyReport("profile_version", PASS, method)
        props["profile_version"] = pv
        if pv.status != PASS:
            for name in ENVELOPE_PROPERTIES[1:]:
                props[name] = PropertyReport(name, NOT_CHECKED, "not run (§3.3 step 5, §7.2)",
                                             "profile_version is not PASS")
            return props, None

        responder, issued_at = env.get("responder"), env.get("issued_at")
        # envelope_signature
        method = "Ed25519 over the JCS signing input (§6.2)"
        if "sig" not in env or "responder" not in env:
            props["envelope_signature"] = PropertyReport("envelope_signature", NOT_PRESENT, method,
                                                         "sig or responder is absent")
        elif not well_formed:
            props["envelope_signature"] = PropertyReport("envelope_signature", FAIL, method,
                                                         f"not well-formed (§5.2): {why}")
        else:
            body = jcs_or_none({k: env[k] for k in _ENVELOPE_SIGNED if k in env})
            ok = body is not None and ed25519_verify_hex(responder, env["sig"], body)
            props["envelope_signature"] = PropertyReport("envelope_signature", PASS if ok else FAIL, method)
        # responder_trust: reported on the key the envelope names, as of its issued_at (P-54).
        method = "trust policy: responder keys, as of the envelope's issued_at"
        if "responder" not in env:
            props["responder_trust"] = PropertyReport("responder_trust", NOT_PRESENT, method)
        else:
            props["responder_trust"] = PropertyReport("responder_trust",
                                                      self.trust.accepts_responder(responder, issued_at), method)
        props["responder_key_current"] = self._responder_key_current(responder)
        # issued_at_form
        method = "§5.2 time form"
        if "issued_at" not in env:
            props["issued_at_form"] = PropertyReport("issued_at_form", NOT_PRESENT, method)
        else:
            props["issued_at_form"] = PropertyReport("issued_at_form",
                                                     PASS if is_profile_time(issued_at) else FAIL, method)
        # request_binding
        method = "SHA-256 over the retained request octets (§5.1)"
        if "request_digest" not in env:
            props["request_binding"] = PropertyReport("request_binding", NOT_PRESENT, method)
        else:
            ok = env["request_digest"] == sha256_hex(request_octets)
            props["request_binding"] = PropertyReport("request_binding", PASS if ok else FAIL, method)
        # subject_binding
        method = "subject and derivation equal the request's, by value (§7.2)"
        if "subject" not in env:
            props["subject_binding"] = PropertyReport("subject_binding", NOT_PRESENT, method)
        else:
            ok = _strict_equal(env["subject"], request.get("subject")) and \
                ("derivation" in env) == ("derivation" in request) and \
                _strict_equal(env.get("derivation"), request.get("derivation"))
            props["subject_binding"] = PropertyReport("subject_binding", PASS if ok else FAIL, method)
        # artifact_digest
        method = "SHA-256 over the artifact octets (§6.2)"
        artifact = _opaque(env.get("artifact"), media_type) if "artifact" in env else None
        if "artifact" not in env or "artifact_digest" not in env:
            props["artifact_digest"] = PropertyReport("artifact_digest", NOT_PRESENT, method)
        elif artifact is None:
            props["artifact_digest"] = PropertyReport("artifact_digest", FAIL, method,
                                                      "artifact is not opaque bytes in this encoding (§4)")
        else:
            ok = sha256_hex(artifact) == env["artifact_digest"]
            props["artifact_digest"] = PropertyReport("artifact_digest", PASS if ok else FAIL, method)
        # verification_binding
        method = "SHA-256 of each verification_content item against verification, in order (§6.2)"
        material: list | None = None
        ver, content = env.get("verification"), env.get("verification_content")
        if ver is None and content is None:
            props["verification_binding"] = PropertyReport("verification_binding", NOT_PRESENT, method,
                                                           "no verification material; not required")
        else:
            items = [_opaque(x, media_type) for x in content] if isinstance(content, list) else None
            entries_ok = isinstance(ver, list) and all(
                isinstance(e, dict) and is_text(e.get("kind")) and is_digest(e.get("digest")) for e in ver)
            ok = entries_ok and items is not None and None not in items and len(items) == len(ver) and all(
                sha256_hex(x) == e["digest"] for x, e in zip(items, ver))
            if ok:
                material = items
            props["verification_binding"] = PropertyReport("verification_binding", PASS if ok else FAIL, method)
        # anchor_match
        props["anchor_match"] = self._anchor_match(env, request)
        # anchor_inclusion
        props["anchor_inclusion"] = check_anchor_inclusion(
            env, material, {k: props[k].status for k in ("envelope_signature", "artifact_digest",
                                                         "verification_binding")},
            self.trust, self.policy.kinds_implemented)
        return props, material

    @staticmethod
    def _anchor_match(env: dict, request: dict) -> PropertyReport:
        name = "anchor_match"
        coverage, anchor = request.get("coverage"), env.get("anchor")
        if not isinstance(coverage, dict) or len(coverage) != 1:
            return PropertyReport(name, NOT_CHECKED, "§7.2 anchor_match",
                                  "the retained request carries no single coverage member")
        if not isinstance(anchor, dict):
            return PropertyReport(name, NOT_PRESENT, "§7.2 anchor_match", "no anchor")
        if "expected_pin" in coverage:
            method = "anchor.digest equals the expected_pin (ER §3.2)"
            if "digest" not in anchor:
                return PropertyReport(name, NOT_PRESENT, method)
            return PropertyReport(name, PASS if anchor["digest"] == coverage["expected_pin"] else FAIL, method)
        floor = coverage.get("min_freshness")
        method = "anchor.freshness meets the min_freshness floor (ER §3.2, §4.1 item 2)"
        if "freshness" not in anchor:
            return PropertyReport(name, NOT_PRESENT, method, "anchor.freshness is absent")
        got = anchor["freshness"]
        if is_uint(floor):
            ok = is_uint(got) and got >= floor
        elif is_profile_time(floor):
            ok = is_profile_time(got) and parse_time(got) >= parse_time(floor)
        else:
            return PropertyReport(name, NOT_CHECKED, method, "the retained request's floor is malformed")
        return PropertyReport(name, PASS if ok else FAIL, method, None if ok else "in the type the request used")

    @staticmethod
    def _required(env: dict, props: Mapping[str, PropertyReport]) -> dict[str, str]:
        """The required envelope properties (§7.2): all but responder_key_current, and
        verification_binding only when verification is present."""
        out = {k: v.status for k, v in props.items() if k != "responder_key_current"}
        if "verification" not in env:
            out.pop("verification_binding", None)
        return out

    # ------------------------------------------------------------------ refusal (§6.3, §7.3)

    def _refusal_properties(self, ref: dict, well_formed: bool, why: str, request_octets: bytes) -> dict:
        props: dict[str, PropertyReport] = {}
        key_id, issued_at = ref.get("key_id"), ref.get("issued_at")
        method = "Ed25519 over JCS of {issued_at, reason, request_digest} (§6.3, ERV A7)"
        if "sig" not in ref or "key_id" not in ref:
            props["refusal_signature"] = PropertyReport("refusal_signature", NOT_PRESENT, method,
                                                        "sig or key_id is absent")
        elif not well_formed:
            props["refusal_signature"] = PropertyReport("refusal_signature", FAIL, method,
                                                        f"not well-formed (§5.2): {why}")
        elif not all(k in ref for k in ("issued_at", "reason", "request_digest")):
            props["refusal_signature"] = PropertyReport("refusal_signature", FAIL, method,
                                                        "a signed member is absent")
        else:
            body = jcs_or_none({k: ref[k] for k in ("issued_at", "reason", "request_digest")})
            ok = body is not None and ed25519_verify_hex(key_id, ref["sig"], body)
            props["refusal_signature"] = PropertyReport("refusal_signature", PASS if ok else FAIL, method)
        method = "trust policy: responder keys, as of the refusal's issued_at"
        if "key_id" not in ref:
            props["responder_trust"] = PropertyReport("responder_trust", NOT_PRESENT, method)
        else:
            props["responder_trust"] = PropertyReport("responder_trust",
                                                      self.trust.accepts_responder(key_id, issued_at), method)
        props["responder_key_current"] = self._responder_key_current(key_id)
        method = "SHA-256 over the retained request octets (§5.1)"
        if "request_digest" not in ref:
            props["request_binding"] = PropertyReport("request_binding", NOT_PRESENT, method)
        else:
            ok = ref["request_digest"] == sha256_hex(request_octets)
            props["request_binding"] = PropertyReport("request_binding", PASS if ok else FAIL, method)
        reason = ref.get("reason")
        props["reason_registered"] = PropertyReport(
            "reason_registered", PASS if isinstance(reason, str) and reason in REFUSAL_REASONS else FAIL,
            "exactly one token of the ER §13 registry, exact case (§9.1, ERV A13)")
        method = "§5.2 time form"
        if "issued_at" not in ref:
            props["issued_at_form"] = PropertyReport("issued_at_form", NOT_PRESENT, method)
        else:
            props["issued_at_form"] = PropertyReport("issued_at_form",
                                                     PASS if is_profile_time(issued_at) else FAIL, method)
        return props

    @staticmethod
    def _refusal_row(props: Mapping[str, PropertyReport], reason: Any) -> str:
        if any(r.status != PASS for k, r in props.items() if k != "responder_key_current"):
            return "refusal-failed"
        if reason in ("not_authorized", "policy_declined", "derivation_unsupported"):
            return "refusal-withheld"
        if reason in ("deadline_unmet", "request_malformed"):
            return "refusal-deadline_or_malformed"
        return f"refusal-{reason}"

    # ------------------------------------------------------------------ one reply

    def _reply(self, message: Message, request_octets: bytes, request: dict) -> ReplyResult:
        obj, well_formed, why = _decode_map(message)
        if obj is None:
            return ReplyResult("not_a_response", detail=f"{why}: a transport condition (§9.2)", _octets=message.octets)
        has_env, has_ref = "artifact_digest" in obj, "reason" in obj
        if has_env and has_ref:
            return ReplyResult("received_and_failed", detail="carries both artifact_digest and reason (§1, P-21)",
                               evidence=[{"digest_alg": "SHA-256", "digest": sha256_hex(message.octets)}],
                               _octets=message.octets)
        if has_env:
            props, material = self._envelope_properties(obj, well_formed, why, message.media_type,
                                                        request_octets, request)
            # §8.3 names artifact_digest. When it is not a digest there is nothing to name by it,
            # so the claim cites the reply octets as received, and says so.
            named = is_digest(obj["artifact_digest"])
            digest = obj["artifact_digest"] if named else sha256_hex(message.octets)
            proofs = []
            if props["anchor_inclusion"].status == PASS:
                entry = [e for e in obj["verification"] if e["kind"] == INCLUSION][0]
                proofs = [{"kind": "inclusion_proof", "digest_alg": "SHA-256", "digest": entry["digest"]}]
            env = dict(obj)
            env["artifact"] = _opaque(obj.get("artifact"), message.media_type)
            return ReplyResult("envelope", [props[k] for k in ENVELOPE_PROPERTIES],
                               evidence=[{"digest_alg": "SHA-256", "digest": digest}], proofs=proofs,
                               detail=None if named else "artifact_digest is not a digest; evidence[] cites "
                                                         "the reply octets",
                               _envelope={"value": env, "props": props}, _octets=message.octets)
        if has_ref:
            props = self._refusal_properties(obj, well_formed, why, request_octets)
            result = ReplyResult("refusal", [props[k] for k in REFUSAL_PROPERTIES],
                                 evidence=[{"digest_alg": "SHA-256", "digest": sha256_hex(message.octets)}],
                                 _octets=message.octets)
            result._row = self._refusal_row(props, obj.get("reason"))
            return result
        return ReplyResult("not_a_response", detail="neither artifact_digest nor reason: a transport condition "
                                                    "(§1, §9.2)", _octets=message.octets)

    # ------------------------------------------------------------------ absence (§6.4, §7.3)

    def _absence(self, record: Message, request_octets: bytes) -> AbsenceResult:
        problems: list[str] = []
        value: Any = None
        if record.media_type == MEDIA_JSON:
            parsed = parse_json(record.octets)
            if parsed is not None and parsed.well_formed:
                value = parsed.value
        elif record.media_type == MEDIA_CBOR:
            try:
                d = decode(record.octets)
                value = d.value if d.well_formed else None
            except CborError:
                value = None
        digest = json_value_digest(value) if isinstance(value, dict) else None
        if not isinstance(value, dict):
            problems.append("not a well-formed map")
            value = {}
        if value.get("outcome") != "recorded_absence":
            problems.append("outcome is not recorded_absence")
        if value.get("request_digest") != sha256_hex(request_octets):
            problems.append("request_digest is not the digest of the retained request")
        window = value.get("window")
        if not (isinstance(window, dict) and set(window) == {"opened", "closed"}
                and is_profile_time(window["opened"]) and is_profile_time(window["closed"])
                and window["opened"] <= window["closed"]):
            problems.append("window is not {opened, closed} in the §5.2 form")
            window = None
        recorded = value.get("recorded_at")
        if not is_profile_time(recorded):
            problems.append("recorded_at is not in the §5.2 form")
        elif window is not None and recorded < window["closed"]:
            problems.append("recorded_at is earlier than window.closed (§6.4)")
        extra = set(value) - _ABSENCE_MEMBERS
        if extra:
            problems.append(f"members outside §6.4, which may read as the responder's act: {sorted(extra)}")
        if "route" in value and not is_text(value["route"]):
            problems.append("route is not a text string")
        if "retention" in value and not is_digest(value["retention"]):
            problems.append("retention is not a digest")
        if ("key_id" in value) != ("sig" in value):
            problems.append("key_id and sig are not both present")
        elif "sig" in value:
            body = unsigned_jcs(value)
            if body is None or not ed25519_verify_hex(value["key_id"], value["sig"], body):
                problems.append("the requester's sig does not verify")
        evidence = [{"digest_alg": "SHA-256", "digest": digest or sha256_hex(record.octets)}]
        return AbsenceResult("not_conforming" if problems else "conforming", "; ".join(problems) or None,
                             evidence=evidence)

    # ------------------------------------------------------------------ §8

    def _requirement(self, req_id: str, row: str, evidence: list, proofs: list,
                     status: str | None = None, verdict: str | None = None,
                     note: str | None = None) -> RequirementResult | None:
        req = self._requirements.get(req_id)
        if row != "envelope-7":
            status = _apply_uncertainty(req, row, _ROW_STATUS[row])
            verdict = "not_met" if row == "envelope-5" else "not_evaluable"
        if status == "NOT_APPLICABLE":
            return None  # excluded from the evaluated population [EC contractResult]
        sufficiency = _PROJECTION.get(status) if status is not None else None
        if verdict in ("met", "not_met") and sufficiency != "SATISFIED":
            raise ValueError(f"{req_id}: {verdict} with sufficiency {sufficiency} breaks §8.2 invariant 1")
        return RequirementResult(req_id, self.contract_ref, row, status, sufficiency, verdict,
                                 list(evidence), list(proofs), note)

    @staticmethod
    def _envelope_row(required: Mapping[str, str], contradicted: bool, native: str | None,
                      relation: str | None) -> str:
        values = set(required.values())
        if contradicted:
            return "envelope-1"
        if FAIL in values:
            return "envelope-2"
        if NOT_PRESENT in values:
            return "envelope-3"
        if values & {NOT_CHECKED, INCONCLUSIVE}:
            return "envelope-4"
        if native == FAIL and relation == "is_check":
            return "envelope-5"
        if native == FAIL and relation == "supports":
            return "envelope-6"
        return "envelope-7"

    def _caller_invariance(self, results: Sequence[ReplyResult]) -> tuple[PropertyReport, set]:
        """§7.2: among verified envelopes for one (responder, subject, derivation, anchor),
        identical artifact digests. Returns the report and the ids of envelopes in a conflict."""
        method = "identical artifact_digest across verified envelopes for one question (§7.2, ER §5)"
        groups: dict[tuple, list] = {}
        for r in results:
            if r.message_type != "envelope":
                continue
            env, props = r._envelope["value"], r._envelope["props"]
            if any(props[k].status != PASS for k in ("envelope_signature", "responder_trust", "artifact_digest")):
                continue
            anchor = env.get("anchor")
            key = (jcs_or_none(env.get("responder")), jcs_or_none(env.get("subject")),
                   jcs_or_none(env["derivation"]) if "derivation" in env else None,
                   jcs_or_none(anchor.get("digest")) if isinstance(anchor, dict) else None)
            groups.setdefault(key, []).append(r)
        compared = [g for g in groups.values() if len(g) >= 2]
        conflicting = [g for g in compared if len({jcs_or_none(r._envelope["value"]["artifact_digest"]) for r in g}) > 1]
        if conflicting:
            ids = {id(r) for g in conflicting for r in g}
            n = sum(len(g) for g in conflicting)
            return PropertyReport("caller_invariance", FAIL, method,
                                  f"{n} verified envelopes for one question name different artifacts"), ids
        if compared:
            return PropertyReport("caller_invariance", PASS, method), set()
        return PropertyReport("caller_invariance", NOT_CHECKED, method,
                              "fewer than two verified envelopes for one question are held (P-17)"), set()

    def _native_check(self, artifact: bytes | None, spec: ForeignObject) -> PropertyReport:
        """``native_check`` over the foreign object's as-transmitted value (§5.1, §7.2)."""
        checker = self.native_checkers.get(spec.media_type)
        value: Any = None
        if artifact is not None:
            # The Artifact's own format governs it, not §5.2: a float elsewhere in it does not
            # hide the foreign object.
            parsed = parse_json(artifact)
            value = parsed.value if parsed is not None else None
        for part in spec.path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is None:
            return PropertyReport("native_check", NOT_PRESENT, f"native check for {spec.media_type}",
                                  f"no object at {spec.path!r} in the Artifact")
        if checker is None:
            return PropertyReport("native_check", NOT_CHECKED, f"native check for {spec.media_type}",
                                  "no native check is implemented for this media type")
        return checker(value, self.trust, self.evaluation_time)

    # ------------------------------------------------------------------ the whole

    def verify(self, exchanges: Sequence[Exchange], requirements: Sequence[str] | None = None,
               requirement_relations: Mapping[str, str] | None = None,
               foreign_object: ForeignObject | None = None,
               content_evaluator: ContentEvaluator | None = None) -> VerificationResult:
        """Verify every exchange held, compare their envelopes (``caller_invariance``) and map each
        reply and absence to a result per requirement.

        ``requirements`` lists the requirement ids evaluated (default: every requirement of the
        contract). ``requirement_relations`` says, per requirement, whether it *is* the foreign
        object's native check (``is_check``) or one the check only *supports* (``supports``) (§8.1
        rows 5 and 6). The contract schema has no member for that relation, so it is an input.
        """
        relations = dict(requirement_relations or {})
        req_ids = list(requirements if requirements is not None else self._requirements)
        unknown = [r for r in req_ids if self.contract is not None and r not in self._requirements]
        if unknown:
            raise ValueError(f"requirements not in the contract: {unknown}")
        out: list[ExchangeResult] = []
        all_replies: list[ReplyResult] = []
        for ex in exchanges:
            request = self._request_map(ex.request)
            result = ExchangeResult(sha256_hex(ex.request.octets))
            for message in ex.replies:
                r = self._reply(message, ex.request.octets, request)
                result.replies.append(r)
                all_replies.append(r)
            if ex.absence_record is not None:
                result.absence = self._absence(ex.absence_record, ex.request.octets)
            out.append(result)
        invariance, conflicted = self._caller_invariance(all_replies)
        for result in out:
            for r in result.replies:
                self._map_reply(r, req_ids, relations, foreign_object, content_evaluator, id(r) in conflicted)
            if result.absence is not None and result.absence.form == "conforming":
                # A record that is not a conforming absence for this request (written before the
                # window closed, or for another request) is no absence: the request is still
                # pending, and a pending request yields no claim (§6.4, §8.2 invariant 3).
                a = result.absence
                a.requirements = {q: self._requirement(q, "absence", a.evidence, []) for q in req_ids}
        return VerificationResult(out, invariance)

    def _map_reply(self, r: ReplyResult, req_ids: Sequence[str], relations: Mapping[str, str],
                   foreign: ForeignObject | None, evaluator: ContentEvaluator | None,
                   contradicted: bool) -> None:
        if r.message_type == "not_a_response":
            return  # a transport condition: pending, then an absence (§9.2); no claim
        if r.message_type == "received_and_failed":
            r.requirements = {q: self._requirement(q, "received-and-failed", r.evidence, []) for q in req_ids}
            return
        if r.message_type == "refusal":
            r.requirements = {q: self._requirement(q, r._row, r.evidence, []) for q in req_ids}
            return
        env, props = r._envelope["value"], r._envelope["props"]
        required = self._required(env, props)
        all_pass = all(v == PASS for v in required.values())
        if foreign is not None and all_pass and not contradicted:
            r.native_check = self._native_check(env.get("artifact"), foreign)
        native = r.native_check.status if r.native_check is not None else None
        r.requirements = {}
        for q in req_ids:
            row = self._envelope_row(required, contradicted, native, relations.get(q))
            if row != "envelope-7":
                result = self._requirement(q, row, r.evidence, r.proofs)
            elif relations.get(q) == "is_check" and native != PASS:
                # The requirement is the native check, and the check did not run to a result
                # (§5.1: no property of the object's signature is reported before its native
                # check). Nothing is missing, and the verifier could not apply the condition, so
                # the requirement is UNKNOWN (§11.3.7).
                result = self._requirement(q, row, r.evidence, r.proofs, "UNKNOWN", "not_evaluable",
                                           note=f"the native check is {native or 'not run'}, so the "
                                                "requirement that is that check is UNKNOWN (§5.1, §11.3.7)")
            else:
                outcome = None
                if evaluator is not None and q in self._requirements:
                    outcome = evaluator(self._requirements[q], env.get("artifact") or b"", r.native_check)
                if outcome is None:
                    result = self._requirement(q, row, r.evidence, r.proofs, note=_ROW_7_NOTE)
                else:
                    status, verdict = outcome
                    if status not in _EVIDENCE_STATUSES:
                        raise ValueError(f"{q}: {status!r} is not an Evidence Contract status")
                    result = self._requirement(q, row, r.evidence, r.proofs, status, verdict)
            if result is not None:
                r.requirements[q] = result
