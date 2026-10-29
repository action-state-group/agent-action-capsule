# SPDX-License-Identifier: BSD-3-Clause
"""Pure AAC Evidence Bundle codec and verifier.

The verifier deliberately reports graph closure, interval coverage, and
per-record membership separately.  The CLL range proof used for interval
coverage binds every leaf in the interval (all ``body_digests`` participate in
rebuilding the root, not just the two endpoints); ``memberships`` separately
carries one detached proof per record for the per-record membership property.
Keeping those proofs outside the enclosed Capsule is necessary: embedding a
proof in a Capsule would change the Capsule ID which is itself the MMR leaf.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .canonical import MAX_SAFE_INTEGER, FloatInDigestError, UnsafeIntegerError, jcs, json_digest
from .disclosure_envelope import (
    INELIGIBLE,
    MATCH,
    MISMATCH,
    NO_COMMITTED_DIGEST,
    _committed_digest,
)
from .registries import DISCLOSURE_ELIGIBLE_FIELDS
from .verify import verify
from .witness import WitnessReceiptResult

__all__ = [
    "ClaimResult",
    "DisclosureResult",
    "ExtensionResult",
    "CountersignatureResult",
    "ProducerSelfReport",
    "BundleVerificationResult",
    "bundle_digest",
    "encode_fragment",
    "decode_fragment",
    "verify_bundle",
    "COMPLETENESS_VERIFIER_UNAVAILABLE",
    "RecordResult",
    "SELECTION_PRODUCER_SELECTED",
    "CERTIFICATE_MODE_UNSUPPORTED",
    "BundleBuildError",
    "ProofSource",
    "StoredRecord",
    "build_evidence_bundle",
    "build_unproven_bundle",
    "proof_source_from_cll",
    "WitnessReceiptResult",
]

# Finding for a well-formed completeness certificate that this installation
# cannot check because the CLL reference (``pip install
# 'agent-action-capsule[bundle]'``) is absent. Distinct from
# ``completeness_certificate_invalid``, which means the certificate is wrong.
COMPLETENESS_VERIFIER_UNAVAILABLE = "completeness_verifier_unavailable"

# ``completeness.selection`` of a producer-selected Bundle: records the producer
# picked from its log, each proven on its own, with no claim about the records
# between them (Bundle -02). Deliberately not named ``PRODUCER_SELECTED``:
# capsule-emit 0.10 and earlier take that name as a sign that the non-strict
# verifier reads such Bundles the way it did before -02.
SELECTION_PRODUCER_SELECTED = "producer-selected"

# Finding for a ``completeness.selection`` value naming a certificate mode this
# verifier does not implement (Bundle -02): interval coverage and per-record
# membership are withheld, never failed.
CERTIFICATE_MODE_UNSUPPORTED = "certificate_mode_unsupported"

# The one non-record leaf type a range can carry (Bundle -02, Evidence Layer
# padding), and the exact members of its content.
_PADDING = "padding"
_PADDING_MEMBERS = frozenset({"capsule_id", "record_type", "epistemic_type", "store_nonce"})

BUNDLE_KIND = "evidence-bundle/v2"

# The checkpoint fields a signed COSE checkpoint states; in strict mode the
# Bundle's JSON copy must match every one it carries.
_SIGNED_CHECKPOINT_FIELDS = ("log_id", "mmr_size", "root", "key_id", "timestamp", "prev_size", "prev_root")

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ClaimResult:
    """One independent completeness-claim result.

    ``status`` is one of ``pass``, ``withheld``, or ``fail``.  A closure with
    explicit missing citations is ``withheld`` with the
    ``declared_incomplete`` finding rather than a silent success or failure.
    """

    status: str
    findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DisclosureResult:
    capsule_id: str
    member: str
    status: str


@dataclass(frozen=True)
class ExtensionResult:
    kind: str
    status: str = "uninterpreted"
    integrity_covered: bool = True


@dataclass(frozen=True)
class CountersignatureResult:
    value: Any
    status: str = "unverified"


@dataclass(frozen=True)
class ProducerSelfReport:
    value: Any
    status: str = "producer_self_report"


@dataclass(frozen=True)
class RecordResult:
    """Strict mode: one record of the Bundle's ``records`` list.

    ``signature`` is ``authored``, ``unclaimed`` or ``invalid``
    (:func:`agent_action_capsule.producer_envelope.verify_record_signature`);
    ``seq`` is the record's log position as its membership states it.
    """

    capsule_id: str
    identity_ok: bool
    signature: str
    key_id: str | None
    seq: int | None
    messages: tuple[str, ...] = ()


@dataclass
class BundleVerificationResult:
    """Structured result for a bundle without collapsing completeness claims.

    The fields after ``capsule_results`` are filled only by
    ``verify_bundle(..., strict=True)`` and stay ``None`` or empty otherwise.
    In strict mode ``interval_coverage`` and ``per_record_membership`` are the
    strict readings: with no signed checkpoint, a claim that did not fail is
    ``withheld`` (``checkpoint_unverified``).
    """

    bundle_digest: str | None
    graph_closure: ClaimResult
    interval_coverage: ClaimResult
    per_record_membership: ClaimResult
    disclosures: list[DisclosureResult] = field(default_factory=list)
    extensions: list[ExtensionResult] = field(default_factory=list)
    countersignatures: tuple[CountersignatureResult, ...] = ()
    verification: ProducerSelfReport | None = None
    capsule_results: dict[str, Any] = field(default_factory=dict)
    kind_ok: bool | None = None
    record_identity: ClaimResult | None = None
    signatures: ClaimResult | None = None
    checkpoint: ClaimResult | None = None
    disclosure_claim: ClaimResult | None = None
    witnesses: ClaimResult | None = None
    records: tuple[RecordResult, ...] = ()
    witness_receipts: tuple[WitnessReceiptResult, ...] = ()
    signed_checkpoint: dict[str, Any] = field(default_factory=dict)
    """The signed checkpoint's own fields (from ``checkpoint.cose``) plus the
    Bundle's ``witnesses`` list, when it verified; else empty."""
    signer_matches_checkpoint: bool | None = None
    category_coverage: dict[str, str] | None = None
    """The ``category_coverage`` member's five properties, in report order
    (:mod:`agent_action_capsule.category_coverage`), or ``None`` when the
    Bundle carries no such member. Filled in both modes."""

    @property
    def claims(self) -> tuple[tuple[str, ClaimResult], ...]:
        """Strict mode: the gating claims, in report order. ``witnesses`` is
        not one: only a failing receipt gates (see :attr:`ok`)."""
        if self.record_identity is None:
            return ()
        named = [("records", self.record_identity)]
        if self.signatures is not None and self.checkpoint is not None:
            named += [
                ("signatures", self.signatures),
                ("graph_closure", self.graph_closure),
                ("checkpoint", self.checkpoint),
                ("interval_coverage", self.interval_coverage),
                ("per_record_membership", self.per_record_membership),
            ]
        if self.disclosure_claim is not None:
            named.append(("disclosures", self.disclosure_claim))
        return tuple(named)

    @property
    def ok(self) -> bool | None:
        """Strict mode: nothing failed (``withheld`` is not a failure)."""
        if self.kind_ok is None:
            return None
        from .category_coverage import GATING

        return (
            self.kind_ok
            and all(claim.status != "fail" for _, claim in self.claims)
            and (self.witnesses is None or self.witnesses.status != "fail")
            and not any((self.category_coverage or {}).get(name) == "FAIL" for name in GATING)
        )

    @property
    def verdict(self) -> str | None:
        """Strict mode: ``VALID`` (every claim passed), ``INCOMPLETE`` (nothing
        failed, something is not shown) or ``INVALID``; ``None`` otherwise."""
        if self.kind_ok is None:
            return None
        if not self.ok:
            return "INVALID"
        return "VALID" if all(claim.status == "pass" for _, claim in self.claims) else "INCOMPLETE"


def encode_fragment(bundle: Any) -> str:
    """Encode a Bundle as unpadded RFC 4648 base64url over UTF-8 JCS bytes."""
    return base64.urlsafe_b64encode(jcs(bundle)).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, refusing non-zero trailing bits.

    Without the round trip a byte string has several accepted spellings; Go
    (strict mode), Rust and TS accept only the canonical one.
    """
    raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise binascii.Error("non-canonical base64url")
    return raw


def decode_fragment(fragment: str) -> Any:
    """Decode an unpadded Evidence Bundle URL fragment.

    The codec is intentionally transport-only; :func:`verify_bundle` applies
    the Bundle object's semantic checks.
    """
    if not isinstance(fragment, str) or not _B64URL.fullmatch(fragment):
        raise ValueError("fragment must be unpadded base64url")
    try:
        raw = _b64url_decode(fragment)
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_checked_object,
        )
        _require_scalar_strings(value)
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as err:
        raise ValueError("fragment is not UTF-8 JSON") from err
    return value


def _reject_constant(name: str) -> Any:
    # NaN, Infinity and -Infinity are not JSON (RFC 8259); json.loads takes them.
    raise json.JSONDecodeError(f"{name} is not JSON", name, 0)


def _checked_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Check every member before a repeated name collapses to its last value,
    # so an earlier, overwritten value cannot hide an unpaired surrogate.
    for key, member in pairs:
        key.encode("utf-8")
        _require_scalar_strings(member)
    return dict(pairs)


def _require_scalar_strings(value: Any) -> None:
    """Reject an unpaired surrogate escape, which json.loads keeps in a str.

    Go, Rust and TypeScript refuse such a fragment; encoding each string (and
    member name) as UTF-8 raises on exactly those code points.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            for key, member in item.items():
                key.encode("utf-8")
                stack.append(member)


def bundle_digest(bundle: Any) -> str:
    """Return the v2 bundle digest, omitting only ``countersignatures``."""
    if not isinstance(bundle, Mapping):
        raise TypeError("bundle must be a JSON object")
    canonical = {key: value for key, value in bundle.items() if key != "countersignatures"}
    return hashlib.sha256(jcs(canonical)).hexdigest()


def verify_bundle(
    bundle: Any,
    *,
    strict: bool = False,
    require_signature: bool = False,
    witness_directory: Any = None,
    category_sets: Mapping[str, Sequence[str]] | None = None,
    category_request: bytes | None = None,
    record_categories: Mapping[str, str] | None = None,
) -> BundleVerificationResult:
    """Verify an AAC Evidence Bundle using only its supplied evidence.

    ``strict=True`` adds the checks a verifier handing a verdict to a person
    needs, and fills :attr:`BundleVerificationResult.verdict`:

    * each record's producer signature (``signatures``; an unsigned record is
      ``withheld`` unless ``require_signature``);
    * the checkpoint read only from its signed COSE form (``checkpoint``):
      ``withheld`` without one, ``fail`` when it does not verify or the JSON
      copy differs from it. Without a signed checkpoint the interval and
      membership claims are not shown, so the Bundle is never ``VALID``;
    * a producer-selected Bundle (``completeness.selection``
      ``producer-selected``, outside the Bundle draft): interval coverage is
      ``withheld`` and each record's own inclusion proof is checked;
    * the ``disclosures`` overlay as one claim, when the Bundle carries one;
    * the witness receipts in ``checkpoint.witnesses`` under the keys of
      ``witness_directory`` (:mod:`agent_action_capsule.witness`); ``None``
      trusts no witness.

    ``completeness_certificate`` uses the portable CLL-shaped form below.  The
    ``range_proof`` is checked with CLL #13's ``verify_range``, which binds
    every leaf in ``[first_seq, last_seq]`` (all ``body_digests`` participate in
    rebuilding the root, not just the two boundaries).  Its detached
    ``memberships`` map is keyed by Capsule ID and each value carries
    ``log_coordinates`` (``log_id``, ``seq``, ``leaf_index``) and an
    ``inclusion_proof`` — an independent per-record membership check.

    A ``category_coverage`` member is reported as five properties
    (:attr:`BundleVerificationResult.category_coverage`). ``category_sets``,
    ``category_request`` (the Evidence Request octets as received) and
    ``record_categories`` are the inputs a Bundle cannot carry for itself;
    see :func:`agent_action_capsule.category_coverage.check_category_coverage`.
    In strict mode a ``FAIL`` of its form, signature or consistency makes the
    verdict ``INVALID``; no property is ever combined into a score.
    """
    coverage_inputs = {
        "category_sets": category_sets,
        "category_request": category_request,
        "record_categories": record_categories,
    }
    try:
        return _verify_bundle(bundle, strict, require_signature, witness_directory, coverage_inputs)
    except RecursionError:
        # Nested deeper than the interpreter reads: refused, never raised.
        invalid = ClaimResult("fail", ("bundle_malformed",))
        result = BundleVerificationResult(None, invalid, invalid, invalid)
        if strict:
            result.kind_ok = False
            result.record_identity = invalid
        return result


def _verify_bundle(
    bundle: Any, strict: bool, require_signature: bool, witness_directory: Any, coverage_inputs: Mapping[str, Any]
) -> BundleVerificationResult:
    invalid = ClaimResult("fail", ("bundle_malformed",))
    if not isinstance(bundle, Mapping):
        result = BundleVerificationResult(None, invalid, invalid, invalid)
        if strict:
            result.kind_ok = False
            result.record_identity = ClaimResult("fail", ("not_an_evidence_bundle_v2",))
        return result

    try:
        digest = bundle_digest(bundle)
    except (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError):
        digest = None

    records, capsule_results, record_findings = _records(bundle.get("records"))
    graph = _verify_graph(bundle, records, record_findings)
    interval, membership = _verify_completeness(bundle, records)
    disclosures = _verify_disclosures(bundle["disclosures"] if "disclosures" in bundle else {}, records)
    extensions = _extensions(bundle.get("extensions"))
    countersignatures = bundle.get("countersignatures")
    result = BundleVerificationResult(
        digest,
        graph,
        interval,
        membership,
        disclosures,
        extensions,
        tuple(CountersignatureResult(value) for value in countersignatures) if isinstance(countersignatures, list) else (),
        ProducerSelfReport(bundle["verification"]) if "verification" in bundle else None,
        capsule_results,
    )
    from .category_coverage import check_category_coverage

    result.category_coverage = check_category_coverage(bundle, **coverage_inputs)
    if strict:
        _apply_strict(result, bundle, require_signature, witness_directory)
    return result


def _apply_strict(result: BundleVerificationResult, bundle: Mapping[str, Any], require_signature: bool, directory: Any) -> None:
    from .producer_envelope import INVALID, UNCLAIMED, verify_record_signature
    from .witness import verify_witness_receipts

    if bundle.get("bundle_kind") != BUNDLE_KIND or bundle.get("bundle_version") != "2":
        result.kind_ok = False
        result.record_identity = ClaimResult("fail", ("not_an_evidence_bundle_v2",))
        return
    result.kind_ok = True
    raw_records = bundle.get("records") if isinstance(bundle.get("records"), list) else []
    seqs = _membership_seqs(bundle)
    records: list[RecordResult] = []
    seen: set[str] = set()
    for record in raw_records:
        if not isinstance(record, Mapping):
            continue
        cid = record.get("capsule_id") if isinstance(record.get("capsule_id"), str) else ""
        verdict, messages = verify_record_signature(dict(record))
        # A repeated capsule_id is a second record the plain verifier skipped.
        aac = result.capsule_results.get(cid) if cid not in seen else None
        seen.add(cid)
        key_id = record.get("key_id")
        records.append(
            RecordResult(
                capsule_id=cid,
                identity_ok=bool(aac is not None and aac.ok and aac.capsule_id == cid),
                signature=verdict,
                key_id=key_id if isinstance(key_id, str) else None,
                seq=seqs.get(cid),
                messages=tuple(messages),
            )
        )
    result.records = tuple(records)
    result.record_identity = ClaimResult(
        "pass" if records and all(r.identity_ok for r in records) else "fail",
        tuple(f"record_identity_invalid:{r.capsule_id}" for r in records if not r.identity_ok)
        or (() if records else ("no_records",)),
    )

    invalid = [r for r in records if r.signature == INVALID]
    unclaimed = [r for r in records if r.signature == UNCLAIMED]
    signature_findings = tuple(
        [f"producer_signature_invalid:{r.capsule_id}" for r in invalid]
        + [f"producer_signature_unclaimed:{r.capsule_id}" for r in unclaimed]
    )
    if invalid or (unclaimed and require_signature) or not records:
        result.signatures = ClaimResult("fail", signature_findings)
    else:
        result.signatures = ClaimResult("withheld" if unclaimed else "pass", signature_findings)

    stated = bundle.get("checkpoint") if isinstance(bundle.get("checkpoint"), Mapping) else {}
    certificate = bundle.get("completeness_certificate")
    result.checkpoint, signed, cose = _strict_checkpoint(stated, certificate if isinstance(certificate, Mapping) else {})
    authenticated = result.checkpoint.status == "pass"

    if _producer_selected(bundle):
        # The certificate binds the producer's selection, not an interval: the
        # interval proof cannot be read, each record's own proof still can.
        result.interval_coverage = ClaimResult("withheld", ("selection_not_checkable",))
        if authenticated:
            result.per_record_membership = _selected_membership(bundle, signed["root"], signed["mmr_size"], signed["log_id"])
        elif result.checkpoint.status == "fail":
            # A signed checkpoint the stated copies contradict anchors nothing
            # (vectors/bundle/strict neg-producer-selected-*-log-id*).
            result.per_record_membership = (
                ClaimResult("fail", ("completeness_certificate_invalid",))
                if _range_member_without_range(bundle)
                else ClaimResult("withheld", ("checkpoint_unverified",))
            )
        # Without a signed checkpoint the plain reading stands: each proof
        # against the stated checkpoint, withheld below unless it failed, as
        # for a range Bundle.
    if not authenticated:
        result.interval_coverage = _unanchored(result.interval_coverage)
        result.per_record_membership = _unanchored(result.per_record_membership)

    if "disclosures" in bundle:
        failed = tuple(
            f"{d.status}:{d.capsule_id}:{d.member}"
            for d in result.disclosures
            if d.status not in (MATCH, "withheld")
        )
        result.disclosure_claim = ClaimResult("fail" if failed else "pass", failed)

    status, findings, receipts = verify_witness_receipts(
        stated.get("witnesses"), signed if authenticated else None, cose if authenticated else None, directory
    )
    result.witnesses = ClaimResult(status, findings)
    result.witness_receipts = receipts
    if authenticated:
        result.signed_checkpoint = {**signed, "witnesses": stated.get("witnesses") if isinstance(stated.get("witnesses"), list) else []}
        checkpoint_key = signed.get("key_id")
        if checkpoint_key and records:
            result.signer_matches_checkpoint = all(r.key_id == checkpoint_key for r in records)


def _same_json(a: Any, b: Any) -> bool:
    """JSON equality that keeps types apart (``1`` is not ``true`` or ``1.0``)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    return type(a) is type(b) and a == b


def _strict_checkpoint(
    stated: Mapping[str, Any], certificate: Mapping[str, Any]
) -> tuple[ClaimResult, dict[str, Any], bytes | None]:
    """Verify ``checkpoint.cose`` and hold the JSON copy, and the completeness
    certificate's ``log_id`` when stated, to it. Returns the claim and, when it
    passed, the signed fields and the COSE bytes."""
    encoded = stated.get("cose")
    if encoded is None:
        return ClaimResult("withheld", ("checkpoint_signature_absent",)), {}, None
    try:
        from cll.checkpoint import verify_checkpoint_cose_offline
    except ImportError:
        return ClaimResult("withheld", ("checkpoint_verifier_unavailable",)), {}, None
    try:
        if not isinstance(encoded, str) or not _B64URL.fullmatch(encoded):
            raise ValueError("checkpoint.cose is not unpadded base64url")
        cose = _b64url_decode(encoded)
        verified = verify_checkpoint_cose_offline(cose)
    except ImportError:
        # cll imports its COSE dependencies lazily.
        return ClaimResult("withheld", ("checkpoint_verifier_unavailable",)), {}, None
    except (ValueError, TypeError, binascii.Error):
        return ClaimResult("fail", ("checkpoint_signature_malformed",)), {}, None
    if not verified.ok or verified.decoded is None:
        return ClaimResult("fail", ("checkpoint_signature_invalid",)), {}, None
    signed = {name: getattr(verified.decoded, name) for name in _SIGNED_CHECKPOINT_FIELDS}
    mismatched = tuple(
        f"checkpoint_field_mismatch:{name}"
        for name in _SIGNED_CHECKPOINT_FIELDS
        if (name in stated and not _same_json(stated[name], signed[name]))
        # The certificate's log_id is a second stated copy of the signed one
        # (bundle -01 §Completeness): either copy differing is one mismatch.
        or (name == "log_id" and "log_id" in certificate and not _same_json(certificate["log_id"], signed[name]))
    )
    missing = tuple(f"checkpoint_field_missing:{name}" for name in ("log_id", "mmr_size", "root") if name not in stated)
    if mismatched or missing:
        return ClaimResult("fail", mismatched + missing), {}, None
    return ClaimResult("pass"), signed, cose


def _unanchored(claim: ClaimResult) -> ClaimResult:
    """A proof claim with no signed checkpoint behind it: a failure stays a
    failure; anything else is not shown."""
    if claim.status == "fail":
        return claim
    return ClaimResult("withheld", tuple(dict.fromkeys((*claim.findings, "checkpoint_unverified"))))


_RANGE = object()


def _selection(bundle: Mapping[str, Any]) -> Any:
    """``completeness.selection``, or ``_RANGE`` when the member is absent (a
    range certificate). A present ``null`` is a value, not an absence."""
    completeness = bundle.get("completeness")
    if not isinstance(completeness, Mapping) or "selection" not in completeness:
        return _RANGE
    return completeness["selection"]


def _producer_selected(bundle: Mapping[str, Any]) -> bool:
    return _selection(bundle) == SELECTION_PRODUCER_SELECTED


def _range_member_without_range(bundle: Mapping[str, Any]) -> bool:
    """A producer-selected certificate carrying ``non_record_leaves``: wrong on
    its face, with or without a signed checkpoint."""
    certificate = bundle.get("completeness_certificate")
    return isinstance(certificate, Mapping) and "non_record_leaves" in certificate


def _selected_membership(bundle: Mapping[str, Any], root_hex: Any, size: Any, log_id: Any) -> ClaimResult:
    """Each record's inclusion proof against ``root_hex`` and ``size``, for a
    producer-selected Bundle. A ``non_record_leaves`` member makes the
    certificate invalid: with no range there is no interval for it to cover."""
    certificate = bundle.get("completeness_certificate")
    members = certificate.get("memberships") if isinstance(certificate, Mapping) else None
    if (
        not isinstance(members, Mapping)
        or _range_member_without_range(bundle)
        or certificate.get("range_root") != root_hex
        or certificate.get("log_id") != log_id
        or not isinstance(log_id, str)
        or not isinstance(root_hex, str)
        or not _HEX64.fullmatch(root_hex)
        or not _safe_int(size)
    ):
        return ClaimResult("fail", ("completeness_certificate_invalid",))
    if not _cll_available():
        return ClaimResult("withheld", ("membership_verifier_unavailable",))
    from cll.checkpoint import verify_inclusion

    root = bytes.fromhex(root_hex)
    raw_records = bundle.get("records") if isinstance(bundle.get("records"), list) else []
    ids = [r["capsule_id"] if isinstance(r.get("capsule_id"), str) else "" for r in raw_records if isinstance(r, Mapping)]
    findings: list[str] = []
    seen: set[int] = set()
    for cid in ids:
        member = members.get(cid)
        coords = member.get("log_coordinates") if isinstance(member, Mapping) else None
        if not isinstance(coords, Mapping):
            findings.append(f"membership_record_unbound:{cid}")
            continue
        seq, index = coords.get("seq"), coords.get("leaf_index")
        if (
            coords.get("log_id") != log_id
            or not _safe_int(seq)
            or not _safe_int(index)
            or seq < 1
            or index != seq - 1
            or seq in seen
        ):
            findings.append(f"membership_coordinates_invalid:{cid}")
            continue
        seen.add(seq)
        try:
            proof = _inclusion_proof(member.get("inclusion_proof"))
            if proof.size != size or not verify_inclusion(root, size, index, bytes.fromhex(cid), proof):
                findings.append(f"membership_proof_invalid:{cid}")
        except (TypeError, ValueError, KeyError, AttributeError):
            findings.append(f"membership_proof_invalid:{cid}")
    findings += [f"membership_record_unknown:{cid}" for cid in sorted(members) if cid not in ids]
    return ClaimResult("fail" if findings else "pass", tuple(findings))


def _membership_seqs(bundle: Mapping[str, Any]) -> dict[str, int]:
    """Each record's ``seq`` as its membership's ``log_coordinates`` state it."""
    certificate = bundle.get("completeness_certificate")
    members = certificate.get("memberships") if isinstance(certificate, Mapping) else None
    out: dict[str, int] = {}
    if isinstance(members, Mapping):
        for cid, member in members.items():
            coords = member.get("log_coordinates") if isinstance(member, Mapping) else None
            seq = coords.get("seq") if isinstance(coords, Mapping) else None
            if _safe_int(seq):
                out[str(cid)] = seq
    return out


def _records(raw: Any) -> tuple[dict[str, Mapping[str, Any]], dict[str, Any], list[str]]:
    records: dict[str, Mapping[str, Any]] = {}
    results: dict[str, Any] = {}
    findings: list[str] = []
    if not isinstance(raw, list):
        return records, results, ["records_malformed"]
    for index, record in enumerate(raw):
        if not isinstance(record, Mapping):
            findings.append(f"record_malformed:{index}")
            continue
        capsule_id = record.get("capsule_id")
        if not isinstance(capsule_id, str) or not _HEX64.fullmatch(capsule_id):
            findings.append(f"record_identity_invalid:{index}")
            continue
        if capsule_id in records:
            findings.append(f"record_duplicate:{capsule_id}")
            continue
        result = verify(record)
        results[capsule_id] = result
        if not result.ok or result.capsule_id != capsule_id:
            findings.append(f"record_identity_invalid:{capsule_id}")
            continue
        records[capsule_id] = record
    return records, results, findings


def _safe_int(value: Any) -> bool:
    """A JSON integer within ±(2**53 - 1), the bound Go, Rust and TS apply.

    Python integers are unbounded, so without this a Bundle integer the other
    verifiers reject (for example a ``closure_depth`` of 2**60) is accepted.
    """
    return isinstance(value, int) and not isinstance(value, bool) and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER


def _verify_graph(bundle: Mapping[str, Any], records: Mapping[str, Mapping[str, Any]], record_findings: list[str]) -> ClaimResult:
    findings = list(record_findings)
    if bundle.get("bundle_version") != "2" or bundle.get("bundle_kind") != "evidence-bundle/v2":
        findings.append("bundle_version_or_kind_invalid")
    root = bundle.get("root")
    if not isinstance(root, str) or root not in records:
        findings.append("root_not_supplied_with_matching_identity")
        return ClaimResult("fail", tuple(findings))
    completeness = bundle.get("completeness")
    if not isinstance(completeness, Mapping):
        return ClaimResult("fail", tuple([*findings, "completeness_malformed"]))
    depth = completeness.get("closure_depth", 2)
    if isinstance(depth, bool) or not _safe_int(depth) or depth < 0:
        return ClaimResult("fail", tuple([*findings, "closure_depth_invalid"]))
    missing_raw = completeness.get("missing", [])
    if not isinstance(missing_raw, list) or any(not isinstance(x, str) or not _HEX64.fullmatch(x) for x in missing_raw):
        return ClaimResult("fail", tuple([*findings, "missing_malformed"]))
    missing = set(missing_raw)
    if len(missing) != len(missing_raw):
        findings.append("missing_duplicate")
    expected_mode = "declared_incomplete" if missing else "complete"
    if completeness.get("records_mode") != expected_mode:
        findings.append("records_mode_mismatch")

    # Breadth-first, each target once: a record first reached at its shortest
    # distance already carries the most remaining depth, and the walk stops when
    # no new record is reached, so work is bounded by the supplied records.
    frontier = [root]
    visited = {root}
    dangling: set[str] = set()
    level = 0
    while level < depth and frontier:
        next_frontier: list[str] = []
        for source_id in frontier:
            for target in _citation_targets(records[source_id]):
                if target in records:
                    if target not in visited:
                        visited.add(target)
                        next_frontier.append(target)
                elif target not in missing and target not in dangling:
                    dangling.add(target)
                    findings.append(f"citation_dangling:{target}")
        frontier = next_frontier
        level += 1
    if findings:
        return ClaimResult("fail", tuple(findings))
    if missing:
        return ClaimResult("withheld", ("declared_incomplete",))
    return ClaimResult("pass")


def _citation_targets(record: Mapping[str, Any]) -> list[str]:
    targets: list[str] = []
    chain = record.get("chain")
    if isinstance(chain, Mapping) and isinstance(chain.get("parent_capsule_id"), str):
        targets.append(chain["parent_capsule_id"])
    references = record.get("references")
    if isinstance(references, list):
        for reference in references:
            if (
                isinstance(reference, Mapping)
                and reference.get("type") == "agent-action-capsule"
                and reference.get("digest_alg") == "SHA-256"
                and isinstance(reference.get("digest"), str)
            ):
                targets.append(reference["digest"])
    return targets


def _verify_completeness(bundle: Mapping[str, Any], records: Mapping[str, Mapping[str, Any]]) -> tuple[ClaimResult, ClaimResult]:
    certificate = bundle.get("completeness_certificate")
    checkpoint = bundle.get("checkpoint")
    if not isinstance(certificate, Mapping) or not isinstance(checkpoint, Mapping):
        absent = ClaimResult("withheld", ("completeness_evidence_absent",))
        return absent, absent
    selection = _selection(bundle)
    if selection == SELECTION_PRODUCER_SELECTED:
        return _plain_selected(bundle, certificate, checkpoint)
    if selection is not _RANGE:
        # A certificate mode this verifier does not implement: not shown, and
        # never a failure (Bundle -02).
        unsupported = ClaimResult("withheld", (CERTIFICATE_MODE_UNSUPPORTED,))
        return unsupported, unsupported
    parsed = _certificate(certificate, checkpoint)
    if parsed is None:
        failure = ClaimResult("fail", ("completeness_certificate_invalid",))
        return failure, failure
    if not _cll_available():
        # The certificate is well formed, but the MMR proofs cannot be checked
        # without the CLL reference (the optional `bundle` extra). Fail closed
        # (never pass) without accusing the producer: "invalid" is reserved for
        # certificates that are actually wrong.
        unavailable = ClaimResult("fail", (COMPLETENESS_VERIFIER_UNAVAILABLE,))
        return unavailable, unavailable
    root, log_id, first_seq, last_seq, range_fields = parsed
    from cll.checkpoint import RangeProof

    range_proof = RangeProof(**range_fields)
    if not _verify_range(root, first_seq, last_seq, certificate, range_proof):
        failure = ClaimResult("fail", ("range_proof_invalid",))
        return failure, failure
    authentication = _authenticate_checkpoint(checkpoint, log_id, root, range_proof.size)
    if authentication == "invalid":
        failure = ClaimResult("fail", ("checkpoint_authentication_invalid",))
        return failure, failure
    # A root/size pair and proof are producer assertions until an independent
    # checkpoint authenticator is verified. Preserve the proof result, but
    # never present it as an unqualified completeness claim.
    interval = ClaimResult("pass") if authentication == "verified" else ClaimResult("pass", ("checkpoint_unverified",))
    membership_findings, failed = _verify_memberships(
        root,
        log_id,
        first_seq,
        last_seq,
        certificate,
        records,
        bundle.get("completeness"),
    )
    qualifier = () if authentication == "verified" else ("checkpoint_unverified",)
    if failed:
        return interval, ClaimResult("fail", tuple(membership_findings))
    if membership_findings:
        return interval, ClaimResult("withheld", (*membership_findings, *qualifier))
    return interval, ClaimResult("pass", qualifier)


def _plain_selected(
    bundle: Mapping[str, Any], certificate: Mapping[str, Any], checkpoint: Mapping[str, Any]
) -> tuple[ClaimResult, ClaimResult]:
    """A producer-selected Bundle without strict mode: no interval to check;
    each record's own proof against the stated checkpoint, qualified like a
    range Bundle's when the checkpoint's COSE form does not authenticate it."""
    interval = ClaimResult("withheld", ("selection_not_checkable",))
    membership = _selected_membership(bundle, checkpoint.get("root"), checkpoint.get("mmr_size"), checkpoint.get("log_id"))
    if membership.status != "pass":
        return interval, membership
    root_hex = checkpoint["root"]
    authentication = _authenticate_checkpoint(checkpoint, checkpoint.get("log_id"), bytes.fromhex(root_hex), checkpoint.get("mmr_size"))
    if authentication == "invalid":
        return interval, ClaimResult("fail", ("checkpoint_authentication_invalid",))
    return interval, ClaimResult("pass", () if authentication == "verified" else ("checkpoint_unverified",))


def _authenticate_checkpoint(checkpoint: Mapping[str, Any], log_id: str, root: bytes, size: int) -> str:
    """Verify an optional portable CLL COSE checkpoint; never trust its presence."""
    if "cose" not in checkpoint:
        return "unverified"
    encoded = checkpoint["cose"]
    if not isinstance(encoded, str) or not _B64URL.fullmatch(encoded):
        return "invalid"
    try:
        from cll.checkpoint import verify_checkpoint_cose_offline

        result = verify_checkpoint_cose_offline(_b64url_decode(encoded))
        decoded = result.decoded
        return (
            "verified"
            if result.ok
            and decoded is not None
            and decoded.log_id == log_id
            and decoded.mmr_size == size
            and decoded.root == root.hex()
            else "invalid"
        )
    except ImportError:
        # No COSE checkpoint authenticator here: the checkpoint stays producer
        # asserted (checkpoint_unverified), as in the TS verifier; it is not
        # evidence that the signature is bad.
        return "unverified"
    except (AttributeError, TypeError, ValueError, binascii.Error):
        return "invalid"


def _cll_available() -> bool:
    """Whether the CLL reference that verifies the MMR proofs is importable."""
    try:
        import cll.checkpoint  # noqa: F401
        import cll.checkpoint.index  # noqa: F401
    except ImportError:
        return False
    return True


def _certificate(certificate: Mapping[str, Any], checkpoint: Mapping[str, Any]) -> tuple[bytes, str, int, int, dict[str, Any]] | None:
    """Structurally validate the certificate without importing CLL.

    Returns ``None`` only for a certificate that is wrong on its face, so a
    verifier missing the CLL substrate still reports a malformed certificate as
    invalid and a well-formed one as unverifiable, never the other way round.
    """
    log_id = certificate.get("log_id")
    root_hex = certificate.get("range_root")
    first_seq = certificate.get("first_seq")
    last_seq = certificate.get("last_seq")
    if (
        not isinstance(log_id, str)
        or not isinstance(root_hex, str)
        or isinstance(first_seq, bool)
        or isinstance(last_seq, bool)
        or not _safe_int(first_seq)
        or not _safe_int(last_seq)
        or first_seq < 1
        or last_seq < first_seq
        or not _HEX64.fullmatch(root_hex)
        or checkpoint.get("root") != root_hex
    ):
        return None
    try:
        root = bytes.fromhex(root_hex)
        if len(root) != 32:
            return None
        range_fields = _range_proof_fields(certificate.get("range_proof"))
        checkpoint_size = checkpoint.get("mmr_size")
        if isinstance(checkpoint_size, bool) or not _safe_int(checkpoint_size) or checkpoint_size != range_fields["size"]:
            return None
        return root, log_id, first_seq, last_seq, range_fields
    except (TypeError, ValueError, KeyError):
        return None


def _verify_range(root: bytes, first_seq: int, last_seq: int, certificate: Mapping[str, Any], range_proof: Any) -> bool:
    try:
        from cll.checkpoint.index import verify_range

        # CLL #13 range membership binds EVERY leaf in [first_seq, last_seq], not
        # just the two boundaries: verify_range rebuilds the root from all body
        # digests plus the proof witness. body_digests[i] is the digest for seq
        # first_seq + i.
        raw = certificate.get("body_digests")
        if not isinstance(raw, list) or len(raw) != last_seq - first_seq + 1:
            return False
        # Canonical lowercase hex only (the drafts define digest fields as
        # lowercase-hex); bytes.fromhex would accept uppercase, diverging from
        # the TS verifier's lowercase gate.
        if any(not isinstance(digest, str) or not _HEX64.fullmatch(digest) for digest in raw):
            return False
        body_digests = [bytes.fromhex(digest) for digest in raw]
        return verify_range(root, first_seq, last_seq, body_digests, range_proof)
    except (ImportError, KeyError, TypeError, ValueError):
        return False


def _verify_memberships(
    root: bytes,
    log_id: str,
    first_seq: int,
    last_seq: int,
    certificate: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    completeness: Any,
) -> tuple[list[str], bool]:
    """Per-record membership over ``[first_seq, last_seq]``: every finding in
    report order, and whether any of them fails the claim (the others are
    ``non_record_leaf_type_unsupported``, which withhold it). Every seq of the
    interval is a record's membership, a non-record leaf, or
    ``membership_record_missing``."""
    raw = certificate.get("memberships")
    if not isinstance(raw, Mapping):
        return ["memberships_absent"], True
    by_seq: dict[int, str] = {}
    bound_records: set[str] = set()
    findings: list[str] = []
    for capsule_id, member in raw.items():
        if not isinstance(capsule_id, str) or capsule_id not in records or not isinstance(member, Mapping):
            findings.append(f"membership_record_unknown:{capsule_id}")
            continue
        coordinates = member.get("log_coordinates")
        if not isinstance(coordinates, Mapping):
            findings.append(f"membership_coordinates_missing:{capsule_id}")
            continue
        seq = coordinates.get("seq")
        leaf_index = coordinates.get("leaf_index")
        if (
            coordinates.get("log_id") != log_id
            or isinstance(seq, bool)
            or isinstance(leaf_index, bool)
            or not _safe_int(seq)
            or not _safe_int(leaf_index)
            or seq < first_seq
            or seq > last_seq
            or leaf_index != seq - 1
        ):
            findings.append(f"membership_coordinates_invalid:{capsule_id}")
            continue
        if seq in by_seq:
            findings.append(f"membership_seq_duplicate:{seq}")
            continue
        by_seq[seq] = capsule_id
        bound_records.add(capsule_id)
        try:
            from cll.checkpoint import verify_inclusion

            proof = _inclusion_proof(member.get("inclusion_proof"))
            if not verify_inclusion(root, proof.size, leaf_index, bytes.fromhex(capsule_id), proof):
                findings.append(f"membership_proof_invalid:{capsule_id}")
        except (ImportError, TypeError, ValueError, KeyError):
            findings.append(f"membership_proof_invalid:{capsule_id}")
    leaf_seqs: set[int] = set()
    unsupported = 0
    if "non_record_leaves" in certificate:
        leaf_findings, leaf_seqs = _non_record_leaves(
            certificate["non_record_leaves"], first_seq, last_seq, certificate.get("body_digests"), _stated_seqs(raw)
        )
        findings += leaf_findings
        unsupported = sum(f.startswith(_UNSUPPORTED_LEAF) for f in leaf_findings)
    for seq in range(first_seq, last_seq + 1):
        if seq not in by_seq and seq not in leaf_seqs:
            findings.append(f"membership_record_missing:{seq}")
    raw_missing = completeness.get("missing", []) if isinstance(completeness, Mapping) else []
    declared_missing = {c for c in raw_missing if isinstance(c, str)} if isinstance(raw_missing, list) else set()
    for capsule_id in records:
        if capsule_id not in bound_records and capsule_id not in declared_missing:
            findings.append(f"membership_record_unbound:{capsule_id}")
    return findings, len(findings) > unsupported


_UNSUPPORTED_LEAF = "non_record_leaf_type_unsupported:"


def _stated_seqs(memberships: Mapping[str, Any]) -> set[int]:
    """Every seq a ``memberships`` entry states in ``log_coordinates``, whatever
    else is wrong with the entry: a non-record leaf may not claim one."""
    out: set[int] = set()
    for member in memberships.values():
        coords = member.get("log_coordinates") if isinstance(member, Mapping) else None
        seq = coords.get("seq") if isinstance(coords, Mapping) else None
        if _safe_int(seq):
            out.add(seq)
    return out


def _non_record_leaves(
    raw: Any, first_seq: int, last_seq: int, body_digests: Any, record_seqs: set[int]
) -> tuple[list[str], set[int]]:
    """Check ``completeness_certificate.non_record_leaves`` (Bundle -02).

    Returns the findings in element order and the seqs the member accounts
    for. Every finding fails the claim except
    ``non_record_leaf_type_unsupported:<seq>``. An element whose ``seq`` is
    valid accounts for that seq whatever else it fails, so the seq is never
    also reported missing. ``body_digests`` has already been checked by the
    range proof."""
    if not isinstance(raw, list):
        return ["non_record_leaves_malformed"], set()
    findings: list[str] = []
    accounted: set[int] = set()
    for index, element in enumerate(raw):
        if not isinstance(element, Mapping):
            findings.append(f"non_record_leaf_element_invalid:{index}")
            continue
        seq = element.get("seq")
        if not _safe_int(seq) or not first_seq <= seq <= last_seq or seq in record_seqs or seq in accounted:
            findings.append(f"non_record_leaf_seq_invalid:{index}")
            continue
        accounted.add(seq)
        content = element.get("content")
        record_type = content.get("record_type") if isinstance(content, Mapping) else None
        if not isinstance(record_type, str):
            # Includes an element that carries a digest in place of content.
            findings.append(f"non_record_leaf_malformed:{seq}")
            continue
        if record_type != _PADDING:
            findings.append(f"{_UNSUPPORTED_LEAF}{seq}")
            continue
        if (
            set(content) != _PADDING_MEMBERS
            or content.get("epistemic_type") != "producer_claim"
            or not isinstance(content.get("store_nonce"), str)
            or not _HEX64.fullmatch(content["store_nonce"])
            or not isinstance(content.get("capsule_id"), str)
            or not _HEX64.fullmatch(content["capsule_id"])
        ):
            findings.append(f"non_record_leaf_malformed:{seq}")
            continue
        leaf = json_digest({k: v for k, v in content.items() if k != "capsule_id"})
        if leaf != content["capsule_id"] or leaf != body_digests[seq - first_seq]:
            findings.append(f"non_record_leaf_mismatch:{seq}")
    return findings, accounted


def _inclusion_proof(raw: Any) -> Any:
    from cll.checkpoint import InclusionProof

    if not isinstance(raw, Mapping):
        raise TypeError("inclusion proof must be an object")
    v = raw["v"]
    size = raw["size"]
    leaf_index = raw["leaf_index"]
    if (
        raw.get("kind") != "inclusion"
        or isinstance(v, bool)
        or isinstance(size, bool)
        or isinstance(leaf_index, bool)
        or not _safe_int(v)
        or not _safe_int(size)
        or not _safe_int(leaf_index)
        or v != 1
        or size < 0
        or leaf_index < 0
    ):
        raise ValueError("invalid inclusion proof")
    # Canonical lowercase hex for every node hash, so Go/Python/TS agree (the
    # drafts define digest fields as lowercase-hex; bytes.fromhex is otherwise lax).
    for hash_field in ("witness", "peaks_left", "peaks_right"):
        values = raw[hash_field]
        if not isinstance(values, list) or not all(isinstance(h, str) and _HEX64.fullmatch(h) for h in values):
            raise ValueError("invalid inclusion proof")
    return InclusionProof(
        v=v,
        kind=raw["kind"],
        size=size,
        leaf_index=leaf_index,
        witness=tuple(raw["witness"]),
        peaks_left=tuple(raw["peaks_left"]),
        peaks_right=tuple(raw["peaks_right"]),
    )


def _range_proof_fields(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise TypeError("range proof must be an object")
    from_seq = raw["from_seq"]
    to_seq = raw["to_seq"]
    size = raw["size"]
    from_index = raw["from_index"]
    to_index = raw["to_index"]
    witness = raw["witness"]
    if (
        isinstance(from_seq, bool)
        or isinstance(to_seq, bool)
        or isinstance(size, bool)
        or isinstance(from_index, bool)
        or isinstance(to_index, bool)
        or not _safe_int(from_seq)
        or not _safe_int(to_seq)
        or not _safe_int(size)
        or not _safe_int(from_index)
        or not _safe_int(to_index)
        or from_seq < 1
        or to_seq < from_seq
        or size < 0
        or from_index < 0
        or to_index < from_index
        or not isinstance(witness, list)
        or not all(isinstance(sibling, str) and _HEX64.fullmatch(sibling) for sibling in witness)
    ):
        raise ValueError("invalid range proof")
    # CLL #13 flat witness shape: (from_seq, to_seq, size, from_index, to_index,
    # witness). The retired (inclusion_from, inclusion_to) boundary pair is gone.
    return {
        "from_seq": from_seq,
        "to_seq": to_seq,
        "size": size,
        "from_index": from_index,
        "to_index": to_index,
        "witness": tuple(witness),
    }


def _verify_disclosures(raw: Any, records: Mapping[str, Mapping[str, Any]]) -> list[DisclosureResult]:
    if not isinstance(raw, Mapping):
        return [DisclosureResult("", "", MISMATCH)]
    findings: list[DisclosureResult] = []
    # Report every actually committed eligible member.  Absence from the
    # overlay is an explicit WITHHELD state, never a digest failure.
    for capsule_id, record in sorted(records.items()):
        supplied = raw.get(capsule_id, {})
        if not isinstance(supplied, Mapping):
            continue
        for member, path in DISCLOSURE_ELIGIBLE_FIELDS.items():
            if member not in supplied and isinstance(_committed_digest(record, path), str):
                findings.append(DisclosureResult(capsule_id, member, "withheld"))
    for capsule_id in sorted(raw):
        members = raw[capsule_id]
        record = records.get(capsule_id)
        if not isinstance(members, Mapping) or record is None:
            findings.append(DisclosureResult(str(capsule_id), "", MISMATCH))
            continue
        for member in sorted(members):
            value = members[member]
            path = DISCLOSURE_ELIGIBLE_FIELDS.get(member)
            if path is None:
                findings.append(DisclosureResult(capsule_id, member, INELIGIBLE))
                continue
            stored = _committed_digest(record, path)
            if not isinstance(stored, str) or not _HEX64.fullmatch(stored):
                findings.append(DisclosureResult(capsule_id, member, NO_COMMITTED_DIGEST))
                continue
            try:
                computed = hashlib.sha256(jcs(value)).hexdigest()
                status = MATCH if computed == stored else MISMATCH
            except (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError):
                status = MISMATCH
            findings.append(DisclosureResult(capsule_id, member, status))
    return findings


def _extensions(raw: Any) -> list[ExtensionResult]:
    if not isinstance(raw, Mapping):
        return []
    return [ExtensionResult(kind) for kind in sorted(raw)]


# -- the producer ----------------------------------------------------------------
#
# ``build_evidence_bundle`` assembles a Bundle from a ``ProofSource`` and checks
# the result with ``verify_bundle(strict=True)`` before returning it. It holds
# no key and trusts nothing the source returns: the checkpoint is verified from
# its COSE form, and every proof and record is checked by the strict verifier.


class BundleBuildError(ValueError):
    """The producer refused to build the Bundle; the message says why."""


@dataclass(frozen=True)
class StoredRecord:
    """A record as a store holds it: the Capsule's JSON bytes and its Producer
    Envelope bytes (empty when the record is unsigned)."""

    capsule: bytes
    producer_envelope: bytes = b""


class ProofSource(Protocol):
    """The read-only proof material ``build_evidence_bundle`` reads.

    - ``checkpoint()``: the signed CLL COSE checkpoint the Bundle is built
      against.
    - ``leaves()``: the 32-byte value of every leaf, seq ``1`` to
      ``leaf_count(mmr_size)``, in order; a record's value is its Capsule ID.
    - ``record(capsule_id)``: the stored record (an object with ``capsule`` and
      ``producer_envelope`` bytes), or ``None`` when the log does not hold that
      leaf as a record. Any other failure raises.
    - ``inclusion_proof(seq)``: the inclusion proof for that leaf at the
      checkpoint's size, in the Bundle's ``inclusion_proof`` wire shape.
    - ``range_proof(first_seq)``: the range proof over ``[first_seq, tip]``, in
      the Bundle's ``range_proof`` wire shape.

    Optional capability: ``leaf_content(seq)``, the content of a leaf that is
    not a record (a padding record's four members), or ``None`` when the
    source does not hold it. ``build_evidence_bundle`` reads it only with
    ``carry_non_record_leaves=True``; a source without it builds exactly as
    before.
    """

    def checkpoint(self) -> bytes: ...

    def leaves(self) -> Sequence[bytes]: ...

    def record(self, capsule_id: str) -> Any: ...

    def inclusion_proof(self, seq: int) -> Mapping[str, Any]: ...

    def range_proof(self, first_seq: int) -> Mapping[str, Any]: ...


#: Extension kinds this package owns; ``extensions`` cannot set them.
_OWNED_EXTENSIONS = ("producer-key/v1", "composed/v1")
_PAYLOADS_MODES = ("all", "selected")


def _proof_wire(proof: Any) -> dict[str, Any]:
    return {k: list(v) if isinstance(v, tuple) else v for k, v in proof.__dict__.items()}


class _CllProofSource:
    """``proof_source_from_cll``'s source: a CLL backend's entries and latest
    checkpoint state, with records from ``records``."""

    def __init__(self, backend: Any, records: Any) -> None:
        from cll.checkpoint import MemoryNodeStore

        self._backend, self._records = backend, records
        state = backend.load_cll()
        self._checkpoint = state.checkpoint
        self._nodes = MemoryNodeStore()
        self._nodes.append_nodes(list(state.nodes))

    def checkpoint(self) -> bytes:
        if self._checkpoint is None:
            raise BundleBuildError("the log has no checkpoint: nothing can be proven until one is cut")
        return bytes(self._checkpoint.bytes)

    def leaves(self) -> list[bytes]:
        if self._checkpoint is None:
            return []
        out: list[bytes] = []
        while len(out) < self._checkpoint.indexed_seq:
            page = self._backend.scan_entries(len(out), min(1000, self._checkpoint.indexed_seq - len(out)))
            if not page:
                break
            out.extend(bytes(entry.value) for entry in page)
        return out

    def record(self, capsule_id: str) -> Any:
        try:
            return self._records.get(capsule_id)
        except Exception as exc:  # the artifact-store contract's not-found code
            if getattr(exc, "code", None) == "not_found":
                return None
            raise

    def inclusion_proof(self, seq: int) -> dict[str, Any]:
        from cll.checkpoint import core

        return _proof_wire(core.inclusion_proof(self._nodes, seq - 1, self._checkpoint.size))

    def range_proof(self, first_seq: int) -> dict[str, Any]:
        from cll.checkpoint import core

        tip = core.leaf_count(self._checkpoint.size)
        proof = core.range_proof(self._nodes, first_seq - 1, tip - 1, self._checkpoint.size)
        return {
            "from_seq": first_seq,
            "to_seq": tip,
            "size": proof.size,
            "from_index": proof.from_index,
            "to_index": proof.to_index,
            "witness": list(proof.witness),
        }


def proof_source_from_cll(backend: Any, records: Any) -> ProofSource:
    """A ``ProofSource`` over a CLL backend (``scan_entries`` and ``load_cll``)
    and a record store: ``records.get(capsule_id)`` returns an object with
    ``capsule`` and ``producer_envelope`` bytes and raises an error whose
    ``code`` is ``"not_found"`` for a record it does not hold. The proofs are
    built from the backend's MMR nodes at the latest checkpoint's size. The
    backend state is read once, here: the source serves one consistent
    snapshot, so build from a fresh source after the log moves on."""
    return _CllProofSource(backend, records)


def _committed_members(record: Mapping[str, Any]) -> set[str]:
    return {
        member
        for member, path in DISCLOSURE_ELIGIBLE_FIELDS.items()
        if isinstance(_committed_digest(record, path), str)
    }


def _check_options(
    closure_depth: Any,
    disclosures: Mapping[str, Any],
    suppressed_fields: Sequence[str],
    payloads_mode: Any,
    extensions: Mapping[str, Any],
    include: Any = (),
    producer_key: Any = None,
    verification: Any = None,
) -> None:
    if not isinstance(include, (list, tuple)) or not all(isinstance(cid, str) for cid in include):
        raise BundleBuildError("include must be a list of Capsule IDs")
    if producer_key is not None and (not isinstance(producer_key, (bytes, bytearray)) or len(producer_key) != 32):
        raise BundleBuildError("producer_key must be a raw 32-byte Ed25519 public key")
    if verification is not None and not isinstance(verification, Mapping):
        raise BundleBuildError("verification must be a JSON object")
    if not _safe_int(closure_depth) or closure_depth < 0:
        raise BundleBuildError("closure_depth must be a non-negative safe integer")
    if payloads_mode is not None and payloads_mode not in _PAYLOADS_MODES:
        raise BundleBuildError(f"payloads_mode must be one of {_PAYLOADS_MODES}")
    ineligible = sorted(set(suppressed_fields) - set(DISCLOSURE_ELIGIBLE_FIELDS))
    if ineligible:
        raise BundleBuildError(f"suppressed_fields names members that are not disclosure-eligible: {ineligible}")
    for cid, members in disclosures.items():
        if not isinstance(members, Mapping):
            raise BundleBuildError(f"disclosures[{cid}] is not an object")
        bad = sorted(set(members) - set(DISCLOSURE_ELIGIBLE_FIELDS))
        if bad:
            raise BundleBuildError(f"disclosures[{cid}] names members that are not disclosure-eligible: {bad}")
        both = sorted(set(members) & set(suppressed_fields))
        if both:
            raise BundleBuildError(f"disclosures[{cid}] reveals member(s) declared suppressed: {both}")
    owned = sorted(set(extensions) & set(_OWNED_EXTENSIONS))
    if owned:
        raise BundleBuildError(f"extensions cannot set kinds this producer owns: {owned}")


def _closure(root: str, depth: int, lookup: Any) -> tuple[dict[str, dict], list[str]]:
    """Records reached from ``root`` within ``depth`` citation edges (root
    included), and the targets ``lookup`` does not hold, in first-seen order:
    the traversal ``verify_bundle`` checks graph closure with."""
    root_record = lookup(root)
    if root_record is None:
        raise BundleBuildError(f"root {root}: no such record")
    found = {root: root_record}
    missing: list[str] = []
    frontier = [root]
    for _ in range(depth):
        if not frontier:
            break
        next_frontier: list[str] = []
        for source in frontier:
            for target in _citation_targets(found[source]):
                if target in found or target in missing:
                    continue
                record = lookup(target)
                if record is None:
                    missing.append(target)
                else:
                    found[target] = record
                    next_frontier.append(target)
        frontier = next_frontier
    return found, missing


def _check_canonical(**inputs: Any) -> None:
    """Refuse caller JSON with no canonical form (a fractional number, an
    integer beyond 2**53 - 1, or nesting too deep) before any source is read."""
    for name, value in inputs.items():
        try:
            jcs(value)
        except (RecursionError, FloatInDigestError, UnsafeIntegerError, TypeError, ValueError) as exc:
            raise BundleBuildError(
                f"the bundle has no canonical digest: {name} holds JSON that does not canonicalize "
                "(a fractional number, an integer beyond 2**53 - 1, or nesting too deep)"
            ) from exc


def _completeness(
    records: Sequence[Mapping[str, Any]],
    closure_depth: int,
    missing: list[str],
    disclosures: Mapping[str, Mapping[str, Any]],
    suppressed_fields: Sequence[str],
    payloads_mode: str | None,
) -> dict[str, Any]:
    suppressed = set(suppressed_fields)
    unrevealed = [
        (r["capsule_id"], member)
        for r in records
        for member in sorted(_committed_members(r) - suppressed)
        if member not in (disclosures.get(r["capsule_id"]) or {})
    ]
    if payloads_mode == "all" and disclosures:
        gaps = [(cid, member) for cid, member in unrevealed if cid in disclosures]
        if gaps:
            raise BundleBuildError(f"payloads_mode all, but the disclosures overlay does not reveal: {gaps}")
    if payloads_mode is None:
        payloads_mode = "selected" if unrevealed else "all"
    return {
        "closure_depth": closure_depth,
        "records_mode": "declared_incomplete" if missing else "complete",
        "payloads_mode": payloads_mode,
        "suppressed_fields": sorted(suppressed),
        "missing": list(missing),
    }


def _inclusion_proof_wire(seq: int, raw: Any) -> dict[str, Any]:
    """A source's inclusion proof, parsed as the verifier parses it; only the
    wire fields are kept."""
    try:
        return _proof_wire(_inclusion_proof(raw))
    except (KeyError, TypeError, ValueError) as exc:
        raise BundleBuildError(f"the source's inclusion proof for seq {seq} is malformed") from exc


def _range_proof_wire(raw: Any) -> dict[str, Any]:
    """A source's range proof, parsed as the verifier parses it; only the
    wire fields are kept."""
    try:
        fields = _range_proof_fields(raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise BundleBuildError("the source's range proof is malformed") from exc
    return {**fields, "witness": list(fields["witness"])}


def _decode_record(capsule_id: str, stored: Any) -> dict[str, Any]:
    """The stored record as a Bundle carries it: the Capsule, with a claimed
    Producer Envelope re-inlined as its local-only ``signature`` and
    ``key_id`` (both outside the ``capsule_id`` preimage)."""
    from .producer_envelope import verify_producer_envelope

    try:
        capsule = json.loads(bytes(stored.capsule), object_pairs_hook=_checked_object)
    except (AttributeError, TypeError, ValueError) as exc:
        raise BundleBuildError(f"record {capsule_id}: the stored capsule is not a JSON object ({exc})") from exc
    if not isinstance(capsule, dict) or capsule.get("capsule_id") != capsule_id:
        raise BundleBuildError(f"record {capsule_id}: the store returned a different capsule")
    # Only a verified envelope may claim authorship: inline copies are dropped.
    capsule.pop("signature", None)
    capsule.pop("key_id", None)
    envelope = bytes(getattr(stored, "producer_envelope", b"") or b"")
    if envelope:
        checked = verify_producer_envelope(capsule_id, envelope)
        if not checked.ok or checked.public_key is None:
            raise BundleBuildError(f"record {capsule_id}: its producer envelope does not verify")
        capsule["signature"] = envelope.hex()
        capsule["key_id"] = checked.public_key.hex()
    return capsule


def build_evidence_bundle(
    source: ProofSource,
    *,
    root: str,
    interval_from: int | None,
    closure_depth: int = 2,
    include: Sequence[str] = (),
    disclosures: Mapping[str, Mapping[str, Any]] | None = None,
    suppressed_fields: Sequence[str] = (),
    payloads_mode: str | None = None,
    producer_key: bytes | None = None,
    extensions: Mapping[str, Any] | None = None,
    verification: Mapping[str, Any] | None = None,
    carry_non_record_leaves: bool = False,
) -> dict[str, Any]:
    """Build an Evidence Bundle around ``root`` from ``source``.

    ``interval_from`` is required: the first seq of a range proof that ends at
    the checkpoint tip, carrying every record in ``[interval_from, tip]`` and
    none below it; or ``None`` for no range proof, each record proven alone
    (``completeness.selection: "producer-selected"``, which ``verify_bundle``
    reads as INCOMPLETE). ``closure_depth`` is the citation depth from
    ``root``; ``include`` names further records to carry. ``disclosures`` is
    the Bundle-level overlay. ``payloads_mode`` (``all`` or ``selected``) is
    derived from the overlay when not given; a given ``all`` must reveal every
    committed, unsuppressed member of each record the overlay discloses.
    ``producer_key`` (raw 32-byte Ed25519) adds ``producer-key/v1``;
    ``extensions`` adds blocks of any other kind; ``verification`` carries the
    producer's self-report.

    ``carry_non_record_leaves`` lets a range cover a padding leaf: the source's
    ``leaf_content(seq)`` is carried in ``completeness_certificate.
    non_record_leaves`` (Bundle -02). It is off by default because a verifier
    that predates -02 reads such a Bundle as missing those seqs; turn it on only
    for readers that check the member.

    Requires checkpointed-local-log (the ``bundle`` extra). Raises
    :class:`BundleBuildError` on every refusal, including any result
    ``verify_bundle(strict=True)`` calls INVALID; a declared-incomplete
    closure or an unsigned record is stated, not refused.
    """
    try:
        from cll.checkpoint import leaf_count, verify_checkpoint_cose_offline
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise BundleBuildError("building a Bundle needs checkpointed-local-log: install agent-action-capsule[bundle]") from exc

    if extensions is not None and not isinstance(extensions, Mapping):
        raise BundleBuildError("extensions must be a JSON object")
    disclosures = {k: dict(v) if isinstance(v, Mapping) else v for k, v in (disclosures or {}).items()}
    extensions = dict(extensions or {})
    _check_options(closure_depth, disclosures, suppressed_fields, payloads_mode, extensions, include, producer_key, verification)
    _check_canonical(disclosures=disclosures, extensions=extensions, verification=verification or {})
    if interval_from is not None and (isinstance(interval_from, bool) or not isinstance(interval_from, int) or interval_from < 1):
        raise BundleBuildError("interval_from must be a seq of at least 1, or None for no range proof")

    cose = bytes(source.checkpoint())
    checked = verify_checkpoint_cose_offline(cose)
    if not checked.ok or checked.decoded is None:
        raise BundleBuildError(f"the checkpoint does not verify: {'; '.join(map(str, checked.errors))}")
    signed = checked.decoded
    tip = leaf_count(signed.mmr_size)
    leaves = [bytes(v) for v in source.leaves()]
    if len(leaves) != tip or any(len(v) != 32 for v in leaves):
        raise BundleBuildError(f"the source gave {len(leaves)} leaves; the checkpoint covers {tip} 32-byte leaves")
    seq_of: dict[str, int] = {}
    for seq, value in enumerate(leaves, 1):
        seq_of.setdefault(value.hex(), seq)

    def lookup(capsule_id: str) -> dict[str, Any] | None:
        stored = source.record(capsule_id)
        if stored is None:
            return None
        if capsule_id not in seq_of:
            raise BundleBuildError(
                f"record {capsule_id} is not a leaf at or below the checkpoint (not yet covered, or not in this log)"
            )
        return _decode_record(capsule_id, stored)

    carried, missing = _closure(root, closure_depth, lookup)
    for capsule_id in include:
        if capsule_id not in carried:
            record = lookup(capsule_id)
            if record is None:
                raise BundleBuildError(f"include: no such record: {capsule_id}")
            carried[capsule_id] = record

    certificate: dict[str, Any] = {"log_id": signed.log_id, "range_root": signed.root}
    if interval_from is not None:
        if interval_from > tip:
            raise BundleBuildError(f"interval_from {interval_from} is past the checkpoint tip {tip}")
        below = sorted((seq_of[cid], cid) for cid in carried if seq_of[cid] < interval_from)
        if below:
            named = ", ".join(f"{cid} (seq {seq})" for seq, cid in below)
            raise BundleBuildError(f"record(s) below interval_from {interval_from}: {named}; lower it or build without a range")
        non_record: list[dict[str, Any]] = []
        for seq in range(interval_from, tip + 1):
            capsule_id = leaves[seq - 1].hex()
            if capsule_id in carried:
                continue
            record = lookup(capsule_id)
            if record is None:
                content = _padding_content(source, seq, capsule_id) if carry_non_record_leaves else None
                if content is None:
                    raise BundleBuildError(
                        f"seq {seq} in the interval is not a record the source holds; a range cannot cover it: "
                        "start the interval after it or build without a range"
                    )
                non_record.append({"seq": seq, "content": content})
                continue
            carried[capsule_id] = record
        certificate.update(
            {
                "first_seq": interval_from,
                "last_seq": tip,
                "body_digests": [leaves[seq - 1].hex() for seq in range(interval_from, tip + 1)],
                "range_proof": _range_proof_wire(source.range_proof(interval_from)),
            }
        )
        if non_record:
            certificate["non_record_leaves"] = non_record

    ordered = sorted(carried, key=lambda cid: seq_of[cid])
    unknown = sorted(set(disclosures) - set(ordered))
    if unknown:
        raise BundleBuildError(f"disclosures given for record(s) the bundle does not carry: {unknown}")
    records = [carried[cid] for cid in ordered]
    certificate["memberships"] = {
        cid: {
            "log_coordinates": {"log_id": signed.log_id, "seq": seq_of[cid], "leaf_index": seq_of[cid] - 1},
            "inclusion_proof": _inclusion_proof_wire(seq_of[cid], source.inclusion_proof(seq_of[cid])),
        }
        for cid in ordered
    }
    completeness = _completeness(records, closure_depth, missing, disclosures, suppressed_fields, payloads_mode)
    if interval_from is None:
        completeness["selection"] = SELECTION_PRODUCER_SELECTED
    bundle: dict[str, Any] = {
        "bundle_version": "2",
        "bundle_kind": BUNDLE_KIND,
        "root": root,
        "records": records,
        "completeness": completeness,
        "completeness_certificate": certificate,
        "checkpoint": {
            "log_id": signed.log_id,
            "mmr_size": signed.mmr_size,
            "root": signed.root,
            "prev_size": signed.prev_size,
            "prev_root": signed.prev_root,
            "key_id": signed.key_id,
            "timestamp": signed.timestamp,
            "cose": base64.urlsafe_b64encode(cose).rstrip(b"=").decode("ascii"),
        },
    }
    if disclosures:
        bundle["disclosures"] = copy.deepcopy(disclosures)
    if producer_key is not None:
        extensions["producer-key/v1"] = {"public_key": bytes(producer_key).hex()}
    if extensions:
        bundle["extensions"] = copy.deepcopy(extensions)
    if verification is not None:
        bundle["verification"] = copy.deepcopy(dict(verification))
    return _self_checked(bundle)


def _padding_content(source: Any, seq: int, leaf_hex: str) -> dict[str, Any] | None:
    """The source's content for a non-record leaf, when it is a padding record
    whose recomputed ``capsule_id`` is that leaf; ``None`` when the source has
    no ``leaf_content`` or holds nothing for ``seq``. Any other content is
    refused by name: the producer carries padding only."""
    reader = getattr(source, "leaf_content", None)
    if reader is None:
        return None
    content = reader(seq)
    if content is None:
        return None
    if not isinstance(content, Mapping) or content.get("record_type") != _PADDING:
        raise BundleBuildError(f"seq {seq}: the source's leaf content is not a padding record; a range cannot cover it")
    # Local-only producer envelope members are outside the leaf's preimage.
    content = {k: v for k, v in content.items() if k not in ("signature", "key_id")}
    try:
        leaf = json_digest({k: v for k, v in content.items() if k != "capsule_id"})
    except (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError) as exc:
        raise BundleBuildError(f"seq {seq}: the padding record has no canonical digest") from exc
    if leaf != leaf_hex or content.get("capsule_id") != leaf_hex:
        raise BundleBuildError(f"seq {seq}: the padding record does not hash to the leaf")
    return copy.deepcopy(dict(content))


def _self_checked(bundle: dict[str, Any]) -> dict[str, Any]:
    result = verify_bundle(bundle, strict=True)
    if result.bundle_digest is None:
        raise BundleBuildError(
            "the bundle has no canonical digest: it holds JSON that does not canonicalize "
            "(a fractional number, an integer beyond 2**53 - 1, or nesting too deep)"
        )
    if result.verdict == "INVALID":
        failed = [f"{name}: {', '.join(claim.findings) or claim.status}" for name, claim in result.claims if claim.status == "fail"]
        raise BundleBuildError(f"the bundle does not verify: {'; '.join(failed) or 'not an evidence bundle'}")
    return bundle


def build_unproven_bundle(
    records: Sequence[Mapping[str, Any]],
    *,
    root: str,
    closure_depth: int = 2,
    disclosures: Mapping[str, Mapping[str, Any]] | None = None,
    suppressed_fields: Sequence[str] = (),
) -> dict[str, Any]:
    """An Evidence Bundle with no log proof: no checkpoint and no certificate,
    for Capsules that belong to no log. Every given record is carried; the
    closure from ``root`` decides ``missing``. ``verify_bundle(strict=True)``
    reads it as INCOMPLETE."""
    disclosures = {k: dict(v) if isinstance(v, Mapping) else v for k, v in (disclosures or {}).items()}
    _check_options(closure_depth, disclosures, suppressed_fields, None, {})
    ids = [r.get("capsule_id") if isinstance(r, Mapping) else None for r in records]
    if not all(isinstance(cid, str) for cid in ids):
        raise BundleBuildError("every record needs a capsule_id")
    if len(set(ids)) != len(ids):
        raise BundleBuildError("duplicate capsule_id among the records")
    by_id = {cid: dict(r) for cid, r in zip(ids, records)}
    if root not in by_id:
        raise BundleBuildError(f"root {root} is not among the records")
    unknown = sorted(set(disclosures) - set(ids))
    if unknown:
        raise BundleBuildError(f"disclosures given for record(s) the bundle does not carry: {unknown}")
    _check_canonical(records=list(by_id.values()), disclosures=disclosures)
    _, missing = _closure(root, closure_depth, by_id.get)
    bundle: dict[str, Any] = {
        "bundle_version": "2",
        "bundle_kind": BUNDLE_KIND,
        "root": root,
        "records": [copy.deepcopy(by_id[cid]) for cid in ids],
        "completeness": _completeness(list(by_id.values()), closure_depth, missing, disclosures, suppressed_fields, None),
    }
    if disclosures:
        bundle["disclosures"] = copy.deepcopy(disclosures)
    return _self_checked(bundle)
