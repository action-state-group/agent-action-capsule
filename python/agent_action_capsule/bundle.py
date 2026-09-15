# SPDX-License-Identifier: BSD-3-Clause
"""Pure AAC Evidence Bundle codec and verifier.

The verifier deliberately reports graph closure, interval coverage, and
per-record membership separately.  The CLL range proof used for interval
coverage authenticates only the interval endpoints; ``memberships`` therefore
contains one detached proof per record.  Keeping those proofs outside the
enclosed Capsule is necessary: embedding a proof in a Capsule would change
the Capsule ID which is itself the MMR leaf.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import FloatInDigestError, UnsafeIntegerError, jcs
from .disclosure_envelope import (
    INELIGIBLE,
    MATCH,
    MISMATCH,
    NO_COMMITTED_DIGEST,
    _committed_digest,
)
from .registries import DISCLOSURE_ELIGIBLE_FIELDS
from .verify import verify

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
]

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


@dataclass
class BundleVerificationResult:
    """Structured result for a bundle without collapsing completeness claims."""

    bundle_digest: str | None
    graph_closure: ClaimResult
    interval_coverage: ClaimResult
    per_record_membership: ClaimResult
    disclosures: list[DisclosureResult] = field(default_factory=list)
    extensions: list[ExtensionResult] = field(default_factory=list)
    countersignatures: tuple[CountersignatureResult, ...] = ()
    verification: ProducerSelfReport | None = None
    capsule_results: dict[str, Any] = field(default_factory=dict)


def encode_fragment(bundle: Any) -> str:
    """Encode a Bundle as unpadded RFC 4648 base64url over UTF-8 JCS bytes."""
    return base64.urlsafe_b64encode(jcs(bundle)).rstrip(b"=").decode("ascii")


def decode_fragment(fragment: str) -> Any:
    """Decode an unpadded Evidence Bundle URL fragment.

    The codec is intentionally transport-only; :func:`verify_bundle` applies
    the Bundle object's semantic checks.
    """
    if not isinstance(fragment, str) or not _B64URL.fullmatch(fragment):
        raise ValueError("fragment must be unpadded base64url")
    try:
        raw = base64.b64decode(fragment + "=" * (-len(fragment) % 4), altchars=b"-_", validate=True)
        return json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ValueError("fragment is not UTF-8 JSON") from err


def bundle_digest(bundle: Any) -> str:
    """Return the v2 bundle digest, omitting only ``countersignatures``."""
    if not isinstance(bundle, Mapping):
        raise TypeError("bundle must be a JSON object")
    canonical = {key: value for key, value in bundle.items() if key != "countersignatures"}
    return hashlib.sha256(jcs(canonical)).hexdigest()


def verify_bundle(bundle: Any) -> BundleVerificationResult:
    """Verify an AAC Evidence Bundle using only its supplied evidence.

    ``completeness_certificate`` uses the portable CLL-shaped form below.  The
    ``range_proof`` is checked with CLL #13's ``verify_range``, which binds
    every leaf in ``[first_seq, last_seq]`` (all ``body_digests`` participate in
    rebuilding the root, not just the two boundaries).  Its detached
    ``memberships`` map is keyed by Capsule ID and each value carries
    ``log_coordinates`` (``log_id``, ``seq``, ``leaf_index``) and an
    ``inclusion_proof`` — an independent per-record membership check.
    """
    invalid = ClaimResult("fail", ("bundle_malformed",))
    if not isinstance(bundle, Mapping):
        return BundleVerificationResult(None, invalid, invalid, invalid)

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
    return BundleVerificationResult(
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
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
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

    frontier = [root]
    for _ in range(depth):
        next_frontier: list[str] = []
        for source_id in frontier:
            source = records.get(source_id)
            if source is None:
                continue
            for target in _citation_targets(source):
                if target in records:
                    next_frontier.append(target)
                elif target not in missing:
                    findings.append(f"citation_dangling:{target}")
        frontier = next_frontier
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
    parsed = _certificate(certificate, checkpoint)
    if parsed is None:
        failure = ClaimResult("fail", ("completeness_certificate_invalid",))
        return failure, failure
    root, log_id, first_seq, last_seq, range_proof = parsed
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
    membership_findings = _verify_memberships(
        root,
        log_id,
        first_seq,
        last_seq,
        certificate.get("memberships"),
        records,
        bundle.get("completeness"),
    )
    membership = ClaimResult("pass") if authentication == "verified" else ClaimResult("pass", ("checkpoint_unverified",))
    return interval, membership if not membership_findings else ClaimResult("fail", tuple(membership_findings))


def _authenticate_checkpoint(checkpoint: Mapping[str, Any], log_id: str, root: bytes, size: int) -> str:
    """Verify an optional portable CLL COSE checkpoint; never trust its presence."""
    if "cose" not in checkpoint:
        return "unverified"
    encoded = checkpoint["cose"]
    if not isinstance(encoded, str) or not _B64URL.fullmatch(encoded):
        return "invalid"
    try:
        from cll.checkpoint import verify_checkpoint_cose_offline

        result = verify_checkpoint_cose_offline(
            base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        )
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
    except (ImportError, AttributeError, TypeError, ValueError, binascii.Error):
        return "invalid"


def _certificate(certificate: Mapping[str, Any], checkpoint: Mapping[str, Any]) -> tuple[bytes, str, int, int, Any] | None:
    log_id = certificate.get("log_id")
    root_hex = certificate.get("range_root")
    first_seq = certificate.get("first_seq")
    last_seq = certificate.get("last_seq")
    if (
        not isinstance(log_id, str)
        or not isinstance(root_hex, str)
        or isinstance(first_seq, bool)
        or isinstance(last_seq, bool)
        or not isinstance(first_seq, int)
        or not isinstance(last_seq, int)
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
        range_proof = _range_proof(certificate.get("range_proof"))
        checkpoint_size = checkpoint.get("mmr_size")
        if isinstance(checkpoint_size, bool) or not isinstance(checkpoint_size, int) or checkpoint_size != range_proof.size:
            return None
        return root, log_id, first_seq, last_seq, range_proof
    except (ImportError, TypeError, ValueError, KeyError):
        # ImportError: `cll` absent — fail the completeness claim closed rather
        # than letting the exception escape verify_bundle and drop the other
        # claims (graph closure, disclosures) with it.
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
    raw: Any,
    records: Mapping[str, Mapping[str, Any]],
    completeness: Any,
) -> list[str]:
    if not isinstance(raw, Mapping):
        return ["memberships_absent"]
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
            or not isinstance(seq, int)
            or not isinstance(leaf_index, int)
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
    for seq in range(first_seq, last_seq + 1):
        if seq not in by_seq:
            findings.append(f"membership_record_missing:{seq}")
    raw_missing = completeness.get("missing", []) if isinstance(completeness, Mapping) else []
    declared_missing = {c for c in raw_missing if isinstance(c, str)} if isinstance(raw_missing, list) else set()
    for capsule_id in records:
        if capsule_id not in bound_records and capsule_id not in declared_missing:
            findings.append(f"membership_record_unbound:{capsule_id}")
    return findings


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
        or not isinstance(v, int)
        or not isinstance(size, int)
        or not isinstance(leaf_index, int)
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


def _range_proof(raw: Any) -> Any:
    from cll.checkpoint import RangeProof

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
        or not isinstance(from_seq, int)
        or not isinstance(to_seq, int)
        or not isinstance(size, int)
        or not isinstance(from_index, int)
        or not isinstance(to_index, int)
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
    return RangeProof(
        from_seq=from_seq,
        to_seq=to_seq,
        size=size,
        from_index=from_index,
        to_index=to_index,
        witness=tuple(witness),
    )


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
