# SPDX-License-Identifier: BSD-3-Clause
"""``anchor_inclusion`` for Checkpointed Local Log material (profile §6.2.1, steps 1 to 14).

The steps run in order and the first that yields a status decides. Step 4 needs the envelope's
own ``envelope_signature``, ``artifact_digest`` and ``verification_binding`` statuses, so the
caller passes them in.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import _mmr
from ._cbor import CborError, Tag, decode, encode_head
from ._common import (
    CLL_KINDS,
    FAIL,
    INCONCLUSIVE,
    NOT_CHECKED,
    NOT_PRESENT,
    PASS,
    PropertyReport,
    TrustPolicy,
    ed25519_verify,
    is_digest,
    is_uint,
    member_of,
    parse_time,
    to_profile_time,
)

__all__ = ["check_anchor_inclusion", "CHECKPOINT", "INCLUSION", "CONSISTENCY"]

CHECKPOINT, INCLUSION, CONSISTENCY = CLL_KINDS
_PROPERTY = "anchor_inclusion"
_BASE_METHOD = "§6.2.1 Checkpointed Local Log procedure"
# An index is an unsigned integer below 2^53 (§5.2), so a tree has fewer than 64 levels: no
# inclusion path, consistency path list or peak list longer than 64 can be valid. Longer input is
# refused before any hashing.
_MAX_PATH = 64


def _report(status: str, detail: str, method: str = _BASE_METHOD) -> PropertyReport:
    return PropertyReport(_PROPERTY, status, method, detail)


class _Malformed(Exception):
    pass


def _peak_list(raw: Any) -> list[bytes]:
    """A ``commitment``: a byte string holding the deterministic CBOR of an array of one or more
    32-octet byte strings (CLL §3.1)."""
    if not isinstance(raw, bytes):
        raise _Malformed("commitment is not a byte string")
    try:
        d = decode(raw)
    except CborError as exc:
        raise _Malformed(f"commitment: {exc}") from exc
    v = d.value
    if not d.deterministic or not d.well_formed:
        raise _Malformed("commitment is not deterministic CBOR")
    if not isinstance(v, list) or not v or len(v) > _MAX_PATH or \
            not all(isinstance(x, bytes) and len(x) == 32 for x in v):
        raise _Malformed("commitment is not an array of one or more 32-octet byte strings")
    return v


class _Checkpoint:
    __slots__ = ("protected", "payload", "signature", "alg", "kid", "crit", "iss", "sub", "claims",
                 "commitment", "prev_commitment")


def _decode_checkpoint(octets: bytes) -> _Checkpoint:
    """Step 7: the one fixed COSE_Sign1 form of a CLL checkpoint, decoded and checked."""
    try:
        outer = decode(octets)
    except CborError as exc:
        raise _Malformed(f"checkpoint: {exc}") from exc
    if not outer.well_formed:
        raise _Malformed("checkpoint has a duplicate map key")
    tagged = outer.value
    if not isinstance(tagged, Tag) or tagged.number != 18:
        raise _Malformed("checkpoint is not CBOR tag 18")
    body = tagged.value
    if not isinstance(body, list) or len(body) != 4:
        raise _Malformed("COSE_Sign1 is not a four-element array")
    protected, unprotected, payload, signature = body
    if unprotected != {}:
        raise _Malformed("unprotected header is not empty")
    if payload is None:
        raise _Malformed("payload is detached")
    if not all(isinstance(x, bytes) for x in (protected, payload, signature)):
        raise _Malformed("COSE_Sign1 member has the wrong type")
    cp = _Checkpoint()
    cp.protected, cp.payload, cp.signature = protected, payload, signature
    try:
        hdr, claims = decode(protected), decode(payload)
    except CborError as exc:
        raise _Malformed(f"checkpoint header or payload: {exc}") from exc
    if not hdr.well_formed or not claims.well_formed:
        raise _Malformed("checkpoint header or payload has a duplicate map key")
    h = hdr.value
    if not isinstance(h, dict) or 1 not in h or 4 not in h:
        raise _Malformed("protected header lacks alg or kid")
    cwt = h.get(15)
    if not isinstance(cwt, dict) or 1 not in cwt or 2 not in cwt:
        raise _Malformed("protected header lacks CWT_Claims with iss and sub")
    cp.alg, cp.kid, cp.crit, cp.iss, cp.sub = h[1], h[4], 2 in h, cwt[1], cwt[2]
    c = claims.value
    if not isinstance(c, dict):
        raise _Malformed("payload is not a claims map")
    if c.get("kind") != "cll-checkpoint":
        raise _Malformed("kind claim is not cll-checkpoint")
    log_size, prev_size = c.get("log_size"), c.get("prev_size")
    if not (is_uint(log_size) and is_uint(prev_size)) or prev_size > log_size:
        raise _Malformed("log_size or prev_size is not a valid unsigned integer pair")
    if parse_time(c.get("issued_at")) is None:
        raise _Malformed("issued_at is not an RFC 3339 text string")
    cp.commitment = _peak_list(c.get("commitment"))
    prev = c.get("prev_commitment")
    if prev_size == 0:
        if prev != b"":
            raise _Malformed("prev_size is 0 and prev_commitment is not zero-length")
        cp.prev_commitment = []
    else:
        cp.prev_commitment = _peak_list(prev)
    cp.claims = c
    return cp


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    """The ``Signature1`` Sig_structure with an empty external AAD (RFC 9052 §4.4)."""
    out = encode_head(4, 4) + encode_head(3, 10) + b"Signature1"
    for part in (protected, b"", payload):
        out += encode_head(2, len(part)) + part
    return out


def _bstr32_list(v: Any) -> bool:
    return isinstance(v, list) and len(v) <= _MAX_PATH and all(isinstance(x, bytes) and len(x) == 32 for x in v)


def _decode_proof(octets: bytes, label: str) -> Any:
    """Proof octets are deterministic CBOR (§6.2.1)."""
    try:
        d = decode(octets)
    except CborError as exc:
        raise _Malformed(f"{label}: {exc}") from exc
    if not d.deterministic or not d.well_formed:
        raise _Malformed(f"{label} is not deterministic CBOR")
    return d.value


def check_anchor_inclusion(
    envelope: Mapping[str, Any],
    material: Sequence[bytes] | None,
    prerequisites: Mapping[str, str],
    trust: TrustPolicy,
    kinds_implemented: frozenset,
) -> PropertyReport:
    """Run §6.2.1 steps 1 to 14 for one envelope.

    ``material`` is the decoded ``verification_content`` octets, in order, or None when the
    envelope carried none that decodes. ``prerequisites`` holds the statuses of
    ``envelope_signature``, ``artifact_digest`` and ``verification_binding``.
    """
    subject, derivation = envelope.get("subject"), envelope.get("derivation")
    # Step 1. Only the record subject with no derivation has a method in this revision (P-13).
    if not (isinstance(subject, dict) and list(subject) == ["record"]) or "derivation" in envelope:
        why = "a derivation is present" if derivation is not None or "derivation" in envelope else \
            "the subject is not the record form"
        return _report(NOT_CHECKED, f"step 1: {why}; no kind in this revision defines a method (P-13)")
    # Step 2.
    verification = envelope.get("verification")
    if verification is None or verification == []:
        return _report(NOT_PRESENT, "step 2: the envelope carries no verification material")
    if not isinstance(verification, list):
        return _report(NOT_CHECKED, "step 3: verification is not an array of entries")
    # Step 3.
    kinds = [e.get("kind") if isinstance(e, dict) else None for e in verification]
    unknown = [k for k in kinds if k not in CLL_KINDS or not member_of(k, kinds_implemented)]
    if unknown:
        return _report(NOT_CHECKED, f"step 3: kind {unknown[0]!r} is not implemented (§6.2)")
    repeated = [k for k in CLL_KINDS if kinds.count(k) > 1]
    if repeated:
        return _report(FAIL, f"step 3: kind {repeated[0]} appears more than once")
    for need in (CHECKPOINT, INCLUSION):
        if need not in kinds:
            return _report(NOT_PRESENT, f"step 3: no {need} entry")
    # Step 4. Material not bound to a verified envelope is never checked.
    unverified = [p for p in ("envelope_signature", "artifact_digest", "verification_binding")
                  if prerequisites.get(p) != PASS]
    if unverified or material is None or len(material) != len(verification):
        return _report(NOT_CHECKED, f"step 4: {', '.join(unverified) or 'verification_binding'} is not PASS")
    # Step 5.
    artifact_digest = envelope.get("artifact_digest")
    if subject["record"] != artifact_digest:
        return _report(NOT_CHECKED, "step 5: subject.record is not the artifact digest; outside the "
                                    "scope of the cll-* kinds (P-31)")
    items = dict(zip(kinds, material))
    # Step 6.
    anchor = envelope.get("anchor")
    anchor_digest = anchor.get("digest") if isinstance(anchor, dict) else None
    if verification[kinds.index(CHECKPOINT)].get("digest") != anchor_digest:
        return _report(FAIL, "step 6: the cll-checkpoint entry's digest is not anchor.digest")
    # Step 7.
    try:
        cp = _decode_checkpoint(items[CHECKPOINT])
    except _Malformed as exc:
        return _report(FAIL, f"step 7: {exc}")
    # Step 8.
    if cp.alg != -8 or cp.crit:
        return _report(NOT_CHECKED, "step 8: only EdDSA (-8) checkpoint signatures with no crit are "
                                    "checked in this revision (P-31)")
    # Step 9. The log key, as of the checkpoint's own issued_at.
    if not isinstance(cp.kid, bytes) or len(cp.kid) != 32:
        return _report(FAIL, "step 9: kid is not a 32-octet Ed25519 public key")
    key_status = trust.accepts_log_key(cp.iss, cp.sub, cp.kid.hex(), cp.claims["issued_at"])
    if key_status == FAIL:
        return _report(FAIL, "step 9: the trust policy does not accept this key for "
                             f"(iss {cp.iss!r}, sub {cp.sub!r}) as of the checkpoint's issued_at")
    if key_status == INCONCLUSIVE:
        return _report(INCONCLUSIVE, "step 9: the trust policy cannot resolve the log key's status")
    # Step 10.
    if not ed25519_verify(cp.kid, cp.signature, _sig_structure(cp.protected, cp.payload)):
        return _report(FAIL, "step 10: the checkpoint's COSE_Sign1 signature does not verify")
    # Step 11.
    if isinstance(anchor, dict) and "freshness" in anchor:
        fresh = anchor["freshness"]
        if is_uint(fresh):
            if fresh != cp.claims["log_size"]:
                return _report(FAIL, "step 11: anchor.freshness is not the checkpoint's log_size")
        elif fresh != to_profile_time(parse_time(cp.claims["issued_at"])):
            return _report(FAIL, "step 11: anchor.freshness is not the checkpoint's issued_at")
    # Step 12.
    try:
        proof = _decode_proof(items[INCLUSION], "inclusion proof")
        if not (isinstance(proof, list) and len(proof) == 2 and is_uint(proof[0]) and _bstr32_list(proof[1])):
            raise _Malformed("inclusion proof is not [index, [32-octet byte strings]]")
    except _Malformed as exc:
        return _report(FAIL, f"step 12: {exc}")
    index, path = proof
    if _mmr.index_height(index) != 0:
        return _report(FAIL, "step 12: index is not a leaf")
    if not is_digest(artifact_digest):
        return _report(FAIL, "step 12: artifact_digest is not a digest")
    leaf = _mmr.leaf_value(bytes.fromhex(artifact_digest))
    if _mmr.included_root(index, leaf, path) not in cp.commitment:
        return _report(FAIL, "step 12: the inclusion path reaches no peak of commitment")
    method = "CLL-01 checkpoint (Ed25519) + MMR-02 inclusion"
    # Step 13.
    if CONSISTENCY in items:
        failure = _consistency_failure(items[CONSISTENCY], cp)
        if failure:
            return _report(FAIL, f"step 13: {failure}")
        method += " + MMR-02 consistency"
    # Step 14.
    return _report(PASS, "steps 1 to 14", method)


def _consistency_failure(octets: bytes, cp: _Checkpoint) -> str | None:
    try:
        proof = _decode_proof(octets, "consistency proof")
    except _Malformed as exc:
        return str(exc)
    if not (isinstance(proof, list) and len(proof) == 4):
        return "consistency proof is not a four-element array"
    size1, size2, paths, right = proof
    if not (is_uint(size1) and is_uint(size2) and size1 >= 1 and isinstance(paths, list)
            and len(paths) <= _MAX_PATH and all(_bstr32_list(p) for p in paths) and _bstr32_list(right)):
        return "consistency proof is malformed"
    if size1 > size2:
        return "tree-size-1 exceeds tree-size-2"
    if cp.claims["prev_size"] == 0:
        return "prev_size is 0, so there is no earlier commitment to extend"
    old_peaks = _mmr.peaks(size1 - 1)
    if not len(old_peaks) == len(paths) == len(cp.prev_commitment):
        return "peak count, path count and prev_commitment length differ"
    roots = _mmr.consistent_roots(size1 - 1, cp.prev_commitment, paths)
    if len(right) != len(_mmr.peaks(size2 - 1)) - len(roots):
        return "right-peaks count does not complete the peaks of tree-size-2"
    if roots + right != cp.commitment:
        return "roots and right-peaks are not the peak list of commitment"
    return None
