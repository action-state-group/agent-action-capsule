#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle ``composed/v1`` conformance vectors (draft).

The extension is the section "The composed/v1 Extension" of
``draft-mih-zhang-agent-disclosure-bundle-01``, registered in REGISTRY.md
section 14. The -01 revision is held for ratification; the text and these
vectors are reviewed together.

Every expected result below is written by hand from the draft text. The
script builds the literal objects (Capsules, member Evidence Bundles, the
composing container), computes the digests the text defines (SHA-256 over RFC
8785 JCS, lowercase hex: the CPB ``jcs`` algorithm), signs each Capsule with a
Producer Envelope from a fixed test-only seed, and records the literal JCS
preimage of every composed digest. Nothing here imports or runs an
implementation of the extension.

Cases:

* ``agree``: two responders granted; one pre-agreed-identifier join, derived
  ``agree``; observers in separate custody domains, so the agreement
  corroborates.
* ``one-member-missing``: the same composition with one member's Evidence
  Bundle not carried and declared in ``missing``. The composed digest is
  byte-identical to ``agree`` (it covers member digests, never member bodies);
  composition closure is ``withheld`` (declared incomplete); the join is
  declared but cannot be re-derived.
* ``same-custody-redundant``: two observers in ONE custody domain agree. The
  join is ``agree`` and the verifier reports the pair as redundant, not
  corroborating.
* ``artifact-response-bound`` and ``artifact-response-other-request``: the
  ``agree`` composition with responder-a carrying its response envelope.
* ``agree-with-checkpoints``: the ``agree`` composition in which the
  container and every member Bundle carry a whole-log completeness
  certificate and a signed COSE checkpoint of their own log (the composer's,
  each responder's), so the strict verdict of each, and the full verdict, is
  ``VALID``.
* ``missing-member-beside-absence``: one artifact member declared missing,
  the other an absence, the join declared ``one_sided``: ``not_derivable``,
  because one of its artifact members is declared missing.
* ``listed-member-carries-body``: the same with responder-a's Bundle still
  carried: not declared missing, so closure fails and the join derives
  ``one_sided``.
* ``join-order-pointer-absent-first``: two ``same_interval`` joins on one
  pair, one with ``pointer`` ``""`` and one without, carried in that order;
  the digest input lists the join without ``pointer`` first (-02).

Output: ``vectors/bundle/composed/`` (or ``--out DIR``). The run is a pure
function of this file: no clock, no randomness (Ed25519 is deterministic).
``README.md`` is hand-written; when present in the output directory it is
included in ``SHA256SUMS`` but never rewritten.

Dependencies: the standard library, ``cryptography`` (Ed25519), and for the
checkpointed case the CLL reference (``cll.checkpoint``: the MMR, its proofs
and the COSE checkpoint) and ``scitt-cose`` (the checkpoint's Signed
Statement), as ``generate_bundle_strict_vectors.py`` uses them.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cll.checkpoint import (
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    core,
    leaf_hash,
    peaks,
    root_from_peaks,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from scitt_cose.statement import build_signed_statement

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "composed"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-01 (The composed/v1 Extension)"
KIND = "composed/v1"
AAC_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-05"
CAPSULE_ID_MEDIA_TYPE = "application/agent-action-capsule-id"
RUN = "example-run-0001"
EXCHANGE_MEMBER = "x-example-exchange-v1"
ID_POINTER = f"/model_attestation/compute_attestation/{EXCHANGE_MEMBER}/exchange_id"
COMPARE_POINTER = f"/model_attestation/compute_attestation/{EXCHANGE_MEMBER}/transcript_digest"

S_SHAPE = "composed/v1: Block"
S_MEMBERS = "composed/v1: Members and Outcomes"
S_JOINS = "composed/v1: Joins"
S_OBSERVERS = "composed/v1: Observers and Redundancy"
S_DIGEST = "composed/v1: Composed Digest"
S_CLOSURE = "composed/v1: Composition Closure"
S_CLAIMS = "Completeness Claims and Log Membership"

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("floats are not used in these vectors")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("map keys in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> bytes:
    """RFC 8785 for the value space these vectors use (no floats, ASCII keys).

    With ASCII keys, UTF-16 code-unit order equals code-point order, so
    ``sort_keys`` is the RFC 8785 member order.
    """
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def label_hex(label: str) -> str:
    return sha256_hex(f"composed/v1 vectors: {label}".encode())


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def cbor(value: Any) -> bytes:
    """Deterministic CBOR for the Producer Envelope's small value space."""
    if isinstance(value, int) and not isinstance(value, bool):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted((cbor(k), cbor(v)) for k, v in value.items())
        return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(type(value).__name__)


# ---------------------------------------------------------------------------
# Keys (test-only)
# ---------------------------------------------------------------------------


class Key:
    def __init__(self, name: str) -> None:
        self.name = name
        self.seed = hashlib.sha256(f"composed/v1 conformance vectors: {name} key".encode()).digest()
        self.private = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_hex(self) -> str:
        return self.public.hex()


COMPOSER = Key("composer")
RESPONDER_A = Key("responder-a")
RESPONDER_B = Key("responder-b")
RUNTIME = Key("runtime observer")
BOUNDARY = Key("boundary observer")
KEYS = [COMPOSER, RESPONDER_A, RESPONDER_B, RUNTIME, BOUNDARY]


def producer_envelope(capsule_id: str, key: Key) -> bytes:
    """A bare Producer Envelope: tagged COSE_Sign1 over the raw 32-byte Capsule ID."""
    protected = cbor({1: -8, 3: CAPSULE_ID_MEDIA_TYPE, 4: key.public})
    payload = bytes.fromhex(capsule_id)
    signature = key.private.sign(cbor(["Signature1", protected, b"", payload]))
    return b"\xd2" + cbor([protected, {}, payload, signature])


# ---------------------------------------------------------------------------
# Logs: a whole-log completeness certificate and a signed COSE checkpoint
# ---------------------------------------------------------------------------


class _StatementSigner:
    """``checkpoint_to_cose``'s signer: a SCITT Signed Statement under one key."""

    def __init__(self, key: Key) -> None:
        self.key = key
        self.key_id = key.public_hex

    def sign_cose_statement(self, payload, *, content_type, issuer, subject, extra_cwt_claims=None):
        pem = self.key.private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return build_signed_statement(payload, alg="EdDSA", private_key_pem=pem, issuer=issuer, subject=subject,
                                      content_type=content_type, extra_cwt_claims=extra_cwt_claims,
                                      kid=self.key.public)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def logged(bundle: dict, key: Key, log_id: str, timestamp: str) -> dict:
    """``bundle`` with its records as the whole log ``log_id`` (seq 1..n): a
    completeness certificate over that interval and the log's first
    checkpoint, signed by ``key`` as a COSE Signed Statement."""
    records = bundle["records"]
    store = MemoryNodeStore()
    for record in records:
        add_leaf(store, leaf_hash(bytes.fromhex(record["capsule_id"])))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    root = root_from_peaks(peak_hashes).hex()
    signer = _StatementSigner(key)
    checkpoint = {"log_id": log_id, "mmr_size": size, "root": root, "prev_size": 0, "prev_root": "",
                  "key_id": signer.key_id, "timestamp": timestamp}
    cp = CheckpointRecord(v=1, kind="mmr_checkpoint", signature="", **checkpoint)
    checkpoint["cose"] = _b64u(checkpoint_to_cose(cp, signer, peak_hashes))
    n = len(records)
    rp = core.range_proof(store, 0, n - 1, size)
    ids = [r["capsule_id"] for r in records]
    memberships = {}
    for i, cid in enumerate(ids):
        p = core.inclusion_proof(store, i, size)
        memberships[cid] = {
            "log_coordinates": {"log_id": log_id, "seq": i + 1, "leaf_index": i},
            "inclusion_proof": {"v": p.v, "kind": p.kind, "size": p.size, "leaf_index": p.leaf_index,
                                "witness": list(p.witness), "peaks_left": list(p.peaks_left),
                                "peaks_right": list(p.peaks_right)},
        }
    out = dict(bundle)
    out["completeness_certificate"] = {
        "log_id": log_id, "range_root": root, "first_seq": 1, "last_seq": n, "body_digests": ids,
        "range_proof": {"from_seq": 1, "to_seq": n, "size": rp.size, "from_index": rp.from_index,
                        "to_index": rp.to_index, "witness": list(rp.witness)},
        "memberships": memberships,
    }
    out["checkpoint"] = checkpoint
    return out


# ---------------------------------------------------------------------------
# Capsules, member bundles, requests
# ---------------------------------------------------------------------------


def t(minute: int) -> str:
    return f"2026-10-02T12:{minute:02d}:00Z"


def seal(body: dict, key: Key) -> dict:
    """Capsule ID over JCS of the body (capsule_id, key_id, signature excluded), then sign."""
    capsule = copy.deepcopy(body)
    capsule_id = sha256_hex(jcs(capsule))
    capsule["capsule_id"] = capsule_id
    capsule["key_id"] = key.public_hex
    capsule["signature"] = producer_envelope(capsule_id, key).hex()
    return capsule


def observation(label: str, operator: str, key: Key, minute: int, *, transcript: str) -> dict:
    body = {
        "spec_version": AAC_SPEC_VERSION,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": f"{RUN}/{label}",
        "action_type": "fyi",
        "operator": operator,
        "developer": "composed-example-agent@1",
        "timestamp": t(minute),
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                      "ledger_mode": "standalone"},
        "model_attestation": {
            "compute_attestation": {
                "agent_input_digest": label_hex(f"{label} input"),
                "agent_output_digest": label_hex(f"{label} output"),
                EXCHANGE_MEMBER: {"exchange_id": RUN, "transcript_digest": label_hex(transcript)},
            }
        },
    }
    return seal(body, key)


def member_bundle(record: dict) -> dict:
    """An Evidence Bundle of one record: closure depth 0, no certificate."""
    return {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": record["capsule_id"],
        "records": [record],
        "completeness": {"closure_depth": 0, "records_mode": "complete", "payloads_mode": "all"},
    }


def bundle_digest(bundle: dict) -> str:
    return sha256_hex(jcs({k: v for k, v in bundle.items() if k != "countersignatures"}))


def request(member_id: str) -> dict:
    return {"subject": {"correlation": RUN}, "coverage": {"min_freshness": 1}, "nonce": f"n-{member_id}"}


def artifact_member(member_id: str, observer: str, record: dict, log_key: Key | None = None) -> dict:
    """With ``log_key``, the member Bundle is that responder's whole log, with
    a completeness certificate and a checkpoint signed by ``log_key``."""
    bundle = member_bundle(record)
    if log_key is not None:
        bundle = logged(bundle, log_key, f"log:composed-vectors/{member_id}", t(12))
    return {
        "id": member_id,
        "observer": observer,
        "request_digest": sha256_hex(jcs(request(member_id))),
        "outcome": "artifact",
        "digest": bundle_digest(bundle),
        "bundle": bundle,
    }


# ---------------------------------------------------------------------------
# composed/v1
# ---------------------------------------------------------------------------

_MEMBER_DIGEST_FIELDS = ("id", "observer", "request_digest", "outcome", "digest")
_JOIN_DIGEST_FIELDS = ("members", "basis", "pointer", "identifier_digest", "compare", "state")


def digest_input(block: dict) -> dict:
    """The exact object the composed digest is computed over (draft text, Composed Digest)."""
    members = sorted(({k: m[k] for k in _MEMBER_DIGEST_FIELDS if k in m} for m in block["members"]),
                     key=lambda m: m["id"])
    observers = sorted(({k: o[k] for k in ("id", "role", "custody_domain")} for o in block.get("observers", [])),
                       key=lambda o: o["id"])
    joins = sorted(({k: j[k] for k in _JOIN_DIGEST_FIELDS if k in j} for j in block.get("joins", [])),
                   key=lambda j: (j["members"][0], j["members"][1], j["basis"], "pointer" in j, j.get("pointer", "")))
    return {
        "kind": KIND,
        "members": members,
        "observers": observers,
        "joins": joins,
        "not_requested": sorted(block.get("not_requested", [])),
    }


def composed_digest(block: dict) -> tuple[str, str]:
    preimage = jcs(digest_input(block))
    return sha256_hex(preimage), preimage.decode("utf-8")


def join(a: str, b: str, state: str) -> dict:
    return {
        "members": sorted([a, b]),
        "basis": "pre_agreed_identifier",
        "pointer": ID_POINTER,
        "identifier_digest": sha256_hex(RUN.encode("utf-8")),
        "compare": [COMPARE_POINTER],
        "state": state,
    }


def block(members: list[dict], observers: list[dict], joins: list[dict], missing: list[str] | None = None) -> dict:
    out: dict[str, Any] = {"members": members, "observers": observers, "joins": joins}
    if missing:
        out["missing"] = sorted(missing)
        for m in out["members"]:
            if m["id"] in missing:
                m.pop("bundle", None)
    digest, _ = composed_digest(out)
    out["composed_digest"] = digest
    return out


def container(composition: dict, *, checkpointed: bool = False) -> dict:
    """An ordinary evidence-bundle/v2 whose root is the composing party's own record.

    With ``checkpointed``, the container is the composer's whole log, with a
    completeness certificate and a checkpoint signed by the composer's key.
    """
    root = seal({
        "spec_version": AAC_SPEC_VERSION,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": f"{RUN}/compose",
        "action_type": "fyi",
        "operator": "composer.example",
        "developer": "composed-example-agent@1",
        "timestamp": t(30),
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                      "ledger_mode": "standalone"},
    }, COMPOSER)
    out = {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": root["capsule_id"],
        "records": [root],
        "completeness": {"closure_depth": 0, "records_mode": "complete", "payloads_mode": "all"},
        "extensions": {KIND: composition},
    }
    return logged(out, COMPOSER, "log:composed-vectors/composer", t(31)) if checkpointed else out


# ---------------------------------------------------------------------------
# Cases (expected results written by hand from the draft text)
# ---------------------------------------------------------------------------

MEMBER_CLAIMS_DEPTH0 = {
    # One record, depth 0, no completeness_certificate: closure passes, the
    # other two claims are not shown (never passed) -- reported per member.
    "graph_closure": "pass",
    "interval_coverage": "withheld",
    "per_record_membership": "withheld",
}


def two_responders(*, checkpointed: bool = False) -> tuple[list[dict], list[dict]]:
    rec_a = observation("responder-a", "responder-a.example", RESPONDER_A, 10, transcript="shared transcript")
    rec_b = observation("responder-b", "responder-b.example", RESPONDER_B, 11, transcript="shared transcript")
    members = [
        artifact_member("responder-a", "obs-a", rec_a, RESPONDER_A if checkpointed else None),
        artifact_member("responder-b", "obs-b", rec_b, RESPONDER_B if checkpointed else None),
    ]
    observers = [
        {"id": "obs-a", "role": "responder", "custody_domain": "custody-a.example"},
        {"id": "obs-b", "role": "responder", "custody_domain": "custody-b.example"},
    ]
    return members, observers


def case_agree() -> dict:
    members, observers = two_responders()
    comp = block(members, observers, [join("responder-a", "responder-b", "agree")])
    digest, preimage = composed_digest(comp)
    return {
        "id": "agree",
        "section": [S_SHAPE, S_MEMBERS, S_JOINS, S_OBSERVERS, S_DIGEST, S_CLOSURE],
        "description": "Two responders granted an Evidence Bundle each. Both root records carry the pre-agreed "
                       "exchange identifier and the same transcript digest, so the join derives agree. The "
                       "observers declare different custody domains and the records carry different keys, so "
                       "the agreement is reported as corroborating (on declared custody).",
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "pass",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
                "responder-b": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
            },
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": ["responder-a", "responder-b"], "declared": "agree", "derived": "agree",
                       "result": "derived_matches"}],
            "corroboration": [{"members": ["responder-a", "responder-b"], "result": "corroborating",
                               "qualifier": "custody_declared"}],
        },
    }


def case_missing() -> dict:
    members, observers = two_responders()
    comp = block(members, observers, [join("responder-a", "responder-b", "agree")], missing=["responder-b"])
    digest, preimage = composed_digest(comp)
    return {
        "id": "one-member-missing",
        "section": [S_MEMBERS, S_DIGEST, S_CLOSURE, S_JOINS],
        "description": "The agree composition with responder-b's Evidence Bundle not carried and declared in "
                       "missing. The composed digest is identical to the agree case: it covers member digests, "
                       "outcomes, observers and join declarations, never member bodies. Composition closure is "
                       "withheld (declared incomplete), not failed; the join is declared but cannot be "
                       "re-derived, and no corroboration is reported.",
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "composed_digest_equals_case": "agree",
            "canonical_preimage": preimage,
            "status": "withheld",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
                "responder-b": {"outcome": "artifact", "body": "declared_missing", "digest": "not_shown",
                                "claims": None},
            },
            "composition_closure": {"status": "withheld", "finding": "declared_incomplete",
                                    "missing": ["responder-b"]},
            "joins": [{"members": ["responder-a", "responder-b"], "declared": "agree", "derived": None,
                       "result": "not_derivable"}],
            "corroboration": [{"members": ["responder-a", "responder-b"], "result": "not_applicable"}],
        },
    }


def case_same_custody() -> dict:
    rec_r = observation("runtime", "operator.example", RUNTIME, 10, transcript="egress to endpoint")
    rec_b = observation("boundary", "operator.example", BOUNDARY, 10, transcript="egress to endpoint")
    members = [artifact_member("boundary", "obs-boundary", rec_b), artifact_member("runtime", "obs-runtime", rec_r)]
    observers = [
        {"id": "obs-boundary", "role": "network_boundary", "custody_domain": "operator.example"},
        {"id": "obs-runtime", "role": "runtime", "custody_domain": "operator.example"},
    ]
    comp = block(members, observers, [join("boundary", "runtime", "agree")])
    digest, preimage = composed_digest(comp)
    return {
        "id": "same-custody-redundant",
        "section": [S_OBSERVERS, S_JOINS, S_DIGEST],
        "description": "A runtime observer and a network-boundary observer agree on one egress, but both "
                       "observers declare the same custody domain. Different signing keys do not change that. "
                       "The join derives agree; the verifier reports the pair as redundant, not corroborating.",
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "pass",
            "members": {
                "boundary": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                             "claims": MEMBER_CLAIMS_DEPTH0},
                "runtime": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                            "claims": MEMBER_CLAIMS_DEPTH0},
            },
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": ["boundary", "runtime"], "declared": "agree", "derived": "agree",
                       "result": "derived_matches"}],
            "corroboration": [{"members": ["boundary", "runtime"], "result": "redundant",
                               "reason": "same_custody_domain",
                               "report": "redundant, not corroborating"}],
        },
    }


S_RESPONSE = "composed/v1: Artifact Response"


def case_response(case_id: str, request_digest_of: str) -> dict:
    """The agree composition with responder-a carrying its response envelope.

    The envelope's request digest is that of the request ``request_digest_of``
    sent, so a member id other than responder-a's names another request.
    """
    members, observers = two_responders()
    a = members[0]
    a["response"] = {
        "request_digest": sha256_hex(jcs(request(request_digest_of))),
        "artifact_digest": a["digest"],
    }
    comp = block(members, observers, [join("responder-a", "responder-b", "agree")])
    digest, preimage = composed_digest(comp)
    bound = request_digest_of == "responder-a"
    if bound:
        description = ("The agree composition, with responder-a carrying its response envelope without the "
                       "artifact bytes: its request_digest is the member's and its artifact_digest is the "
                       "member's bundle digest. The envelope is outside the composed digest, so the digest is "
                       "the agree case's. The envelope carries no signature in any deployment profile, so it "
                       "is reported signature_unverified (withheld), as a refusal's signature would be.")
    else:
        description = ("As artifact-response-bound, but the envelope's request_digest is the digest of "
                       "another request (the one responder-b answered): the artifact is bound to a request "
                       "other than its member's, and the block fails.")
    return {
        "id": case_id,
        "section": [S_MEMBERS, S_RESPONSE, S_DIGEST],
        "description": description,
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "composed_digest_equals_case": "agree",
            "canonical_preimage": preimage,
            "status": "withheld" if bound else "fail",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0,
                                "response": {"request_digest": "matches" if bound else "mismatch",
                                             "artifact_digest": "matches",
                                             "signature": "signature_unverified"}},
                "responder-b": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
            },
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": ["responder-a", "responder-b"], "declared": "agree", "derived": "agree",
                       "result": "derived_matches"}],
            "corroboration": [{"members": ["responder-a", "responder-b"], "result": "corroborating",
                               "qualifier": "custody_declared"}],
        },
    }


MEMBER_CLAIMS_LOGGED = {
    # The member Bundle is its responder's whole log: the certificate's range
    # and membership proofs verify against a checkpoint whose COSE form
    # verifies, so all three claims pass with no finding.
    "graph_closure": "pass",
    "interval_coverage": "pass",
    "per_record_membership": "pass",
}

def case_agree_with_checkpoints() -> dict:
    members, observers = two_responders(checkpointed=True)
    comp = block(members, observers, [join("responder-a", "responder-b", "agree")])
    digest, preimage = composed_digest(comp)
    return {
        "id": "agree-with-checkpoints",
        "section": [S_SHAPE, S_MEMBERS, S_JOINS, S_OBSERVERS, S_DIGEST, S_CLOSURE, S_CLAIMS],
        "description": "The agree composition, with every Bundle checkpointed. Each member Bundle is its "
                       "responder's whole log (one record): a completeness certificate over seq 1..1 and the "
                       "log's first checkpoint, signed as a COSE statement by the responder's key. The "
                       "container is the composer's whole log, checkpointed the same way under the composer's "
                       "key. Every claim of the container and of each member passes, so the strict verdict of "
                       "each is VALID, and with the block passing the full verdict is VALID. The member digests "
                       "cover the certificates and checkpoints, so the composed digest is not the agree case's.",
        "container": container(comp, checkpointed=True),
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "pass",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_LOGGED},
                "responder-b": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_LOGGED},
            },
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": ["responder-a", "responder-b"], "declared": "agree", "derived": "agree",
                       "result": "derived_matches"}],
            "corroboration": [{"members": ["responder-a", "responder-b"], "result": "corroborating",
                               "qualifier": "custody_declared"}],
            # Strict verdicts (vectors/bundle/strict/README.md): the container's
            # and each carried member Bundle's. The full verdict is VALID only
            # when all of them are and the block's status is pass.
            "strict": {"container": "VALID", "members": {"responder-a": "VALID", "responder-b": "VALID"}},
            "verdict": "VALID",
        },
    }


def case_missing_beside_absence() -> dict:
    members, observers = two_responders()
    request_digest = members[1]["request_digest"]
    absence = {"request_digest": request_digest, "window": {"from": t(0), "to": t(20)}}
    members[1] = {"id": "responder-b", "observer": "obs-b", "request_digest": request_digest,
                  "outcome": "absence", "digest": sha256_hex(jcs(absence)), "absence": absence}
    comp = block(members, observers, [join("responder-a", "responder-b", "one_sided")], missing=["responder-a"])
    digest, preimage = composed_digest(comp)
    return {
        "id": "missing-member-beside-absence",
        "section": [S_MEMBERS, S_JOINS, S_CLOSURE],
        "description": "responder-a's artifact Evidence Bundle is declared missing and responder-b reports an "
                       "absence. The producer declares the join one_sided. A join one of whose artifact members "
                       "is declared missing is not_derivable, whatever the other member is, so the verifier "
                       "reports not_derivable, never a derived one_sided.",
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "withheld",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "declared_missing", "digest": "not_shown",
                                "claims": None},
                "responder-b": {"outcome": "absence", "body": "carried", "digest": "reproduced",
                                "claims": None},
            },
            "composition_closure": {"status": "withheld", "finding": "declared_incomplete",
                                    "missing": ["responder-a"]},
            "joins": [{"members": ["responder-a", "responder-b"], "declared": "one_sided", "derived": None,
                       "result": "not_derivable"}],
            "corroboration": [{"members": ["responder-a", "responder-b"], "result": "not_applicable"}],
        },
    }


def case_listed_member_carries_body() -> dict:
    members, observers = two_responders()
    request_digest = members[1]["request_digest"]
    absence = {"request_digest": request_digest, "window": {"from": t(0), "to": t(20)}}
    members[1] = {"id": "responder-b", "observer": "obs-b", "request_digest": request_digest,
                  "outcome": "absence", "digest": sha256_hex(jcs(absence)), "absence": absence}
    comp = block(members, observers, [join("responder-a", "responder-b", "one_sided")])
    comp["missing"] = ["responder-a"]  # listed, yet its body is still carried
    digest, preimage = composed_digest(comp)
    return {
        "id": "listed-member-carries-body",
        "section": [S_MEMBERS, S_JOINS, S_CLOSURE],
        "description": "The missing-member-beside-absence composition with responder-a listed in missing but "
                       "its Evidence Bundle still carried. A member is declared missing only when it is listed "
                       "and carries no body, so composition closure fails (missing_member_carries_body) and the "
                       "join derives from the carried body: one_sided.",
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "fail",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
                "responder-b": {"outcome": "absence", "body": "carried", "digest": "reproduced",
                                "claims": None},
            },
            "composition_closure": {"status": "fail", "missing": ["responder-a"]},
            "joins": [{"members": ["responder-a", "responder-b"], "declared": "one_sided", "derived": "one_sided",
                       "result": "derived_matches"}],
            "corroboration": [{"members": ["responder-a", "responder-b"], "result": "not_applicable"}],
        },
    }


def case_join_order_pointer_absent_first() -> dict:
    members, observers = two_responders()
    pair = ["responder-a", "responder-b"]
    # Carried with pointer "" first: the digest input puts the join without
    # pointer first, so the carried order does not reach the digest.
    joins = [
        join("responder-a", "responder-b", "agree"),
        {"members": pair, "basis": "same_interval", "pointer": "", "state": "agree"},
        {"members": pair, "basis": "same_interval", "state": "unjoined"},
    ]
    comp = block(members, observers, joins)
    digest, preimage = composed_digest(comp)
    not_derivable = {"members": pair, "derived": None, "result": "not_derivable"}
    return {
        "id": "join-order-pointer-absent-first",
        "section": [S_DIGEST, S_JOINS],
        "description": "The agree composition with two more joins on one pair and one basis: one with pointer "
                       "\"\" (the whole-document JSON Pointer), one without pointer, carried in that order. They "
                       "are distinct joins. In the digest input (draft-mih-zhang-agent-disclosure-bundle-02) a "
                       "join without pointer sorts before every join with one, so the canonical preimage lists "
                       "the join without pointer first and the carried order does not change the composed "
                       "digest. same_interval is a reserved basis, so both joins are not_derivable.",
        "container": container(comp),
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "withheld",
            "members": {
                "responder-a": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
                "responder-b": {"outcome": "artifact", "body": "carried", "digest": "reproduced",
                                "claims": MEMBER_CLAIMS_DEPTH0},
            },
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": pair, "declared": "agree", "derived": "agree", "result": "derived_matches"},
                      {**not_derivable, "declared": "agree"},
                      {**not_derivable, "declared": "unjoined"}],
            "corroboration": [{"members": pair, "result": "corroborating", "qualifier": "custody_declared"},
                              {"members": pair, "result": "not_applicable"},
                              {"members": pair, "result": "not_applicable"}],
        },
    }


def cases() -> list[dict]:
    return [case_agree(), case_missing(), case_same_custody(),
            case_response("artifact-response-bound", "responder-a"),
            case_response("artifact-response-other-request", "responder-b"),
            case_agree_with_checkpoints(), case_missing_beside_absence(),
            case_listed_member_carries_body(), case_join_order_pointer_absent_first()]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "vectors.json": _dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "status": "registered in REGISTRY.md section 14; held for ratification with -01",
            "kind": KIND,
            "digest_rule": "composed_digest = lowercase hex SHA-256 of the UTF-8 RFC 8785 (JCS) serialization "
                           "of the digest input object (CPB canonicalization algorithm 'jcs'); see "
                           "canonical_preimage in each case.",
            "envelope_profile": "AAC Producer Envelope: tagged COSE_Sign1, protected {1: -8, 3: "
                                "'application/agent-action-capsule-id', 4: raw Ed25519 public key}, empty "
                                "unprotected map, attached payload = raw 32-byte capsule_id.",
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in KEYS},
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = _dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_bundle_composed_vectors.py",
        "files": [{"path": name, "sha256": sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
