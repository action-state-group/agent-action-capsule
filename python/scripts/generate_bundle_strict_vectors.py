#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the strict Evidence Bundle vectors (``vectors/bundle/strict/``).

``verify_bundle(..., strict=True)`` adds checks on top of the Bundle draft's:
each record's producer signature (base profile, local-only ``signature`` and
``key_id``), the checkpoint read only from its signed COSE form, producer-selected
Bundles, the ``disclosures`` overlay as one claim, and witness receipts in
``checkpoint.witnesses`` under a caller-supplied witness directory. See
``vectors/bundle/strict/README.md``.

Every expected result below is written by hand, per case, from those rules;
nothing here runs a verifier. The script builds the literal Bundles: Capsules
(RFC 8785 JCS, SHA-256), producer envelopes, an MMR log and its proofs (CLL
reference), a COSE checkpoint, and witness receipts of the three bindings.
Keys are fixed test seeds and every signature is deterministic (Ed25519, and
RFC 6979 ECDSA for the Rekor key), so the output is a pure function of this
file. ``README.md`` is hand-written and never rewritten here.

Dependencies: ``agent-action-capsule[bundle,envelope]`` and ``cryptography``.
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose import build_receipt
from scitt_cose.cose_sign1 import sign_sign1
from scitt_cose.statement import build_signed_statement

from agent_action_capsule.canonical import compute_capsule_id, jcs, normalize

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "strict"
CAPSULE_ID_MEDIA_TYPE = "application/agent-action-capsule-id"

PRODUCER_SEED = bytes([0x0B]) * 32
OTHER_SEED = bytes([0x21]) * 32
LOG_SEED = bytes([0x2C]) * 32
CLL_WITNESS_SEED = bytes([0x31]) * 32
SCRAPI_SEED = bytes([0x32]) * 32
REKOR_SCALAR = int.from_bytes(bytes([0x33]) * 32, "big") % (2**255)

CLL_URL = "https://cll-witness.example"
SCRAPI_URL = "scrapi+https://scitt.example"
REKOR_URL = "rekor+https://rekor.example"
UNLISTED_URL = "https://unlisted-witness.example"
LOG_ID = "log:strict-vectors"
TIMESTAMP = "2026-10-15T00:00:00Z"


def ed25519(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def private_pem(key: Any) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def spki_der(key: Any) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_pem(key: Any) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


PRODUCER = ed25519(PRODUCER_SEED)
OTHER = ed25519(OTHER_SEED)
LOG_KEY = ed25519(LOG_SEED)
CLL_WITNESS = ed25519(CLL_WITNESS_SEED)
SCRAPI_KEY = ed25519(SCRAPI_SEED)
REKOR_KEY = ec.derive_private_key(REKOR_SCALAR, ec.SECP256R1())
REKOR_LOG_ID = hashlib.sha256(spki_der(REKOR_KEY)).hexdigest()


# -- records ------------------------------------------------------------------


def capsule(action_id: str, **extra: Any) -> dict:
    record = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": TIMESTAMP,
        "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
        "disposition": {"verdict_class": "not_applicable", "decision": "report", "approver": "policy", "human_disposed": False},
        **extra,
    }
    record["capsule_id"] = compute_capsule_id(record)
    return record


def envelope(capsule_id: str, key: Ed25519PrivateKey) -> str:
    return sign_sign1(
        bytes.fromhex(capsule_id),
        alg="EdDSA",
        private_key_pem=private_pem(key),
        protected={3: CAPSULE_ID_MEDIA_TYPE, 4: raw_public(key)},
        unprotected={},
    ).hex()


def signed(record: dict, key: Ed25519PrivateKey = PRODUCER, *, capsule_id: str | None = None) -> dict:
    out = dict(record)
    out["signature"] = envelope(capsule_id or record["capsule_id"], key)
    out["key_id"] = raw_public(key).hex()
    return out


# -- the log ------------------------------------------------------------------


class _StatementSigner:
    """``checkpoint_to_cose``'s signer: a SCITT Signed Statement under one key."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key
        self.key_id = raw_public(key).hex()

    def sign_cose_statement(self, payload, *, content_type, issuer, subject, extra_cwt_claims=None):
        return build_signed_statement(
            payload,
            alg="EdDSA",
            private_key_pem=private_pem(self.key),
            issuer=issuer,
            subject=subject,
            content_type=content_type,
            extra_cwt_claims=extra_cwt_claims,
            kid=raw_public(self.key),
        )


def proof_dict(p: Any) -> dict:
    return {
        "v": p.v,
        "kind": p.kind,
        "size": p.size,
        "leaf_index": p.leaf_index,
        "witness": list(p.witness),
        "peaks_left": list(p.peaks_left),
        "peaks_right": list(p.peaks_right),
    }


def bundle_over(records: list[dict], *, log_key: Ed25519PrivateKey = LOG_KEY, cose: bool = True) -> dict:
    """A Bundle over a whole log of ``records`` (seq 1..n), checkpoint signed by ``log_key``."""
    store = MemoryNodeStore()
    for record in records:
        add_leaf(store, leaf_hash(bytes.fromhex(record["capsule_id"])))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    root = root_from_peaks(peak_hashes).hex()
    signer = _StatementSigner(log_key)
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=LOG_ID, mmr_size=size, root=root, prev_size=0, prev_root="",
        key_id=signer.key_id, timestamp=TIMESTAMP, signature="",
    )
    checkpoint = {
        "log_id": LOG_ID, "mmr_size": size, "root": root, "prev_size": 0, "prev_root": "",
        "key_id": signer.key_id, "timestamp": TIMESTAMP,
    }
    if cose:
        checkpoint["cose"] = b64u(checkpoint_to_cose(cp, signer, peak_hashes))
    n = len(records)
    rp = core.range_proof(store, 0, n - 1, size)
    ids = [r["capsule_id"] for r in records]
    return {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": ids[-1],
        "records": records,
        "completeness": {
            "closure_depth": 0, "records_mode": "complete", "payloads_mode": "selected", "suppressed_fields": [],
            "missing": [],
        },
        "completeness_certificate": {
            "log_id": LOG_ID, "range_root": root, "first_seq": 1, "last_seq": n, "body_digests": ids,
            "range_proof": {
                "from_seq": 1, "to_seq": n, "size": rp.size, "from_index": rp.from_index,
                "to_index": rp.to_index, "witness": list(rp.witness),
            },
            "memberships": {
                cid: {
                    "log_coordinates": {"log_id": LOG_ID, "seq": i + 1, "leaf_index": i},
                    "inclusion_proof": proof_dict(core.inclusion_proof(store, i, size)),
                }
                for i, cid in enumerate(ids)
            },
        },
        "checkpoint": checkpoint,
    }


def cose_bytes(bundle: dict) -> bytes:
    text = bundle["checkpoint"]["cose"]
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def entry_hash(checkpoint: dict) -> str:
    body = {"v": 1, "kind": "mmr_checkpoint", **{k: checkpoint[k] for k in (
        "log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp")}}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return hashlib.sha256(bytes.fromhex(digest)).hexdigest()


# -- witness receipts ---------------------------------------------------------


def cll_receipt(leaf: str, key: Ed25519PrivateKey = CLL_WITNESS, *, ts_url: str = CLL_URL, grade: str | None = "mmr-verified") -> dict:
    receipt = build_receipt(
        leaf_entry_hex=leaf, leaf_index=0, tree_entries_hex=[leaf], alg="EdDSA",
        log_private_key_pem=private_pem(key), grade=grade,
    )
    return {"ts_url": ts_url, "entry_hash": leaf, "receipt_b64": b64(receipt), "leaf_index": 0, "tree_size": 1}


def scrapi_receipt(cose: bytes, *, grade: str | None = None) -> dict:
    leaf = hashlib.sha256(cose).hexdigest()
    receipt = build_receipt(
        leaf_entry_hex=leaf, leaf_index=0, tree_entries_hex=[leaf], alg="EdDSA",
        log_private_key_pem=private_pem(SCRAPI_KEY), grade=grade,
    )
    return {"ts_url": SCRAPI_URL, "entry_hash": leaf, "receipt_b64": b64(receipt), "leaf_index": 0, "tree_size": 1}


def _sorted_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def rekor_receipt(cose: bytes, checkpoint_key: Ed25519PrivateKey = LOG_KEY, *, payload: bytes | None = None) -> dict:
    """A Rekor ``dsse`` log entry (``GET /api/v1/log/entries`` shape, one entry)."""
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": hashlib.sha256(b"envelope").hexdigest()},
            "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(payload or cose).hexdigest()},
            "signatures": [{"signature": b64(b"\x00" * 64), "verifier": b64(spki_pem(checkpoint_key))}],
        },
    }
    entry = {"body": b64(_sorted_json(body)), "integratedTime": 1792022400, "logID": REKOR_LOG_ID, "logIndex": 7}
    set_signature = REKOR_KEY.sign(_sorted_json(entry), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    receipt = {**entry, "verification": {"signedEntryTimestamp": b64(set_signature)}}
    return {"ts_url": REKOR_URL, "entry_hash": hashlib.sha256(cose).hexdigest(),
            "receipt_b64": b64(_sorted_json(receipt)), "leaf_index": 7, "tree_size": 8}


DIRECTORY = {
    "directory_version": "1",
    "witnesses": [
        {"name": "CLL witness", "endpoint": "https://cll-witness.example", "since": "2026-01-01",
         "key_ids": [raw_public(CLL_WITNESS).hex()]},
        {"name": "Keyless witness", "endpoint": "https://keyless-witness.example", "since": "2026-01-01", "key_ids": []},
        {"name": "Rekor", "endpoint": "https://rekor.example", "since": "2026-01-01", "binding": "rekor",
         "key_ids": [REKOR_LOG_ID], "public_keys": [b64(spki_der(REKOR_KEY))]},
        {"name": "Rekor without key", "endpoint": "https://rekor-nokey.example", "since": "2026-01-01",
         "binding": "rekor", "key_ids": [REKOR_LOG_ID]},
        {"name": "SCITT service", "endpoint": "https://scitt.example", "since": "2026-01-01", "binding": "scrapi",
         "key_ids": [raw_public(SCRAPI_KEY).hex()]},
    ],
}


# -- expectations -------------------------------------------------------------

PASS: dict[str, Any] = {"status": "pass", "findings": []}


def claims(**overrides: Any) -> list[dict]:
    """The gating claims in report order, each ``pass`` unless overridden."""
    names = ["records", "signatures", "graph_closure", "checkpoint", "interval_coverage", "per_record_membership"]
    out = []
    for name in names:
        value = overrides.pop(name, PASS)
        out.append({"name": name, **value})
    if "disclosures" in overrides:
        out.append({"name": "disclosures", **overrides.pop("disclosures")})
    assert not overrides, overrides
    return out


def claim(status: str, *findings: str) -> dict:
    return {"status": status, "findings": list(findings)}


ABSENT = {"status": "withheld", "findings": ["witness_receipt_absent"], "receipts": []}
UNANCHORED = claim("withheld", "checkpoint_unverified")


def records_expect(bundle: dict, signature: dict[int, str] | None = None, identity: dict[int, bool] | None = None) -> list[dict]:
    seqs = {cid: m["log_coordinates"]["seq"] for cid, m in bundle["completeness_certificate"]["memberships"].items()}
    out = []
    for i, r in enumerate(bundle["records"]):
        out.append({
            "capsule_id": r["capsule_id"],
            "identity_ok": (identity or {}).get(i, True),
            "signature": (signature or {}).get(i, "authored"),
            "key_id": r.get("key_id"),
            "seq": seqs.get(r["capsule_id"]),
        })
    return out


def case(case_id: str, description: str, bundle: dict, expect: dict, **options: Any) -> dict:
    return {"id": case_id, "description": description, "options": {
        "require_signature": options.get("require_signature", False),
        "witness_directory": options.get("witness_directory", False),
    }, "bundle": bundle, "expect": expect}


def build_cases() -> list[dict]:
    base_records = [signed(capsule(f"strict-{i}")) for i in range(1, 4)]
    base = bundle_over(base_records)
    ids = [r["capsule_id"] for r in base_records]
    cases = []

    cases.append(case(
        "pos-signed-whole-log",
        "Three signed records, a whole-log certificate, a signed COSE checkpoint; no receipts.",
        base,
        {"verdict": "VALID", "claims": claims(), "witnesses": ABSENT, "records": records_expect(base),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))

    same_key = bundle_over([signed(capsule(f"strict-{i}"), LOG_KEY) for i in range(1, 4)])
    cases.append(case(
        "pos-records-signed-by-the-log-key",
        "The records' key is the checkpoint's key: reported, never gating.",
        same_key,
        {"verdict": "VALID", "claims": claims(), "witnesses": ABSENT, "records": records_expect(same_key),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": True},
    ))

    no_cose = bundle_over(base_records, cose=False)
    cases.append(case(
        "incomplete-no-signed-checkpoint",
        "No checkpoint.cose: the checkpoint is not shown, so neither are the proofs under it.",
        no_cose,
        {"verdict": "INCOMPLETE", "claims": claims(
            checkpoint=claim("withheld", "checkpoint_signature_absent"),
            interval_coverage=UNANCHORED, per_record_membership=UNANCHORED),
         "witnesses": ABSENT, "records": records_expect(no_cose),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    mismatch = copy.deepcopy(base)
    mismatch["checkpoint"]["timestamp"] = "2026-10-15T00:00:01Z"
    cases.append(case(
        "neg-checkpoint-field-differs-from-signed",
        "The JSON copy's timestamp differs from the signed statement's.",
        mismatch,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_mismatch:timestamp"),
            interval_coverage=UNANCHORED, per_record_membership=UNANCHORED),
         "witnesses": ABSENT, "records": records_expect(mismatch),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    typed = copy.deepcopy(base)
    typed["checkpoint"]["prev_size"] = False
    cases.append(case(
        "neg-checkpoint-field-differs-in-type",
        "prev_size is JSON false where the signed statement says 0: a different value.",
        typed,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_mismatch:prev_size"),
            interval_coverage=UNANCHORED, per_record_membership=UNANCHORED),
         "witnesses": ABSENT, "records": records_expect(typed),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    missing_root = copy.deepcopy(base)
    del missing_root["checkpoint"]["log_id"]
    cases.append(case(
        "neg-checkpoint-field-missing",
        "The JSON copy has no log_id.",
        missing_root,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_missing:log_id"),
            interval_coverage=UNANCHORED, per_record_membership=UNANCHORED),
         "witnesses": ABSENT, "records": records_expect(missing_root),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    bad_sig = copy.deepcopy(base)
    raw = bytearray(cose_bytes(base))
    raw[-1] ^= 0x01
    bad_sig["checkpoint"]["cose"] = b64u(bytes(raw))
    cases.append(case(
        "neg-checkpoint-signature-invalid",
        "The last byte of the COSE checkpoint's signature is flipped.",
        bad_sig,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_signature_invalid"),
            interval_coverage=claim("fail", "checkpoint_authentication_invalid"),
            per_record_membership=claim("fail", "checkpoint_authentication_invalid")),
         "witnesses": ABSENT, "records": records_expect(bad_sig),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    malformed = copy.deepcopy(base)
    malformed["checkpoint"]["cose"] = "not base64url!"
    cases.append(case(
        "neg-checkpoint-cose-malformed",
        "checkpoint.cose is not unpadded base64url.",
        malformed,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_signature_malformed"),
            interval_coverage=claim("fail", "checkpoint_authentication_invalid"),
            per_record_membership=claim("fail", "checkpoint_authentication_invalid")),
         "witnesses": ABSENT, "records": records_expect(malformed),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    unsigned_records = [dict(r) for r in base_records]
    del unsigned_records[1]["signature"], unsigned_records[1]["key_id"]
    unsigned = bundle_over(unsigned_records)
    cases.append(case(
        "incomplete-unsigned-record",
        "The second record carries no producer signature.",
        unsigned,
        {"verdict": "INCOMPLETE", "claims": claims(
            signatures=claim("withheld", f"producer_signature_unclaimed:{ids[1]}")),
         "witnesses": ABSENT, "records": records_expect(unsigned, {1: "unclaimed"}),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))
    cases.append(case(
        "neg-unsigned-record-signature-required",
        "The same Bundle, checked with require_signature.",
        unsigned,
        {"verdict": "INVALID", "claims": claims(
            signatures=claim("fail", f"producer_signature_unclaimed:{ids[1]}")),
         "witnesses": ABSENT, "records": records_expect(unsigned, {1: "unclaimed"}),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
        require_signature=True,
    ))

    forged_records = [dict(r) for r in base_records]
    forged_records[0] = signed(capsule("strict-1"), OTHER)
    forged_records[0]["key_id"] = raw_public(PRODUCER).hex()
    forged = bundle_over(forged_records)
    cases.append(case(
        "neg-record-signature-wrong-key",
        "The first record's envelope is signed by another key than its key_id.",
        forged,
        {"verdict": "INVALID", "claims": claims(
            signatures=claim("fail", f"producer_signature_invalid:{ids[0]}")),
         "witnesses": ABSENT, "records": records_expect(forged, {0: "invalid"}),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))

    edited = copy.deepcopy(base)
    edited["records"][2]["action_id"] = "strict-3-edited"
    cases.append(case(
        "neg-record-edited",
        "The third record's content is edited after signing: identity, signature, closure and membership fail.",
        edited,
        {"verdict": "INVALID", "claims": claims(
            records=claim("fail", f"record_identity_invalid:{ids[2]}"),
            signatures=claim("fail", f"producer_signature_invalid:{ids[2]}"),
            graph_closure=claim("fail", f"record_identity_invalid:{ids[2]}", "root_not_supplied_with_matching_identity"),
            per_record_membership=claim("fail", f"membership_record_unknown:{ids[2]}", "membership_record_missing:3")),
         "witnesses": ABSENT, "records": records_expect(edited, {2: "invalid"}, {2: False}),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))

    # Producer-selected: records 1 and 3 of the log, each with its own proof.
    selected = copy.deepcopy(base)
    selected["records"] = [base["records"][0], base["records"][2]]
    selected["completeness"]["selection"] = "producer-selected"
    cert = selected["completeness_certificate"]
    del cert["memberships"][ids[1]]
    cases.append(case(
        "incomplete-producer-selected",
        "Records 1 and 3 of the log, producer-selected: the interval is not checkable, each record's proof is.",
        selected,
        {"verdict": "INCOMPLETE", "claims": claims(
            interval_coverage=claim("withheld", "selection_not_checkable")),
         "witnesses": ABSENT, "records": records_expect(selected),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))
    selected_bad = copy.deepcopy(selected)
    proof = selected_bad["completeness_certificate"]["memberships"][ids[2]]["inclusion_proof"]
    proof["peaks_left"] = [hashlib.sha256(b"not a peak").hexdigest()]
    cases.append(case(
        "neg-producer-selected-proof-invalid",
        "The same, with the third record's inclusion proof edited.",
        selected_bad,
        {"verdict": "INVALID", "claims": claims(
            interval_coverage=claim("withheld", "selection_not_checkable"),
            per_record_membership=claim("fail", f"membership_proof_invalid:{ids[2]}")),
         "witnesses": ABSENT, "records": records_expect(selected_bad),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))

    payload = {"question": "strict"}
    digest = hashlib.sha256(jcs(payload)).hexdigest()
    disclosed_records = [dict(r) for r in base_records]
    disclosed_records[2] = signed(capsule("strict-3", model_attestation={"compute_attestation": {"agent_input_digest": digest}}))
    disclosed = bundle_over(disclosed_records)
    disclosed_id = disclosed_records[2]["capsule_id"]
    disclosed["disclosures"] = {disclosed_id: {"agent_input": payload}}
    cases.append(case(
        "pos-disclosure-matches",
        "A disclosures overlay whose member matches the digest its record commits to.",
        disclosed,
        {"verdict": "VALID", "claims": claims(disclosures=PASS), "witnesses": ABSENT,
         "records": records_expect(disclosed), "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))
    undisclosed = copy.deepcopy(disclosed)
    undisclosed["disclosures"][disclosed_id]["agent_input"] = {"question": "edited"}
    cases.append(case(
        "neg-disclosure-mismatch",
        "The same overlay with the disclosed member edited.",
        undisclosed,
        {"verdict": "INVALID", "claims": claims(
            disclosures=claim("fail", f"disclosure_mismatch:{disclosed_id}:agent_input")),
         "witnesses": ABSENT, "records": records_expect(undisclosed),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))

    not_bundle = copy.deepcopy(base)
    not_bundle["bundle_kind"] = "evidence-bundle/v1"
    cases.append(case(
        "neg-not-an-evidence-bundle-v2",
        "bundle_kind is not evidence-bundle/v2: refused before any other strict check.",
        not_bundle,
        {"verdict": "INVALID", "kind_ok": False, "claims": [{"name": "records", **claim("fail", "not_an_evidence_bundle_v2")}],
         "witnesses": None, "records": [], "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    # -- witness receipts over the base checkpoint --
    cose = cose_bytes(base)
    leaf = entry_hash(base["checkpoint"])

    def witnessed(*receipts: dict) -> dict:
        out = copy.deepcopy(base)
        out["checkpoint"]["witnesses"] = list(receipts)
        return out

    def receipt_expect(ts_url: str, binding: str, status: str, grade: str | None = None) -> dict:
        return {"ts_url": ts_url, "binding": binding, "status": status, "grade": grade}

    def witness_case(case_id: str, description: str, bundle: dict, witnesses: dict, *, verdict: str = "VALID", directory: bool = True) -> None:
        cases.append(case(case_id, description, bundle, {
            "verdict": verdict, "claims": claims(), "witnesses": witnesses, "records": records_expect(bundle),
            "checkpoint_authenticated": True, "signer_matches_checkpoint": False,
        }, witness_directory=directory))

    one_cll = witnessed(cll_receipt(leaf))
    witness_case("pos-witness-cll", "A CLL witness receipt verifies under the directory's key for it.", one_cll,
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(CLL_URL, "cll", "pass", "mmr-verified")]})
    witness_case("pos-witness-cll-no-directory", "The same receipt with no directory: no witness is trusted.", one_cll,
                 {"status": "withheld", "findings": [f"witness_unverified:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "withheld")]}, directory=False)
    witness_case("pos-witness-cll-legacy-grade", "A receipt labelled with the pre-rename grade reads as observed-only.",
                 witnessed(cll_receipt(leaf, grade="countersigned-observed")),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(CLL_URL, "cll", "pass", "observed-only")]})
    witness_case("pos-witness-cll-no-grade", "A receipt with no grade label verifies, with no grade.",
                 witnessed(cll_receipt(leaf, grade=None)),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(CLL_URL, "cll", "pass")]})
    witness_case("pos-witness-unlisted", "A receipt from a witness the directory has no row for is not checked.",
                 witnessed(cll_receipt(leaf, ts_url=UNLISTED_URL)),
                 {"status": "withheld", "findings": [f"witness_unverified:{UNLISTED_URL}"],
                  "receipts": [receipt_expect(UNLISTED_URL, "cll", "withheld")]})
    keyless = "https://keyless-witness.example"
    witness_case("pos-witness-row-without-keys", "A directory row with no keys checks nothing.",
                 witnessed(cll_receipt(leaf, ts_url=keyless)),
                 {"status": "withheld", "findings": [f"witness_unverified:{keyless}"],
                  "receipts": [receipt_expect(keyless, "cll", "withheld")]})
    stub = cll_receipt(leaf)
    stub["is_stub"] = True
    witness_case("pos-witness-stub", "A stub receipt never counts.", witnessed(stub),
                 {"status": "withheld", "findings": [f"witness_unverified:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "withheld")]})
    other_leaf = hashlib.sha256(b"another checkpoint").hexdigest()
    witness_case("neg-witness-cll-other-checkpoint", "A genuine receipt for another checkpoint.",
                 witnessed(cll_receipt(other_leaf)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "fail")]}, verdict="INVALID")
    witness_case("neg-witness-cll-wrong-key", "A receipt for this checkpoint signed by a key the row does not list.",
                 witnessed(cll_receipt(leaf, OTHER)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "fail")]}, verdict="INVALID")
    no_size = cll_receipt(leaf)
    del no_size["tree_size"]
    witness_case("neg-witness-malformed", "A receipt entry without tree_size, beside a good one.",
                 witnessed(cll_receipt(leaf), no_size),
                 {"status": "fail", "findings": ["witness_receipt_malformed:1"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "pass", "mmr-verified")]}, verdict="INVALID")
    witness_case("pos-witness-scrapi", "A SCRAPI receipt over SHA-256 of the COSE checkpoint, no grade label.",
                 witnessed(scrapi_receipt(cose)),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(SCRAPI_URL, "scrapi", "pass", "observed-only")]})
    witness_case("pos-witness-scrapi-unknown-grade", "A SCRAPI receipt with an unknown grade label reads as observed-only.",
                 witnessed(scrapi_receipt(cose, grade="fully-audited")),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(SCRAPI_URL, "scrapi", "pass", "observed-only")]})
    witness_case("neg-witness-scrapi-other-statement", "A SCRAPI receipt over other bytes.",
                 witnessed(scrapi_receipt(b"other statement")),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{SCRAPI_URL}"],
                  "receipts": [receipt_expect(SCRAPI_URL, "scrapi", "fail")]}, verdict="INVALID")
    witness_case("pos-witness-rekor", "A Rekor dsse entry for the COSE checkpoint, logged under the checkpoint's key.",
                 witnessed(rekor_receipt(cose)),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(REKOR_URL, "rekor", "pass", "observed-only")]})
    witness_case("neg-witness-rekor-other-payload", "A Rekor entry whose payloadHash is other bytes.",
                 witnessed(rekor_receipt(cose, payload=b"other statement")),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{REKOR_URL}"],
                  "receipts": [receipt_expect(REKOR_URL, "rekor", "fail")]}, verdict="INVALID")
    witness_case("neg-witness-rekor-other-signer", "A Rekor entry for these bytes logged under another key.",
                 witnessed(rekor_receipt(cose, OTHER)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{REKOR_URL}"],
                  "receipts": [receipt_expect(REKOR_URL, "rekor", "fail")]}, verdict="INVALID")
    nokey = "rekor+https://rekor-nokey.example"
    nokey_receipt = rekor_receipt(cose)
    nokey_receipt["ts_url"] = nokey
    witness_case("pos-witness-rekor-row-without-key", "A rekor row listing a log ID with no public key checks nothing.",
                 witnessed(nokey_receipt),
                 {"status": "withheld", "findings": [f"witness_unverified:{nokey}"],
                  "receipts": [receipt_expect(nokey, "rekor", "withheld")]})
    witness_case("pos-witness-three-bindings", "One receipt of each binding, all verifying.",
                 witnessed(cll_receipt(leaf), rekor_receipt(cose), scrapi_receipt(cose)),
                 {"status": "pass", "findings": [], "receipts": [
                     receipt_expect(CLL_URL, "cll", "pass", "mmr-verified"),
                     receipt_expect(REKOR_URL, "rekor", "pass", "observed-only"),
                     receipt_expect(SCRAPI_URL, "scrapi", "pass", "observed-only")]})

    unanchored = copy.deepcopy(no_cose)
    unanchored["checkpoint"]["witnesses"] = [cll_receipt(leaf)]
    cases.append(case(
        "incomplete-witness-on-unsigned-checkpoint",
        "Receipts are never checked against a checkpoint that is not signed.",
        unanchored,
        {"verdict": "INCOMPLETE", "claims": claims(
            checkpoint=claim("withheld", "checkpoint_signature_absent"),
            interval_coverage=UNANCHORED, per_record_membership=UNANCHORED),
         "witnesses": {"status": "withheld", "findings": ["checkpoint_unverified"], "receipts": []},
         "records": records_expect(unanchored), "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
        witness_directory=True,
    ))
    return cases


def record_cases() -> list[dict]:
    """``verify_record_signature`` alone: one record each."""
    jcs_record = signed(capsule("record-jcs"))
    vintage = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-03",
        "format_version": "3",
        "action_id": "record-vintage",
        "action_type": "fyi",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": TIMESTAMP,
        "chain": {"parent_capsule_id": "11" * 32, "relation": "follows"},
        "constraints": [],
        "effect": None,
    }
    preimage = {k: v for k, v in vintage.items() if k != "chain"}
    vintage["capsule_id"] = hashlib.sha256(jcs(normalize(preimage))).hexdigest()
    vintage_signed = signed(vintage)
    half = dict(jcs_record)
    del half["signature"]
    unknown = signed({**capsule("record-other"), "canonicalization_id": "as-transmitted"},
                     capsule_id=hashlib.sha256(b"x").hexdigest())
    not_hex = dict(jcs_record)
    not_hex["signature"] = "zz"
    other = signed(capsule("record-jcs"), OTHER)
    other["key_id"] = raw_public(PRODUCER).hex()
    return [
        {"id": "authored-jcs", "description": "A format-4 record signed by its key_id.", "record": jcs_record,
         "expect": "authored"},
        {"id": "authored-jcs-n", "description": "A vintage record with no canonicalization_id: jcs-n drops chain and "
         "null or empty members.", "record": vintage_signed, "expect": "authored"},
        {"id": "unclaimed", "description": "No signature and no key_id.", "record": capsule("record-unsigned"),
         "expect": "unclaimed"},
        {"id": "invalid-half-claim", "description": "key_id without signature.", "record": half, "expect": "invalid"},
        {"id": "invalid-other-key", "description": "Signed by another key than key_id.", "record": other,
         "expect": "invalid"},
        {"id": "invalid-not-hex", "description": "signature is not hex.", "record": not_hex, "expect": "invalid"},
        {"id": "invalid-unknown-canonicalization", "description": "A canonicalization_id the Capsule ID cannot be "
         "recomputed under.", "record": unknown, "expect": "invalid"},
    ]


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    cases = build_cases()
    vectors = {
        "format_version": "1",
        "description": "verify_bundle strict mode: producer signatures, the signed checkpoint, producer-selected "
        "Bundles, the disclosures claim and witness receipts. See README.md.",
        "keys": {
            "producer_public_key": raw_public(PRODUCER).hex(),
            "other_public_key": raw_public(OTHER).hex(),
            "log_public_key": raw_public(LOG_KEY).hex(),
            "cll_witness_public_key": raw_public(CLL_WITNESS).hex(),
            "scrapi_public_key": raw_public(SCRAPI_KEY).hex(),
            "rekor_log_id": REKOR_LOG_ID,
        },
        "witness_directory": DIRECTORY,
        "cases": cases,
        "record_signatures": record_cases(),
    }
    files = {"vectors.json": dump(vectors)}
    files["manifest.json"] = dump({
        "format_version": "1",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()},
        "case_count": len(cases),
        "record_signature_count": len(vectors["record_signatures"]),
    })
    for name, data in files.items():
        (out / name).write_bytes(data)
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    sums = "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    (out / "SHA256SUMS").write_text(sums)


if __name__ == "__main__":
    main()
