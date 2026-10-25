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

Dependencies: ``agent-action-capsule[bundle,envelope]``, ``scitt-cose`` 0.3.0 or later (``build_receipt``'s
``iat``) and ``cryptography``.
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
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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
#: TIMESTAMP as a CWT NumericDate: a witness that registers the checkpoint in
#: the same second signs this ``iat``.
TIMESTAMP_SECONDS = 1792022400


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
P256_WITNESS = ec.derive_private_key(int.from_bytes(bytes([0x34]) * 32, "big") % (2**255), ec.SECP256R1())
K1_WITNESS = ec.derive_private_key(int.from_bytes(bytes([0x35]) * 32, "big") % (2**255), ec.SECP256K1())
P256_URL = "https://p256-witness.example"


def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + body


# Two well-formed SubjectPublicKeyInfo values that are not usable directory
# keys: an RSA key (a fixed public modulus, never used to sign) and a key under
# an unknown algorithm OID (1.3.6.1.4.1.32473.1, the documentation arc).
RSA_SPKI = rsa.RSAPublicNumbers(65537, (1 << 2047) | 0x1D).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
UNKNOWN_SPKI = _tlv(0x30, _tlv(0x30, _tlv(0x06, bytes([0x2B, 6, 1, 4, 1, 0x81, 0xFE, 0x59, 1])))
                    + _tlv(0x03, b"\x00" + bytes(32)))
K1_URL = "https://k1-witness.example"


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


def bundle_over(
    records: list[dict],
    *,
    log_key: Ed25519PrivateKey = LOG_KEY,
    cose: bool = True,
    prior_after: int | None = None,
    log_id: str = LOG_ID,
) -> dict:
    """A Bundle over a whole log of ``records`` (seq 1..n), checkpoint signed by
    ``log_key``. With ``prior_after``, the checkpoint follows a prior one taken
    after that many records and carries the consistency proof between them."""
    store = MemoryNodeStore()
    prev_size, prev_root, prev_peaks = 0, "", None
    for index, record in enumerate(records):
        if prior_after is not None and index == prior_after:
            prev_size = store.size()
            prev_peaks = [store.node(p) for p in peaks(prev_size)]
            prev_root = root_from_peaks(prev_peaks).hex()
        add_leaf(store, leaf_hash(bytes.fromhex(record["capsule_id"])))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    root = root_from_peaks(peak_hashes).hex()
    signer = _StatementSigner(log_key)
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=log_id, mmr_size=size, root=root, prev_size=prev_size, prev_root=prev_root,
        key_id=signer.key_id, timestamp=TIMESTAMP, signature="",
    )
    checkpoint = {
        "log_id": log_id, "mmr_size": size, "root": root, "prev_size": prev_size, "prev_root": prev_root,
        "key_id": signer.key_id, "timestamp": TIMESTAMP,
    }
    if cose:
        proof = core.consistency_proof(store, prev_size, size) if prev_size else None
        checkpoint["cose"] = b64u(checkpoint_to_cose(
            cp, signer, peak_hashes, prev_peak_hashes=prev_peaks, consistency_proof=proof))
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
            "log_id": log_id, "range_root": root, "first_seq": 1, "last_seq": n, "body_digests": ids,
            "range_proof": {
                "from_seq": 1, "to_seq": n, "size": rp.size, "from_index": rp.from_index,
                "to_index": rp.to_index, "witness": list(rp.witness),
            },
            "memberships": {
                cid: {
                    "log_coordinates": {"log_id": log_id, "seq": i + 1, "leaf_index": i},
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


def cll_receipt(
    leaf: str, key: Ed25519PrivateKey = CLL_WITNESS, *, ts_url: str = CLL_URL, grade: str | None = "mmr-verified",
    iat: int | None = None,
) -> dict:
    """A ``cll`` receipt; with ``iat``, the witness signs it into the protected
    CWT claims (label 15, claim 6). Without it the bytes are the older wire
    shape, unchanged."""
    receipt = build_receipt(
        leaf_entry_hex=leaf, leaf_index=0, tree_entries_hex=[leaf], alg="EdDSA",
        log_private_key_pem=private_pem(key), grade=grade, iat=iat,
    )
    return {"ts_url": ts_url, "entry_hash": leaf, "receipt_b64": b64(receipt), "leaf_index": 0, "tree_size": 1}


def attached_payload_receipt(leaf: str) -> dict:
    """A genuine-looking ``cll`` receipt whose payload is attached and signed:
    the signature covers that payload, not the rebuilt root, so it binds
    nothing. A verifier must refuse it, not verify the attached bytes."""
    import cbor2

    genuine = cll_receipt(leaf)
    outer = cbor2.loads(base64.b64decode(genuine["receipt_b64"]))
    protected = cbor2.loads(outer.value[0])
    forged = sign_sign1(
        b"any payload the witness key signed",
        alg="EdDSA",
        private_key_pem=private_pem(CLL_WITNESS),
        protected={k: v for k, v in protected.items() if k != 1},
        unprotected=dict(outer.value[1]),
    )
    return {**genuine, "receipt_b64": b64(forged)}


def resigned_receipt(leaf: str, protected_overrides: dict[int, Any]) -> dict:
    """A ``cll`` receipt for ``leaf`` signed over the right root by the listed
    key, but with protected-header values the profile refuses (``vds``,
    ``alg``). Built by hand: the COSE library would not write them."""
    import cbor2

    genuine = cll_receipt(leaf)
    outer = cbor2.loads(base64.b64decode(genuine["receipt_b64"]))
    protected = {**cbor2.loads(outer.value[0]), **protected_overrides}
    protected_bstr = cbor2.dumps(protected, canonical=True)
    root = hashlib.sha256(b"\x00" + bytes.fromhex(leaf)).digest()  # RFC 9162 leaf hash of a one-leaf tree
    signature = CLL_WITNESS.sign(cbor2.dumps(["Signature1", protected_bstr, b"", root]))
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, outer.value[1], None, signature]))
    return {**genuine, "receipt_b64": b64(forged)}


def unprotected_iat_receipt(leaf: str, iat: int) -> dict:
    """A genuine ``cll`` receipt with no protected ``iat``, given CWT claims
    carrying ``iat`` in its unprotected header, which no signature covers: it
    still verifies, and it has no registration time."""
    import cbor2

    genuine = cll_receipt(leaf)
    outer = cbor2.loads(base64.b64decode(genuine["receipt_b64"]))
    unprotected = {**outer.value[1], 15: {6: iat}}
    moved = cbor2.dumps(cbor2.CBORTag(18, [outer.value[0], unprotected, None, outer.value[3]]), canonical=True)
    return {**genuine, "receipt_b64": b64(moved)}


def es256_receipt(leaf: str, key: Any, ts_url: str) -> dict:
    """A ``cll`` receipt signed ES256 by ``key``, built by hand with RFC 6979
    deterministic ECDSA so the vectors stay reproducible (the COSE library's
    ES256 signatures are randomized)."""
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    genuine = cll_receipt(leaf, ts_url=ts_url)
    outer = cbor2.loads(base64.b64decode(genuine["receipt_b64"]))
    protected_bstr = cbor2.dumps({1: -7, 395: 1, -65537: "mmr-verified"}, canonical=True)
    root = hashlib.sha256(b"\x00" + bytes.fromhex(leaf)).digest()  # RFC 9162 leaf hash of a one-leaf tree
    der = key.sign(cbor2.dumps(["Signature1", protected_bstr, b"", root]),
                   ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s_ = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s_.to_bytes(32, "big")
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, outer.value[1], None, signature]))
    return {**genuine, "receipt_b64": b64(forged)}


def scrapi_receipt(cose: bytes, *, grade: str | None = None, iat: int | None = None) -> dict:
    leaf = hashlib.sha256(cose).hexdigest()
    receipt = build_receipt(
        leaf_entry_hex=leaf, leaf_index=0, tree_entries_hex=[leaf], alg="EdDSA",
        log_private_key_pem=private_pem(SCRAPI_KEY), grade=grade, iat=iat,
    )
    return {"ts_url": SCRAPI_URL, "entry_hash": leaf, "receipt_b64": b64(receipt), "leaf_index": 0, "tree_size": 1}


def _sorted_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def rekor_receipt(
    cose: bytes, checkpoint_key: Ed25519PrivateKey = LOG_KEY, *, payload: bytes | None = None, string_time: bool = False
) -> dict:
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
    if string_time:
        receipt["integratedTime"] = "1792022400"  # the signed value, as a JSON string
    return {"ts_url": REKOR_URL, "entry_hash": hashlib.sha256(cose).hexdigest(),
            "receipt_b64": b64(_sorted_json(receipt)), "leaf_index": 7, "tree_size": 8}


DIRECTORY = {
    "directory_version": "1",
    "witnesses": [
        {"name": "CLL witness", "endpoint": "https://cll-witness.example", "since": "2026-01-01",
         "key_ids": [raw_public(CLL_WITNESS).hex()]},
        {"name": "K1 witness", "endpoint": "https://k1-witness.example", "since": "2026-01-01",
         "key_ids": [hashlib.sha256(spki_der(K1_WITNESS)).hexdigest()], "public_keys": [b64(spki_der(K1_WITNESS))]},
        {"name": "Keyless witness", "endpoint": "https://keyless-witness.example", "since": "2026-01-01", "key_ids": []},
        {"name": "Off-curve witness", "endpoint": "https://off-curve-witness.example", "since": "2026-01-01",
         "key_ids": ["ff" * 32]},
        {"name": "Null binding witness", "endpoint": "https://null-binding-witness.example", "since": "2026-01-01",
         "binding": None, "key_ids": [raw_public(CLL_WITNESS).hex()]},
        {"name": "P-256 witness", "endpoint": "https://p256-witness.example", "since": "2026-01-01",
         "key_ids": [hashlib.sha256(spki_der(P256_WITNESS)).hexdigest()], "public_keys": [b64(spki_der(P256_WITNESS))]},
        {"name": "Rekor", "endpoint": "https://rekor.example", "since": "2026-01-01", "binding": "rekor",
         "key_ids": [REKOR_LOG_ID], "public_keys": [b64(spki_der(REKOR_KEY))]},
        {"name": "Rekor with an RSA key", "endpoint": "https://rekor-rsa.example", "since": "2026-01-01",
         "binding": "rekor", "key_ids": [hashlib.sha256(RSA_SPKI).hexdigest()], "public_keys": [b64(RSA_SPKI)]},
        {"name": "Rekor with an unknown key", "endpoint": "https://rekor-unknown.example", "since": "2026-01-01",
         "binding": "rekor", "key_ids": [hashlib.sha256(UNKNOWN_SPKI).hexdigest()],
         "public_keys": [b64(UNKNOWN_SPKI)]},
        {"name": "Rekor without key", "endpoint": "https://rekor-nokey.example", "since": "2026-01-01",
         "binding": "rekor", "key_ids": [REKOR_LOG_ID]},
        {"name": "SCITT service", "endpoint": "https://scitt.example", "since": "2026-01-01", "binding": "scrapi",
         "key_ids": [raw_public(SCRAPI_KEY).hex()]},
        {"name": "Two-key witness", "endpoint": "https://two-key-witness.example", "since": "2026-01-01",
         "key_ids": [raw_public(OTHER).hex(), raw_public(CLL_WITNESS).hex()]},
    ],
}


#: The directory key id a passing receipt from each witness verifies under.
PASS_KEY_IDS = {
    CLL_URL: raw_public(CLL_WITNESS).hex(),
    P256_URL: hashlib.sha256(spki_der(P256_WITNESS)).hexdigest(),
    REKOR_URL: REKOR_LOG_ID,
    SCRAPI_URL: raw_public(SCRAPI_KEY).hex(),
    "https://two-key-witness.example": raw_public(CLL_WITNESS).hex(),
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
    seqs = {cid: m["log_coordinates"]["seq"] for cid, m in bundle["completeness_certificate"]["memberships"].items()
            if "log_coordinates" in m}
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


def _with_witnesses(bundle: dict, *receipts: dict) -> dict:
    out = copy.deepcopy(bundle)
    out["checkpoint"]["witnesses"] = list(receipts)
    return out


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

    selected_log = copy.deepcopy(selected)
    selected_log["completeness_certificate"]["log_id"] = "log:other"
    cases.append(case(
        "neg-producer-selected-certificate-log-id",
        "Producer-selected: the certificate's log_id is not the signed one, though the checkpoint's copy is.",
        selected_log,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_mismatch:log_id"),
            interval_coverage=claim("withheld", "selection_not_checkable", "checkpoint_unverified"),
            per_record_membership=claim("withheld", "checkpoint_unverified")),
         "witnesses": ABSENT, "records": records_expect(selected_log),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    selected_both = copy.deepcopy(selected)
    selected_both["completeness_certificate"]["log_id"] = "log:other"
    selected_both["checkpoint"]["log_id"] = "log:other"
    cases.append(case(
        "neg-producer-selected-both-log-ids",
        "Producer-selected: the certificate's and the checkpoint's log_id both name another log; one mismatch.",
        selected_both,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_mismatch:log_id"),
            interval_coverage=claim("withheld", "selection_not_checkable", "checkpoint_unverified"),
            per_record_membership=claim("withheld", "checkpoint_unverified")),
         "witnesses": ABSENT, "records": records_expect(selected_both),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))
    selected_null = copy.deepcopy(selected)
    selected_null["completeness_certificate"]["log_id"] = None
    del selected_null["checkpoint"]["log_id"]
    cases.append(case(
        "neg-producer-selected-certificate-log-id-null",
        "Producer-selected: the certificate's log_id is null and the checkpoint carries none.",
        selected_null,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_mismatch:log_id", "checkpoint_field_missing:log_id"),
            interval_coverage=claim("withheld", "selection_not_checkable", "checkpoint_unverified"),
            per_record_membership=claim("withheld", "checkpoint_unverified")),
         "witnesses": ABSENT, "records": records_expect(selected_null),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

    def selected_with(case_id: str, description: str, edit: Any, findings: list[str]) -> None:
        bundle = copy.deepcopy(selected)
        edit(bundle["completeness_certificate"]["memberships"])
        cases.append(case(case_id, description, bundle, {
            "verdict": "INVALID", "claims": claims(
                interval_coverage=claim("withheld", "selection_not_checkable"),
                per_record_membership=claim("fail", *findings)),
            "witnesses": ABSENT, "records": records_expect(bundle),
            "checkpoint_authenticated": True, "signer_matches_checkpoint": False,
        }))

    def wrong_log_and_seq(members: dict) -> None:
        members[ids[0]]["log_coordinates"]["log_id"] = "log:other"
        members[ids[2]]["log_coordinates"].update(seq=0, leaf_index=-1)

    def leaf_index_off(members: dict) -> None:
        members[ids[2]]["log_coordinates"]["leaf_index"] = 3

    def repeated_seq(members: dict) -> None:
        members[ids[2]]["log_coordinates"].update(seq=1, leaf_index=0)

    def unbound(members: dict) -> None:
        del members[ids[0]]["log_coordinates"]

    selected_with("neg-producer-selected-coordinates-log-and-seq",
                  "Producer-selected: one membership names another log, another has seq 0.", wrong_log_and_seq,
                  [f"membership_coordinates_invalid:{ids[0]}", f"membership_coordinates_invalid:{ids[2]}"])
    selected_with("neg-producer-selected-leaf-index", "Producer-selected: leaf_index is not seq - 1.",
                  leaf_index_off, [f"membership_coordinates_invalid:{ids[2]}"])
    selected_with("neg-producer-selected-repeated-seq", "Producer-selected: two memberships claim seq 1.",
                  repeated_seq, [f"membership_coordinates_invalid:{ids[2]}"])
    selected_with("neg-producer-selected-unbound", "Producer-selected: a record's membership has no coordinates.",
                  unbound, [f"membership_record_unbound:{ids[0]}"])

    continued = bundle_over(base_records, prior_after=2)
    cases.append(case(
        "pos-checkpoint-with-prior",
        "The checkpoint follows a prior one after two records and carries the consistency proof (prev_size > 0).",
        continued,
        {"verdict": "VALID", "claims": claims(), "witnesses": ABSENT, "records": records_expect(continued),
         "checkpoint_authenticated": True, "signer_matches_checkpoint": False},
    ))
    prior_null = copy.deepcopy(base)
    prior_null["checkpoint"]["prev_root"] = None
    cases.append(case(
        "neg-checkpoint-prev-root-null",
        "The first checkpoint's JSON copy says prev_root null where the signed statement says \"\".",
        prior_null,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("fail", "checkpoint_field_mismatch:prev_root"),
            interval_coverage=UNANCHORED, per_record_membership=UNANCHORED),
         "witnesses": ABSENT, "records": records_expect(prior_null),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
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

    duplicate = copy.deepcopy(base)
    duplicate["records"].append(copy.deepcopy(base["records"][2]))
    dup_records = records_expect(duplicate)
    dup_records[3]["identity_ok"] = False
    cases.append(case(
        "neg-record-duplicate",
        "The third record appears twice: the second copy is a record the plain verifier skipped.",
        duplicate,
        {"verdict": "INVALID", "claims": claims(
            records=claim("fail", f"record_identity_invalid:{ids[2]}"),
            graph_closure=claim("fail", f"record_duplicate:{ids[2]}")),
         "witnesses": ABSENT, "records": dup_records,
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
        return _with_witnesses(base, *receipts)

    def receipt_expect(
        ts_url: str, binding: str, status: str, grade: str | None = None, *,
        registration_time: int | None = None, reason: str | None = None,
    ) -> dict:
        """A receipt result. A passing receipt names the directory key it
        verified under, and its registration time or why it has none."""
        key_id = PASS_KEY_IDS[ts_url] if status == "pass" else None
        if status != "pass":
            reason = "receipt_not_passed"
        elif binding == "rekor":
            reason = "binding_without_iat"
        elif registration_time is None:
            reason = reason or "iat_absent"
        return {"ts_url": ts_url, "binding": binding, "status": status, "grade": grade, "key_id": key_id,
                "registration_time": registration_time, "registration_time_reason": reason}

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
    witness_case("neg-witness-cll-attached-payload",
                 "A receipt whose payload is attached and signed by the listed key: not bound to the root.",
                 witnessed(attached_payload_receipt(leaf)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "fail")]}, verdict="INVALID")
    for case_id, description, overrides in (
        ("neg-witness-cll-vds-ccf", "A receipt signed over the right root that declares vds 2 (CCF).", {395: 2}),
        ("neg-witness-cll-alg-unsupported", "A receipt signed over the right root that declares alg -257.",
         {1: -257}),
    ):
        witness_case(case_id, description, witnessed(resigned_receipt(leaf, overrides)),
                     {"status": "fail", "findings": [f"witness_receipt_invalid:{CLL_URL}"],
                      "receipts": [receipt_expect(CLL_URL, "cll", "fail")]}, verdict="INVALID")
    witness_case("pos-witness-cll-es256", "A cll receipt signed ES256 under the row's P-256 key.",
                 witnessed(es256_receipt(leaf, P256_WITNESS, P256_URL)),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(P256_URL, "cll", "pass", "mmr-verified")]})
    witness_case("neg-witness-cll-es256-other-curve",
                 "A receipt declaring ES256, signed with the secp256k1 key the row lists: that key does not count, "
                 "so the row's key id is read as a raw Ed25519 key and nothing verifies.",
                 witnessed(es256_receipt(leaf, K1_WITNESS, K1_URL)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{K1_URL}"],
                  "receipts": [receipt_expect(K1_URL, "cll", "fail")]}, verdict="INVALID")
    off_curve = "https://off-curve-witness.example"
    witness_case("neg-witness-cll-key-not-a-point",
                 "The row's key id is 32 bytes that are not an Ed25519 public key: nothing verifies under it.",
                 witnessed(cll_receipt(leaf, ts_url=off_curve)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{off_curve}"],
                  "receipts": [receipt_expect(off_curve, "cll", "fail")]}, verdict="INVALID")
    two_key = "https://two-key-witness.example"
    witness_case("pos-witness-cll-second-key", "The row's first key does not verify the receipt; its second does.",
                 witnessed(cll_receipt(leaf, ts_url=two_key)),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(two_key, "cll", "pass", "mmr-verified")]})
    null_binding = "https://null-binding-witness.example"
    witness_case("pos-witness-row-binding-null",
                 "The only row for this endpoint says binding null: it is no cll row, so the receipt is not checked.",
                 witnessed(cll_receipt(leaf, ts_url=null_binding)),
                 {"status": "withheld", "findings": [f"witness_unverified:{null_binding}"],
                  "receipts": [receipt_expect(null_binding, "cll", "withheld")]})
    not_a_stub = {**cll_receipt(leaf), "receipt_b64": b64(b"not a receipt"), "is_stub": 1}
    witness_case("neg-witness-stub-not-boolean",
                 "is_stub is 1, not JSON true: the entry is checked as a receipt, and its bytes are not one.",
                 witnessed(not_a_stub),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "fail")]}, verdict="INVALID")
    no_size = cll_receipt(leaf)
    del no_size["tree_size"]
    witness_case("neg-witness-malformed", "A receipt entry without tree_size, beside a good one.",
                 witnessed(cll_receipt(leaf), no_size),
                 {"status": "fail", "findings": ["witness_receipt_malformed:1"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "pass", "mmr-verified")]}, verdict="INVALID")
    empty_receipt = {**cll_receipt(leaf, ts_url="https://unlisted.example"), "receipt_b64": ""}
    witness_case("neg-witness-malformed-member-no-row",
                 "A receipt entry whose receipt_b64 is empty, for a witness the directory has no row for: malformed, "
                 "not merely unchecked.",
                 witnessed(empty_receipt),
                 {"status": "fail", "findings": ["witness_receipt_malformed:0"], "receipts": []}, verdict="INVALID")
    non_canonical = {**cll_receipt(leaf), "receipt_b64": "AB=="}
    hash_not_text = {**cll_receipt(leaf), "entry_hash": True}
    witness_case("neg-witness-malformed-members",
                 "Beside a good receipt, one whose receipt_b64 is not canonical base64 and one whose entry_hash is not a string.",
                 witnessed(cll_receipt(leaf), non_canonical, hash_not_text),
                 {"status": "fail", "findings": ["witness_receipt_malformed:1", "witness_receipt_malformed:2"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "pass", "mmr-verified")]}, verdict="INVALID")
    good = cll_receipt(leaf)
    shapes = [
        {**good, "ts_url": 7},
        {**good, "entry_hash": ""},
        {**good, "receipt_b64": good["receipt_b64"][:8] + "\n" + good["receipt_b64"][8:]},
        {**good, "receipt_b64": "AA"},  # "AA==" without its padding
        {**good, "is_stub": True, "receipt_b64": ""},
    ]
    witness_case("neg-witness-malformed-shapes",
                 "Beside a good receipt: a non-string ts_url, an empty entry_hash, a receipt_b64 with a line break, "
                 "one without its padding, and a stub with an empty receipt_b64.",
                 witnessed(good, *shapes),
                 {"status": "fail", "findings": [f"witness_receipt_malformed:{i}" for i in range(1, 6)],
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
    witness_case("neg-witness-rekor-string-integer", "integratedTime is the signed value as a JSON string.",
                 witnessed(rekor_receipt(cose, string_time=True)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{REKOR_URL}"],
                  "receipts": [receipt_expect(REKOR_URL, "rekor", "fail")]}, verdict="INVALID")
    nokey = "rekor+https://rekor-nokey.example"
    nokey_receipt = rekor_receipt(cose)
    nokey_receipt["ts_url"] = nokey
    witness_case("pos-witness-rekor-row-without-key", "A rekor row listing a log ID with no public key checks nothing.",
                 witnessed(nokey_receipt),
                 {"status": "withheld", "findings": [f"witness_unverified:{nokey}"],
                  "receipts": [receipt_expect(nokey, "rekor", "withheld")]})
    for case_id, url, what in (
        ("pos-witness-rekor-row-rsa-key", "rekor+https://rekor-rsa.example", "an RSA key"),
        ("pos-witness-rekor-row-unknown-key", "rekor+https://rekor-unknown.example",
         "a well-formed key under an unknown algorithm"),
    ):
        unusable = {**rekor_receipt(cose), "ts_url": url}
        witness_case(case_id, f"The rekor row's only public key is {what}: it is skipped, so the row has no key "
                     "for its log ID and the receipt is not checked.", witnessed(unusable),
                     {"status": "withheld", "findings": [f"witness_unverified:{url}"],
                      "receipts": [receipt_expect(url, "rekor", "withheld")]})
    witness_case("pos-witness-three-bindings", "One receipt of each binding, all verifying.",
                 witnessed(cll_receipt(leaf), rekor_receipt(cose), scrapi_receipt(cose)),
                 {"status": "pass", "findings": [], "receipts": [
                     receipt_expect(CLL_URL, "cll", "pass", "mmr-verified"),
                     receipt_expect(REKOR_URL, "rekor", "pass", "observed-only"),
                     receipt_expect(SCRAPI_URL, "scrapi", "pass", "observed-only")]})

    # -- registration time: the protected CWT iat of a passing COSE receipt --
    witness_case("pos-witness-registration-time",
                 "A cll receipt whose witness signed iat into its protected header, in the checkpoint's own second: "
                 "the receipt's registration time is that iat.",
                 witnessed(cll_receipt(leaf, iat=TIMESTAMP_SECONDS)),
                 {"status": "pass", "findings": [], "receipts": [
                     receipt_expect(CLL_URL, "cll", "pass", "mmr-verified", registration_time=TIMESTAMP_SECONDS)]})
    witness_case("pos-witness-registration-time-not-checkpoint-time",
                 "A receipt whose signed iat is 90 seconds after the checkpoint's timestamp: the registration time is "
                 "the iat, never the checkpoint's timestamp.",
                 witnessed(cll_receipt(leaf, iat=TIMESTAMP_SECONDS + 90)),
                 {"status": "pass", "findings": [], "receipts": [
                     receipt_expect(CLL_URL, "cll", "pass", "mmr-verified", registration_time=TIMESTAMP_SECONDS + 90)]})
    witness_case("pos-witness-registration-time-no-directory",
                 "A receipt with a signed iat and no directory: it is not checked, so it has no registration time.",
                 witnessed(cll_receipt(leaf, iat=TIMESTAMP_SECONDS)),
                 {"status": "withheld", "findings": [f"witness_unverified:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "withheld")]}, directory=False)
    witness_case("neg-witness-registration-time-wrong-key",
                 "A receipt with an iat, signed by a key the row does not list: it fails, so it has no registration time.",
                 witnessed(cll_receipt(leaf, OTHER, iat=TIMESTAMP_SECONDS)),
                 {"status": "fail", "findings": [f"witness_receipt_invalid:{CLL_URL}"],
                  "receipts": [receipt_expect(CLL_URL, "cll", "fail")]}, verdict="INVALID")
    witness_case("pos-witness-registration-time-unprotected",
                 "A receipt with no protected iat whose unprotected header carries one: no signature covers it, so "
                 "the receipt has no registration time.",
                 witnessed(unprotected_iat_receipt(leaf, TIMESTAMP_SECONDS)),
                 {"status": "pass", "findings": [], "receipts": [receipt_expect(CLL_URL, "cll", "pass", "mmr-verified")]})
    witness_case("pos-witness-registration-time-invalid",
                 "A receipt whose signed iat is a float: the receipt verifies, and its iat is no registration time.",
                 witnessed(resigned_receipt(leaf, {15: {6: TIMESTAMP_SECONDS + 0.5}})),
                 {"status": "pass", "findings": [], "receipts": [
                     receipt_expect(CLL_URL, "cll", "pass", "mmr-verified", reason="iat_invalid")]})
    for case_id, description, claims_value, reason in (
        ("pos-witness-registration-time-claims-not-a-map",
         "A receipt whose protected CWT claims (label 15) are an integer, not a map: no registration time.", 7,
         "iat_invalid"),
        ("pos-witness-registration-time-out-of-range",
         "A receipt whose signed iat is 2^53, past the largest integer every language reads exactly.", {6: 2**53},
         "iat_invalid"),
        ("pos-witness-registration-time-float-claim-key",
         "A receipt whose protected CWT claims key a time by the float 6.0: that is no iat claim.",
         {6.0: TIMESTAMP_SECONDS}, "iat_absent"),
    ):
        witness_case(case_id, description, witnessed(resigned_receipt(leaf, {15: claims_value})),
                     {"status": "pass", "findings": [], "receipts": [
                         receipt_expect(CLL_URL, "cll", "pass", "mmr-verified", reason=reason)]})
    witness_case("pos-witness-scrapi-registration-time", "A SCRAPI receipt with a signed iat.",
                 witnessed(scrapi_receipt(cose, iat=TIMESTAMP_SECONDS + 5)),
                 {"status": "pass", "findings": [], "receipts": [
                     receipt_expect(SCRAPI_URL, "scrapi", "pass", "observed-only", registration_time=TIMESTAMP_SECONDS + 5)]})

    cose_null = copy.deepcopy(base)
    cose_null["checkpoint"]["cose"] = None
    cases.append(case(
        "neg-checkpoint-cose-null",
        "checkpoint.cose is JSON null: the strict checkpoint claim reads it as absent; the plain verifier's "
        "proof claims refuse it as an authenticator that is present but not a string.",
        cose_null,
        {"verdict": "INVALID", "claims": claims(
            checkpoint=claim("withheld", "checkpoint_signature_absent"),
            interval_coverage=claim("fail", "checkpoint_authentication_invalid"),
            per_record_membership=claim("fail", "checkpoint_authentication_invalid")),
         "witnesses": ABSENT, "records": records_expect(cose_null),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None},
    ))

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
    declared = signed({**vintage, "canonicalization_id": "jcs-n"},
                      capsule_id=hashlib.sha256(jcs(normalize({**preimage, "canonicalization_id": "jcs-n"}))).hexdigest())
    declared["capsule_id"] = hashlib.sha256(jcs(normalize({**preimage, "canonicalization_id": "jcs-n"}))).hexdigest()
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
        {"id": "authored-jcs-n-declared", "description": "A vintage record declaring canonicalization_id jcs-n.",
         "record": declared, "expect": "authored"},
        {"id": "unclaimed", "description": "No signature and no key_id.", "record": capsule("record-unsigned"),
         "expect": "unclaimed"},
        {"id": "invalid-half-claim", "description": "key_id without signature.", "record": half, "expect": "invalid"},
        {"id": "invalid-other-key", "description": "Signed by another key than key_id.", "record": other,
         "expect": "invalid"},
        {"id": "invalid-null-members", "description": "signature and key_id are present as JSON null.",
         "record": {**capsule("record-null"), "signature": None, "key_id": None}, "expect": "invalid"},
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
